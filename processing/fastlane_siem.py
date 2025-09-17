#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import requests
from datetime import datetime

from pyspark.sql import SparkSession, functions as F, types as T

# --------------------------
# Config (env overrides ok)
# --------------------------
KAFKA_BOOTSTRAP   = os.getenv("KAFKA_BOOTSTRAP", "kafka:9092")
KAFKA_OFFSETS     = os.getenv("KAFKA_OFFSETS", "earliest")   # earliest en dev, latest en prod
SINK              = os.getenv("SINK", "console")              # console | es
ES_URL            = os.getenv("ES_URL", "http://elasticsearch:9200")
ES_INDEX          = os.getenv("ES_INDEX", "siem-scored-fast")
CHECKPOINT_DIR    = os.getenv("CHECKPOINT_DIR", "/tmp/ckpt-siem-fast")
APP_NAME          = os.getenv("APP_NAME", "siem-fastlane")
PIPELINE_VERSION  = os.getenv("PIPELINE_VERSION", "fastlane-0.1.2")

TRIGGER_SEC       = os.getenv("TRIGGER_SEC", "5 seconds")    # 5–10s conseillé pour démo
SHUFFLE_PARTS     = int(os.getenv("SPARK_SHUFFLE_PARTS", "8"))

# --------------------------
# Schemas (minimal)
# --------------------------
FW_SCHEMA = T.StructType([
    T.StructField("ts", T.StringType()),
    T.StructField("event_type", T.StringType()),
    T.StructField("source", T.StringType()),
    T.StructField("severity", T.StringType()),
    T.StructField("host", T.StringType()),
    T.StructField("event_id", T.StringType()),
    T.StructField("raw", T.StringType()),
    T.StructField("srcip", T.StringType()),
    T.StructField("dstip", T.StringType()),
    T.StructField("dstport", T.IntegerType())
])

WEB_SCHEMA = T.StructType([
    T.StructField("ts", T.StringType()),
    T.StructField("event_type", T.StringType()),
    T.StructField("source", T.StringType()),
    T.StructField("severity", T.StringType()),
    T.StructField("host", T.StringType()),
    T.StructField("event_id", T.StringType()),
    T.StructField("message", T.StringType()),
    T.StructField("client_ip", T.StringType()),
    T.StructField("status", T.IntegerType())
])

ESXI_SCHEMA = T.StructType([
    T.StructField("ts", T.StringType()),
    T.StructField("event_type", T.StringType()),
    T.StructField("source", T.StringType()),
    T.StructField("severity", T.StringType()),
    T.StructField("host", T.StringType()),
    T.StructField("event_id", T.StringType()),
    T.StructField("file", T.StringType()),
    T.StructField("message", T.StringType()),
    T.StructField("usage_pct", T.IntegerType())
])

# --------------------------
# Spark session
# --------------------------
spark = (
    SparkSession.builder
    .appName(APP_NAME)
    .config("spark.sql.shuffle.partitions", SHUFFLE_PARTS)
    .config("spark.sql.session.timeZone", "UTC")
    .config("spark.sql.streaming.statefulOperator.allowMultiple", "false")
    .getOrCreate()
)
spark.sparkContext.setLogLevel("WARN")

# --------------------------
# Kafka sources
# --------------------------
def read_kafka_topic(topic):
    return (
        spark.readStream
        .format("kafka")
        .option("kafka.bootstrap.servers", KAFKA_BOOTSTRAP)
        .option("subscribe", topic)
        .option("startingOffsets", KAFKA_OFFSETS)   # pris au 1er démarrage (checkpoint sinon)
        .option("failOnDataLoss", "false")
        .option("groupIdPrefix", APP_NAME)          # groupe lisible: siem-fastlane-*
        .load()
        .withColumn("kafka_topic", F.col("topic"))
        .withColumn("kafka_partition", F.col("partition"))
        .withColumn("kafka_offset", F.col("offset"))
        .withColumn("key_str", F.col("key").cast("string"))
        .withColumn("value_str", F.col("value").cast("string"))
    )

fw_raw  = read_kafka_topic("sec.firewall.raw")
web_raw = read_kafka_topic("sec.web.raw")
esx_raw = read_kafka_topic("sec.esxi.raw")

# --------------------------
# Parse JSON, normalize time
# --------------------------
def parse_json(df, schema):
    parsed = df.select(
        "kafka_topic", "kafka_partition", "kafka_offset", "key_str",
        F.from_json("value_str", schema).alias("j")
    ).select(
        "kafka_topic", "kafka_partition", "kafka_offset", "key_str", "j.*"
    )
    # Parse ISO ts -> timestamp
    parsed = parsed.withColumn("timestamp", F.to_timestamp(F.col("ts"))).drop("ts")
    return parsed

fw = (
    parse_json(fw_raw, FW_SCHEMA)
    .withWatermark("timestamp", "10 minutes")
    .withColumn("dstport", F.col("dstport").cast("int"))  # défensif
    .filter(F.col("dstport").isNotNull())
    .withColumn(
        "key",
        F.coalesce(
            F.col("key_str"),
            F.concat_ws(":", F.col("srcip"), F.col("dstport").cast("string"))
        )
    )
)

web = (
    parse_json(web_raw, WEB_SCHEMA)
    .withWatermark("timestamp", "10 minutes")
    .withColumn("status", F.col("status").cast("int"))     # défensif
    .filter(F.col("client_ip").isNotNull())
    .filter(F.col("status").isNotNull())
    .withColumn("key", F.coalesce(F.col("key_str"), F.col("client_ip")))
)

esx = (
    parse_json(esx_raw, ESXI_SCHEMA)
    # pas de watermark ici → on l'applique uniquement au moment de l'agrégat
    .withColumn("key", F.coalesce(F.col("key_str"), F.col("host")))
)

# --------------------------
# FIREWALL: 30s features & scoring (NO joins)
# --------------------------
fw30 = (
    fw.groupBy(
        F.window("timestamp", "30 seconds").alias("w30"),
        F.col("key"),
        F.col("dstport")
    )
    .agg(
        F.count(F.lit(1)).alias("count_30s"),
        F.max(
            F.when(
                (F.col("event_type") == "fw.ips.block") |
                (F.lower(F.col("raw")).contains("action=blocked")),
                1
            ).otherwise(0)
        ).alias("blocked_any")
    )
)

def score_firewall(df):
    # pondérations
    sensitive = (
        F.when(F.col("dstport").isin(22, 3389), F.lit(25))          # SSH/RDP
         .when(F.col("dstport").isin(9200, 9092, 5601), F.lit(15))  # ES/Kafka/Kibana
         .when(F.col("dstport").isin(443, 80), F.lit(10))           # Web
         .otherwise(F.lit(0))
    )
    s_burst = (
        F.when(F.col("count_30s") >= 40, F.lit(50))
         .when(F.col("count_30s") >= 25, F.lit(35))
         .when(F.col("count_30s") >= 15, F.lit(20))
         .otherwise(F.lit(0))
    )
    s_blocked = F.when(F.col("blocked_any") == 1, F.lit(30)).otherwise(F.lit(0))

    score_expr = F.least(F.lit(100), s_burst + sensitive + s_blocked)

    severity_expr = (
        F.when(score_expr >= 90, F.lit("critical"))
         .when(score_expr >= 75, F.lit("high"))
         .when(score_expr >= 50, F.lit("medium"))
         .when(score_expr >= 25, F.lit("low"))
         .otherwise(F.lit("info"))
    )

    reason = F.concat(
        F.lit("Firewall 30s burst on "),
        F.col("dstport").cast("string"),
        F.lit(": "),
        F.col("count_30s").cast("string"),
        F.lit(" hits"),
        F.when(F.col("blocked_any") == 1, F.lit(" [blocked]")).otherwise(F.lit(""))
    )

    evidence = F.struct(
        F.lit("30s").alias("win"),
        F.col("count_30s").alias("count_30s"),
        F.col("dstport").alias("dstport"),
        (F.col("blocked_any") == 1).alias("blocked")
    )

    return df.select(
        F.col("w30.end").alias("@timestamp"),
        F.lit("firewall").alias("source"),
        F.col("key"),
        score_expr.alias("score"),
        severity_expr.alias("severity"),
        reason.alias("reason"),
        evidence.alias("evidence"),
        F.lit("sec.firewall.raw").alias("kafka_topic"),
        F.lit(PIPELINE_VERSION).alias("pipeline_version")
    )


fw_scored = score_firewall(fw30)

# --------------------------
# WEB: 60s features & scoring
# --------------------------
def extract_path(col_msg):
    return F.regexp_extract(col_msg, r'\"(?:GET|POST)\s+([^\"\s]+)', 1)

web_feats = (
    web.withColumn("is_4xx", (F.col("status") >= 400) & (F.col("status") <= 499))
       .withColumn("is_5xx", (F.col("status") >= 500) & (F.col("status") <= 599))
       .withColumn("path", extract_path(F.col("message")))
       .withColumn("is_admin",
                   F.col("path").startswith("/admin") | F.col("path").startswith("/login"))
       .groupBy(
           F.window("timestamp", "60 seconds").alias("w60"),
           F.col("key")
       )
       .agg(
           F.count(F.lit(1)).alias("n"),
           F.sum(F.col("is_4xx").cast("int")).alias("n_4xx"),
           F.sum(F.col("is_5xx").cast("int")).alias("n_5xx"),
           F.sum(F.col("is_admin").cast("int")).alias("admin_hits"),
           F.max(
               F.when(
                   (F.col("event_type") == "web.waf.block") |
                   ((F.col("status") == 403) & F.col("is_admin")),
                   1
               ).otherwise(0)
           ).alias("waf_block")
       )
       .withColumn("rate_4xx", F.when(F.col("n") > 0, F.col("n_4xx")/F.col("n")).otherwise(F.lit(0.0)))
       .withColumn("rate_5xx", F.when(F.col("n") > 0, F.col("n_5xx")/F.col("n")).otherwise(F.lit(0.0)))
)

def score_web(df):
    n_ok    = (F.col("n") >= 5)
    s_5xx   = F.when(n_ok & (F.col("rate_5xx") >= 0.10), F.lit(45)).otherwise(F.lit(0))
    s_4xx   = F.when(n_ok & (F.col("rate_4xx") >= 0.40), F.lit(25)).otherwise(F.lit(0))
    s_admin = (
        F.when(F.col("admin_hits") >= 10, F.lit(40))
         .when(F.col("admin_hits") >= 5,  F.lit(25))
         .otherwise(F.lit(0))
    )
    s_waf   = F.when(F.col("waf_block") == 1, F.lit(30)).otherwise(F.lit(0))
    s_burst = F.when(F.col("n") >= 100, F.lit(15)).otherwise(F.lit(0))

    score_expr = F.least(F.lit(100), s_5xx + s_4xx + s_admin + s_waf + s_burst)

    severity_expr = (
        F.when(score_expr >= 90, F.lit("critical"))
         .when(score_expr >= 75, F.lit("high"))
         .when(score_expr >= 50, F.lit("medium"))
         .when(score_expr >= 25, F.lit("low"))
         .otherwise(F.lit("info"))
    )

    reason = F.concat(
        F.lit("Web anomalies from "), F.col("key"),
        F.lit(": admin_hits="), F.col("admin_hits").cast("string"),
        F.lit(", 4xx="), (F.round(F.col("rate_4xx") * 100, 0)).cast("string"), F.lit("%"),
        F.lit(", 5xx="), (F.round(F.col("rate_5xx") * 100, 0)).cast("string"), F.lit("%"),
        F.when(F.col("waf_block") == 1, F.lit(" [WAF block]")).otherwise(F.lit(""))
    )

    evidence = F.struct(
        F.lit("60s").alias("win"),
        F.col("n").alias("n"),
        F.round(F.col("rate_4xx"), 3).alias("rate_4xx"),
        F.round(F.col("rate_5xx"), 3).alias("rate_5xx"),
        F.col("admin_hits").alias("admin_hits")
    )

    return df.select(
        F.col("w60.end").alias("@timestamp"),
        F.lit("web").alias("source"),
        F.col("key"),
        score_expr.alias("score"),
        severity_expr.alias("severity"),
        reason.alias("reason"),
        evidence.alias("evidence"),
        F.lit("sec.web.raw").alias("kafka_topic"),
        F.lit(PIPELINE_VERSION).alias("pipeline_version")
    )

web_scored = score_web(web_feats)

# --------------------------
# ESXi: agrégation anti-spam (2 min, max usage, nb msgs)
# --------------------------
esx_agg = (
    esx.withWatermark("timestamp", "15 minutes")   # unique watermark sur ESXi, appliquée ici seulement
       .groupBy(F.window("timestamp", "2 minutes").alias("w2"), F.col("host"))
       .agg(
           F.max("usage_pct").alias("max_usage"),
           F.count(F.lit(1)).alias("n_msgs")
       )
       .filter(F.col("max_usage") >= 85)
       .select(
           F.col("w2.end").alias("@timestamp"),
           F.lit("esxi").alias("source"),
           F.col("host").alias("key"),
           F.lit(95.0).alias("score"),
           F.lit("critical").alias("severity"),
           F.concat(
               F.lit("ESXi datastore alert on "),
               F.col("host"),
               F.lit(": max "),
               F.col("max_usage").cast("string"),
               F.lit("% in last 2m (threshold >85%)")
           ).alias("reason"),
           F.struct(
               F.lit("2m").alias("win"),
               F.lit("datastore").alias("alert"),
               F.col("max_usage").alias("max_usage"),
               F.col("n_msgs").alias("n_msgs")
           ).alias("evidence"),
           F.lit("sec.esxi.raw").alias("kafka_topic"),
           F.lit(PIPELINE_VERSION).alias("pipeline_version")
       )
)

# --------------------------
# Normalize evidence → JSON + union
# --------------------------
fw_scored  = fw_scored.withColumn("evidence", F.to_json(F.col("evidence")))
web_scored = web_scored.withColumn("evidence", F.to_json(F.col("evidence")))
esx_agg    = esx_agg.withColumn("evidence", F.to_json(F.col("evidence")))

alerts_cols = ["@timestamp","source","key","score","severity","reason","evidence","kafka_topic","pipeline_version"]
alerts = (
    fw_scored.select(alerts_cols)
    .unionByName(web_scored.select(alerts_cols))
    .unionByName(esx_agg.select(alerts_cols))
).withColumn("score", F.col("score").cast("double"))

# --------------------------
# Sink: console (dev) ou Elasticsearch (prod)
# --------------------------
def foreach_batch_es(df, epoch_id: int):
    if df.rdd.isEmpty():
        return
    rows = [json.loads(r) for r in df.toJSON().collect()]
    lines = []
    for doc in rows:
        if isinstance(doc.get("@timestamp"), (int, float)):
            doc["@timestamp"] = datetime.utcfromtimestamp(doc["@timestamp"]).isoformat() + "Z"
        action = {"index": {"_index": ES_INDEX}}
        lines.append(json.dumps(action))
        lines.append(json.dumps(doc, ensure_ascii=False))
    payload = "\n".join(lines) + "\n"
    url = f"{ES_URL.rstrip('/')}/_bulk"
    r = requests.post(url, data=payload, headers={"Content-Type": "application/x-ndjson"})
    if r.status_code >= 300:
        raise RuntimeError(f"Elasticsearch bulk error {r.status_code}: {r.text[:500]}")

if SINK == "console":
    (
        alerts.writeStream
        .outputMode("update")
        .format("console")
        .option("truncate", True)     # moins verbeux pour éviter le "falling behind"
        .option("numRows", 20)
        .trigger(processingTime=TRIGGER_SEC)
        .option("checkpointLocation", os.path.join(CHECKPOINT_DIR, PIPELINE_VERSION, "console"))
        .queryName(f"{APP_NAME}-console")
        .start()
        .awaitTermination()
    )
else:
    (
        alerts.writeStream
        .outputMode("append")
        .foreachBatch(foreach_batch_es)
        .trigger(processingTime=TRIGGER_SEC)
        .option("checkpointLocation", os.path.join(CHECKPOINT_DIR, PIPELINE_VERSION, "es"))
        .queryName(f"{APP_NAME}-es")
        .start()
        .awaitTermination()
    )
