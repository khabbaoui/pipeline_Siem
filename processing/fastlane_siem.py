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
KAFKA_TOPICS_PATTERN = os.getenv("KAFKA_TOPICS_PATTERN", "sec\\..*").strip()
if not KAFKA_TOPICS_PATTERN:
    KAFKA_TOPICS_PATTERN = None
SINK              = os.getenv("SINK", "console")              # console | es
ES_URL            = os.getenv("ES_URL", "http://elasticsearch:9200")
ES_INDEX          = os.getenv("ES_INDEX", "siem-scored-fast")
CHECKPOINT_DIR    = os.getenv("CHECKPOINT_DIR", "/tmp/ckpt-siem-fast")
APP_NAME          = os.getenv("APP_NAME", "siem-fastlane")
PIPELINE_VERSION  = os.getenv("PIPELINE_VERSION", "fastlane-0.1.2")

TRIGGER_SEC       = os.getenv("TRIGGER_SEC", "5 seconds")    # 5–10s conseillé pour démo
SHUFFLE_PARTS     = int(os.getenv("SPARK_SHUFFLE_PARTS", "8"))

# --------------------------
# Schemas
# --------------------------
BASE_FIELDS = [
    T.StructField("ts", T.StringType()),
    T.StructField("event_type", T.StringType()),
    T.StructField("source", T.StringType()),
    T.StructField("severity", T.StringType()),
    T.StructField("host", T.StringType()),
    T.StructField("event_id", T.StringType()),
]

FW_SCHEMA = T.StructType(BASE_FIELDS + [
    T.StructField("raw", T.StringType()),
    T.StructField("srcip", T.StringType()),
    T.StructField("dstip", T.StringType()),
    T.StructField("dstport", T.IntegerType()),
])

WEB_SCHEMA = T.StructType(BASE_FIELDS + [
    T.StructField("message", T.StringType()),
    T.StructField("client_ip", T.StringType()),
    T.StructField("status", T.IntegerType()),
])

ESXI_SCHEMA = T.StructType(BASE_FIELDS + [
    T.StructField("file", T.StringType()),
    T.StructField("message", T.StringType()),
    T.StructField("usage_pct", T.IntegerType()),
])

AUTH_SCHEMA = T.StructType(BASE_FIELDS + [
    T.StructField("username", T.StringType()),
    T.StructField("outcome", T.StringType()),
    T.StructField("srcip", T.StringType()),
])

DNS_SCHEMA = T.StructType(BASE_FIELDS + [
    T.StructField("message", T.StringType()),
    T.StructField("client_ip", T.StringType()),
    T.StructField("qname", T.StringType()),
    T.StructField("qtype", T.StringType()),
    T.StructField("rcode", T.StringType()),
])

IDS_SCHEMA = T.StructType(BASE_FIELDS + [
    T.StructField("srcip", T.StringType()),
    T.StructField("dstip", T.StringType()),
    T.StructField("dstport", T.IntegerType()),
    T.StructField("signature", T.StringType()),
])

VPN_SCHEMA = T.StructType(BASE_FIELDS + [
    T.StructField("user", T.StringType()),
    T.StructField("srcip", T.StringType()),
    T.StructField("geo", T.StringType()),
    T.StructField("action", T.StringType()),
])

WINLOG_SCHEMA = T.StructType(BASE_FIELDS + [
    T.StructField("win_event_id", T.IntegerType()),
    T.StructField("message", T.StringType()),
    T.StructField("details", T.MapType(T.StringType(), T.StringType())),
])

NETFLOW_SCHEMA = T.StructType(BASE_FIELDS + [
    T.StructField("srcip", T.StringType()),
    T.StructField("dstip", T.StringType()),
    T.StructField("dstport", T.IntegerType()),
    T.StructField("bytes", T.LongType()),
    T.StructField("pkts", T.LongType()),
])

VULN_SCHEMA = T.StructType(BASE_FIELDS + [
    T.StructField("asset", T.StringType()),
    T.StructField("cve", T.StringType()),
    T.StructField("severity_vuln", T.StringType()),
    T.StructField("first_seen", T.StringType()),
])

LINUX_SCHEMA = T.StructType(BASE_FIELDS + [
    T.StructField("facility", T.StringType()),
    T.StructField("message", T.StringType()),
    T.StructField("src_ip", T.StringType()),
])

DOCKER_SCHEMA = T.StructType(BASE_FIELDS + [
    T.StructField("container", T.StringType()),
    T.StructField("message", T.StringType()),
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
# Kafka source (single reader)
# --------------------------
if not KAFKA_TOPICS_PATTERN:
    raise ValueError("KAFKA_TOPICS_PATTERN must be non-empty for subscribePattern")

raw = (
    spark.readStream
    .format("kafka")
    .option("kafka.bootstrap.servers", KAFKA_BOOTSTRAP)
    .option("subscribePattern", KAFKA_TOPICS_PATTERN)
    .option("startingOffsets", KAFKA_OFFSETS)
    .option("failOnDataLoss", "false")
    .option("groupIdPrefix", APP_NAME)
    .option("maxOffsetsPerTrigger", "5000")
    .load()
    .selectExpr(
        "topic as kafka_topic",
        "partition as kafka_partition",
        "offset as kafka_offset",
        "CAST(key AS STRING)  as key_str",
        "CAST(value AS STRING) as value_str",
    )
)

(
    raw.groupBy("kafka_topic").count()
    .writeStream.outputMode("complete")
    .format("console")
    .option("truncate", "false")
    .option("numRows", "100")
    .option(
        "checkpointLocation",
        os.path.join(CHECKPOINT_DIR, PIPELINE_VERSION, "diag-by-topic"),
    )
    .queryName("diag-by-topic")
    .start()
)


def parse_by_topic(df, topic_name, schema):
    return (
        df.filter(F.col("kafka_topic") == topic_name)
          .select(
              "kafka_topic",
              "kafka_partition",
              "kafka_offset",
              "key_str",
              F.from_json("value_str", schema).alias("j"),
          )
          .select("kafka_topic", "kafka_partition", "kafka_offset", "key_str", "j.*")
          .withColumn("timestamp", F.to_timestamp("ts"))
    )


fw = (
    parse_by_topic(raw, "sec.firewall.raw", FW_SCHEMA)
    .withWatermark("timestamp", "10 minutes")
    .withColumn("dstport", F.col("dstport").cast("int"))
    .filter(F.col("dstport").isNotNull())
    .withColumn(
        "key",
        F.coalesce(
            F.col("key_str"),
            F.concat_ws(":", F.col("srcip"), F.col("dstport").cast("string")),
        ),
    )
)

web = (
    parse_by_topic(raw, "sec.web.raw", WEB_SCHEMA)
    .withWatermark("timestamp", "10 minutes")
    .withColumn("status", F.col("status").cast("int"))
    .filter(F.col("client_ip").isNotNull())
    .filter(F.col("status").isNotNull())
    .withColumn("key", F.coalesce(F.col("key_str"), F.col("client_ip")))
)

esx = (
    parse_by_topic(raw, "sec.esxi.raw", ESXI_SCHEMA)
    .withColumn("key", F.coalesce(F.col("key_str"), F.col("host")))
)

auth = (
    parse_by_topic(raw, "sec.auth.raw", AUTH_SCHEMA)
    .withColumn(
        "key",
        F.coalesce(F.col("key_str"), F.col("srcip"), F.col("username"), F.col("host")),
    )
)

dns = (
    parse_by_topic(raw, "sec.dns.raw", DNS_SCHEMA)
    .withWatermark("timestamp", "10 minutes")
    .withColumn(
        "qname",
        F.coalesce(
            F.col("qname"),
            F.regexp_extract(F.col("message"), r"query:\s+([A-Za-z0-9\.\-]+)\s", 1),
        ),
    )
    .withColumn("key", F.coalesce(F.col("key_str"), F.col("client_ip"), F.col("host")))
)

ids = (
    parse_by_topic(raw, "sec.ids.raw", IDS_SCHEMA)
    .withColumn("dstport", F.col("dstport").cast("int"))
    .withColumn("key", F.coalesce(F.col("key_str"), F.col("srcip"), F.col("host")))
)

vpn = (
    parse_by_topic(raw, "sec.vpn.raw", VPN_SCHEMA)
    .withWatermark("timestamp", "30 minutes")
    .withColumn("key", F.coalesce(F.col("key_str"), F.col("user"), F.col("srcip"), F.col("host")))
)

winl = (
    parse_by_topic(raw, "sec.winlog.raw", WINLOG_SCHEMA)
    .withColumn("key", F.coalesce(F.col("key_str"), F.col("host")))
)

nfl = (
    parse_by_topic(raw, "sec.netflow.raw", NETFLOW_SCHEMA)
    .withWatermark("timestamp", "15 minutes")
    .withColumn("dstport", F.col("dstport").cast("int"))
    .withColumn("bytes", F.col("bytes").cast("long"))
    .withColumn("pkts", F.col("pkts").cast("long"))
    .withColumn("key", F.coalesce(F.col("key_str"), F.col("srcip")))
)

vuln = (
    parse_by_topic(raw, "sec.vuln.raw", VULN_SCHEMA)
    .withColumn("key", F.coalesce(F.col("key_str"), F.col("asset"), F.col("host")))
)

linux = (
    parse_by_topic(raw, "sec.linux.raw", LINUX_SCHEMA)
    .withColumn("key", F.coalesce(F.col("key_str"), F.col("host")))
)

docker = (
    parse_by_topic(raw, "sec.docker.raw", DOCKER_SCHEMA)
    .withColumn("key", F.coalesce(F.col("key_str"), F.col("container"), F.col("host")))
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
# AUTH (Linux/Windows)
# --------------------------
auth_scored = (
    auth.select(
        F.col("timestamp").alias("@timestamp"),
        F.lit("auth").alias("source"),
        F.col("key"),
        F.least(
            F.lit(100.0),
            (
                F.when(F.col("outcome") == "fail", F.lit(40)).otherwise(F.lit(0))
                + F.when(
                    (F.col("outcome") == "success") & (F.col("severity") == "HIGH"),
                    F.lit(60),
                ).otherwise(F.lit(0))
            ).cast("double"),
        ).alias("score"),
        F.when(F.col("outcome") == "fail", F.lit("low"))
         .when(
             (F.col("outcome") == "success") & (F.col("severity") == "HIGH"),
             F.lit("high"),
         )
         .otherwise(F.lit("info")).alias("severity"),
        F.concat(
            F.lit("Auth "), F.coalesce(F.col("outcome"), F.lit("?")),
            F.lit(" user="), F.coalesce(F.col("username"), F.lit("?")),
            F.lit(" from "), F.coalesce(F.col("srcip"), F.lit("?")),
        ).alias("reason"),
        F.to_json(F.struct("username", "outcome", "srcip")).alias("evidence"),
        F.lit("sec.auth.raw").alias("kafka_topic"),
        F.lit(PIPELINE_VERSION).alias("pipeline_version"),
    )
)

# DNS (60s ratios NXDOMAIN, diversité de qnames)
dns_60 = (
    dns.withColumn("is_nx", F.lower(F.coalesce(F.col("rcode"), F.lit(""))) == F.lit("nxdomain"))
       .groupBy(F.window("timestamp", "60 seconds").alias("w60"), "key")
       .agg(
           F.count(F.lit(1)).alias("n"),
           F.sum(F.col("is_nx").cast("int")).alias("n_nx"),
           F.approx_count_distinct("qname").alias("uniq_q"),   # <— HLL au lieu de countDistinct
       )
       .withColumn(
           "nx_rate",
           F.when(F.col("n") > 0, F.col("n_nx") / F.col("n")).otherwise(F.lit(0.0)),
       )
)

dns_scored = (
    dns_60.select(
        F.col("w60.end").alias("@timestamp"),
        F.lit("dns").alias("source"),
        F.col("key"),
        F.least(
            F.lit(100.0),
            (
                F.when(F.col("n") >= 30, F.lit(10)).otherwise(F.lit(0))
                + F.when(F.col("nx_rate") >= 0.3, F.lit(60)).otherwise(F.lit(0))
                + F.when(F.col("uniq_q") >= 20, F.lit(30)).otherwise(F.lit(0))
            ).cast("double"),
        ).alias("score"),
        F.when(F.col("nx_rate") >= 0.5, F.lit("high"))
         .when(F.col("nx_rate") >= 0.3, F.lit("medium"))
         .when(F.col("n") >= 30, F.lit("low"))
         .otherwise(F.lit("info")).alias("severity"),
        F.concat(
            F.lit("DNS anomalies: n="), F.col("n").cast("string"),
            F.lit(", nx="), F.col("n_nx").cast("string"),
            F.lit(", uniq_q~"), F.col("uniq_q").cast("string"),
        ).alias("reason"),
        F.to_json(
            F.struct(
                F.lit("60s").alias("win"),
                F.col("n").alias("n"),
                F.col("n_nx").alias("n_nx"),
                F.col("uniq_q").alias("uniq_q"),
                F.round(F.col("nx_rate"), 3).alias("nx_rate"),
            )
        ).alias("evidence"),
        F.lit("sec.dns.raw").alias("kafka_topic"),
        F.lit(PIPELINE_VERSION).alias("pipeline_version"),
    )
)

# IDS (Suricata/Snort)
ids_sev = (
    F.when(F.lower(F.coalesce(F.col("severity"), F.lit(""))) == "high", F.lit(80))
     .when(F.lower(F.coalesce(F.col("severity"), F.lit(""))) == "medium", F.lit(50))
     .when(F.lower(F.coalesce(F.col("severity"), F.lit(""))) == "low", F.lit(25))
     .otherwise(F.lit(20))
)

signature_lower = F.lower(F.coalesce(F.col("signature"), F.lit("")))
ids_boost = (
    F.when(signature_lower.contains("malware"), F.lit(15))
     .when(signature_lower.contains("c2"), F.lit(20))
     .when(signature_lower.contains("exploit"), F.lit(10))
     .otherwise(F.lit(0))
)

ids_scored = (
    ids.select(
        F.col("timestamp").alias("@timestamp"),
        F.lit("ids").alias("source"),
        F.col("key"),
        F.least(F.lit(100.0), (ids_sev + ids_boost).cast("double")).alias("score"),
        F.when(ids_sev >= 80, F.lit("high"))
         .when(ids_sev >= 50, F.lit("medium"))
         .when(ids_sev >= 25, F.lit("low"))
         .otherwise(F.lit("info")).alias("severity"),
        F.concat(
            F.lit("IDS: "), F.coalesce(F.col("signature"), F.lit("alert")),
            F.lit(" "), F.coalesce(F.col("srcip"), F.lit("?")), F.lit("→"),
            F.coalesce(F.col("dstip"), F.lit("?")), F.lit(":"),
            F.coalesce(F.col("dstport").cast("string"), F.lit("?")),
        ).alias("reason"),
        F.to_json(F.struct("srcip", "dstip", "dstport", "signature")).alias("evidence"),
        F.lit("sec.ids.raw").alias("kafka_topic"),
        F.lit(PIPELINE_VERSION).alias("pipeline_version"),
    )
)

# VPN (échecs + multi-géos sur 60 min)
vpn_60m = (
    vpn.groupBy(F.window("timestamp", "60 minutes").alias("w60m"), F.col("key"))
       .agg(
           F.approx_count_distinct("geo").alias("geo_cnt"),  # <- HLL au lieu de count(distinct)
           F.sum(F.when(F.col("action") == "fail", 1).otherwise(0)).alias("fails"),
           F.sum(F.when(F.col("action") == "login", 1).otherwise(0)).alias("logins"),
       )
)

vpn_scored = (
    vpn_60m.select(
        F.col("w60m.end").alias("@timestamp"),
        F.lit("vpn").alias("source"),
        F.col("key"),
        F.least(
            F.lit(100.0),
            (
                F.when(F.col("geo_cnt") >= 2, F.lit(60)).otherwise(F.lit(0))
                + F.when(F.col("fails") >= 3, F.lit(30)).otherwise(F.lit(0))
                + F.when(F.col("logins") >= 10, F.lit(10)).otherwise(F.lit(0))
            ).cast("double"),
        ).alias("score"),
        F.when(F.col("geo_cnt") >= 3, F.lit("high"))
         .when(F.col("geo_cnt") >= 2, F.lit("medium"))
         .when(F.col("fails") >= 3, F.lit("low"))
         .otherwise(F.lit("info")).alias("severity"),
        F.concat(
            F.lit("VPN geo/bad logins: geos="), F.col("geo_cnt").cast("string"),
            F.lit(" fails="), F.col("fails").cast("string"),
        ).alias("reason"),
        F.to_json(
            F.struct(
                F.lit("60m").alias("win"),
                "geo_cnt",
                "fails",
                "logins",
            )
        ).alias("evidence"),
        F.lit("sec.vpn.raw").alias("kafka_topic"),
        F.lit(PIPELINE_VERSION).alias("pipeline_version"),
    )
)

# Winlog (4625 échecs / 4688 process suspects)
susp_proc = F.lower(F.coalesce(F.col("message"), F.lit(""))).rlike(
    r"(powershell|cmd\.exe|wmic|rundll32|certutil|mshta|regsvr32)"
)

winl_scored = (
    winl.select(
        F.col("timestamp").alias("@timestamp"),
        F.lit("winlog").alias("source"),
        F.col("key"),
        F.least(
            F.lit(100.0),
            (
                F.when(F.col("win_event_id") == 4625, F.lit(50)).otherwise(F.lit(0))
                + F.when(
                    F.col("win_event_id") == 4688,
                    F.when(susp_proc, F.lit(40)).otherwise(F.lit(10)),
                ).otherwise(F.lit(0))
            ).cast("double"),
        ).alias("score"),
        F.when((F.col("win_event_id") == 4625) & (~susp_proc), F.lit("medium"))
         .when((F.col("win_event_id") == 4688) & susp_proc, F.lit("high"))
         .otherwise(F.lit("info")).alias("severity"),
        F.concat(
            F.lit("WinEvent "), F.col("win_event_id").cast("string"),
            F.lit(": "), F.coalesce(F.col("message"), F.lit("")),
        ).alias("reason"),
        F.to_json(F.struct("win_event_id", "details")).alias("evidence"),
        F.lit("sec.winlog.raw").alias("kafka_topic"),
        F.lit(PIPELINE_VERSION).alias("pipeline_version"),
    )
)

# Netflow (1m: scans & ports rares)
COMMON_PORTS = [22, 80, 443, 3389, 53, 25, 1433, 1521, 3306, 5432, 6379, 8080, 9200, 9092, 5601]
common_ports_arr = F.array(*[F.lit(p) for p in COMMON_PORTS])
nfl_1m = (
    nfl.groupBy(F.window("timestamp", "60 seconds").alias("w1m"), F.col("key"))
       .agg(
           # remplace countDistinct -> approx_count_distinct (compatible streaming)
           F.approx_count_distinct("dstport").alias("dports"),
           # cast explicites pour éviter les overflows et nulls
           F.sum(F.coalesce(F.col("pkts").cast("long"), F.lit(0))).alias("pkts"),
           F.sum(F.coalesce(F.col("bytes").cast("long"), F.lit(0))).alias("bytes"),
           # sum d’un indicateur 1/0 (array_contains retourne bool)
           F.sum(
               F.when(~F.array_contains(common_ports_arr, F.col("dstport")), F.lit(1)).otherwise(F.lit(0))
           ).alias("rare_ports"),
       )
)

nfl_scored = (
    nfl_1m.select(
        F.col("w1m.end").alias("@timestamp"),
        F.lit("netflow").alias("source"),
        F.col("key"),
        F.least(
            F.lit(100.0),
            (
                F.when(F.col("dports") >= 20, F.lit(50)).otherwise(F.lit(0))
                + F.when(F.col("rare_ports") >= 10, F.lit(30)).otherwise(F.lit(0))
                + F.when(F.col("bytes") >= F.lit(10_000_000), F.lit(20)).otherwise(F.lit(0))
            ).cast("double"),
        ).alias("score"),
        F.when(F.col("dports") >= 30, F.lit("high"))
         .when(F.col("dports") >= 20, F.lit("medium"))
         .when(F.col("rare_ports") >= 10, F.lit("low"))
         .otherwise(F.lit("info")).alias("severity"),
        F.concat(
            F.lit("Netflow: dports="), F.col("dports").cast("string"),
            F.lit(" rare="), F.col("rare_ports").cast("string"),
            F.lit(" bytes="), F.col("bytes").cast("string"),
        ).alias("reason"),
        F.to_json(
            F.struct(
                F.lit("60s").alias("win"),
                "dports",
                "rare_ports",
                "pkts",
                "bytes",
            )
        ).alias("evidence"),
        F.lit("sec.netflow.raw").alias("kafka_topic"),
        F.lit(PIPELINE_VERSION).alias("pipeline_version"),
    )
)

# Vuln (mapping sévérité)
vuln_base = (
    F.when(F.lower(F.coalesce(F.col("severity_vuln"), F.lit(""))) == "critical", F.lit(95))
     .when(F.lower(F.coalesce(F.col("severity_vuln"), F.lit(""))) == "high", F.lit(80))
     .when(F.lower(F.coalesce(F.col("severity_vuln"), F.lit(""))) == "medium", F.lit(50))
     .when(F.lower(F.coalesce(F.col("severity_vuln"), F.lit(""))) == "low", F.lit(20))
     .otherwise(F.lit(10))
)

vuln_scored = (
    vuln.select(
        F.coalesce(F.to_timestamp("first_seen"), F.col("timestamp")).alias("@timestamp"),
        F.lit("vuln").alias("source"),
        F.col("key"),
        vuln_base.cast("double").alias("score"),
        F.when(vuln_base >= 90, F.lit("critical"))
         .when(vuln_base >= 75, F.lit("high"))
         .when(vuln_base >= 50, F.lit("medium"))
         .when(vuln_base >= 25, F.lit("low"))
         .otherwise(F.lit("info")).alias("severity"),
        F.concat(
            F.lit("VULN "), F.coalesce(F.col("asset"), F.lit("?")), F.lit(" "),
            F.coalesce(F.col("cve"), F.lit("?")), F.lit(" severity="),
            F.coalesce(F.col("severity_vuln"), F.lit("?")),
        ).alias("reason"),
        F.to_json(F.struct("asset", "cve", "severity_vuln", "first_seen")).alias("evidence"),
        F.lit("sec.vuln.raw").alias("kafka_topic"),
        F.lit(PIPELINE_VERSION).alias("pipeline_version"),
    )
)

# Linux & Docker (pass-through utile)
linux_msg_lower = F.lower(F.coalesce(F.col("message"), F.lit("")))
linux_scored = (
    linux.select(
        F.col("timestamp").alias("@timestamp"),
        F.lit("linux").alias("source"),
        F.col("key"),
        F.when(F.col("event_type") == "linux.auth.failed", F.lit(50.0))
         .when(linux_msg_lower.contains("error"), F.lit(25.0))
         .otherwise(F.lit(10.0)).alias("score"),
        F.when(F.col("event_type") == "linux.auth.failed", F.lit("medium"))
         .when(linux_msg_lower.contains("error"), F.lit("low"))
         .otherwise(F.lit("info")).alias("severity"),
        F.coalesce(F.col("message"), F.lit("linux event")).alias("reason"),
        F.to_json(F.struct("facility", "message", "src_ip")).alias("evidence"),
        F.lit("sec.linux.raw").alias("kafka_topic"),
        F.lit(PIPELINE_VERSION).alias("pipeline_version"),
    )
)

docker_msg_lower = F.lower(F.coalesce(F.col("message"), F.lit("")))
docker_scored = (
    docker.select(
        F.col("timestamp").alias("@timestamp"),
        F.lit("docker").alias("source"),
        F.col("key"),
        F.when(F.col("event_type") == "docker.oom", F.lit(80.0))
         .when(docker_msg_lower.contains("error"), F.lit(40.0))
         .otherwise(F.lit(10.0)).alias("score"),
        F.when(F.col("event_type") == "docker.oom", F.lit("high"))
         .when(docker_msg_lower.contains("error"), F.lit("medium"))
         .otherwise(F.lit("info")).alias("severity"),
        F.concat(F.col("container"), F.lit(": "), F.coalesce(F.col("message"), F.lit(""))).alias("reason"),
        F.to_json(F.struct("container", "message")).alias("evidence"),
        F.lit("sec.docker.raw").alias("kafka_topic"),
        F.lit(PIPELINE_VERSION).alias("pipeline_version"),
    )
)

# --------------------------
# Normalize evidence → JSON + union
# --------------------------
fw_scored  = fw_scored.withColumn("evidence", F.to_json(F.col("evidence")))
web_scored = web_scored.withColumn("evidence", F.to_json(F.col("evidence")))
esx_agg    = esx_agg.withColumn("evidence", F.to_json(F.col("evidence")))

alerts_cols = ["@timestamp", "source", "key", "score", "severity", "reason", "evidence", "kafka_topic", "pipeline_version"]
alerts = (
    fw_scored.select(alerts_cols)
    .unionByName(web_scored.select(alerts_cols))
    .unionByName(esx_agg.select(alerts_cols))
    .unionByName(auth_scored.select(alerts_cols))
    .unionByName(dns_scored.select(alerts_cols))
    .unionByName(ids_scored.select(alerts_cols))
    .unionByName(vpn_scored.select(alerts_cols))
    .unionByName(winl_scored.select(alerts_cols))
    .unionByName(nfl_scored.select(alerts_cols))
    .unionByName(vuln_scored.select(alerts_cols))
    .unionByName(linux_scored.select(alerts_cols))
    .unionByName(docker_scored.select(alerts_cols))
)
alerts = alerts.withColumn("score", F.col("score").cast("double"))

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
