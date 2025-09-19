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

TRIGGER_SEC       = os.getenv("TRIGGER_SEC", "10 seconds")   # 5–10s conseillé pour démo
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

AUTH_SCHEMA = T.StructType([
    T.StructField("ts", T.StringType()),
    T.StructField("event_type", T.StringType()),
    T.StructField("source", T.StringType()),
    T.StructField("severity", T.StringType()),
    T.StructField("host", T.StringType()),
    T.StructField("event_id", T.StringType()),
    T.StructField("username", T.StringType()),
    T.StructField("outcome", T.StringType()),
    T.StructField("srcip", T.StringType())
])

DNS_SCHEMA = T.StructType([
    T.StructField("ts", T.StringType()),
    T.StructField("event_type", T.StringType()),
    T.StructField("source", T.StringType()),
    T.StructField("severity", T.StringType()),
    T.StructField("host", T.StringType()),
    T.StructField("event_id", T.StringType()),
    T.StructField("message", T.StringType()),
    T.StructField("client_ip", T.StringType()),
    T.StructField("qname", T.StringType()),
    T.StructField("qtype", T.StringType()),
    T.StructField("rcode", T.StringType())
])

WINLOG_SCHEMA = T.StructType([
    T.StructField("ts", T.StringType()),
    T.StructField("event_type", T.StringType()),
    T.StructField("source", T.StringType()),
    T.StructField("severity", T.StringType()),
    T.StructField("host", T.StringType()),
    T.StructField("event_id", T.StringType()),
    T.StructField("win_event_id", T.IntegerType()),
    T.StructField("message", T.StringType())
])

NETFLOW_SCHEMA = T.StructType([
    T.StructField("ts", T.StringType()),
    T.StructField("event_type", T.StringType()),
    T.StructField("source", T.StringType()),
    T.StructField("severity", T.StringType()),
    T.StructField("host", T.StringType()),
    T.StructField("event_id", T.StringType()),
    T.StructField("srcip", T.StringType()),
    T.StructField("dstip", T.StringType()),
    T.StructField("dstport", T.IntegerType()),
    T.StructField("bytes", T.LongType()),
    T.StructField("pkts", T.LongType())
])

VULN_SCHEMA = T.StructType([
    T.StructField("ts", T.StringType()),
    T.StructField("event_type", T.StringType()),
    T.StructField("source", T.StringType()),
    T.StructField("severity", T.StringType()),
    T.StructField("host", T.StringType()),
    T.StructField("event_id", T.StringType()),
    T.StructField("asset", T.StringType()),
    T.StructField("cve", T.StringType()),
    T.StructField("vuln_severity", T.StringType()),
    T.StructField("first_seen", T.StringType())
])

IDS_SCHEMA = T.StructType([
    T.StructField("ts", T.StringType()),
    T.StructField("event_type", T.StringType()),
    T.StructField("source", T.StringType()),
    T.StructField("severity", T.StringType()),
    T.StructField("host", T.StringType()),
    T.StructField("event_id", T.StringType()),
    T.StructField("srcip", T.StringType()),
    T.StructField("dstip", T.StringType()),
    T.StructField("dstport", T.IntegerType()),
    T.StructField("signature", T.StringType()),
    T.StructField("ids_severity", T.StringType())
])

VPN_SCHEMA = T.StructType([
    T.StructField("ts", T.StringType()),
    T.StructField("event_type", T.StringType()),
    T.StructField("source", T.StringType()),
    T.StructField("severity", T.StringType()),
    T.StructField("host", T.StringType()),
    T.StructField("event_id", T.StringType()),
    T.StructField("user", T.StringType()),
    T.StructField("srcip", T.StringType()),
    T.StructField("geo", T.StringType()),
    T.StructField("action", T.StringType())
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
def _read_kafka_stream(*, topics=None, pattern=None):
    if (topics and pattern) or (not topics and not pattern):
        raise ValueError("Specify either topics or pattern for Kafka subscription")

    reader = (
        spark.readStream
        .format("kafka")
        .option("kafka.bootstrap.servers", KAFKA_BOOTSTRAP)
        .option("startingOffsets", KAFKA_OFFSETS)   # pris au 1er démarrage (checkpoint sinon)
        .option("failOnDataLoss", "false")
        .option("groupIdPrefix", APP_NAME)          # groupe lisible: siem-fastlane-*
        .option("maxOffsetsPerTrigger", "5000")
    )
    if pattern:
        reader = reader.option("subscribePattern", pattern)
    else:
        reader = reader.option("subscribe", ",".join(topics))

    return (
        reader.load()
        .withColumn("kafka_topic", F.col("topic"))
        .withColumn("kafka_partition", F.col("partition"))
        .withColumn("kafka_offset", F.col("offset"))
        .withColumn("key_str", F.col("key").cast("string"))
        .withColumn("value_str", F.col("value").cast("string"))
    )


kafka_all_raw = _read_kafka_stream(pattern=KAFKA_TOPICS_PATTERN) if KAFKA_TOPICS_PATTERN else None


def read_kafka_topic(topic):
    if kafka_all_raw is not None:
        return kafka_all_raw.filter(F.col("kafka_topic") == topic)
    return _read_kafka_stream(topics=[topic])


fw_raw  = read_kafka_topic("sec.firewall.raw")
web_raw = read_kafka_topic("sec.web.raw")
esx_raw = read_kafka_topic("sec.esxi.raw")
auth_raw = read_kafka_topic("sec.auth.raw")
dns_raw  = read_kafka_topic("sec.dns.raw")
win_raw  = read_kafka_topic("sec.winlog.raw")
flow_raw = read_kafka_topic("sec.netflow.raw")
vuln_raw = read_kafka_topic("sec.vuln.raw")
ids_raw  = read_kafka_topic("sec.ids.raw")
vpn_raw  = read_kafka_topic("sec.vpn.raw")

HANDLED_TOPICS = [
    "sec.firewall.raw",
    "sec.web.raw",
    "sec.esxi.raw",
    "sec.auth.raw",
    "sec.dns.raw",
    "sec.winlog.raw",
    "sec.netflow.raw",
    "sec.vuln.raw",
    "sec.ids.raw",
    "sec.vpn.raw",
]

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

auth = (
    parse_json(auth_raw, AUTH_SCHEMA)
    .withColumn(
        "key",
        F.coalesce(F.col("key_str"), F.col("srcip"), F.col("username"), F.col("host"))
    )
)

dns = (
    parse_json(dns_raw, DNS_SCHEMA)
    .withColumn(
        "qname",
        F.coalesce(
            F.col("qname"),
            F.regexp_extract(F.col("message"), r"query:\s+([A-Za-z0-9\.\-]+)\s", 1)
        )
    )
    .withColumn("key", F.coalesce(F.col("key_str"), F.col("client_ip")))
)

win = (
    parse_json(win_raw, WINLOG_SCHEMA)
    .withColumn("key", F.coalesce(F.col("key_str"), F.col("host")))
)

flow = (
    parse_json(flow_raw, NETFLOW_SCHEMA)
    .withColumn("dstport", F.col("dstport").cast("int"))
    .withColumn("bytes", F.col("bytes").cast("long"))
    .withColumn("pkts", F.col("pkts").cast("long"))
    .withColumn(
        "key",
        F.coalesce(
            F.col("key_str"),
            F.concat_ws(":", F.col("srcip"), F.col("dstip"), F.col("dstport").cast("string"))
        )
    )
)

vuln = (
    parse_json(vuln_raw, VULN_SCHEMA)
    .withColumn("key", F.coalesce(F.col("key_str"), F.col("asset"), F.col("host")))
)

ids = (
    parse_json(ids_raw, IDS_SCHEMA)
    .withColumn("dstport", F.col("dstport").cast("int"))
    .withColumn(
        "key",
        F.coalesce(
            F.col("key_str"),
            F.concat_ws(":", F.col("srcip"), F.col("dstip"), F.col("dstport").cast("string"))
        )
    )
)

vpn = (
    parse_json(vpn_raw, VPN_SCHEMA)
    .withColumn("key", F.coalesce(F.col("key_str"), F.col("user"), F.col("srcip")))
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
# AUTH: stateless scoring
# --------------------------
def score_auth(df):
    s_fail = F.when(F.col("outcome") == "fail", F.lit(40)).otherwise(F.lit(0))
    s_succ_after_fail = F.when(
        (F.col("outcome") == "success") & (F.col("severity") == "HIGH"), F.lit(60)
    ).otherwise(F.lit(0))
    score_expr = F.least(F.lit(100), s_fail + s_succ_after_fail)

    severity_expr = (
        F.when(score_expr >= 90, "critical")
         .when(score_expr >= 75, "high")
         .when(score_expr >= 50, "medium")
         .when(score_expr >= 25, "low")
         .otherwise("info")
    )

    reason = F.concat(
        F.lit("Auth "), F.col("outcome"), F.lit(" user="), F.col("username"),
        F.lit(" from "), F.coalesce(F.col("srcip"), F.lit("?"))
    )

    evidence = F.struct(
        F.lit("auth").alias("type"),
        F.col("username").alias("username"),
        F.col("outcome").alias("outcome"),
        F.col("srcip").alias("srcip")
    )

    return df.select(
        F.col("timestamp").alias("@timestamp"),
        F.lit("auth").alias("source"),
        F.col("key"),
        score_expr.alias("score"),
        severity_expr.alias("severity"),
        reason.alias("reason"),
        evidence.alias("evidence"),
        F.lit("sec.auth.raw").alias("kafka_topic"),
        F.lit(PIPELINE_VERSION).alias("pipeline_version")
    )


auth_scored = score_auth(auth)


# --------------------------
# DNS: stateless scoring
# --------------------------
def score_dns(df):
    qlen = F.length(F.coalesce(F.col("qname"), F.lit("")))
    s_len = F.when(qlen >= 35, F.lit(40)).when(qlen >= 25, F.lit(20)).otherwise(F.lit(0))
    s_tldx = F.when(
        F.col("qname").endswith(".xyz") |
        F.col("qname").endswith(".top") |
        F.col("qname").endswith(".icu"),
        F.lit(20)
    ).otherwise(F.lit(0))
    score_expr = F.least(F.lit(100), s_len + s_tldx)

    severity_expr = (
        F.when(score_expr >= 90, "critical")
         .when(score_expr >= 75, "high")
         .when(score_expr >= 50, "medium")
         .when(score_expr >= 25, "low")
         .otherwise("info")
    )

    reason = F.concat(
        F.lit("DNS query from "), F.col("key"),
        F.lit(" qname="), F.coalesce(F.col("qname"), F.lit("?"))
    )

    evidence = F.struct(
        F.lit("dns").alias("type"),
        F.col("client_ip").alias("client_ip"),
        F.col("qname").alias("qname")
    )

    return df.select(
        F.col("timestamp").alias("@timestamp"),
        F.lit("dns").alias("source"),
        F.col("key"),
        score_expr.alias("score"),
        severity_expr.alias("severity"),
        reason.alias("reason"),
        evidence.alias("evidence"),
        F.lit("sec.dns.raw").alias("kafka_topic"),
        F.lit(PIPELINE_VERSION).alias("pipeline_version")
    )


dns_scored = score_dns(dns)


# --------------------------
# WINLOG: stateless scoring
# --------------------------
def score_win(df):
    msg = F.lower(F.coalesce(F.col("message"), F.lit("")))
    eid = F.coalesce(F.col("win_event_id"), F.lit(0))

    s_fail = F.when(eid == 4625, F.lit(35)).otherwise(F.lit(0))
    s_priv = F.when(eid == 4672, F.lit(30)).otherwise(F.lit(0))
    s_proc = F.when((eid == 4688) & (msg.rlike("powershell|cmd.exe|wmic|certutil")), F.lit(40))
    s_proc = s_proc.otherwise(F.lit(0))

    score_expr = F.least(F.lit(100), s_fail + s_priv + s_proc)

    severity_expr = (
        F.when(score_expr >= 90, "critical")
         .when(score_expr >= 75, "high")
         .when(score_expr >= 50, "medium")
         .when(score_expr >= 25, "low")
         .otherwise("info")
    )

    reason = F.concat(F.lit("Win event "), eid.cast("string"), F.lit(" on "), F.col("host"))

    evidence = F.struct(
        F.lit("winlog").alias("type"),
        eid.alias("event_id"),
        F.col("message").alias("message")
    )

    return df.select(
        F.col("timestamp").alias("@timestamp"),
        F.lit("winlog").alias("source"),
        F.col("key"),
        score_expr.alias("score"),
        severity_expr.alias("severity"),
        reason.alias("reason"),
        evidence.alias("evidence"),
        F.lit("sec.winlog.raw").alias("kafka_topic"),
        F.lit(PIPELINE_VERSION).alias("pipeline_version")
    )


win_scored = score_win(win)


# --------------------------
# NETFLOW: stateless scoring
# --------------------------
def score_flow(df):
    sensitive = (
        F.when(F.col("dstport").isin(22, 3389), F.lit(20))
         .when(F.col("dstport").isin(9200, 9092, 5601), F.lit(15))
         .when(F.col("dstport").isin(80, 443), F.lit(5))
         .otherwise(F.lit(0))
    )
    s_bytes = (
        F.when(F.col("bytes") >= 10_000_000, F.lit(40))
         .when(F.col("bytes") >= 1_000_000, F.lit(20))
         .otherwise(F.lit(0))
    )
    score_expr = F.least(F.lit(100), sensitive + s_bytes)

    severity_expr = (
        F.when(score_expr >= 90, "critical")
         .when(score_expr >= 75, "high")
         .when(score_expr >= 50, "medium")
         .when(score_expr >= 25, "low")
         .otherwise("info")
    )

    reason = F.concat(
        F.lit("Netflow "), F.col("srcip"), F.lit("→"),
        F.col("dstip"), F.lit(":"), F.col("dstport").cast("string"),
        F.lit(" bytes="), F.col("bytes").cast("string")
    )

    evidence = F.struct(
        F.lit("netflow").alias("type"),
        F.col("srcip").alias("srcip"),
        F.col("dstip").alias("dstip"),
        F.col("dstport").alias("dstport"),
        F.col("bytes").alias("bytes"),
        F.col("pkts").alias("pkts")
    )

    return df.select(
        F.col("timestamp").alias("@timestamp"),
        F.lit("netflow").alias("source"),
        F.col("key"),
        score_expr.alias("score"),
        severity_expr.alias("severity"),
        reason.alias("reason"),
        evidence.alias("evidence"),
        F.lit("sec.netflow.raw").alias("kafka_topic"),
        F.lit(PIPELINE_VERSION).alias("pipeline_version")
    )


flow_scored = score_flow(flow)


# --------------------------
# VULN: stateless scoring
# --------------------------
def score_vuln(df):
    sev = F.lower(F.coalesce(F.col("vuln_severity"), F.lit("")))
    s_map = (
        F.when(sev == "critical", F.lit(95))
         .when(sev == "high", F.lit(75))
         .when(sev == "medium", F.lit(45))
         .when(sev == "low", F.lit(20))
         .otherwise(F.lit(10))
    )

    severity_expr = (
        F.when(s_map >= 90, "critical")
         .when(s_map >= 75, "high")
         .when(s_map >= 50, "medium")
         .when(s_map >= 25, "low")
         .otherwise("info")
    )

    evidence = F.struct(
        F.lit("vuln").alias("type"),
        F.col("asset").alias("asset"),
        F.col("cve").alias("cve"),
        F.col("vuln_severity").alias("vuln_severity"),
        F.col("first_seen").alias("first_seen")
    )

    reason = F.concat(F.lit("Vuln "), F.col("cve"), F.lit(" on "), F.col("asset"))

    return df.select(
        F.col("timestamp").alias("@timestamp"),
        F.lit("vuln").alias("source"),
        F.col("key"),
        s_map.cast("double").alias("score"),
        severity_expr.alias("severity"),
        reason.alias("reason"),
        evidence.alias("evidence"),
        F.lit("sec.vuln.raw").alias("kafka_topic"),
        F.lit(PIPELINE_VERSION).alias("pipeline_version")
    )


vuln_scored = score_vuln(vuln)


# --------------------------
# IDS: stateless scoring
# --------------------------
def score_ids(df):
    sev = F.lower(F.coalesce(F.col("ids_severity"), F.lit("")))
    s_sig = F.when(F.col("signature").rlike("malware|ransom|c2|command.?and.?control"), F.lit(60))
    s_sig = s_sig.otherwise(F.lit(0))
    s_lvl = (
        F.when(sev.isin("critical", "high", "5", "4"), F.lit(40))
         .when(sev.isin("medium", "3"), F.lit(25))
         .when(sev.isin("low", "2", "1"), F.lit(10))
         .otherwise(F.lit(0))
    )
    score_expr = F.least(F.lit(100), s_sig + s_lvl)

    severity_expr = (
        F.when(score_expr >= 90, "critical")
         .when(score_expr >= 75, "high")
         .when(score_expr >= 50, "medium")
         .when(score_expr >= 25, "low")
         .otherwise("info")
    )

    reason = F.concat(
        F.lit("IDS "), F.col("signature"), F.lit(" "),
        F.col("srcip"), F.lit("→"), F.col("dstip"), F.lit(":"),
        F.col("dstport").cast("string")
    )

    evidence = F.struct(
        F.lit("ids").alias("type"),
        F.col("srcip").alias("srcip"),
        F.col("dstip").alias("dstip"),
        F.col("dstport").alias("dstport"),
        F.col("signature").alias("signature"),
        F.col("ids_severity").alias("ids_severity")
    )

    return df.select(
        F.col("timestamp").alias("@timestamp"),
        F.lit("ids").alias("source"),
        F.col("key"),
        score_expr.alias("score"),
        severity_expr.alias("severity"),
        reason.alias("reason"),
        evidence.alias("evidence"),
        F.lit("sec.ids.raw").alias("kafka_topic"),
        F.lit(PIPELINE_VERSION).alias("pipeline_version")
    )


ids_scored = score_ids(ids)


# --------------------------
# VPN: stateless scoring
# --------------------------
def score_vpn(df):
    s_fail = F.when(F.col("action") == "fail", F.lit(40)).otherwise(F.lit(0))
    s_geo = F.when(~F.lower(F.coalesce(F.col("geo"), F.lit("ma"))).startswith("ma"), F.lit(20)).otherwise(F.lit(0))
    score_expr = F.least(F.lit(100), s_fail + s_geo)

    severity_expr = (
        F.when(score_expr >= 90, "critical")
         .when(score_expr >= 75, "high")
         .when(score_expr >= 50, "medium")
         .when(score_expr >= 25, "low")
         .otherwise("info")
    )

    reason = F.concat(
        F.lit("VPN "), F.col("action"),
        F.lit(" user="), F.col("user"),
        F.lit(" from "), F.coalesce(F.col("geo"), F.lit("?")),
        F.lit(" ip="), F.coalesce(F.col("srcip"), F.lit("?"))
    )

    evidence = F.struct(
        F.lit("vpn").alias("type"),
        F.col("user").alias("user"),
        F.col("srcip").alias("srcip"),
        F.col("geo").alias("geo"),
        F.col("action").alias("action")
    )

    return df.select(
        F.col("timestamp").alias("@timestamp"),
        F.lit("vpn").alias("source"),
        F.col("key"),
        score_expr.alias("score"),
        severity_expr.alias("severity"),
        reason.alias("reason"),
        evidence.alias("evidence"),
        F.lit("sec.vpn.raw").alias("kafka_topic"),
        F.lit(PIPELINE_VERSION).alias("pipeline_version")
    )


vpn_scored = score_vpn(vpn)

generic_scored = None
if kafka_all_raw is not None:
    generic_raw = kafka_all_raw.filter(~F.col("kafka_topic").isin(HANDLED_TOPICS))
    ts_expr = F.coalesce(
        F.to_timestamp(F.get_json_object(F.col("value_str"), "$.@timestamp")),
        F.to_timestamp(F.get_json_object(F.col("value_str"), "$.timestamp")),
        F.to_timestamp(F.get_json_object(F.col("value_str"), "$.ts")),
        F.current_timestamp(),
    )
    generic_evidence = F.struct(
        F.col("value_str").alias("raw"),
        F.col("kafka_partition").alias("partition"),
        F.col("kafka_offset").alias("offset"),
        F.col("key_str").alias("key"),
    )
    generic_scored = generic_raw.select(
        ts_expr.alias("@timestamp"),
        F.col("kafka_topic").alias("source"),
        F.coalesce(F.col("key_str"), F.lit("generic")).alias("key"),
        F.lit(0.0).alias("score"),
        F.lit("info").alias("severity"),
        F.concat(F.lit("Generic ingestion from topic "), F.col("kafka_topic")).alias("reason"),
        generic_evidence.alias("evidence"),
        F.col("kafka_topic"),
        F.lit(PIPELINE_VERSION).alias("pipeline_version"),
    )

# --------------------------
# Normalize evidence → JSON + union
# --------------------------
fw_scored  = fw_scored.withColumn("evidence", F.to_json(F.col("evidence")))
web_scored = web_scored.withColumn("evidence", F.to_json(F.col("evidence")))
esx_agg    = esx_agg.withColumn("evidence", F.to_json(F.col("evidence")))
auth_scored = auth_scored.withColumn("evidence", F.to_json(F.col("evidence")))
dns_scored  = dns_scored.withColumn("evidence", F.to_json(F.col("evidence")))
win_scored  = win_scored.withColumn("evidence", F.to_json(F.col("evidence")))
flow_scored = flow_scored.withColumn("evidence", F.to_json(F.col("evidence")))
vuln_scored = vuln_scored.withColumn("evidence", F.to_json(F.col("evidence")))
ids_scored  = ids_scored.withColumn("evidence", F.to_json(F.col("evidence")))
vpn_scored  = vpn_scored.withColumn("evidence", F.to_json(F.col("evidence")))
if generic_scored is not None:
    generic_scored = generic_scored.withColumn("evidence", F.to_json(F.col("evidence")))

alerts_cols = ["@timestamp","source","key","score","severity","reason","evidence","kafka_topic","pipeline_version"]
scored_streams = [
    fw_scored.select(alerts_cols),
    web_scored.select(alerts_cols),
    esx_agg.select(alerts_cols),
    auth_scored.select(alerts_cols),
    dns_scored.select(alerts_cols),
    win_scored.select(alerts_cols),
    flow_scored.select(alerts_cols),
    vuln_scored.select(alerts_cols),
    ids_scored.select(alerts_cols),
    vpn_scored.select(alerts_cols),
]
if generic_scored is not None:
    scored_streams.append(generic_scored.select(alerts_cols))

alerts = scored_streams[0]
for df in scored_streams[1:]:
    alerts = alerts.unionByName(df)
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
