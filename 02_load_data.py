# Databricks notebook source
# MAGIC %run ./01_config

# COMMAND ----------

# DBTITLE 1,Recreate Database/Schema
ddls = [
f"""DROP SCHEMA IF EXISTS {getParam('db')} CASCADE""",
f"""CREATE SCHEMA IF NOT EXISTS {getParam('db')} LOCATION '{getParam('data_path')}'"""    
]

for d in ddls:
  print(d)
  spark.sql(d)

# COMMAND ----------

# MAGIC %sh
# MAGIC 
# MAGIC mkdir /dbfs/tmp/forensics2021
# MAGIC cd /dbfs/tmp/forensics2021
# MAGIC pwd
# MAGIC echo "Removing all files"
# MAGIC rm -rf *
# MAGIC echo
# MAGIC wget https://raw.githubusercontent.com/lipyeow-lim/security-datasets01/main/forensics-2021/logs.zip
# MAGIC 
# MAGIC unzip logs.zip
# MAGIC 
# MAGIC ls -lR

# COMMAND ----------

from pyspark.sql.functions import col
from pyspark.sql.types import *

# Load the zeek logs extracted from pcaps
for t in getParam('tables'):
  tb = f"{getParam('db')}.{t}"
  for f in getParam('folders'):
    jsonfile=f"{getParam('download_path')}/{f}/{t}.log"
    print(f"Loading {jsonfile} into {tb} ...")
    df = spark.read.format("json").load(jsonfile).withColumn("eventDate", col("ts").cast("Timestamp").cast("Date"))
    df.write.option("mergeSchema", "true").partitionBy("eventDate").mode("append").saveAsTable(tb)

# Load email alerts separately
t = "email_alerts"
f = "2021-10"
tb = f"{getParam('db')}.{t}"
jsonfile=f"{getParam('download_path')}/{f}/{t}.log"
print(f"Loading {jsonfile} into {tb} ...")
df = spark.read.format("json").load(jsonfile).withColumn("alertDate", col("detection_ts").cast("Timestamp").cast("Date"))
df.write.option("mergeSchema", "true").partitionBy("alertDate").mode("append").saveAsTable(tb)


# COMMAND ----------

def gen_create_view(db, tblist, view_name):
  ddl = f"""CREATE VIEW IF NOT EXISTS {db}.{view_name}\nAS\n"""
  db = getParam('db')
  querylist = []
  for t in getParam('tables'):
    if t in ["dhcp", "files", "ocsp", "pe", "x509"]:
      continue
    sqlstr = f"""
SELECT {db}.{t}.`id.orig_h` AS src,
       {db}.{t}.`id.resp_h` AS dst,
       '{t}' AS edge_type,
       ts::timestamp, eventDate,
       to_json(struct({db}.{t}.*)) AS raw
FROM {db}.{t}"""
    querylist.append(sqlstr)
  sqlstr = f"""
select `id.orig_h` as src, query as dst, 'dns-query' as edge_type, ts::timestamp, eventDate,
       to_json(struct({db}.dns.*)) AS raw
from {db}.dns"""
  querylist.append(sqlstr)
  sqlstr = f"""
select query as src, explode(answers) AS dst, 'dns-answer' as edge_type, ts::timestamp, eventDate,
       to_json(struct({db}.dns.*)) AS raw 
from {db}.dns where answers is not null"""
  querylist.append(sqlstr)
  sqlstr = f"""
select `id.orig_h` as src, client AS dst, 'kerberos-client' as edge_type, ts::timestamp, eventDate,
       to_json(struct({db}.kerberos.*)) AS raw 
from {db}.kerberos"""
  querylist.append(sqlstr)

  ddl = ddl + "\nUNION\n".join(querylist)
  return ddl

ddl = gen_create_view(getParam('db'), getParam('tables'), getParam('view_name'))
print(ddl)
spark.sql(f"DROP VIEW IF EXISTS {getParam('db')}.{getParam('view_name')}")
spark.sql(ddl)

# COMMAND ----------

# MAGIC %sql
# MAGIC 
# MAGIC select detection_ts, category, name, priority, left(raw, 200) as raw_prefix
# MAGIC from forensics_lipyeow_lim.email_alerts

# COMMAND ----------

# MAGIC %sql
# MAGIC 
# MAGIC select *
# MAGIC from forensics_lipyeow_lim.edges

# COMMAND ----------


