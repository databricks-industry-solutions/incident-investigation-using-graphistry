# Databricks notebook source
# MAGIC %md
# MAGIC 
# MAGIC # Investigation using Graphistry Visual Analytics
# MAGIC 
# MAGIC This use case is adapted from the SANS Internet Storm Center's October 2021 Contest:
# MAGIC * Question: https://isc.sans.edu/diary/October+2021+Contest+Forensic+Challenge/27960
# MAGIC * Solution: https://isc.sans.edu/diary/October+2021+Forensic+Contest+Answers+and+Analysis/27998

# COMMAND ----------

# MAGIC %run ./01_config

# COMMAND ----------

# DBTITLE 1,Install graphistry
! pip install graphistry

# COMMAND ----------

# DBTITLE 1,Initialize graphistry
#Optional: Uncomment - We find this speeds up calls 10%+ on some datasets
spark.conf.set("spark.sql.execution.arrow.enabled", "true")

import graphistry  # if not yet available, install and/or restart Python kernel using the above

# To specify Graphistry account & server, use:
graphistry.register(api=3, username='lipyeow', password=dbutils.secrets.get(scope="lipyeow-sec01", key="graphistry-pw"), protocol='https', server='hub.graphistry.com')
# For more options, see https://github.com/graphistry/pygraphistry#configure

graphistry.__version__

# COMMAND ----------

# DBTITLE 1,Get the vertices & edges from delta lake
edges_table = f"{getParam('db')}.{getParam('view_name')}"
v = spark.sql(f"""
SELECT distinct src AS id, src AS name
FROM {edges_table}
WHERE eventDate = '2021-10-22'
UNION
SELECT distinct dst AS id, dst AS name
FROM {edges_table}
WHERE eventDate = '2021-10-22'
""")

# duplicate the edges in the reverse direction in order to enable undirected path finding
e = spark.sql(f"""
SELECT src, dst, edge_type AS relationship, ts 
FROM {edges_table}
WHERE eventDate = '2021-10-22'
""")

#print(e.count())
display(e)

# COMMAND ----------

p = (graphistry
    .bind(point_title='name')
    .nodes(v, 'id')
    .bind(edge_title='relationship')
    .edges(e, 'src', 'dst')
    .settings(url_params={'strongGravity': 'true'})
    .plot()
)
p

# COMMAND ----------

sqlstr = f"""
SELECT detection_ts, category, name, priority, left(raw, 200) as raw_prefix
FROM {getParam('db')}.email_alerts
"""
df = spark.sql(sqlstr)
display(df)

# COMMAND ----------

# MAGIC %md
# MAGIC 
# MAGIC # Investigation Flow
# MAGIC 
# MAGIC * You are a Tier 2 SOC analyst
# MAGIC * You are investigating three email alerts where the alert and the eml file is in the `email_alerts` table.
# MAGIC * All three emails have attachments containing malware
# MAGIC * The PCAP for the relevant time window has been parsed using zeek and the extracted L7 metadata loaded into your lakehouse
# MAGIC * You pull the relevant edges and start visualizing the network traffic using Graphistry
# MAGIC * Your main objectives in the investigation is to answer the following questions:
# MAGIC   * Which host/machine was infected by the malware if any
# MAGIC   * Which users are involved on those infected machines
# MAGIC   
# MAGIC ## Email Alert 1 : NanoCore RAT
# MAGIC 
# MAGIC * Examining the email, you see that it was received by `macrus.cobb@enemywatch.net`
# MAGIC * Using the inspect->table in Graphistry UI, use the search on the points:
# MAGIC   * `macrus` got no hits
# MAGIC   * `cobb` got a hit for kerberos client `marcus.cobb@ENEMYWATCH`. 
# MAGIC   * Click on the row to highlight the point in the visualization.
# MAGIC * Continue your investigations using the visualization and zoom in as needed.
# MAGIC * You discover that the kerberos authentication is coming from `10.10.22.157`.
# MAGIC * Looking at other kerberos requests from `10.10.22.157`, you discover that it maps to the host `desktop-nz875r4`. Is this host infected?
# MAGIC * Looking at the graph, you see many DNS requests for `kamuchehddhgfgf.ddns.net` and you also see that it resolves to `37.0.10.22`
# MAGIC * A bit of googling yields an important piece of info that `kamuchehddhgfgf.ddns.net` and `37.0.10.22` is a C2 server (see https://tria.ge/211103-1q6ljacear) 
# MAGIC * Looking at the edges between `10.10.22.157` and `37.0.10.22`, you discover many `conn` edges (connections) and you now hypothesize that `10.10.22.157` is an infected node.
# MAGIC * You double check the timestamps to validate that your hypothesis holds up.
# MAGIC * You are now ready to write an incident report and take the required remediation actions.

# COMMAND ----------


