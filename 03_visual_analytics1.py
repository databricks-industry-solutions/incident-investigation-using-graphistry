# Databricks notebook source
# MAGIC %md This notebook is available at https://github.com/databricks-industry-solutions/incident-investigation-using-graphistry

# COMMAND ----------

# MAGIC %md
# MAGIC 
# MAGIC # Investigation Workflow using Graphistry Visual Analytics
# MAGIC 
# MAGIC The 2021-10-22 use case is adapted from the SANS Internet Storm Center's October 2021 Contest:
# MAGIC * Question: https://isc.sans.edu/diary/October+2021+Contest+Forensic+Challenge/27960
# MAGIC * Solution: https://isc.sans.edu/diary/October+2021+Forensic+Contest+Answers+and+Analysis/27998
# MAGIC 
# MAGIC The 2021-12-03 use case is adapted from the SANS Internet Storm Center's December 2021 Contest:
# MAGIC 
# MAGIC * Question: https://isc.sans.edu/diary/December+2021+Forensic+Challenge/28108
# MAGIC * Solution: https://isc.sans.edu/diary/December+2021+Forensic+Contest+Answers+and+Analysis/28160

# COMMAND ----------

# MAGIC %run ./config/notebook_config

# COMMAND ----------

dbutils.widgets.dropdown("date_filter", "2021-10-22", ["2021-10-22", "2021-12-03"])

# COMMAND ----------

# DBTITLE 1,Install graphistry
! pip install graphistry

# COMMAND ----------

# DBTITLE 1,Initialize graphistry
#Optional: Uncomment - We find this speeds up calls 10%+ on some datasets
spark.conf.set("spark.sql.execution.arrow.enabled", "true")

import graphistry  # if not yet available, install and/or restart Python kernel using the above

user = dbutils.secrets.get(scope="solution-accelerator-cicd", key="graphistry-username")
pw = dbutils.secrets.get(scope="solution-accelerator-cicd", key="graphistry-password")
# To specify Graphistry account & server, use:
graphistry.register(api=3, username=user, password=pw, protocol='https', server='hub.graphistry.com')
# For more options, see https://github.com/graphistry/pygraphistry#configure

graphistry.__version__

# COMMAND ----------

# DBTITLE 1,Get the vertices & edges from delta lake & send to graphistry
edges_table = f"{getParam('db')}.{getParam('view_name')}"
threat_intel = f"{getParam('db')}.threat_intel"
date_filter = dbutils.widgets.get("date_filter")

v = spark.sql(f"""
SELECT distinct e.src AS id, e.src AS name, t.disposition AS intel
FROM {edges_table} AS e LEFT OUTER JOIN {threat_intel} AS t ON e.src = t.obs_value
WHERE e.eventDate = '{date_filter}'
UNION
SELECT distinct e.dst AS id, e.dst AS name, t.disposition AS intel
FROM {edges_table} AS e LEFT OUTER JOIN {threat_intel} AS t ON e.dst = t.obs_value
WHERE e.eventDate = '{date_filter}'
""")

e = spark.sql(f"""
SELECT src, dst, edge_type AS relationship, ts, raw
FROM {edges_table}
WHERE eventDate = '{date_filter}'
""")

#print(e.count())
display(e)

p = (graphistry
    .bind(point_title='name')
    .nodes(v, 'id')
    .bind(edge_title='relationship')
    .edges(e, 'src', 'dst')
    .settings(url_params={'strongGravity': 'true'})
    .encode_point_color('intel', categorical_mapping={'malicious': '#F44'}, default_mapping='#09F')
    .plot()
)
p

# COMMAND ----------

sqlstr = f"""
SELECT detection_ts, category, name, priority, left(raw, 2000) as raw_prefix
FROM {getParam('db')}.email_alerts
"""
df = spark.sql(sqlstr)
display(df)

# COMMAND ----------

displayHTML("""<iframe width="420" height="315"
src="https://www.youtube.com/embed/tgbNymZ7vqY">
</iframe>""") # dummy video to show how to embed Youtube videos into notebooks

# COMMAND ----------

# MAGIC %md
# MAGIC 
# MAGIC # Investigation Flow
# MAGIC 
# MAGIC * You are a Tier 2 SOC analyst
# MAGIC * You are investigating three email alerts where the alert and the eml file is in the `email_alerts` table.
# MAGIC * All three emails have attachments containing malware
# MAGIC * The PCAP for the relevant time window has been parsed using zeek and the extracted L7 metadata loaded into your lakehouse. We restrict investigation to the L7 metadata (instead of the full packet capture).
# MAGIC * You pull the relevant edges and start visualizing the network traffic using Graphistry
# MAGIC * Your main objectives in the investigation is to answer the following questions:
# MAGIC   * Which host/machine was infected by the malware if any
# MAGIC   * Is there evidence of malware activity on the host/machine
# MAGIC   * Which users are involved on those infected machines
# MAGIC   
# MAGIC ## 2021-10-22: Email Alert - NanoCore RAT
# MAGIC 
# MAGIC * Inspecting the email, observe that it was received by `macrus.cobb@enemywatch.net`
# MAGIC * Using the inspect->table in Graphistry UI, use the search on the points:
# MAGIC   * `macrus` got no hits
# MAGIC   * `cobb` got a hit for kerberos client `marcus.cobb@ENEMYWATCH`. 
# MAGIC   * Click on the row to highlight the point in the visualization.
# MAGIC * Continue your investigations using the visualization and zoom in as needed.
# MAGIC * Observe the kerberos authentication is coming from `10.10.22.157`.
# MAGIC * Looking at other kerberos requests from `10.10.22.157`, observe that it maps to the host `desktop-nz875r4`. Is this host infected?
# MAGIC * Observe the many DNS requests for `kamuchehddhgfgf.ddns.net` (colored red because threat intelligence considered it malicious) and observe that it resolves to `37.0.10.22`. A bit of research will show that `kamuchehddhgfgf.ddns.net` with IPv4 `37.0.10.22` is a C2 server (see https://tria.ge/211103-1q6ljacear) 
# MAGIC * Looking at the edges between `10.10.22.157` and `37.0.10.22`, observe the many `conn` edges (connections) indicating data transfers.
# MAGIC * There is sufficient evidence that `10.10.22.157` has been infected with malware.
# MAGIC * You are now ready to write an incident report and take the required remediation actions.

# COMMAND ----------

# MAGIC %md
# MAGIC 
# MAGIC ## 2021-10-22 Email Alert - "Stolen Images Evidence"
# MAGIC 
# MAGIC * Examining the email, we see that the receipient is `kevin.henderson`.
# MAGIC * Using the `INSPECT`->`Data Table` in Graphistry UI, use the tab for points, and search for `kevin`.
# MAGIC * Click on the row for `kevin` to highlight the node in the visualization.
# MAGIC * Observe that Kevin is associated with the machine with IPv4 `10.10.22.158`.
# MAGIC * Looking at other `kerberos-client` edges, observe that the machine is associated with host name `DESKTOP-87WCE26`.
# MAGIC * From the node info pop out on the top-right, click on the round circle (Toggle Selection Expander), then click on the tick or check mark twice.
# MAGIC * Click the filter icon on the left side of the pop up to filter out the edges not in the selection. Re-center and re-cluster as needed.
# MAGIC * Look for nodes in the sub-graph that are red in color - nodes considered malicious by threat intelligence are colored red.
# MAGIC * Zoom in on the red node. Observe that it corresponds to an fqdn `sobolpand.top` and `10.10.22.158` has made DNS requests for it. See https://urlhaus.abuse.ch/host/sobolpand.top/
# MAGIC * Observe that the `dns-answer` edge resolves the malicious fqdn to `172.67.139.101` which is likely a C2 server.
# MAGIC * Click on `dns-answer` edge and click the circle icon to get the toggle selection expander. Click on the check mark twice and click filter. Re-center and re-cluster as needed.
# MAGIC * Observe that there are three edges between `10.10.22.158` and `172.67.139.101`. The two `http` edges indicate requests for files; the one `conn` edge indicates a file transfer.
# MAGIC * At this point, there is sufficient evidence that `10.10.22.158` is infected and communicates with a C2 server corresponding `sobolpand.top`.

# COMMAND ----------

# MAGIC %md
# MAGIC 
# MAGIC ## 2021-10-22: Email Alert - Qakbot
# MAGIC 
# MAGIC * Examining the email, we see that the receipient is `agnes.warren`.
# MAGIC * Using the `INSPECT`->`Data Table` in Graphistry UI, use the tab for points, and search for `agnes`.
# MAGIC * Click on the row for `agnes` to highlight the node in the visualization.
# MAGIC * Observe that `agnes` is associated with the machine with IPv4 `10.10.22.156`.
# MAGIC * Looking at other `kerberos-client` edges, observe that the machine is associated with host name `DESKTOP-CFA3367`.
# MAGIC * From the node info pop out on the top-right, click on the round circle (Toggle Selection Expander), then click on the tick or check mark twice.
# MAGIC * Click the filter icon on the left side of the pop up to filter out the edges not in the selection. Re-center and re-cluster as needed.
# MAGIC * Look for nodes in the sub-graph that are red in color - nodes considered malicious by threat intelligence are colored red.
# MAGIC * Observe there are two red nodes in the sub-graph: `194.36.191.35` and `23.111.114.52` Zoom in on `194.36.191.35`.
# MAGIC * Use the toggle selection expander to filter and focus on the two edges incident on `194.36.191.35`.
# MAGIC * Observe that there was a `http` get request for a URI/file `/44491.6090605324.dat` followed by `conn` data transfer. A bit of research reading will show that the filename is associated with the Qakbot malware (see https://tria.ge/211103-27thzacehl).
# MAGIC * Repeating the same procedure on `23.111.114.52` reveals a `conn` data transfer edge as well.
# MAGIC * Perform an `edge:relationship` histogram and click on the `smtp` bar to filter out non-`smtp` edges from `10.10.22.156`. 
# MAGIC * Observe that the unusually large number of smtp servers that Agnes' desktop `10.10.22.156` is connecting to.
# MAGIC * There is sufficient evidence that Agnes' desktop has been compromised.

# COMMAND ----------

# MAGIC %md
# MAGIC 
# MAGIC * A Tier 1 SOC analyst noticed some suspicious network traffic on Dec 3, 2021 and asked you to take a look at the PCAP.
# MAGIC 
# MAGIC ## 2021-12-03: SpamBot
# MAGIC 
# MAGIC * Just looking at the Graphistry visualization, it is clear that `10.12.3.66` is connecting with an unusually large number of other hosts.
# MAGIC * Click on `10.12.3.66`.
# MAGIC * In the node info popup on the top right, click the circle icon for the toggle selection expander. Click the check mark once and click on the filter icon to focus on the neighborhood of `10.12.3.66`
# MAGIC * Use the histogram filter on `edge:relationship` and click on the bar for `kerberos`
# MAGIC * Observe that the user of `10.12.3.66` is `darin.figueroa`.
# MAGIC * Click on the bar for `dns-query` and observe that the host name is `DESKTOP-LUOABV1`. Now, let's look for more evidence of infection?
# MAGIC * Look around for malicious nodes (colored red based on threat intelligence).
# MAGIC * Observe two red nodes: `gamaes.shop`, `newsaarctech.com`. Both are associated with the **emotet** malware.
# MAGIC * Zoom in and observe they resolve to `104.21.29.80`, `139.59.6.175` respectively - these are malicious too.
# MAGIC * For each of the IPv4, use the toggle selection expander to filter for the edges to the malicious IPv4
# MAGIC * For `104.21.29.80`, observe a `http` edge for getting `/wp-content/Sx9tvV5/` and a `conn` edge for data transfer.
# MAGIC * For `139.59.6.175`, observe a `http` edge for getting `/wp-content/plugins/sSTToaEwCG5VASw/` and a `conn` edge for data transfer
# MAGIC * On the histogram filter on `edge:relationship`, click on the bar for `smtp`. Observe the unusual number of connections to different smtp servers. Repeat for `ssl` handshakes.
# MAGIC * At this point, there is sufficient evidence that `10.12.3.66` is infected with the emotet malware.
# MAGIC * You are now ready to write an incident report and take the required remediation actions.
