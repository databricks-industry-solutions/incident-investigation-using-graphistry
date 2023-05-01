# Databricks notebook source
# MAGIC %md
# MAGIC
# MAGIC # Investigation Workflow using SQL Analytics
# MAGIC
# MAGIC This notebook demonstrates how to use Databricks notebooks for incident investigations on network L7 metadata extracted from PCAP using Zeek. The scenario starts with either an email alert from a detection system or an email in an abuse email mailbox (where user reported phishing emails are stored) and the objective of the investigation is to determine if the malware from the email did infect a machine and hence needs to be contained and remediated. 
# MAGIC
# MAGIC We will assume that the analyst performing the investigation:
# MAGIC 1. knows how to write SQL queries, and 
# MAGIC 2. knows the schema of the zeek data (the tables and the columns).
# MAGIC
# MAGIC ## Prerequisites
# MAGIC Run the `02_load_data.py` notebook first to load the required data sets before running this notebook. 
# MAGIC
# MAGIC ## Source Materials
# MAGIC
# MAGIC The 4 incidents are derived from the sources listed below. The key difference between this notebook and the original use cases is that the original use cases assume full access to the PCAP including the binaries/payload in the PCAP - this notebook only rely on the L7 metadata and some threat intelligence for the investigation workflow.
# MAGIC
# MAGIC The 2021-10-22 use case is adapted from the SANS Internet Storm Center's October 2021 Contest and consist of three tasks/incidents:
# MAGIC * Question: https://isc.sans.edu/diary/October+2021+Contest+Forensic+Challenge/27960
# MAGIC * Solution: https://isc.sans.edu/diary/October+2021+Forensic+Contest+Answers+and+Analysis/27998
# MAGIC
# MAGIC The 2021-12-03 use case is adapted from the SANS Internet Storm Center's December 2021 Contest ans consist of one task/incident:
# MAGIC
# MAGIC * Question: https://isc.sans.edu/diary/December+2021+Forensic+Challenge/28108
# MAGIC * Solution: https://isc.sans.edu/diary/December+2021+Forensic+Contest+Answers+and+Analysis/28160

# COMMAND ----------

# MAGIC %run ./config/notebook_config

# COMMAND ----------

spark.sql(f"""use schema {getParam('db')}""")

# COMMAND ----------

# MAGIC %md
# MAGIC
# MAGIC ## List of email alerts

# COMMAND ----------

# MAGIC %sql
# MAGIC select detection_ts, category, name, priority, left(raw, 2000) as raw_prefix
# MAGIC from email_alerts

# COMMAND ----------

# MAGIC %md
# MAGIC
# MAGIC # 1. Let's investigate the `Nanocore RAT` email alert.
# MAGIC
# MAGIC * Observe that the recipient is `macrus.cobb@enemywatch.net`
# MAGIC
# MAGIC ## 1.1 Let's look in the `kerberos` authentication data
# MAGIC
# MAGIC to hopefully find the desktop

# COMMAND ----------

# MAGIC %sql
# MAGIC select * 
# MAGIC from kerberos
# MAGIC where eventDate = '2021-10-22' and client ilike 'macrus.cobb%'

# COMMAND ----------

# MAGIC %md
# MAGIC
# MAGIC ### Observations
# MAGIC
# MAGIC * `macrus.cobb` got no hits.
# MAGIC
# MAGIC ## 1.2 Let's try the lastname.

# COMMAND ----------

# MAGIC %sql
# MAGIC select * 
# MAGIC from kerberos
# MAGIC where eventDate = '2021-10-22' and client ilike '%cobb%'

# COMMAND ----------

# MAGIC %md
# MAGIC ### Observations
# MAGIC * The recipient `macrus.cobb` in the email header is misspelled. It is possible that the header might have been tampered with.
# MAGIC * User `marcus.cobb` is associated with the IPv4 `10.10.22.157` and that is the only IPv4 associated.
# MAGIC * User `marcus.cobb` is associated with the host `desktop-nz875r4` and that is the only host associated.
# MAGIC
# MAGIC ## 1.3 Let's check what IP address the host resolves to.

# COMMAND ----------

# MAGIC %sql
# MAGIC select *
# MAGIC from dns
# MAGIC where eventDate = '2021-10-22' and query ilike '%desktop-nz875r4%' and answers is not null

# COMMAND ----------

# MAGIC %md
# MAGIC ### Observations
# MAGIC * The DNS requests confirm that `desktop-nz875r4` resolves to `10.10.22.157`
# MAGIC * So this host is likely Marcus' desktop and has the IPv4 `10.10.22.157`. If Marcus downloaded the malware in the email onto his desktop and if malware has been executed, we will likely see network traffic from the malware from this IPv4 address. 
# MAGIC
# MAGIC ## 1.4 Let's look at the traffic to/fro `10.10.22.157`

# COMMAND ----------

# MAGIC %sql
# MAGIC select *
# MAGIC from http
# MAGIC where eventDate = '2021-10-22' and `id.orig_h` = '10.10.22.157'

# COMMAND ----------

# MAGIC %md
# MAGIC
# MAGIC ### Observations
# MAGIC
# MAGIC * Only two http records and they don't look suspicious or interesting
# MAGIC
# MAGIC ## 1.5 Let's check the connections records

# COMMAND ----------

# MAGIC %sql
# MAGIC
# MAGIC select `id.orig_h` as src_ip, `id.resp_h` as dst_ip, `id.resp_p` as dst_port, count(*) as conn_cnt, sum(orig_bytes) as orig_total_bytes, sum(resp_bytes) as resp_total_bytes
# MAGIC from conn
# MAGIC where eventDate = '2021-10-22' and `id.orig_h` = '10.10.22.157'
# MAGIC group by `id.orig_h`, `id.resp_h`, `id.resp_p`
# MAGIC order by conn_cnt desc

# COMMAND ----------

# MAGIC %md
# MAGIC
# MAGIC ### Observations
# MAGIC
# MAGIC * We will start by looking at the top few destinations with the most traffic.
# MAGIC * There are a lot of communications to `37.0.10.22` on port 1187 which is also an external IPv4 address
# MAGIC * `8.8.8.8` is just the Google DNS server
# MAGIC * `10.10.22.*` are internal to the organization
# MAGIC
# MAGIC ## 1.6 Let's check `DNS` to see what is the fqdn for `37.0.10.22`

# COMMAND ----------

# MAGIC %sql
# MAGIC
# MAGIC select *
# MAGIC from dns
# MAGIC where eventDate = '2021-10-22' and array_contains(answers, '37.0.10.22') 

# COMMAND ----------

# MAGIC %md
# MAGIC
# MAGIC ### Observations
# MAGIC
# MAGIC * `kamuchehddhgfgf.ddns.net` looks suspicious, because the first part looks like a random string from a domain generating algorithm (DGA).
# MAGIC * VirusTotal thinks the fqdn is malicious: https://www.virustotal.com/gui/url/73e548597b6144b72164f7fc09d4a65005ac6487a3535838bcb9cfc014aee2cb
# MAGIC * RecordedFuture gives more info and shows that the IPv4 `37.0.10.22` (on port 1187) is a C2 server for the nanocore family of malware: https://tria.ge/211103-1q6ljacear
# MAGIC
# MAGIC ## 1.7 Disposition
# MAGIC
# MAGIC * At this point there is enough evidence that `10.10.22.157` is infected with the Nanocore RAT malware and is communicating with the associated C2 server at `37.0.10.22`.
# MAGIC * Next steps would be to write an incident report and to contain/remediate `10.10.22.157`

# COMMAND ----------


