# Databricks notebook source
# MAGIC %md
# MAGIC 
# MAGIC # Setup Configuration

# COMMAND ----------

import os
import json
import re

cfg={}
cfg["useremail"] = dbutils.notebook.entry_point.getDbutils().notebook().getContext().userName().get()
cfg["username"] = cfg["useremail"].split('@')[0]
cfg["username_sql_compatible"] = re.sub('\W', '_', cfg["username"])
cfg["db"] = f"forensics_{cfg['username_sql_compatible']}"
cfg["data_path"] = f"/tmp/{cfg['username_sql_compatible']}/forensics2021/"
cfg["download_path"] = "/tmp/forensics2021"
cfg["view_name"] = "edges"
cfg["folders"] = ["2021-10", "2021-12"]
cfg["tables"] = ["conn",
"dce_rpc",
"dhcp",
"dns",
"dpd",
"files",
"http",
"kerberos",
"ntlm",
"ocsp",
"pe",
"smb_files",
"smb_mapping",
"smtp",
"ssl",
"weird",
"x509"]

if "getParam" not in vars():
  def getParam(param):
    assert param in cfg
    return cfg[param]

print(json.dumps(cfg, indent=2))


