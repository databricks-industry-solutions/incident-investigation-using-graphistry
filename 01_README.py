# Databricks notebook source
# MAGIC %md This notebook is available at https://github.com/databricks-industry-solutions/incident-investigation-using-graphistry

# COMMAND ----------

# MAGIC %md 
# MAGIC ![image](https://github.com/lipyeowlim/public/raw/main/img/logo/databricks_cyber_logo_v1.png)
# MAGIC 
# MAGIC [![CLOUD](https://img.shields.io/badge/CLOUD-ALL-blue?logo=googlecloud&style=for-the-badge)](https://cloud.google.com/databricks)
# MAGIC [![POC](https://img.shields.io/badge/POC-10_days-green?style=for-the-badge)](https://databricks.com/try-databricks)
# MAGIC 
# MAGIC # Incident Investigation using Graphistry
# MAGIC 
# MAGIC Contact Author: <lipyeow.lim@databricks.com>
# MAGIC 
# MAGIC ## Use Cases
# MAGIC 
# MAGIC Personas: SOC analyts, Incident Responders, Threat Hunters
# MAGIC 
# MAGIC * Investigate an incident or alert to determine if it is true positive or false positive. If it is a true positive, determine the host and users impacted, so that remediation steps can be taken.
# MAGIC * Investigate leads from a threat hunting exercise.
# MAGIC * Hunt for threats given a piece of threat intelligence or a news release
# MAGIC 
# MAGIC ## Reference Architecture
# MAGIC 
# MAGIC ![image](https://github.com/lipyeowlim/public/raw/main/img/incident-investigation/incident-investigation-graphistry-arch.png)
# MAGIC 
# MAGIC The above reference architecture only shows a specific data path for network packet capture data. In production, there will be many data paths for different cybersecurity  data sources.
# MAGIC 
# MAGIC ## Technical Overview
# MAGIC 
# MAGIC ___
# MAGIC 
# MAGIC &copy; 2022 Databricks, Inc. All rights reserved. The source in this notebook is provided subject to the Databricks License [https://databricks.com/db-license-source].  All included or referenced third party libraries are subject to the licenses set forth below.
# MAGIC 
# MAGIC | library                                | description             | license    | source                                              |
# MAGIC |----------------------------------------|-------------------------|------------|-----------------------------------------------------|
# MAGIC | Graphistry | GPU-accelerated graph visualization | BSD-3-Clause | https://github.com/graphistry/pygraphistry |
# MAGIC 
# MAGIC ## Pre-requisites
# MAGIC 
# MAGIC 1. Create a free graphistry account at https://hub.graphistry.com/ if you do not already have an account. Take note of your graphistry username and password. You will need them to use the graphistry visualization in the notebooks.
# MAGIC 2. Install the databricks CLI using the instructions: https://docs.databricks.com/dev-tools/cli/index.html
# MAGIC 3. Create a secret scope using the databricks CLI: 
# MAGIC     databricks secrets create-scope --scope lipyeow-sec01
# MAGIC 4. Create a secret key storing the graphistry password:
# MAGIC     databricks secrets put --scope lipyeow-sec01 --key graphistry-pw
# MAGIC 
# MAGIC You could skip steps 2-4 above and put your graphistry password into the notebooks, but that is not recommended, because it is not a security best practice.
# MAGIC 
# MAGIC ## Getting started
# MAGIC 
# MAGIC Although specific solutions can be downloaded as .dbc archives from our websites, we recommend cloning these repositories onto your databricks environment. Not only will you get access to latest code, but you will be part of a community of experts driving industry best practices and re-usable solutions, influencing our respective industries. 
# MAGIC 
# MAGIC <img width="500" alt="add_repo" src="https://user-images.githubusercontent.com/4445837/177207338-65135b10-8ccc-4d17-be21-09416c861a76.png">
# MAGIC 
# MAGIC To start using a solution accelerator in Databricks simply follow these steps: 
# MAGIC 
# MAGIC 1. Clone solution accelerator repository in Databricks using [Databricks Repos](https://www.databricks.com/product/repos)
# MAGIC 2. Attach the `RUNME` notebook to any cluster and execute the notebook via Run-All. A multi-step-job describing the accelerator pipeline will be created, and the link will be provided. The job configuration is written in the RUNME notebook in json format. 
# MAGIC 3. Execute the multi-step-job to see how the pipeline runs. 
# MAGIC 4. You might want to modify the samples in the solution accelerator to your need, collaborate with other users and run the code samples against your own data. To do so start by changing the Git remote of your repository  to your organization’s repository vs using our samples repository (learn more). You can now commit and push code, collaborate with other user’s via Git and follow your organization’s processes for code development.
# MAGIC 
# MAGIC The cost associated with running the accelerator is the user's responsibility.
# MAGIC 
# MAGIC 
# MAGIC ## Project support 
# MAGIC 
# MAGIC Please note the code in this project is provided for your exploration only, and are not formally supported by Databricks with Service Level Agreements (SLAs). They are provided AS-IS and we do not make any guarantees of any kind. Please do not submit a support ticket relating to any issues arising from the use of these projects. The source in this project is provided subject to the Databricks [License](./LICENSE). All included or referenced third party libraries are subject to the licenses set forth below.
# MAGIC 
# MAGIC Any issues discovered through the use of this project should be filed as GitHub Issues on the Repo. They will be reviewed as time permits, but there are no formal SLAs for support. 
