# ConfigMgr Client Health Development for historical data and dashboard reporting Code
Version: 0.1.10

This is the unstable development version. DO NOT run this in a production environment. 
This is part of ConfigMgr Client Health 

Note: Script version 0.1.10 requires database version 0.8.2.

# Short Installationsguide
a) to create the new objects for the DB,  start SQL Management Studio and run the SQL Script .\CreateDBObjects\Create_All_Hist_Report_Object_0.1.10.sql
b) import the Report to Reporting Services .\Reporting\output\ConfigMgrClientHealth Dashboard.rdl
c) import the Report to Reporting Services .\Reporting\output\ConfigMgrClientHealth ClientData.rdl
d) change the Datasources for the RDL to your Server and DB
e) import the Data for the Tables, using the file from .\DataLoad\Raw_data_4_all_Tables_0.1.10.xls
   the best way is here to use the SQL Import data wizard

## 
This software is provided "AS IS" with no warranties. Use at your own risk.
