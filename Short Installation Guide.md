# Short Installation Guide

*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** * 
*** *** please before you add this extension make a backup of your current DB (only for security reasons) *** *** 
*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** * 
# Client Health DB Extension
1) to create the new objects for the DB, start SQL Management Studio 
    and run the SQL Script .\Create_All_Hist_Report_Object_0.1.13.sql

*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** 
*** depend on your Reporting Server Version you can use the 
*** Report Version (Report4_2016andHigher) or (Reports4_2008R2_2012_2014)
*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** 

# Reports 4 SRS 2008R2-2014
if you use Report Server 2008R2-/-2012-/-2014
    2.1) import the Report to Reporting Services 
            .\Reports4_2008R2_2012_2014\ConfigMgrClientHealth Dashboard.rdl
    3.1) import the Report to Reporting Services 
            .\Reports4_2008R2_2012_2014\ConfigMgrClientHealth ClientData.rdl

# Reports 4 SRS 2016
if you use Report Server 2016 and higher
    2.2) import the Report to Reporting Services 
            .\Report4_2016andHigher\ConfigMgrClientHealth Dashboard.rdl
    3.2) import the Report to Reporting Services 
        .\Report4_2016andHigher\ConfigMgrClientHealth ClientData.rdl

4) change the Data Source for the RDL to your Server and DB
5) import the Data for the Tables, using the file from .\Raw_data_4_all_Tables_0.1.13.xls
   the best way is here to use the SQL Import data wizard
   see Install Guide to import the configuration data.htm

# configuration 
6) after the installation is done you need to configure the extension to reflect your environment.
   Open the table "[SCCM_Config]" 
   check -/- or change the values 
   a = Para_Actual_Term	1,3,4,5,6,7,43503	this is for the actual term view (show clients based on this timestamp), 43503 is to show all please not remove this value.
   b = SCCM_Current_ClientVersion       	40.1012	Version for the SCCM Client Version you use; should the same as inside the Configuration XML
   c = Para_Long_Term	                        basically same as Para Actual Term but for the long term data!, the value 43503 is to show all please not remove this value
   d = SCCM_ClientHealthTargetCount		this value is your current total count of your Windows machine (managed through SCCM)

EOF