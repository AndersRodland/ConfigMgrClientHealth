# ConfigMgr Client Health Development Code

Version: 0.7.6 Beta

This is the unstable development version.
[Download stable version](https://gallery.technet.microsoft.com/ConfigMgr-Client-Health-ccd00bd7)

[ConfigMgr Client Health Full documentation](https://www.andersrodland.com/configmgr-client-health/)

Note: Script version 0.7.6 requires database version 0.7.5.

## Setup For Custom Database Information
### Required Files
* SetupAdvDBCreation.ps1
* ConfigMgrClientHealth.ps1

### Steps
1. Configure the SetupAdvDBCreation.ps1 script to name the database and tables how you need them in your environment.  This will let you target a database that already exists as well as change the names of the tables if you need to.
  * When run, this will create a `CreateDatabaseAdv_Custom.sql` file.  Use this to setup your database environment.
2. Make sure you update the SQL entry in the `config.xml` to have the custom names you defined:
  * `<Log Name="SQL" Server="server-name" Enabled="True" Database="ClientHealth" ClientsTable="Clients" />`

## Changes since stable release

* Changed test to verify SMSTSMgr is not dependent on CCMExec service, and only WMI service.
* Added test to verify no active task sequence is executing on computer

This software is provided "AS IS" with no warranties. Use at your own risk.