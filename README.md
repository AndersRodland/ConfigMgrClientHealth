# ConfigMgrClientHealth
ConfigMgr Client Health Development code. Version: 0.7.4 Beta

This is the unstable development version. 
Latest stable version: https://gallery.technet.microsoft.com/ConfigMgr-Client-Health-ccd00bd7

Full documentation of stable version: https://www.andersrodland.com/configmgr-client-health/

Note: Script version 0.7.4 requires database version 0.7.3.

Changes since stable release:
* Experimental Powershell Core support, tested successfulyl with PowerShell 6.0.1 on Windows 10 64-Bit 1709.
* Script will uninstall ConfigMgr client before installing it again if local database files are missing (less than 7).
* Corrupt WMI check now works on Finish OS language.
* Did some cleanup on code to improve readability.
* LocalFiles will now default to C:\ClientHealth if nothing is specified in config.xml

This software is provided "AS IS" with no warranties. Use at your own risk.