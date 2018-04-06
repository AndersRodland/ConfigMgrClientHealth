# ConfigMgr Client Health Development Code.

Version: 0.7.5 Beta

This is the unstable development version. 
Latest stable version: https://gallery.technet.microsoft.com/ConfigMgr-Client-Health-ccd00bd7

Full documentation of stable version: https://www.andersrodland.com/configmgr-client-health/

Note: Script version 0.7.5 requires database version 0.7.3.

## Changes since stable release:

* Added test to verify SMSTSMgr is dependent on CCMExec service.
* Added support in script for updating database with webservice. The webservice will not be released in 0.7.5.
* Improved test on local group policy file.
* Removed more hardcoded paths in the script.
* Script will resend clients compliance state.
* Script will now write a timestamp in registry when it runs to show last run time.
* More fixes from Bryan Adams

This software is provided "AS IS" with no warranties. Use at your own risk.