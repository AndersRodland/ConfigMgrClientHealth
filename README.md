# ConfigMgr Client Health Development Code

Version: 0.8.2

This is the master branch of ConfigMgr Client Health and is ready for production.

Download the stable version including the webservice: [Technet Galleries](https://gallery.technet.microsoft.com/ConfigMgr-Client-Health-ccd00bd7)

[ConfigMgr Client Health Full documentation](https://www.andersrodland.com/configmgr-client-health/)

Note: Script version 0.8.2 requires database version 0.7.5.


## Changes since stable release

* Fixed a bug where logging directly to SQL database would not work.
* Fixed an issue with BITS test.
* Fixed a bug where service uptime test didn't work properly.
* ClientCacheSize check no longer need to restart CM Agent when changing the cache size.
* ClientCacheSize max limit 99999.
* Fixes errors where configuration baselines fails because script is not signed even when bypass is set as execution policy in client settings.
* Script will now stop services that are in a degraded state.
* Improved code to detect last installed patched.
* Updated database to allow null for LastLoggedOnUser.
* Check client version is now run at end of script in case client was upgraded by script.
* Script will no longer run if it detects a task sequence already running on the computer.
* Script will not restart services if another installation is running.
* Hostname is now read from environmental variable and not WMI.
* Several bugfixes to script.
* Add Windows Server 2019 support.
* Improved WMI test and fix.
* Will only log to webservice if parameter is specificed.
* Improved the error message when script fails to update SQL.
* Logfiles are now compatible with CMTrace.


This software is provided "AS IS" with no warranties. Use at your own risk.
