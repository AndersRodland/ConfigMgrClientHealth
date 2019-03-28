# ConfigMgr Client Health Development Code

Version: 0.8.2

This is the unstable development version. DO NOT run this in a production environment.
[Download stable version instead](https://gallery.technet.microsoft.com/ConfigMgr-Client-Health-ccd00bd7)

[ConfigMgr Client Health Full documentation](https://www.andersrodland.com/configmgr-client-health/)

Note: Script version 0.8.2 requires database version 0.8.2.

## Changes since stable release

* Fixed a bug where logging directly to SQL database would not work.
* Fixed an issue with BITS test.
* Fixed a bug where service uptime test didn't work properly.
* ClientCacheSize check no longer need to restart CM Agent when changing the cache size.
* ClientCacheSize max limit 99999 (Lauri Kurvinen)
* Fixes erros where configuration baselines fails because script is not signed even when bypass is set as executionpolicy in client settings (Lauri Kurvinen).
* Script will now stop services that are in a degraded state (Cody Mathis)
* Improved code to detect last installed patched (Cody Mathis)
* Updated database to allow null for LastLoggedOnUser
* Check client version is now run at end of script in case client was upgraded by script
* Config is stored in SQL database and presented to script through webservice
* Script will no longer run if it detects a task sequence already running on the computer
* Several bugfixes to script thanks to Apila22

This software is provided "AS IS" with no warranties. Use at your own risk.
