# ConfigMgr Client Health

Version: 0.8.3

This is the master branch of ConfigMgr Client Health and is ready for production.

Download the stable version including the webservice: [ConfigMgr Client Health 0.8.3](https://github.com/AndersRodland/ConfigMgrClientHealth/raw/master/Download/ConfigMgrClientHealth-0.8.3.zip)

[ConfigMgr Client Health Full documentation](https://www.andersrodland.com/configmgr-client-health/)

Note: Script version 0.8.3 requires database version 0.7.5.


## Changes since stable release

* Client Health now successfully sets the client max log history.
* Client Health now successfully sets the client cache size.
* Fixed an issue where ClientInstallProperty using /skipprereq and specifying multiple components while separating with ";" would break the script.
* Updated criteria for excluding Defender signature updates in the Get-LastInstalledPatches function. Thanks to Scott Ladewig.
* Enabled debug logging in the webservice by default to make troubleshooting easier. Debug logs are stored in the "logs" folder.


This software is provided "AS IS" with no warranties. Use at your own risk.
