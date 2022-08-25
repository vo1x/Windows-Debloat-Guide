<h1 align="center"> 🗑 Windows Debloat Guide </h1>

## Introduction

Because of its extensive telemetry and online features, Windows has sparked several privacy concerns. When telemetry is set to basic, most of it appears to be legitimate, but if you don't trust them, here's how to stop Windows from sending your data to Microsoft and debloat your system.
> **Last updated:** August 25, 2022


#### ⚠ IMPORTANT:

All changes you make after following this guide **CANNOT** be reversed or undone without reinstalling Windows. Therefore, please do not follow this guide if:
- You have no idea what you're doing or are inexperienced
- For whatever reason, you must use a Microsoft Account
- You need the Windows Store to install applications
- You want to receive Windows feature updates
- You do not use a third-party antivirus and therefore require Windows Defender

Please keep in mind that you are doing this entirely at your own risk, and I will not be held liable for any data loss or damage. So make a backup of all your files.

## Prerequisites

The following are the prerequisites you must have before you begin. And wherever possible, an installation/setup guide has been included.

ℹ Please clone the repository to your computer. The repo contains all of the necessary files.

- Wim Tweak Tool:
    - Open RUN (`Win + R`), type `system32` and press **OK**. This will open the **System32** folder.
    - Copy the `install_wim_tweak.exe` file to the folder.
    - Open RUN again, type `C:\Windows`, and press **OK**. This will open the **Windows** folder.
    - Copy the `install_wim_tweak.exe` file to the folder.

- NTFS Access 2.5
- Dism++ 10.1.1002.1


## Preliminary Tweaking

> If your are not a clean install, please skip this step.

If you have a fresh Windows installation and haven't yet configured anything, you might want to clean up the component store. Please follow the instructions below to do so.

- Extract the provided `Dism++ 10.1.1002.1` and run `DISM++ x64` or `DISM++ x86` file as per your OS.
- Navigate to **Disk Cleanup** from the left-pane, and tick all the checkboxes you see.
- Press **Scan** which is on the bottom right, and after it's done, just press **Clean Up**.

![DISM_Guide](https://imgur.com/hWozpNi.png)
<p align="center"><sub>DISM Guide</sub></p>

If you encounter an error while cleaning up the component store, use Command Prompt (Admin) to execute the following command:
```
DISM /Online /Cleanup-Image /StartComponentCleanup /ResetBase
```
<br>

Once that's done, you can move on to uninstalling the apps.

## Removing Bloatware

**⚠IMPORTANT:** When executing the commands below, always run Powershell and/or Command Prompt as Administrator.

### Alarms and Clock

**Run in Powershell,**
```ps
Get-AppxPackage -AllUsers *alarms* | Remove-AppxPackage
Get-AppxPackage -AllUsers *people* | Remove-AppxPackage
```

### Calculator

**Run in Powershell,**
```ps
Get-AppxPackage -AllUsers *calc* | Remove-AppxPackage
```
> As a replacement, you can use the [Classic Calculator](https://winaero.com/get-calculator-from-windows-8-and-windows-7-in-windows-10/) app.

### Mail, Calendar, ...

**Run in Powershell,**
```ps
Get-AppxPackage -AllUsers *comm* | Remove-AppxPackage
Get-AppxPackage -AllUsers *mess* | Remove-AppxPackage
```

### Camera

**Run in Powershell,**
```ps
Get-AppxPackage -AllUsers *camera* | Remove-AppxPackage
```
> Ignore errors, if there are any.

### Connect


**Run in Command Prompt,**
```cmd
install_wim_tweak /o /c Microsoft-PPIProjection-Package /r
```

### Contact Support, Get Help

**Run in Command Prompt,**
```cmd
install_wim_tweak /o /c Microsoft-Windows-ContactSupport /r
```

### Cortana (UWP App)

**Run in Powershell,**
```ps
Get-AppxPackage -allusers Microsoft.549981C3F5F10 | Remove-AppxPackage
```

### Music, TV

**Run in Powershell,**
```
Get-AppxPackage -AllUsers *zune* | Remove-AppxPackage
Get-WindowsPackage -Online | Where PackageName -like *MediaPlayer* | Remove-WindowsPackage -Online -NoRestart
```

### Groove Music

**Run in Powershell,**
```ps
Get-AppxPackage -AllUsers *zune* | Remove-AppxPackage
```

### Microsoft Solitare Collection

**Run in Powershell,**
```ps
Get-AppxPackage *Microsoft.MicrosoftSolitaireCollection* | Remove-AppxPackage
```

### Office

**Run in Powershell,**
```ps
Get-AppxPackage *Microsoft.MicrosoftOfficeHub* | Remove-AppxPackage
Get-AppxPackage *Microsoft.Office.Sway* | Remove-AppxPackage
Get-AppxPackage *Microsoft.Office.Desktop* | Remove-AppxPackage
```

### Get Help

**Run in Powershell,**
```ps
Get-AppxPackage -AllUsers *GetHelp* | Remove-AppxPackage
```

### Feedback Hub

**Run in Powershell,**
```
Get-AppxPackage *Microsoft.WindowsFeedbackHub* | Remove-AppxPackage
```

### Sticky Notes

**Run in Powershell,**
```
Get-AppxPackage -AllUsers *sticky* | Remove-AppxPackage
```

### Maps

**Run in Powershell,**
```
Get-AppxPackage -AllUsers *maps* | Remove-AppxPackage
```

**Run in Command Prompt,**
```
sc delete MapsBroker
sc delete lfsvc
schtasks /Change /TN "\Microsoft\Windows\Maps\MapsUpdateTask" /disable
schtasks /Change /TN "\Microsoft\Windows\Maps\MapsToastTask" /disable
```

### OneNote

**Run in Powershell,**
```
Get-AppxPackage -AllUsers *onenote* | Remove-AppxPackage
```

### Photos

**Run in Powershell,**
```
Get-AppxPackage -AllUsers *photo* | Remove-AppxPackage
```

### Weather, News, ...

**Run in Powershell,**
```
Get-AppxPackage -AllUsers *bing* | Remove-AppxPackage
```

### Sound Recorder

**Run in Powershell,**
```
Get-AppxPackage -AllUsers *soundrec* | Remove-AppxPackage
```
> As a replacement, you can use [Audacity](http://www.audacityteam.org/).

### Microsoft Quick Assist

**Run in Powershell,**
```
Get-WindowsPackage -Online | Where PackageName -like *QuickAssist* | Remove-WindowsPackage -Online -NoRestart
```
### OneDrive

**Run in Command Prompt,**
```
%SystemRoot%\SysWOW64\OneDriveSetup.exe /uninstall
rd "%UserProfile%\OneDrive" /s /q
rd "%LocalAppData%\Microsoft\OneDrive" /s /q
rd "%ProgramData%\Microsoft OneDrive" /s /q
rd "C:\OneDriveTemp" /s /q
del "%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" /s /f /q
```

### Your Phone

**Run in Powershell,**
```ps
Get-AppxPackage -AllUsers *phone* | Remove-AppxPackage
```

### Hello Face

**Run in Powershell,**
```
Get-WindowsPackage -Online | Where PackageName -like *Hello-Face* | Remove-WindowsPackage -Online -NoRestart
```

**Run in Command Prompt,**
```
schtasks /Change /TN "\Microsoft\Windows\HelloFace\FODCleanupTask" /Disable
```

### Microsoft Store 

**Run in Powershell,**
```ps
Get-AppxPackage -AllUsers *store* | Remove-AppxPackage
```
> Ignore errors, if there are any.

**Run in Command Prompt,**
```
install_wim_tweak /o /c Microsoft-Windows-ContentDeliveryManager /r
install_wim_tweak /o /c Microsoft-Windows-Store /r
``` 

<br> **⚠ Warning:** Do NOT run the following commands if you will be using any UWP app in the future.

**Run in Command Prompt,**
```cmd
reg add "HKLM\Software\Policies\Microsoft\WindowsStore" /v RemoveWindowsStore /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsStore" /v DisableStoreApps /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\PushToInstall" /v DisablePushToInstall /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f
sc delete PushToInstall
```

### Xbox and Game DVR

**Run in Powershell,**
```ps
Get-AppxPackage -AllUsers *xbox* | Remove-AppxPackage
```

**Run in Command Prompt,**
```cmd
sc delete XblAuthManager
sc delete XblGameSave
sc delete XboxNetApiSvc
sc delete XboxGipSvc
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\xbgm" /f
schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTask" /disable
schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTaskLogon" /disable
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowGameDVR /t REG_DWORD /d 0 /f
```

### Microsoft Edge (Chromium)

- Open RUN (`Win + R`), type `%programfiles(x86)%` and press **OK**. This will open the **Program Files (x86)** folder.
- Now navigate to `Microsoft\Edge\Application\104.0.1293.63\Installer`. The application version maybe different for you so please proceed accordingly.
- Click on the **[address bar](https://www.customguide.com/windows-10/file-explorer#:~:text=The%20File%20Explorer%20address%20bar,(i.e.%2C%20higher)%20one.)**, type `cmd` and press **Enter**. This will open a Command Prompt window.
- Run `setup --uninstall --force-uninstall --system-level`.
- Quit the CMD window, and open RUN(`Win+R`), type `cmd` and press **OK**. This will open another CMD window.
- Run the commands that follow:
    ```
    install_wim_tweak.exe /o /l
    install_wim_tweak.exe /o /c "Microsoft-Windows-Internet-Browser-Package" /r
    install_wim_tweak.exe /h /o /l
    ```
**⚠ Warning:** After running the above commands, you must restart your computer. However, you can skip it for the time being and restart after the debloating process is complete.

## Removing Windows Defender

**⚠ Warning:** This will break Windows Updates.

**Run in Command Prompt,**
```
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "Off" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpyNetReporting /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v DontReportInfectionInformation /t REG_DWORD /d 1 /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d 1 /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SecHealthUI.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
install_wim_tweak /o /c Windows-Defender /r
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d 0 /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /f
```

Now, restart your computer and return to the guide.

Next, you will have to take ownership of `C:\Program Files\WindowsApps\` and `C:\ProgramData\Microsoft` using **NFTS Access**. 
> Refer to the images below.

![NTFSAcess Removal Preview](https://imgur.com/orEK0zz.png)
<p align="center"><sub>NTFSAcess Removal Preview</sub></p>

Once you take ownership of both folders,
- Navigate to `C:\Program Files\WindowsApps\` and delete the **SecHealthUI** folder.
- Navigate to `C:\ProgramData\Microsoft` and delete all Windows Defender-related files.

## Disabling Cortana

With the Anniversary Update, Microsoft hid the option to disable Cortana. So you need to make a couple registry changes to disable Cortana (to an extent). 
**Run in Command Prompt,**
```
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"  /v "{2765E0F4-2918-4A46-B9C9-43CDD8FCBA2B}" /t REG_SZ /d  "BlockCortana|Action=Block|Active=TRUE|Dir=Out|App=C:\windows\systemapps\microsoft.windows.cortana_cw5n1h2txyewy\searchui.exe|Name=Search  and Cortana  application|AppPkgId=S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742|" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f
```
**⚠ Warning:** Do not try removing the Cortana package using `install_wim_tweak` or the PowerShell, as it will break Windows Search and you will have to reinstall Windows.

## Disabling Windows Updates

**⚠ Warning:** You will be unable to use Microsoft Store or any other app that requires Windows Updates to be enabled if you do this.

**Run in Command Prompt,**
```
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wuauserv" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UsoSvc" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DoSvc" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v ScheduledInstallDay /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v ScheduledInstallTime /t REG_DWORD /d 3 /f
```

## Removing Telemetry and other unnecessary services

**Run in Command Prompt,**
```
sc delete DiagTrack
sc delete dmwappushservice
sc delete WerSvc
sc delete OneSyncSvc
sc delete MessagingService
sc delete wercplsupport
sc delete PcaSvc
sc config wlidsvc start=demand
sc delete wisvc
sc delete RetailDemo
sc delete diagsvc
sc delete shpamsvc 
sc delete TermService
sc delete UmRdpService
sc delete SessionEnv
sc delete TroubleshootingSvc
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "wscsvc" ^| find /i "wscsvc"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "OneSyncSvc" ^| find /i "OneSyncSvc"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "MessagingService" ^| find /i "MessagingService"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "PimIndexMaintenanceSvc" ^| find /i "PimIndexMaintenanceSvc"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "UserDataSvc" ^| find /i "UserDataSvc"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "UnistoreSvc" ^| find /i "UnistoreSvc"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "BcastDVRUserService" ^| find /i "BcastDVRUserService"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "Sgrmbroker" ^| find /i "Sgrmbroker"') do (reg delete %I /f)
sc delete diagnosticshub.standardcollector.service
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f
reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v Start /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v AITEnable /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableInventory /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisablePCA /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableUAR /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
```

### Modifying Scheduled Tasks

**Run in Command Prompt,**
```
schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\AitAgent" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /disable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /disable
schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /disable
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /disable
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /disable
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /disable
schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefresh" /disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyUpload" /disable
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /disable
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /disable
schtasks /Change /TN "Microsoft\Windows\Clip\License Validation" /disable
schtasks /Change /TN "\Microsoft\Windows\ApplicationData\DsSvcCleanup" /disable
schtasks /Change /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable
schtasks /Change /TN "\Microsoft\Windows\PushToInstall\LoginCheck" /disable
schtasks /Change /TN "\Microsoft\Windows\PushToInstall\Registration" /disable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitor" /disable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitorToastTask" /disable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefreshTask" /disable
schtasks /Change /TN "\Microsoft\Windows\Subscription\EnableLicenseAcquisition" /disable
schtasks /Change /TN "\Microsoft\Windows\Subscription\LicenseAcquisition" /disable
schtasks /Change /TN "\Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner" /disable
schtasks /Change /TN "\Microsoft\Windows\Diagnosis\Scheduled" /disable
schtasks /Change /TN "\Microsoft\Windows\NetTrace\GatherNetworkInfo" /disable
del /F /Q "C:\Windows\System32\Tasks\Microsoft\Windows\SettingSync\*" 
```
> Ignore errors, if any.


## Extra Tweaking

Now that you've debloated your system to some extent, it's recommended that you make the following changes as well.

### Disable Edit with 3D Paint / 3D Print

Microsoft allows you to uninstall the Paint 3D app as well as other associated apps. When you uninstall those apps, however, the context menu remains unchanged. Run the following commands in command prompt to remove the 'Edit with 3D Paint' option from the context menu:
```
for /f "tokens=1* delims=" %I in (' reg query "HKEY_CLASSES_ROOT\SystemFileAssociations" /s /k /f "3D Edit" ^| find /i "3D Edit" ') do (reg delete "%I" /f )
for /f "tokens=1* delims=" %I in (' reg query "HKEY_CLASSES_ROOT\SystemFileAssociations" /s /k /f "3D Print" ^| find /i "3D Print" ') do (reg delete "%I" /f )
```
### Turn off Windows Error reporting

**Run in Command Prompt,**
```
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
```
### Disable forced updates

**Run in Command Prompt,** 
```
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v ScheduledInstallDay /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v ScheduledInstallTime /t REG_DWORD /d 3 /f
```
With this you will be notified every time Windows attempts to install an update.

### Disable license checking

**Run in Command Prompt,**
```
reg add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v NoGenTicket /t REG_DWORD /d 1 /f
```
This change will prevent Windows from checking your license everytime you turn on your PC.

### Disable Sync

**Run in Command Prompt,**
```
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSync /t REG_DWORD /d 2 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSyncUserOverride /t REG_DWORD /d 1 /f
```
### Disable Windows Tips

**Run in Command Prompt,**
```
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace" /v AllowSuggestedAppsInWindowsInkWorkspace /t REG_DWORD /d 0 /f
```

## Final Touches

We must disable Windows Spotlight, and other "Suggestions" which are literal ads. To do this, follow the steps below.

1. Go to `Start > Settings > Personalization > Lock screen`:
    - Set the background to Picture.
    - Set **Get fun facts, tips, tricks and more on your lock screen** to off.

2. Go to `Personalization > Start`:
    - Set **Show suggestions occasionally in Start** to off.

3. Go back to Settings and go to `System > Notifications and actions`:
    - Set **Get tips, tricks, and suggestions as you use Windows** to off.
    - Set **Show me the Windows welcome...** to off

4. Go to `System > Multitasking`:
    - Set **Show suggestions occasionally in your timeline** to off.

5. Go back to Settings and go to Privacy:
    - Turn everything off under **Permissions and History**.

Lastly, **REBOOT YOUR SYSTEM TO FINISH DEBLOATING**.

## FAQs

1. Can Windows revert these changes?

**->** Yes, Windows can and will revert these changes whenever a major update is installed. Users who've disabled Windows Updates
should be unaffected.

2. Will this hinder my daily workflow?

**->** In most cases this shouldn't affect your daily workflow. However, as we've disabled quite a lot of "features" some users may be affected. So it's highly recommended you do not skip anything mentioned in the guide.



















