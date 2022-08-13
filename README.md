<h1 align="center"> Windows Debloat Guide </h1>

## Introduction

Because of its extensive telemetry and online features, Windows has sparked several privacy concerns. When telemetry is set to basic, most of it appears to be legitimate, but if you don't trust them, here's how to stop Windows from sending your data to Microsoft and debloat your system.
> **Last updated:** August 13, 2022


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
- Winaero Tweaker
    - Extract the `winaerotweaker` zip file.
    - Run the installer and follow through to install Winaero Tweaker.


## Uninstalling Bloatware

#### For clean installs ONLY:

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

**⚠IMPORTANT:** When executing the commands below, always run Powershell and/or Command Prompt as Administrator.

### Alarms and Clock

- Run in Powershell,
```ps
Get-AppxPackage -AllUsers *alarms* | Remove-AppxPackage
Get-AppxPackage -AllUsers *people* | Remove-AppxPackage
```

### Calculator

- Run in Powershell,
```ps
Get-AppxPackage -AllUsers *calc* | Remove-AppxPackage
```
> As a replacement, you can use the [Classic Calculator](https://winaero.com/get-calculator-from-windows-8-and-windows-7-in-windows-10/) app.

### Mail, Calendar, ...

- Run in Powershell,
```ps
Get-AppxPackage -AllUsers *comm* | Remove-AppxPackage
Get-AppxPackage -AllUsers *mess* | Remove-AppxPackage
```

### Camera

- Run in Powershell,
```ps
Get-AppxPackage -AllUsers *camera* | Remove-AppxPackage
```
> Ignore errors, if there are any.

### Connect


- Run in Command Prompt,
```cmd
install_wim_tweak /o /c Microsoft-PPIProjection-Package /r
```

### Contact Support, Get Help

- Run in Command Prompt,
```cmd
install_wim_tweak /o /c Microsoft-Windows-ContactSupport /r
```

### Cortana (UWP App)

- Run in Powershell,
```ps
Get-AppxPackage -allusers Microsoft.549981C3F5F10 | Remove-AppxPackage
```

### Music, TV

- Run in Powershell,
```
Get-AppxPackage -AllUsers *zune* | Remove-AppxPackage
Get-WindowsPackage -Online | Where PackageName -like *MediaPlayer* | Remove-WindowsPackage -Online -NoRestart
```

### Groove Music

- Run in Powershell,
```ps
Get-AppxPackage -AllUsers *zune* | Remove-AppxPackage
```

### Microsoft Solitare Collection

- Run in Powershell,
```ps
Get-AppxPackage *Microsoft.MicrosoftSolitaireCollection* | Remove-AppxPackage
```

### Office

- Run in Powershell,
```ps
Get-AppxPackage *Microsoft.MicrosoftOfficeHub* | Remove-AppxPackage
Get-AppxPackage *Microsoft.Office.Sway* | Remove-AppxPackage
Get-AppxPackage *Microsoft.Office.Desktop* | Remove-AppxPackage
```

### Get Help

- Run in Powershell,
```ps
Get-AppxPackage -AllUsers *GetHelp* | Remove-AppxPackage
```

### Feedback Hub

- Run in Powershell,
```
Get-AppxPackage *Microsoft.WindowsFeedbackHub* | Remove-AppxPackage
```

### Sticky Notes

- Run in Powershell,
```
Get-AppxPackage -AllUsers *sticky* | Remove-AppxPackage
```

### Maps

- Run in Powershell,
```
Get-AppxPackage -AllUsers *maps* | Remove-AppxPackage
```

- Run in Command Prompt,
```
sc delete MapsBroker
sc delete lfsvc
schtasks /Change /TN "\Microsoft\Windows\Maps\MapsUpdateTask" /disable
schtasks /Change /TN "\Microsoft\Windows\Maps\MapsToastTask" /disable
```

### OneNote

- Run in Powershell,
```
Get-AppxPackage -AllUsers *onenote* | Remove-AppxPackage
```

### Photos

- Run in Powershell,
```
Get-AppxPackage -AllUsers *photo* | Remove-AppxPackage
```

### Weather, News, ...

- Run in Powershell,
```
Get-AppxPackage -AllUsers *bing* | Remove-AppxPackage
```

### Sound Recorder

- Run in Powershell,
```
Get-AppxPackage -AllUsers *soundrec* | Remove-AppxPackage
```
> As a replacement, you can use [Audacity](http://www.audacityteam.org/).

### Microsoft Quick Assist

- Run in Powershell,
```
Get-WindowsPackage -Online | Where PackageName -like *QuickAssist* | Remove-WindowsPackage -Online -NoRestart
```
### OneDrive

- Run in Command Prompt,
```
%SystemRoot%\SysWOW64\OneDriveSetup.exe /uninstall
rd "%UserProfile%\OneDrive" /s /q
rd "%LocalAppData%\Microsoft\OneDrive" /s /q
rd "%ProgramData%\Microsoft OneDrive" /s /q
rd "C:\OneDriveTemp" /s /q
del "%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" /s /f /q
```

### Your Phone

- Run in Powershell,
```ps
Get-AppxPackage -AllUsers *phone* | Remove-AppxPackage
```

### Hello Face

- Run in Powershell,
```
Get-WindowsPackage -Online | Where PackageName -like *Hello-Face* | Remove-WindowsPackage -Online -NoRestart
```

- Run in Command Prompt,
```
schtasks /Change /TN "\Microsoft\Windows\HelloFace\FODCleanupTask" /Disable
```

### Microsoft Store 

- Run in Powershell,
```ps
Get-AppxPackage -AllUsers *store* | Remove-AppxPackage
```
> Ignore errors, if there are any.

- Run in Command Prompt,
```
install_wim_tweak /o /c Microsoft-Windows-ContentDeliveryManager /r
install_wim_tweak /o /c Microsoft-Windows-Store /r
``` 

<br> **⚠ Do NOT run the following commands if you will be using any UWP app in the future.**

- Run in Command Prompt,
```cmd
reg add "HKLM\Software\Policies\Microsoft\WindowsStore" /v RemoveWindowsStore /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsStore" /v DisableStoreApps /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\PushToInstall" /v DisablePushToInstall /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f
sc delete PushToInstall
```

### Xbox and Game DVR

- Run in Powershell,
```ps
Get-AppxPackage -AllUsers *xbox* | Remove-AppxPackage
```

- Run in Command Prompt,
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

## Removing Windows Defender

⚠ Please note that this will break Windows Updates.

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

![NTFSAcess Removal Preview](https://imgur.com/a/WHVi6u6.png)
<p align="center"><sub>NTFSAcess Removal Preview</sub></p>

Once you take ownership of both folders,
- Navigate to `C:\Program Files\WindowsApps\` and delete the **SecHealthUI** folder.
- Navigate to `C:\ProgramData\Microsoft` and delete all Windows Defender-related files.




