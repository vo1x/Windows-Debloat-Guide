# Windows Debloat Guide

## IMPORTANT

All of the modifications you will be making after following this guide **CANNOT* be reversed or undone without reinstalling Windows. Therefore, please do not follow this guide if:
- You do not know what you are doing or are inexperienced
- You need to use a Microsoft Account for whatever reason
- You need the Windows Store to install applications
- You want to receive feature updates for Windows
- You do not use a third-party antivirus and need Windows Defender

> **NOTE:** Please keep in mind that you are doing this at your own risk, and I won't be held accountable for any form of data loss or damage. So make sure to backup all your files.

## Pre-Requisite

Following are the things you will need to have setup before getting started. An installation/setup guide for each has also been provided whereever necessary.

> **NOTE** Please clone the repository to your system. The repo has all the required files.

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


### For clean installs ONLY

If you are on a clean install of Windows and haven't set anything up, you might want to clean up the component store. Please follow the steps below to do so,

- Extract the provided `Dism++ 10.1.1002.1` and run `DISM++ x64` or `DISM++ x86` file as per your OS.
- Navigate to **Disk Cleanup** from the left-pane, and tick all the checkboxes you see.
- Press **Scan** which is on the bottom right, and after it's done, just press **Clean Up**.

![DISM_Guide](https://imgur.com/hWozpNi)
<p align="center"><sub>DISM Guide</sub></p>

**NOTE:** If get an error while cleaning up the component store, run the following command in Command Prompt (Admin):
```cmd
DISM /Online /Cleanup-Image /StartComponentCleanup /ResetBase
```
Once the command finishes executing, you can move on to uninstalling metro apps.


**IMPORTANT:** Always run Powershell and/or Command Prompt as Admin when executing the commands below. Also, each command will have a flair stating in which of the two aforementioned terminals you need to the command. 

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
As a replacement, you can use the [Classic Calculator](https://winaero.com/get-calculator-from-windows-8-and-windows-7-in-windows-10/).

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
> Ignore any errors, if there are any.

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
Alternatives [Audacity](http://www.audacityteam.org/)

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
You can ignore any error that pops up.<br>

- Run in Command Prompt,
```
install_wim_tweak /o /c Microsoft-Windows-ContentDeliveryManager /r
install_wim_tweak /o /c Microsoft-Windows-Store /r
```
>**NOTE:** Do NOT run the commands below if you will be using any UWP app in the future.

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
