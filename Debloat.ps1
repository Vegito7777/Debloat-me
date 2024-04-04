Function Remove-App-MSI-QN([String]$appName)
{
    $appCheck = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -eq $appName } | Select-Object -Property DisplayName,UninstallString
    if($appCheck -ne $null){
        Write-host "Uninstalling "$appCheck.DisplayName
        $uninst = $appCheck.UninstallString + " /qn /norestart"
        cmd /c $uninst
    }
    else{
        Write-Host "$appName is not installed on this computer"
    }
}

Function Remove-App-EXE-SILENT([String]$appName)
{
    $appCheck = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -eq $appName } | Select-Object -Property DisplayName,UninstallString
    if($appCheck -ne $null){
        Write-host "Uninstalling "$appCheck.DisplayName
        $uninst = $appCheck.UninstallString + " -silent"
        cmd /c $uninst
    }
    else{
        Write-Host "$appName is not installed on this computer"
    }
}

Function Remove-App-MSI_EXE-Quiet([String]$appName)
{
    $appCheck = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -eq $appName } | Select-Object -Property DisplayName,UninstallString
    if($appCheck -ne $null){
        Write-host "Uninstalling "$appCheck.DisplayName
        $uninst = $appCheck.UninstallString[1] +  " /qn /restart"
        cmd /c $uninst

    }
    else{
        Write-Host "$appName is not installed on this computer"
    }
}
Function Remove-App-MSI_EXE-S([String]$appName)
{
    $appCheck = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -eq $appName } | Select-Object -Property DisplayName,UninstallString
    if($appCheck -ne $null){
        Write-host "Uninstalling "$appCheck.DisplayName
        $uninst = $appCheck.UninstallString[1] +  " /S"
        cmd /c $uninst

    }
    else{
        Write-Host "$appName is not installed on this computer"
    }
}

Function Remove-App-MSI-I-QN([String]$appName)
{
    $appCheck = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -eq $appName } | Select-Object -Property DisplayName,UninstallString
    if($appCheck -ne $null){
        Write-host "Uninstalling "$appCheck.DisplayName
        $uninst = $appCheck.UninstallString.Replace("/I","/X") + " /qn /norestart"
        cmd /c $uninst
    }
    else{
        Write-Host "$appName is not installed on this computer"
    }
}


Function Remove-App([String]$appName){
    $app = Get-AppxPackage -AllUsers $appName
    if($app -ne $null){
        $packageFullName = $app.PackageFullName
        Write-Host "Uninstalling $appName"
        Remove-AppxPackage -package $packageFullName -AllUsers
        $provApp = Get-AppxProvisionedPackage -Online 
        $proPackageFullName = (Get-AppxProvisionedPackage -Online | where {$_.Displayname -eq $appName}).DisplayName
        if($proPackageFillName -ne $null){
            Write-Host "Uninstalling provisioned $appName"
            Remove-AppxProvisionedPackage -online -packagename $proPackageFullName -AllUsers
        }
    }
    else{
        Write-Host "$appName is not installed on this computer"
    }
}

Function Remove-M365([String]$appName)
{
    $uninstall = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where {$_.DisplayName -like $appName} | Select UninstallString)
    if($uninstall -ne $null){
        Write-Host "Uninstalling $appName"
        $uninstall = $uninstall.UninstallString + " DisplayLevel=False"
        cmd /c $uninstall
    }
    else{
        Write-Host "$appName is not installed on this computer"
    }
}

Function Check-UninstallString([String]$appName)
{
    $appCheck = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -eq $appName } | Select-Object -Property DisplayName,UninstallString
    if($appCheck -ne $null){
        Write-host $appCheck.DisplayName $appCheck.UninstallString
    }
    else{
        Write-Host "$appName is not installed on this computer"
    }
}

Function Remove-App-EXE-S-QUOTES([String]$appName)
{
    $appCheck = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -eq $appName } | Select-Object -Property DisplayName,UninstallString
    if($appCheck -ne $null){
        Write-host "Uninstalling "$appCheck.DisplayName
        $uninst ="`""+$appCheck.UninstallString+"`"" + " /S"
        cmd /c $uninst
    }
    else{
        Write-Host "$appName is not installed on this computer"
    }
}

Remove-App-MSI-QN "Dell SupportAssist"                                             #working
Remove-App-MSI-QN "Dell Digital Delivery Services"                                 #working
Remove-App-EXE-SILENT "Dell Optimizer Core"                                        #working
Remove-App-MSI_EXE-S "Dell SupportAssist OS Recovery Plugin for Dell Update"       #working
Remove-App-MSI_EXE-S "Dell SupportAssist Remediation"                              #working
Remove-App-EXE-S-QUOTES "Dell Display Manager 2.1"                                 #working
Remove-App-EXE-S-QUOTES "Dell Peripheral Manager"                                  #working
Remove-App-MSI-I-QN "Dell Core Services"                                           #working
Remove-App-MSI-I-QN "Dell Trusted Device Agent"                                    #working
Remove-App-MSI-I-QN "Dell Optimizer"                                               #working
Remove-App "Microsoft.GamingApp"                                                   #working
Remove-App "Microsoft.MicrosoftOfficeHub"                                          #working
Remove-App "DellInc.DellDigitalDelivery"                                           #working 
Remove-App "Microsoft.GetHelp"                                                     #working
Remove-App "Microsoft.Getstarted"                                                  #working
Remove-App "Microsoft.Messaging"                                                   #working
Remove-App "Microsoft.MicrosoftSolitaireCollection"                                #working
Remove-App "Microsoft.OneConnect"                                                  #working
Remove-App "Microsoft.SkypeApp"                                                    #working
Remove-App "Microsoft.Wallet"                                                      #working
Remove-App "microsoft.windowscommunicationsapps"                                   #working

Remove-App "Microsoft.WindowsFeedbackHub"                                          #working
Remove-App "Microsoft.YourPhone"                                                   #working
Remove-App "ZuneMusic"                                                             #working        
Remove-M365 "Microsoft 365 - fr-fr"                                                #working
Remove-M365 "Microsoft 365 - es-es"                                                #working                                            
Remove-M365 "Microsoft 365 - pt-br"                                                #working
Remove-M365 "Microsoft OneNote - fr-fr"                                            #working
Remove-M365 "Microsoft OneNote - es-es"                                            #working
Remove-M365 "Microsoft OneNote - pt-br"                                            #working
Check-UninstallString "DELLOSD"
Remove-App "Microsoft.Xbox.TCUI"    #working

Remove-App "Microsoft.XboxApp"   #working 

Remove-App "Microsoft.XboxGameOverlay"   #working

Remove-App "Microsoft.XboxIdentityProvider"    #working

Remove-App "Microsoft.XboxSpeechToTextOverlay"     #working


Write-Host -ForegroundColor Yellow Disabling Xbox features...
Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" | Out-Null
}

Write-Host -ForegroundColor Yellow "Setting Control Panel view to small icons..."
If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel")) {
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Type DWord -Value 1





# Uninstalling Apps & Features 

$Bloatware = @(

        #Add sponsored/featured apps to remove in the "*AppName*" format
        "*EclipseManager*"
   
        "*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
        "*Duolingo-LearnLanguagesforFree*"
        "*PandoraMediaInc*"
        "*CandyCrush*"
        "*BubbleWitch3Saga*"
        "*Wunderlist*"
        "*Flipboard*"
        "*Twitter*"
        "*Facebook*"
        "*Spotify*"
        "*Minecraft*"
        "*Royal Revolt*"
        "*Sway*"
        "*Speed Test*"
        "*Dolby*"
	"*Paint*"
    "*PowerAutomate*"
    "*QuickAssist*"
    "*MaxxAudioPro*"
    "*Copilot*"
    "Clipchamp*"
    "*ActiproSoftware*"
	"*Alexa*"
	"*AdobePhotoshopExpress*"
	"*Advertising*"
             "*ASUSPCAssistant*"
	"*AutodeskSketchBook*"
	"*BingNews*"
	"*BingSports*"
	"*BingTranslator*"
	"*BingWeather*"
	"*BubbleWitch3Saga*"
	"*CandyCrush*"
	"*Casino*"
	"*COOKINGFEVER*"
	"*CyberLink*"
	"*Disney*"
	"*Dolby*"
	"*DrawboardPDF*"
	"*Duolingo*"
	"*ElevocTechnology*"
	"*EclipseManager*"
	"*Facebook*"
	"*FarmVille*"
	"*Fitbit*"
	"*flaregames*"
	"*Flipboard*"
	"*GamingApp*"
	"*GamingServices*"
	"*GetHelp*"
	"*Getstarted*"
	"*HPPrinter*"
	"*iHeartRadio*"
	"*Instagram*"
	"*Lenovo*"
	"*Lens*"
	"*LinkedInforWindows*"
	"*MarchofEmpires*"
	"*McAfee*"
	"*Messaging*"
	"*MirametrixInc*"
	"*Microsoft3DViewer*"
	"*MicrosoftOfficeHub*"
	"*MicrosoftSolitaireCollection*"
	"*Minecraft*"
	"*MixedReality*"
	"*Netflix*"
	"*News*"
	"*PandoraMediaInc*"
	"*People*"
	"*PhototasticCollage*"
	"*PicsArt-PhotoStudio*"
	"*Plex*"
	"*PolarrPhotoEditor*"
	"*PPIProjection*"
	"*Print3D*"
	"*Royal Revolt*"
	"*ScreenSketch*"
	"*Shazam*"
	"*SkypeApp*"
	"*SlingTV*"
	"*Spotify*"
	"*StickyNotes*"
	"*Teams*"
	"*TheNewYorkTimes*"
	"*TuneIn*"
	"*Twitter*"
	"*Wallet*"
	"*WebExperience*" 
	"*Whiteboard*"
	"*WindowsAlarms*"
	"*windowscommunicationsapps*"
	"*WindowsFeedbackHub*"
	"*WindowsMaps*"
	"*WindowsSoundRecorder*"
	"*WinZipComputing*"
            “*Solitaire*”
           "*Xbox.TCUI*"
	"*XboxApp*"
	"*XboxGameOverlay*"
	"*XboxGamingOverlay*"
	"*XboxIdentityProvider*"
	"*XboxSpeechToTextOverlay*"
          "*Movies&TV*"

            


)

Get-AppxPackage *copilot* | Remove-AppxPackage 
Get-AppxPackage -AllUsers | Where-Object { $_.Name -Like '*copilot*' } | Remove-AppxPackage



Get-AppxPackage *clipchamp* | Remove-AppxPackage
 Get-AppxPackage -AllUsers | Where-Object { $_.Name -Like '*clipchamp*' } | Remove-AppxPackage


Get-appxpackage *Microsoft.ToDo* | Remove-AppxPackage
Get-AppxPackage -AllUsers | Where-Object { $_.Name -Like '*Microsoft.ToDo*' } | Remove-AppxPackage


Get-AppxPackage -AllUsers | Where-Object {$_.Name -Like '*OutlookForWindows*'} | Remove-AppxPackage

Get-AppxPackage Microsoft.ZuneVideo | Remove-AppxPackage

Get-AppxPackage -AllUsers | Where-Object { $_.Name -Like 'Microsoft.ZuneVideo' } | Remove-AppxPackage



# Debloat all the apps


foreach ($App in $Bloatware) {

	Write-Host Searching and Removing Package $App for All Users
	Get-AppxPackage -Name $App -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue -Verbose
						
	Write-Host Searching and Removing Package $App for Current User
	Get-AppxPackage -Name $App | Remove-AppxPackage -ErrorAction SilentlyContinue -Verbose

	Write-Host Searching and Removing Package $App for Provision Package
	Get-AppxProvisionedPackage -Online | Where-Object DisplayName -Like $App | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue -Verbose
}

Write-Host "Waiting for Jobs to Complete"


Shutdown.exe -r -t 90
Write-Host
Write-Host -ForegroundColor Yellow "System will restart in 90 seconds. To abort, send command: Shutdown.exe -a "




