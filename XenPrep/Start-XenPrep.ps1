<#
        .SYNOPSIS 
        Prepares the vDisk to be deployed via MCS/PVS.

        .DESCRIPTION
        Prepares the current vDisk to be deployed via MCS/PVS.

        .INPUTS
        None. You cannot pipe objects to this script.

        .EXAMPLE
		C:\PS> Start-XenPrep.ps1 -Mode Seal -ProvisioningMethod MCS -CleanupProfiles -CleanupEventlogs -Optimize -Shutdown
		This examples show how Start-XenPrep can be used to generalize and seal a vDisk when using MCS.
		
        C:\PS> Start-XenPrep.ps1 -Mode Seal -ProvisioningMethod MCS -CleanupProfiles -CleanupEventlogs -Optimize -VMware -Appsense -Shutdown
		This example show how Start-XenPrep is used in Seal (Rearm) Mode with additional Optimizations for VMware, TrendMicro and Appsense.
		
		.NOTES
		Tim Arenz, arenz.cc, @timarenz
		Claus Jan Harms, mail@cjharms.info, cjharms.info, @cjharms
#>

[CmdletBinding()]
Param (
	[parameter(Mandatory = $true, HelpMessage = "Specifies if this script is used to seal (Seal) or start up (Startup)")]
	[string][ValidateSet("Seal","Startup")]$Mode = "Seal",
	
	[parameter(Mandatory = $true, HelpMessage = "Specifies the used Delivery Method (MCS or PVS)")]
	[alias("ProvMethod","Prov","Provisioning")]
	[string][ValidateSet("MCS","PVS")]$ProvisioningMethod = "MCS",
	
	[parameter(Mandatory = $false, HelpMessage = "Specifiy the Persistent Disk in the following Format n without the :")]
	[alias("Disk","Drive","DiskDrive","HDD")]
	[string][ValidatePattern("[A-Z]")]$PersistentDisk = "D",
	
	[parameter(Mandatory = $false, HelpMessage = "Clean up Profiles")]
	[Switch]$CleanupProfiles,

    [parameter(Mandatory = $false, HelpMessage = "Clear Temp Files, Memory Dumps, Windows Installer, etc via cleanmgr.exe")]
	[Switch]$CleanupWindows,

	[parameter(Mandatory = $false, HelpMessage = "Clear Eventlogs (Application, Security and System)")]
	[Switch]$CleanupEventlog,
	
	[parameter(Mandatory = $false, HelpMessage = "Generalize Appsense Agent")]
	[Switch]$AppSense,
	
	[parameter(Mandatory = $false, HelpMessage = "Generalize TrendMicro Anti Virus Client")]
	[Switch]$TrendMicro,
	
	[parameter(Mandatory = $false, HelpMessage = "Run VMware specific Optimizations")]
	[Switch]$VMware,
	
	[parameter(Mandatory = $false, HelpMessage = "Optimize vDisk and Disk Space")]
	[Switch]$Optimize,
	
    [parameter(Mandatory = $false, HelpMessage = "Forces the Script to run with all the First Run Actions")]
	[Switch]$ForceFirstRun,
		
    [parameter(Mandatory = $false, HelpMessage = "Shuts down the System after running the Script")]
	[Switch]$Shutdown,
    
    [parameter(Mandatory = $false, HelpMessage = "Runs this Script silent and without any User Interaction")]
	[Switch]$Silent
	
)

$ScriptFolder = Split-Path -Parent $MyInvocation.MyCommand.Path
$AddonFolder = "$ScriptFolder\Addons"
$LogFolder = "$ScriptFolder\Logs"
$ErrorActionPreference = "Stop"

Clear-Host
Write-Host "------------------------------------------------------------------------------"
Write-Host "-- XenPrep Script"
Write-Host "-- Original Development by Tim Arenz, arenz.cc, @timarenz"
Write-Host "-- Changes by Claus Jan Harms, mail@cjharms.info, cjharms.info"
Write-Host "------------------------------------------------------------------------------"

###
### Enable Logging
###

#Start-Transcript -Path "$LogFolder\XenPrep.log" -ErrorAction SilentlyContinue | Out-Null

###
### Variables
###

$PersistentDiskDrive = "$PersistentDisk`:"

###
### Functions
###

function Test-Admin {
  $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
  $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

###
### Pre check
###

#Admin User?
If ((Test-Admin) -eq $false) {
		Write-Host ""
		Write-Warning "You do not have the needed administrative rights to run this script!"
		Write-Warning "Please re-run this script as an administrator or in an elevated session."
		Write-Host ""
		Break
}

#Check Bitness
Write-Host -NoNewLine "Checking operating system bitness..."
If(((Get-WmiObject -Class Win32_ComputerSystem).SystemType) -match "x64") {
	$Bitness = "x64"
	$ProgramFiles = ${env:ProgramFiles(X86)}
	$ProgramFiles64 = ${env:ProgramFiles}
} Else { 
	$Bitness = "x86"
	$ProgramFiles = ${env:ProgramFiles}
}
Write-Host -ForegroundColor Green " done" 

#Create first run registry key
If ($ForceFirstRun -eq $true) {
	New-Item "HKLM:\SOFTWARE\XenPrep" -Force | Out-Null
	New-ItemProperty "HKLM:\SOFTWARE\XenPrep" -Name "FirstRun" -Value "0" -PropertyType "DWORD" -Force | Out-Null
}

#Check first run registry key
If (((Get-ItemProperty "HKLM:\SOFTWARE\XenPrep" -ErrorAction SilentlyContinue).FirstRun) -eq "1") {
	$FirstRunActions = $false
} Else {
	$FirstRunActions = $true
}

#Set first run key
New-Item "HKLM:\SOFTWARE\XenPrep" -Force | Out-Null
New-ItemProperty "HKLM:\SOFTWARE\XenPrep" -Name "FirstRun" -Value "1" -PropertyType "DWORD" -Force | Out-Null

###
### First run actions, proccessed only one time in Seal/Rearm mode.
###

If ($Mode -eq "Seal" -and $FirstRunActions -eq $true) {

#Create SageRun Set 11 in the cleanmgr Registry Hive. Used by cleanmgr.exe to clean specific Things like old Logs and MemoryDumps...
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\*" -Name "StateFlags0011" -Value "2" -PropertyType "DWORD" -Force | Out-Null
#Delete specific SageRun Set 11 Flags for Windows Update Cleanup because WU Cleanup requires a restart to complete the Cleanup. WU Cleanup should be done manually for now.
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Update Cleanup" -Name "StateFlags0011" -ErrorAction SilentlyContinue

}

###
### General actions, processed in Startup and Seal/Rearm mode
###

If ($Mode -eq "Startup" -or $Mode -eq "Seal") {
	#Time Sync
	Write-Host -NoNewLine "Syncing time..."
	Start-Process "w32tm.exe" -ArgumentList "/config /update" -Wait -WindowStyle Minimized
	Start-Process "w32tm.exe" -ArgumentList "/resync" -Wait -WindowStyle Minimized
	Write-Host -ForegroundColor Green " done"
    
	#Group Policy Update
	Write-Host -NoNewLine "Updating group policy..."
	Start-Process "cmd.exe" -ArgumentList "/C echo n | gpupdate.exe /target:computer" -Wait -WindowStyle Minimized
	Write-Host -ForegroundColor Green " done"
    
}

###
### Shut down actions, proccessed only in Seal/Rearm mode
###
 
If ($Mode -eq "Seal") {
	
    ## Disable certain Scheduled Tasks
	If ($Optimize -eq $true) {
	    Write-Host -NoNewLine "Disabling Scheduled Tasks..."
        Start-Process "schtasks.exe" -ArgumentList "/change /tn ""microsoft\windows\Application Experience\AitAgent"" /disable" -Wait -WindowStyle Hidden
        Start-Process "schtasks.exe" -ArgumentList "/change /tn ""microsoft\windows\Application Experience\ProgramDataUpdater"" /disable" -Wait -WindowStyle Hidden
        Start-Process "schtasks.exe" -ArgumentList "/change /tn ""microsoft\windows\Application Experience\StartupAppTask"" /disable" -Wait -WindowStyle Hidden
        Start-Process "schtasks.exe" -ArgumentList "/change /tn ""microsoft\windows\Autochk\Proxy"" /disable" -Wait -WindowStyle Hidden
        Start-Process "schtasks.exe" -ArgumentList "/change /tn ""microsoft\windows\Bluetooth\UninstallDeviceTask"" /disable" -Wait -WindowStyle Hidden
        Start-Process "schtasks.exe" -ArgumentList "/change /tn ""microsoft\windows\Customer Experience Improvement Program\BthSQM"" /disable" -Wait -WindowStyle Hidden
        Start-Process "schtasks.exe" -ArgumentList "/change /tn ""microsoft\windows\Customer Experience Improvement Program\Consolidator"" /disable" -Wait -WindowStyle Hidden
        Start-Process "schtasks.exe" -ArgumentList "/change /tn ""microsoft\windows\Customer Experience Improvement Program\KernelCeipTask"" /disable" -Wait -WindowStyle Hidden
        Start-Process "schtasks.exe" -ArgumentList "/change /tn ""microsoft\windows\Customer Experience Improvement Program\Uploader"" /disable" -Wait -WindowStyle Hidden
        Start-Process "schtasks.exe" -ArgumentList "/change /tn ""microsoft\windows\Customer Experience Improvement Program\UsbCeip"" /disable" -Wait -WindowStyle Hidden
        Start-Process "schtasks.exe" -ArgumentList "/change /tn ""microsoft\windows\Diagnosis\Scheduled"" /disable" -Wait -WindowStyle Hidden
        Start-Process "schtasks.exe" -ArgumentList "/change /tn ""microsoft\windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"" /disable" -Wait -WindowStyle Hidden
        Start-Process "schtasks.exe" -ArgumentList "/change /tn ""microsoft\windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver"" /disable" -Wait -WindowStyle Hidden
        Start-Process "schtasks.exe" -ArgumentList "/change /tn ""microsoft\windows\Maintenance\WinSAT"" /disable" -Wait -WindowStyle Hidden
        Start-Process "schtasks.exe" -ArgumentList "/change /tn ""microsoft\windows\MobilePC\HotStart"" /disable" -Wait -WindowStyle Hidden
        Start-Process "schtasks.exe" -ArgumentList "/change /tn ""microsoft\windows\Power Efficiency Diagnostic\AnalyzeSystem"" /disable" -Wait -WindowStyle Hidden
        Start-Process "schtasks.exe" -ArgumentList "/change /tn ""microsoft\windows\RAC\RacTask"" /disable" -Wait -WindowStyle Hidden
        Start-Process "schtasks.exe" -ArgumentList "/change /tn ""microsoft\windows\Ras\MobilityManager"" /disable" -Wait -WindowStyle Hidden
        Start-Process "schtasks.exe" -ArgumentList "/change /tn ""microsoft\windows\Shell\FamilySafetyMonitor"" /disable" -Wait -WindowStyle Hidden
        Start-Process "schtasks.exe" -ArgumentList "/change /tn ""microsoft\windows\Shell\FamilySafetyRefresh"" /disable" -Wait -WindowStyle Hidden
        Start-Process "schtasks.exe" -ArgumentList "/change /tn ""microsoft\windows\SideShow\AutoWake"" /disable" -Wait -WindowStyle Hidden
        Start-Process "schtasks.exe" -ArgumentList "/change /tn ""microsoft\windows\SideShow\GadgetManager"" /disable" -Wait -WindowStyle Hidden
        Start-Process "schtasks.exe" -ArgumentList "/change /tn ""microsoft\windows\SideShow\SessionAgent"" /disable" -Wait -WindowStyle Hidden
        Start-Process "schtasks.exe" -ArgumentList "/change /tn ""microsoft\windows\SideShow\SystemDataProviders"" /disable" -Wait -WindowStyle Hidden
        Start-Process "schtasks.exe" -ArgumentList "/change /tn ""microsoft\windows\UPnP\UPnPHostConfig"" /disable" -Wait -WindowStyle Hidden
        Start-Process "schtasks.exe" -ArgumentList "/change /tn ""microsoft\windows\WDI\ResolutionHost"" /disable" -Wait -WindowStyle Hidden
        Start-Process "schtasks.exe" -ArgumentList "/change /tn ""microsoft\windows\Windows Filtering Platform\BfeOnServiceStartTypeChange"" /disable" -Wait -WindowStyle Hidden
        Start-Process "schtasks.exe" -ArgumentList "/change /tn ""microsoft\windows\Windows Media Sharing\UpdateLibrary"" /disable" -Wait -WindowStyle Hidden
        Start-Process "schtasks.exe" -ArgumentList "/change /tn ""microsoft\windows\WindowsBackup\ConfigNotification"" /disable" -Wait -WindowStyle Hidden
        Write-Host -ForegroundColor Green " done"
	}

	## Delete cached profiles
	If ($CleanupProfiles -eq $true) {
		Write-Host -NoNewLine "Cleaning up cached profiles..."
		If ((Test-Path "$AddonFolder\DelProf2\delprof2.exe") -eq $false ) {
			Write-Host -ForegroundColor Red " failed"
            Write-Host ""
			Write-Warning "Profile clean up failed!"
			Write-Warning "delprof2.exe couldn't be found."
			Write-Host ""
		} Else {
			Start-Process -FilePath "$AddonFolder\DelProf2\delprof2.exe" -ArgumentList "/u /i" -Wait -WindowStyle Minimized
            Write-Host -ForegroundColor Green " done"
		}
	}

    ## Delete Temp Files, Windows installers, Memory Dumps and much more via Cleanup Manager (cleanmgr.exe)
	If ($CleanupWindows -eq $true) {
		Write-Host -NoNewLine "Cleaning up Temp Files..."
		# Check if cleanmgr.exe is installed/present on the System
		If ((Get-Command "cleanmgr.exe" -ErrorAction SilentlyContinue) -eq $null ) {
			Write-Host -ForegroundColor Red " failed"
            Write-Host ""
			Write-Warning "Windows Cleanup failed!"
			Write-Warning "cleanmgr.exe couldn't be found."
			Write-Host ""
		} Else {
			# Run Sageset 11, which we created in the First Run Action Part
			Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/sagerun:11" -Wait -WindowStyle Minimized
            Write-Host -ForegroundColor Green " done"
		}   
	}
	
	## Generalize AppSense CCA and EM
	If ($AppSense -eq $true) {
		Write-Host -NoNewLine "Generalizing AppSense components..."
		# Here we check if the specific Appsense Service is installed
		Get-Service -Name "AppSense Client Communications Agent" -ErrorAction SilentlyContinue | Out-Null
		If($?) {
			Set-ItemProperty -Path "HKLM:\Software\AppSense Technologies\Communications Agent" -Name "Machine ID" -Value ""
			Set-ItemProperty -Path "HKLM:\Software\AppSense Technologies\Communications Agent" -Name "Group ID" -Value ""
			Get-ChildItem -Path "C:\appsensevirtual" -Recurse | Remove-Item -Force
            Write-Host -ForegroundColor Green " done"
		} Else {
            Write-Host -ForegroundColor Red " failed"
			Write-Host ""
			Write-Warning "AppSense generalization failed!"
			Write-Warning "AppSense components couldn't be found."
			Write-Host ""
		}
	}
	
    ## Generalize TrendMicro OfficeScan
	If ($TrendMicro -eq $true) {
		
        ## TrendMicro Performance Part
        Write-Host -NoNewLine "Setting TrendMicro Performance Registry Key..."
		# Setting DisableCtProcCheck=1 to prevent Performance Issues with TrendMicro - see: https://support.citrix.com/article/CTX136680
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TmFilter\Parameters" -Name "DisableCtProcCheck" -Type "DWORD" -Value "1"
        Write-Host -ForegroundColor Green " done"		

        ## TrendMicro Generalization Part
        Write-Host -NoNewLine "Generalizing TrendMicro Anti Virus..."
        # Workaround: Because TrendMicro is deleting the TCacheGenCli_x64.exe after sucessful execution we need to copy it into the TM Folder everytime before running
        # Tested with Office Scan 10.6 SP3

        If ((Test-Path "$ProgramFiles\Trend Micro\OfficeScan Client\TCacheGenCli_x64.exe") -eq "$false") {
           Copy-Item -Path "$AddonFolder\TrendMicro\TCacheGenCli_x64.exe" -Destination "$ProgramFiles\Trend Micro\OfficeScan Client\" -ErrorAction SilentlyContinue
           Copy-Item -Path "$AddonFolder\TrendMicro\TCacheGen_x64.exe" -Destination "$ProgramFiles\Trend Micro\OfficeScan Client\" -ErrorAction SilentlyContinue
        } Else {
           Copy-Item -Path "$AddonFolder\TrendMicro\TCacheGenCli.exe" -Destination "$ProgramFiles\Trend Micro\OfficeScan Client\" -ErrorAction SilentlyContinue
           Copy-Item -Path "$AddonFolder\TrendMicro\TCacheGen.exe" -Destination "$ProgramFiles\Trend Micro\OfficeScan Client\" -ErrorAction SilentlyContinue
           }
        # End of Workaround

        If ((Test-Path "$ProgramFiles\Trend Micro\OfficeScan Client\TCacheGenCli_x64.exe") -eq $false) {
			Write-Host -ForegroundColor Red " failed"
            Write-Host ""
			Write-Warning "TrendMicro generalization failed!"
			Write-Warning "TrendMicro Tools for generalization couldn't be found."
			Write-Host ""
		} Else {
            If ($Bitness -eq "x64") {
			        Start-Process -FilePath "$ProgramFiles\Trend Micro\OfficeScan Client\TCacheGenCli_x64.exe" -ArgumentList "Remove_GUID" -Wait -WindowStyle Minimized
		        } Else {
			        Start-Process -FilePath "$ProgramFiles\Trend Micro\OfficeScan Client\TCacheGenCli.exe" -ArgumentList "Remove_GUID" -Wait -WindowStyle Minimized
	            }
        Write-Host -ForegroundColor Green " done"        
	    }
    }
    	
	## Delete VMware Tools Status Tray Icons
	If ($Optimize -eq $true -and $VMware -eq $true) {
		Write-Host -NoNewLine "Disabling VMware Tools Status Tray..."
		# Set Registry Key to disable Status Tray Icon
        Set-ItemProperty -Path "HKLM:\SOFTWARE\VMware, Inc.\VMware Tools" -Name "ShowTray" -Value "0" -Type "DWORD" -ErrorAction SilentlyContinue
        # Deleting VMware Tools Status Tray Icons from Run
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "VMware Tools" -Force -ErrorAction SilentlyContinue
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "VMware User Process" -Force -ErrorAction SilentlyContinue
        Write-Host -ForegroundColor Green " done"		
	}
	
	## Clear event logs
	If ($CleanupEventlog -eq $true) {
		Write-Host -NoNewLine "Clearing event logs..."
		Clear-EventLog -LogName Application
		Clear-EventLog -LogName Security
		Clear-EventLog -LogName System
        Write-Host -ForegroundColor Green " done"
	}

	## Optimize target device
	If ($Optimize -eq $true) {
		Write-Host -NoNewLine "Optimizing target device..."
		If ((Test-Path "$ProgramFiles64\Citrix\PvsVm\TargetOSOptimizer\TargetOSOptimizer.exe") -eq $false) {
			Write-Host -ForegroundColor Red " failed"
            Write-Host ""
			Write-Warning "Citrix Target Optimization failed!"
			Write-Warning "Citrix Target Optimizer couldn't be found."
			Write-Host ""
			} Else {	
				If ($Bitness -eq "x64") {
					Start-Process -FilePath "$ProgramFiles64\Citrix\PvsVm\TargetOSOptimizer\TargetOSOptimizer.exe" -ArgumentList "/silent" -Wait -WindowStyle Minimized
				} Else {
					Start-Process -FilePath "$ProgramFiles\Citrix\PvsVm\TargetOSOptimizer\TargetOSOptimizer.exe" -ArgumentList "/silent" -Wait -WindowStyle Minimized
				}
            Write-Host -ForegroundColor Green " done"    
			}
	}
	
    ## Reclaim Space on vDisk/Harddisk
	If ($Optimize -eq $true) {
		Write-Host -NoNewLine "Reclaiming Disk Space..."
		If ((Test-Path "$AddonFolder\sdelete\sdelete.exe") -eq $false ) {
			Write-Host -ForegroundColor Red " failed"
            Write-Host ""
			Write-Warning "Space Reclamation failed!"
			Write-Warning "sdelete.exe couldn't be found."
			Write-Host ""
		} Else {
			Start-Process -FilePath "$AddonFolder\sdelete\sdelete.exe" -ArgumentList "/accepteula -q -z `"$env:SystemDrive`"" -Wait -WindowStyle Minimized
            Write-Host -ForegroundColor Green " done"
		}
	}
	
	## Flush DNS cache
	Write-Host -NoNewLine "Flushing DNS cache..."
	Start-Process -FilePath "ipconfig.exe" -ArgumentList "/flushdns" -Wait -WindowStyle Minimized
	Write-Host -ForegroundColor Green " done"
    
}

###
### Start up actions, proccessed only in startup mode
###

If ($Mode -eq "Startup" -and $ProvisioningMethod -eq "PVS") {
	#Create persistent drive (for PVS Write Cache) if not already available
	If ((Test-Path $PersistentDiskDrive) -eq $false) {
		Write-Output "select disk 0" | Out-File -Force -FilePath "$env:TEMP\xenprep-diskpart.txt" -Encoding ASCII
		Write-Output "clean" | Out-File -Force -FilePath "$env:TEMP\xenprep-diskpart.txt" -Append -Encoding ASCII
		Write-Output "create partition primary align=1024" | Out-File -Force -FilePath "$env:TEMP\xenprep-diskpart.txt" -Append -Encoding ASCII
		Write-Output "assign letter=$PersistentDisk" | Out-File -Force -FilePath "$env:TEMP\xenprep-diskpart.txt" -Append -Encoding ASCII
		Write-Output "active" | Out-File -Force -FilePath "$env:TEMP\xenprep-diskpart.txt" -Append -Encoding ASCII
		Write-Output "format fs=ntfs label=PersistentDisk quick" | Out-File -Force -FilePath "$env:TEMP\xenprep-diskpart.txt" -Append -Encoding ASCII
		Write-Output "exit" | Out-File -Force -FilePath "$env:TEMP\xenprep-diskpart.txt" -Append -Encoding ASCII
		Start-Process -FilePath "diskpart.exe" -ArgumentList "/s `"$env:TEMP\xenprep-diskpart.txt`"" -Wait -WindowStyle Minimized
		Remove-Item -Path "$env:TEMP\xenprep-diskpart.txt" -Force
	}
}


###
### Stop Logging (should be last one before Shutdown Task)
###

#Stop-Transcript | Out-Null

###
### Shutdown task
###

If ($Mode -eq "Seal" -and $Shutdown -eq $true) {
	Write-Host "Shutting down computer..."
	If ($Silent -eq $true) {
	Stop-Computer
	} Else {
	Stop-Computer -Confirm
	}
}

# SIG # Begin signature block
# MIIYcgYJKoZIhvcNAQcCoIIYYzCCGF8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAzn7D8tQFUAL6V
# MGkMMLCmZbUUlmc9uYi0kuJ3vazm2qCCE30wggPuMIIDV6ADAgECAhB+k+v7fMZO
# WepLmnfUBvw7MA0GCSqGSIb3DQEBBQUAMIGLMQswCQYDVQQGEwJaQTEVMBMGA1UE
# CBMMV2VzdGVybiBDYXBlMRQwEgYDVQQHEwtEdXJiYW52aWxsZTEPMA0GA1UEChMG
# VGhhd3RlMR0wGwYDVQQLExRUaGF3dGUgQ2VydGlmaWNhdGlvbjEfMB0GA1UEAxMW
# VGhhd3RlIFRpbWVzdGFtcGluZyBDQTAeFw0xMjEyMjEwMDAwMDBaFw0yMDEyMzAy
# MzU5NTlaMF4xCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3Jh
# dGlvbjEwMC4GA1UEAxMnU3ltYW50ZWMgVGltZSBTdGFtcGluZyBTZXJ2aWNlcyBD
# QSAtIEcyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsayzSVRLlxwS
# CtgleZEiVypv3LgmxENza8K/LlBa+xTCdo5DASVDtKHiRfTot3vDdMwi17SUAAL3
# Te2/tLdEJGvNX0U70UTOQxJzF4KLabQry5kerHIbJk1xH7Ex3ftRYQJTpqr1SSwF
# eEWlL4nO55nn/oziVz89xpLcSvh7M+R5CvvwdYhBnP/FA1GZqtdsn5Nph2Upg4XC
# YBTEyMk7FNrAgfAfDXTekiKryvf7dHwn5vdKG3+nw54trorqpuaqJxZ9YfeYcRG8
# 4lChS+Vd+uUOpyyfqmUg09iW6Mh8pU5IRP8Z4kQHkgvXaISAXWp4ZEXNYEZ+VMET
# fMV58cnBcQIDAQABo4H6MIH3MB0GA1UdDgQWBBRfmvVuXMzMdJrU3X3vP9vsTIAu
# 3TAyBggrBgEFBQcBAQQmMCQwIgYIKwYBBQUHMAGGFmh0dHA6Ly9vY3NwLnRoYXd0
# ZS5jb20wEgYDVR0TAQH/BAgwBgEB/wIBADA/BgNVHR8EODA2MDSgMqAwhi5odHRw
# Oi8vY3JsLnRoYXd0ZS5jb20vVGhhd3RlVGltZXN0YW1waW5nQ0EuY3JsMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMIMA4GA1UdDwEB/wQEAwIBBjAoBgNVHREEITAfpB0wGzEZ
# MBcGA1UEAxMQVGltZVN0YW1wLTIwNDgtMTANBgkqhkiG9w0BAQUFAAOBgQADCZuP
# ee9/WTCq72i1+uMJHbtPggZdN1+mUp8WjeockglEbvVt61h8MOj5aY0jcwsSb0ep
# rjkR+Cqxm7Aaw47rWZYArc4MTbLQMaYIXCp6/OJ6HVdMqGUY6XlAYiWWbsfHN2qD
# IQiOQerd2Vc/HXdJhyoWBl6mOGoiEqNRGYN+tjCCBKMwggOLoAMCAQICEA7P9DjI
# /r81bgTYapgbGlAwDQYJKoZIhvcNAQEFBQAwXjELMAkGA1UEBhMCVVMxHTAbBgNV
# BAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMTAwLgYDVQQDEydTeW1hbnRlYyBUaW1l
# IFN0YW1waW5nIFNlcnZpY2VzIENBIC0gRzIwHhcNMTIxMDE4MDAwMDAwWhcNMjAx
# MjI5MjM1OTU5WjBiMQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29y
# cG9yYXRpb24xNDAyBgNVBAMTK1N5bWFudGVjIFRpbWUgU3RhbXBpbmcgU2Vydmlj
# ZXMgU2lnbmVyIC0gRzQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCi
# Yws5RLi7I6dESbsO/6HwYQpTk7CY260sD0rFbv+GPFNVDxXOBD8r/amWltm+YXkL
# W8lMhnbl4ENLIpXuwitDwZ/YaLSOQE/uhTi5EcUj8mRY8BUyb05Xoa6IpALXKh7N
# S+HdY9UXiTJbsF6ZWqidKFAOF+6W22E7RVEdzxJWC5JH/Kuu9mY9R6xwcueS51/N
# ELnEg2SUGb0lgOHo0iKl0LoCeqF3k1tlw+4XdLxBhircCEyMkoyRLZ53RB9o1qh0
# d9sOWzKLVoszvdljyEmdOsXF6jML0vGjG/SLvtmzV4s73gSneiKyJK4ux3DFvk6D
# Jgj7C72pT5kI4RAocqrNAgMBAAGjggFXMIIBUzAMBgNVHRMBAf8EAjAAMBYGA1Ud
# JQEB/wQMMAoGCCsGAQUFBwMIMA4GA1UdDwEB/wQEAwIHgDBzBggrBgEFBQcBAQRn
# MGUwKgYIKwYBBQUHMAGGHmh0dHA6Ly90cy1vY3NwLndzLnN5bWFudGVjLmNvbTA3
# BggrBgEFBQcwAoYraHR0cDovL3RzLWFpYS53cy5zeW1hbnRlYy5jb20vdHNzLWNh
# LWcyLmNlcjA8BgNVHR8ENTAzMDGgL6AthitodHRwOi8vdHMtY3JsLndzLnN5bWFu
# dGVjLmNvbS90c3MtY2EtZzIuY3JsMCgGA1UdEQQhMB+kHTAbMRkwFwYDVQQDExBU
# aW1lU3RhbXAtMjA0OC0yMB0GA1UdDgQWBBRGxmmjDkoUHtVM2lJjFz9eNrwN5jAf
# BgNVHSMEGDAWgBRfmvVuXMzMdJrU3X3vP9vsTIAu3TANBgkqhkiG9w0BAQUFAAOC
# AQEAeDu0kSoATPCPYjA3eKOEJwdvGLLeJdyg1JQDqoZOJZ+aQAMc3c7jecshaAba
# tjK0bb/0LCZjM+RJZG0N5sNnDvcFpDVsfIkWxumy37Lp3SDGcQ/NlXTctlzevTcf
# Q3jmeLXNKAQgo6rxS8SIKZEOgNER/N1cdm5PXg5FRkFuDbDqOJqxOtoJcRD8HHm0
# gHusafT9nLYMFivxf1sJPZtb4hbKE4FtAC44DagpjyzhsvRaqQGvFZwsL0kb2yK7
# w/54lFHDhrGCiF3wPbRRoXkzKy57udwgCRNx62oZW8/opTBXLIlJP7nPf8m/PiJo
# Y1OavWl0rMUdPH+S4MO8HNgEdTCCBQQwggPsoAMCAQICEEq/9LXHFfx6o0eioj0F
# KmcwDQYJKoZIhvcNAQELBQAwdTELMAkGA1UEBhMCSUwxFjAUBgNVBAoTDVN0YXJ0
# Q29tIEx0ZC4xKTAnBgNVBAsTIFN0YXJ0Q29tIENlcnRpZmljYXRpb24gQXV0aG9y
# aXR5MSMwIQYDVQQDExpTdGFydENvbSBDbGFzcyAyIE9iamVjdCBDQTAeFw0xNjAy
# MTYxMDAwMTJaFw0xODAyMTYxMDAwMTJaMHExCzAJBgNVBAYTAkRFMRswGQYDVQQI
# DBJCYWRlbi1XdWVydHRlbWJlcmcxETAPBgNVBAcMCE1hbm5oZWltMRgwFgYDVQQK
# DA9DbGF1cyBKYW4gSGFybXMxGDAWBgNVBAMMD0NsYXVzIEphbiBIYXJtczCCASIw
# DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALlPW92VVN0btzht8h6pkIDJtOwR
# VK4oRWsdMqXt0bWir55Ghwd4YGcVMlxg44nifkC6Y1ess3CbITsr58P7qfoIXQVg
# ediSYDd3hCXjO1Gk+VJYRm/4o3Pu3eo61ElXZ73dnOfRtOB1rfn27Ib0y44386nA
# yez1ayj5bzXmP/p4wthFTeSwP7qBeajHugMaUn8DZuS7r6VxvbJI877Nlu04Hcue
# NM0+Ac9kDxtmiEUpVD0LusuYFBSelmeEegBCKaj+ElHmhtGoNRq5fPXOnSO+6HJ7
# moTyZnYiZ33tN4nbDjwvf6IQwI7FQuyvj2xwNoNLzxEal8t5aHJpvl0V48sCAwEA
# AaOCAZIwggGOMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAJ
# BgNVHRMEAjAAMB0GA1UdDgQWBBSgy7/6vlBFBQv509wal/37+Tpy0DAfBgNVHSME
# GDAWgBQ+YpOa18cZ7j6PSRCFVRUg45SEHDBtBggrBgEFBQcBAQRhMF8wJAYIKwYB
# BQUHMAGGGGh0dHA6Ly9vY3NwLnN0YXJ0c3NsLmNvbTA3BggrBgEFBQcwAoYraHR0
# cDovL2FpYS5zdGFydHNzbC5jb20vY2VydHMvc2NhLmNvZGUyLmNydDA2BgNVHR8E
# LzAtMCugKaAnhiVodHRwOi8vY3JsLnN0YXJ0c3NsLmNvbS9zY2EtY29kZTIuY3Js
# MCMGA1UdEgQcMBqGGGh0dHA6Ly93d3cuc3RhcnRzc2wuY29tLzBQBgNVHSAESTBH
# MAgGBmeBDAEEATA7BgsrBgEEAYG1NwECBDAsMCoGCCsGAQUFBwIBFh5odHRwOi8v
# d3d3LnN0YXJ0c3NsLmNvbS9wb2xpY3kwDQYJKoZIhvcNAQELBQADggEBAHeTBk8y
# 3koPGUrzIny5YrtXNHlUx8kgBOd6eXL4ka09jTopGZqrbTdKq6Rde7ZLTIYw+s4n
# vGmKVbmpEndYbISTAyQgPVMDAieHV7+aVfv3NrGpVuRNw9A/3osErjfHtmqfrl+7
# sliKZdLOOXA8Zdsb5Ii4AjRH+juE2Uy7jB4bpvgM3Bg41r8Y3UgWSpPZTic1s/FD
# houhKkig6ltmlcTRbnQssiqDwEdn0/kEMtti8n7BH874+8BZnBnY6jsjymERfJZ4
# DHh/CZTO4syw2PdJmln692b35SYUOzVMQpmLQcIuEZVu8FCoGjoKjdcQF3Q9BOaI
# C8nvHmMgr71ZqU0wggXYMIIDwKADAgECAhBsO9J+3TyUnpWOKKmzx1egMA0GCSqG
# SIb3DQEBCwUAMH0xCzAJBgNVBAYTAklMMRYwFAYDVQQKEw1TdGFydENvbSBMdGQu
# MSswKQYDVQQLEyJTZWN1cmUgRGlnaXRhbCBDZXJ0aWZpY2F0ZSBTaWduaW5nMSkw
# JwYDVQQDEyBTdGFydENvbSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0xNTEy
# MTYwMTAwMDVaFw0zMDEyMTYwMTAwMDVaMHUxCzAJBgNVBAYTAklMMRYwFAYDVQQK
# Ew1TdGFydENvbSBMdGQuMSkwJwYDVQQLEyBTdGFydENvbSBDZXJ0aWZpY2F0aW9u
# IEF1dGhvcml0eTEjMCEGA1UEAxMaU3RhcnRDb20gQ2xhc3MgMiBPYmplY3QgQ0Ew
# ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC5FARY97LFhiwIMmCtCCbA
# gXe5aBnZFSsdGGnk2hqWBZcuZHkaqT1RM1rQd2r0ApNBw466cBur2Ht0b5jo17mp
# Pmh2pImgIqwX1in4u7hhn9IH0GYOMEcgK3ACHv5zCRxxNLXifqmsqKfxjjpABnaS
# yvd4bO9YBXN9f4NQ6aJVAuMArpanxsJke+P4WECVLk17v92CAN5JVaczI+baT/lg
# o5NVcTEkloCViSbIfU6ILeyhOSQZvpomMYk8eJqI0nimOTJJfmXangNDsrX8np+3
# lXD0+6rCZisXRWIaeffyTMHZ31Qj1D50WYdRtX5yev4WgaXoKJQN3lkgXUcytvyH
# AgMBAAGjggFaMIIBVjAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYBBQUH
# AwMwEgYDVR0TAQH/BAgwBgEB/wIBADAyBgNVHR8EKzApMCegJaAjhiFodHRwOi8v
# Y3JsLnN0YXJ0c3NsLmNvbS9zZnNjYS5jcmwwZgYIKwYBBQUHAQEEWjBYMCQGCCsG
# AQUFBzABhhhodHRwOi8vb2NzcC5zdGFydHNzbC5jb20wMAYIKwYBBQUHMAKGJGh0
# dHA6Ly9haWEuc3RhcnRzc2wuY29tL2NlcnRzL2NhLmNydDAdBgNVHQ4EFgQUPmKT
# mtfHGe4+j0kQhVUVIOOUhBwwHwYDVR0jBBgwFoAUTgvvGqRAW6UXaYcwyjRoQ9BB
# rvIwPwYDVR0gBDgwNjA0BgRVHSAAMCwwKgYIKwYBBQUHAgEWHmh0dHA6Ly93d3cu
# c3RhcnRzc2wuY29tL3BvbGljeTANBgkqhkiG9w0BAQsFAAOCAgEAY6U81bNtJyjY
# 67pTrzAL6kpdEtX5mspw+kxjjNdNVH5G6lLnhaEkIxqdpvY/Wdw+UdNtExs+N8ef
# KPSwh2m/BxXj2fSeLMwXcwHFookScEER8ez0quCNzioqNHac7LCXPEnQzbtG2FHl
# ePKNDWh8eU6KxiAzNzIrIxPthinHGgLTBOACHQM2YTlD8YoU5oN3dLmBOqtH0BDM
# ZoLcjEIoEW1zC+TnVb3yU1G0xub6gnN7lP50vbAiHJYrnywQiXaloBV8B9YYfe6Z
# gvjqxwufwFcMVyE3UmCuDTsOpjqDEKpJ25s+FUdkie5VqCS1aaudLo31X+9UvP45
# pfgyRqzyfUnVEhH4ZXxlBWZMzj2Xov5+m/+H3kxYuFA5xdqdshj/Zx00S7PkCSF+
# 8M1NCcvFgQwjIw61bZAjDBl3P3a8xNTXsb2CjFdiNKbT3LD6IGeIf0b/EbPf0FXd
# vBrxm0ofMOhnngdPolPYCtoOGtZPAVe/xeu+/ZyKv6TSHlshaUO0iYfsmbXnZ51v
# vt/kkjwms9/qPFxSuE0fjEfF7aQazwREDf2hiVPR0pAhvShtM3oU4XreEFEUWEYH
# s25fYV4WMmxkUKSgmSmwRq45tvtGH4LTb5+cd+iLqK8rBQL0E6xaUjjGfsYx7bue
# IvqTvCkrQvoxMbn/qDHCiypowDVq6TAxggRLMIIERwIBATCBiTB1MQswCQYDVQQG
# EwJJTDEWMBQGA1UEChMNU3RhcnRDb20gTHRkLjEpMCcGA1UECxMgU3RhcnRDb20g
# Q2VydGlmaWNhdGlvbiBBdXRob3JpdHkxIzAhBgNVBAMTGlN0YXJ0Q29tIENsYXNz
# IDIgT2JqZWN0IENBAhBKv/S1xxX8eqNHoqI9BSpnMA0GCWCGSAFlAwQCAQUAoIGE
# MBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQB
# gjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkE
# MSIEIMx+gHct09EQqwKQYuZNFM0mynifgiuB+7rmSxRmXOwGMA0GCSqGSIb3DQEB
# AQUABIIBAJZde8E/1SkwiXrg7bZVREIK/Yf1fD9FPwTlf6o7g0m+v7hy2gLcUnx2
# rrAmYFRLzg7Rp3ng6oYoA0lrfWRgECeDE8xU/S2W+WVMEuyGUjpXNYhKRuCHFMVa
# Wyf7h8gaGq0RdO+rxgGf1ELsRc1RLRe5h5Xgw2BIyJk6CE5k2V3/ZYfwn/fYZRMx
# V4xp02mHFXqhK2wVvMe2k/5OBsdbp8ChfL/a1m0vHTMwS0ILNmtECiOtd7SHrIfF
# 3P+lOlWpoSR0LIGU1w12SBzzNYtFYRy2FSX0pIENTFDGBsM+SlwKCq+wrAtoYkeo
# ai6DO3lGCT+eFEoM1Sgv0G5aS/tPILihggILMIICBwYJKoZIhvcNAQkGMYIB+DCC
# AfQCAQEwcjBeMQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9y
# YXRpb24xMDAuBgNVBAMTJ1N5bWFudGVjIFRpbWUgU3RhbXBpbmcgU2VydmljZXMg
# Q0EgLSBHMgIQDs/0OMj+vzVuBNhqmBsaUDAJBgUrDgMCGgUAoF0wGAYJKoZIhvcN
# AQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTYwMzA4MDk0ODU1WjAj
# BgkqhkiG9w0BCQQxFgQUdZdVmRTF6Z5baSvJzOuVmc7dvEIwDQYJKoZIhvcNAQEB
# BQAEggEAfpDY+x9dEnW3yikyBfhBMyeZSBUUSbP+HiDJekU7iDhAq5TLTB9prUGx
# 2H5JMSC3I8NcGXeszOtoRdDjaRrA/5T0Tm3j5XrEgYrozJuCbQtWk/IoGzz97++v
# Mq+BMR3HdigI0tcmwELogPR66C0N8Nee1M6QiJ/bOCqaZrGjdZNF4GQE2KtwtDSl
# VTDG6xdorfmUcgLUmlyScbSGQtfQQGlEolq1Z3Ew4lCKmAUxAY0GDQFQ/8O1Ndqp
# vAmTMs0nWnRA6Yir4Bk5T1VysfGOUNixCy0j29qS+oYNWkNpiX6Ok3YNHw6KNvqQ
# 5xAt9ZNbUF+f/1+jB7lAxLj1fF36xg==
# SIG # End signature block
