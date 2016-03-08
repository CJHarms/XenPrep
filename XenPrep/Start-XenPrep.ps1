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
	New-ItemProperty "HKLM:\SOFTWARE\XenPrep" -Name "FirstRun" -PropertyType "DWord" -Value 0 -Force | Out-Null
}

#Check first run registry key
If (((Get-ItemProperty "HKLM:\SOFTWARE\XenPrep" -ErrorAction SilentlyContinue).FirstRun) -eq "1") {
	$FirstRunActions = $false
} Else {
	$FirstRunActions = $true
}

#Set first run key
New-Item "HKLM:\SOFTWARE\XenPrep" -Force | Out-Null
New-ItemProperty "HKLM:\SOFTWARE\XenPrep" -Name "FirstRun" -PropertyType "DWord" -Value 1 -Force | Out-Null

###
### First run actions, proccessed only one time in Seal/Rearm mode.
###

If ($Mode -eq "Seal" -and $FirstRunActions -eq $true) {

#Create SageRun Set 11 in the cleanmgr Registry Hive. Used by cleanmgr.exe to clean specific Things like old Logs and MemoryDumps...
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\*' -Name StateFlags0011 -Value 2 -PropertyType DWord -Force | Out-Null
#Delete specific SageRun Set 11 Flags for Windows Update Cleanup because WU Cleanup requires a restart to complete the Cleanup. WU Cleanup should be done manually for now.
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Update Cleanup' -Name StateFlags0011 -ErrorAction SilentlyContinue

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
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TmFilter\Parameters" -Name "DisableCtProcCheck" -Type "DWord" -Value "1" | Out-Null
        
        Write-Host -ForegroundColor Green " done"		

        ## TrendMicro Generalization Part
        
        Write-Host -NoNewLine "Generalizing TrendMicro Anti Virus..."
        # Workaround: Because TrendMicro is deleting the TCacheGenCli_x64.exe after sucessful execution we need to copy it into the TM Folder everytime before running
        # tested with Office Scan 10.6 SP3 - 11.02.2016

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
		# Deleting VMware Tools Status Tray Icons
		Remove-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name "VMware Tools" -Force -ErrorAction SilentlyContinue
		Remove-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name "VMware User Process" -Force -ErrorAction SilentlyContinue
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
# MIIYTQYJKoZIhvcNAQcCoIIYPjCCGDoCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUETXRyL7qR1/y9mJV4GcsQAV6
# UKagghN9MIID7jCCA1egAwIBAgIQfpPr+3zGTlnqS5p31Ab8OzANBgkqhkiG9w0B
# AQUFADCBizELMAkGA1UEBhMCWkExFTATBgNVBAgTDFdlc3Rlcm4gQ2FwZTEUMBIG
# A1UEBxMLRHVyYmFudmlsbGUxDzANBgNVBAoTBlRoYXd0ZTEdMBsGA1UECxMUVGhh
# d3RlIENlcnRpZmljYXRpb24xHzAdBgNVBAMTFlRoYXd0ZSBUaW1lc3RhbXBpbmcg
# Q0EwHhcNMTIxMjIxMDAwMDAwWhcNMjAxMjMwMjM1OTU5WjBeMQswCQYDVQQGEwJV
# UzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xMDAuBgNVBAMTJ1N5bWFu
# dGVjIFRpbWUgU3RhbXBpbmcgU2VydmljZXMgQ0EgLSBHMjCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBALGss0lUS5ccEgrYJXmRIlcqb9y4JsRDc2vCvy5Q
# WvsUwnaOQwElQ7Sh4kX06Ld7w3TMIte0lAAC903tv7S3RCRrzV9FO9FEzkMScxeC
# i2m0K8uZHqxyGyZNcR+xMd37UWECU6aq9UksBXhFpS+JzueZ5/6M4lc/PcaS3Er4
# ezPkeQr78HWIQZz/xQNRmarXbJ+TaYdlKYOFwmAUxMjJOxTawIHwHw103pIiq8r3
# +3R8J+b3Sht/p8OeLa6K6qbmqicWfWH3mHERvOJQoUvlXfrlDqcsn6plINPYlujI
# fKVOSET/GeJEB5IL12iEgF1qeGRFzWBGflTBE3zFefHJwXECAwEAAaOB+jCB9zAd
# BgNVHQ4EFgQUX5r1blzMzHSa1N197z/b7EyALt0wMgYIKwYBBQUHAQEEJjAkMCIG
# CCsGAQUFBzABhhZodHRwOi8vb2NzcC50aGF3dGUuY29tMBIGA1UdEwEB/wQIMAYB
# Af8CAQAwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2NybC50aGF3dGUuY29tL1Ro
# YXd0ZVRpbWVzdGFtcGluZ0NBLmNybDATBgNVHSUEDDAKBggrBgEFBQcDCDAOBgNV
# HQ8BAf8EBAMCAQYwKAYDVR0RBCEwH6QdMBsxGTAXBgNVBAMTEFRpbWVTdGFtcC0y
# MDQ4LTEwDQYJKoZIhvcNAQEFBQADgYEAAwmbj3nvf1kwqu9otfrjCR27T4IGXTdf
# plKfFo3qHJIJRG71betYfDDo+WmNI3MLEm9Hqa45EfgqsZuwGsOO61mWAK3ODE2y
# 0DGmCFwqevzieh1XTKhlGOl5QGIllm7HxzdqgyEIjkHq3dlXPx13SYcqFgZepjhq
# IhKjURmDfrYwggSjMIIDi6ADAgECAhAOz/Q4yP6/NW4E2GqYGxpQMA0GCSqGSIb3
# DQEBBQUAMF4xCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3Jh
# dGlvbjEwMC4GA1UEAxMnU3ltYW50ZWMgVGltZSBTdGFtcGluZyBTZXJ2aWNlcyBD
# QSAtIEcyMB4XDTEyMTAxODAwMDAwMFoXDTIwMTIyOTIzNTk1OVowYjELMAkGA1UE
# BhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMTQwMgYDVQQDEytT
# eW1hbnRlYyBUaW1lIFN0YW1waW5nIFNlcnZpY2VzIFNpZ25lciAtIEc0MIIBIjAN
# BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAomMLOUS4uyOnREm7Dv+h8GEKU5Ow
# mNutLA9KxW7/hjxTVQ8VzgQ/K/2plpbZvmF5C1vJTIZ25eBDSyKV7sIrQ8Gf2Gi0
# jkBP7oU4uRHFI/JkWPAVMm9OV6GuiKQC1yoezUvh3WPVF4kyW7BemVqonShQDhfu
# ltthO0VRHc8SVguSR/yrrvZmPUescHLnkudfzRC5xINklBm9JYDh6NIipdC6Anqh
# d5NbZcPuF3S8QYYq3AhMjJKMkS2ed0QfaNaodHfbDlsyi1aLM73ZY8hJnTrFxeoz
# C9Lxoxv0i77Zs1eLO94Ep3oisiSuLsdwxb5OgyYI+wu9qU+ZCOEQKHKqzQIDAQAB
# o4IBVzCCAVMwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAO
# BgNVHQ8BAf8EBAMCB4AwcwYIKwYBBQUHAQEEZzBlMCoGCCsGAQUFBzABhh5odHRw
# Oi8vdHMtb2NzcC53cy5zeW1hbnRlYy5jb20wNwYIKwYBBQUHMAKGK2h0dHA6Ly90
# cy1haWEud3Muc3ltYW50ZWMuY29tL3Rzcy1jYS1nMi5jZXIwPAYDVR0fBDUwMzAx
# oC+gLYYraHR0cDovL3RzLWNybC53cy5zeW1hbnRlYy5jb20vdHNzLWNhLWcyLmNy
# bDAoBgNVHREEITAfpB0wGzEZMBcGA1UEAxMQVGltZVN0YW1wLTIwNDgtMjAdBgNV
# HQ4EFgQURsZpow5KFB7VTNpSYxc/Xja8DeYwHwYDVR0jBBgwFoAUX5r1blzMzHSa
# 1N197z/b7EyALt0wDQYJKoZIhvcNAQEFBQADggEBAHg7tJEqAEzwj2IwN3ijhCcH
# bxiy3iXcoNSUA6qGTiWfmkADHN3O43nLIWgG2rYytG2/9CwmYzPkSWRtDebDZw73
# BaQ1bHyJFsbpst+y6d0gxnEPzZV03LZc3r03H0N45ni1zSgEIKOq8UvEiCmRDoDR
# EfzdXHZuT14ORUZBbg2w6jiasTraCXEQ/Bx5tIB7rGn0/Zy2DBYr8X9bCT2bW+IW
# yhOBbQAuOA2oKY8s4bL0WqkBrxWcLC9JG9siu8P+eJRRw4axgohd8D20UaF5Mysu
# e7ncIAkTcetqGVvP6KUwVyyJST+5z3/Jvz4iaGNTmr1pdKzFHTx/kuDDvBzYBHUw
# ggUEMIID7KADAgECAhBKv/S1xxX8eqNHoqI9BSpnMA0GCSqGSIb3DQEBCwUAMHUx
# CzAJBgNVBAYTAklMMRYwFAYDVQQKEw1TdGFydENvbSBMdGQuMSkwJwYDVQQLEyBT
# dGFydENvbSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEjMCEGA1UEAxMaU3RhcnRD
# b20gQ2xhc3MgMiBPYmplY3QgQ0EwHhcNMTYwMjE2MTAwMDEyWhcNMTgwMjE2MTAw
# MDEyWjBxMQswCQYDVQQGEwJERTEbMBkGA1UECAwSQmFkZW4tV3VlcnR0ZW1iZXJn
# MREwDwYDVQQHDAhNYW5uaGVpbTEYMBYGA1UECgwPQ2xhdXMgSmFuIEhhcm1zMRgw
# FgYDVQQDDA9DbGF1cyBKYW4gSGFybXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
# ggEKAoIBAQC5T1vdlVTdG7c4bfIeqZCAybTsEVSuKEVrHTKl7dG1oq+eRocHeGBn
# FTJcYOOJ4n5AumNXrLNwmyE7K+fD+6n6CF0FYHnYkmA3d4Ql4ztRpPlSWEZv+KNz
# 7t3qOtRJV2e93Zzn0bTgda359uyG9MuON/OpwMns9Wso+W815j/6eMLYRU3ksD+6
# gXmox7oDGlJ/A2bku6+lcb2ySPO+zZbtOB3LnjTNPgHPZA8bZohFKVQ9C7rLmBQU
# npZnhHoAQimo/hJR5obRqDUauXz1zp0jvuhye5qE8mZ2Imd97TeJ2w48L3+iEMCO
# xULsr49scDaDS88RGpfLeWhyab5dFePLAgMBAAGjggGSMIIBjjAOBgNVHQ8BAf8E
# BAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwCQYDVR0TBAIwADAdBgNVHQ4EFgQU
# oMu/+r5QRQUL+dPcGpf9+/k6ctAwHwYDVR0jBBgwFoAUPmKTmtfHGe4+j0kQhVUV
# IOOUhBwwbQYIKwYBBQUHAQEEYTBfMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5z
# dGFydHNzbC5jb20wNwYIKwYBBQUHMAKGK2h0dHA6Ly9haWEuc3RhcnRzc2wuY29t
# L2NlcnRzL3NjYS5jb2RlMi5jcnQwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2Ny
# bC5zdGFydHNzbC5jb20vc2NhLWNvZGUyLmNybDAjBgNVHRIEHDAahhhodHRwOi8v
# d3d3LnN0YXJ0c3NsLmNvbS8wUAYDVR0gBEkwRzAIBgZngQwBBAEwOwYLKwYBBAGB
# tTcBAgQwLDAqBggrBgEFBQcCARYeaHR0cDovL3d3dy5zdGFydHNzbC5jb20vcG9s
# aWN5MA0GCSqGSIb3DQEBCwUAA4IBAQB3kwZPMt5KDxlK8yJ8uWK7VzR5VMfJIATn
# enly+JGtPY06KRmaq203SqukXXu2S0yGMPrOJ7xpilW5qRJ3WGyEkwMkID1TAwIn
# h1e/mlX79zaxqVbkTcPQP96LBK43x7Zqn65fu7JYimXSzjlwPGXbG+SIuAI0R/o7
# hNlMu4weG6b4DNwYONa/GN1IFkqT2U4nNbPxQ4aLoSpIoOpbZpXE0W50LLIqg8BH
# Z9P5BDLbYvJ+wR/O+PvAWZwZ2Oo7I8phEXyWeAx4fwmUzuLMsNj3SZpZ+vdm9+Um
# FDs1TEKZi0HCLhGVbvBQqBo6Co3XEBd0PQTmiAvJ7x5jIK+9WalNMIIF2DCCA8Cg
# AwIBAgIQbDvSft08lJ6Vjiips8dXoDANBgkqhkiG9w0BAQsFADB9MQswCQYDVQQG
# EwJJTDEWMBQGA1UEChMNU3RhcnRDb20gTHRkLjErMCkGA1UECxMiU2VjdXJlIERp
# Z2l0YWwgQ2VydGlmaWNhdGUgU2lnbmluZzEpMCcGA1UEAxMgU3RhcnRDb20gQ2Vy
# dGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTUxMjE2MDEwMDA1WhcNMzAxMjE2MDEw
# MDA1WjB1MQswCQYDVQQGEwJJTDEWMBQGA1UEChMNU3RhcnRDb20gTHRkLjEpMCcG
# A1UECxMgU3RhcnRDb20gQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxIzAhBgNVBAMT
# GlN0YXJ0Q29tIENsYXNzIDIgT2JqZWN0IENBMIIBIjANBgkqhkiG9w0BAQEFAAOC
# AQ8AMIIBCgKCAQEAuRQEWPeyxYYsCDJgrQgmwIF3uWgZ2RUrHRhp5NoalgWXLmR5
# Gqk9UTNa0Hdq9AKTQcOOunAbq9h7dG+Y6Ne5qT5odqSJoCKsF9Yp+Lu4YZ/SB9Bm
# DjBHICtwAh7+cwkccTS14n6prKin8Y46QAZ2ksr3eGzvWAVzfX+DUOmiVQLjAK6W
# p8bCZHvj+FhAlS5Ne7/dggDeSVWnMyPm2k/5YKOTVXExJJaAlYkmyH1OiC3soTkk
# Gb6aJjGJPHiaiNJ4pjkySX5l2p4DQ7K1/J6ft5Vw9PuqwmYrF0ViGnn38kzB2d9U
# I9Q+dFmHUbV+cnr+FoGl6CiUDd5ZIF1HMrb8hwIDAQABo4IBWjCCAVYwDgYDVR0P
# AQH/BAQDAgEGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMBIGA1UdEwEB/wQIMAYBAf8C
# AQAwMgYDVR0fBCswKTAnoCWgI4YhaHR0cDovL2NybC5zdGFydHNzbC5jb20vc2Zz
# Y2EuY3JsMGYGCCsGAQUFBwEBBFowWDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3Au
# c3RhcnRzc2wuY29tMDAGCCsGAQUFBzAChiRodHRwOi8vYWlhLnN0YXJ0c3NsLmNv
# bS9jZXJ0cy9jYS5jcnQwHQYDVR0OBBYEFD5ik5rXxxnuPo9JEIVVFSDjlIQcMB8G
# A1UdIwQYMBaAFE4L7xqkQFulF2mHMMo0aEPQQa7yMD8GA1UdIAQ4MDYwNAYEVR0g
# ADAsMCoGCCsGAQUFBwIBFh5odHRwOi8vd3d3LnN0YXJ0c3NsLmNvbS9wb2xpY3kw
# DQYJKoZIhvcNAQELBQADggIBAGOlPNWzbSco2Ou6U68wC+pKXRLV+ZrKcPpMY4zX
# TVR+RupS54WhJCManab2P1ncPlHTbRMbPjfHnyj0sIdpvwcV49n0nizMF3MBxaKJ
# EnBBEfHs9Krgjc4qKjR2nOywlzxJ0M27RthR5XjyjQ1ofHlOisYgMzcyKyMT7YYp
# xxoC0wTgAh0DNmE5Q/GKFOaDd3S5gTqrR9AQzGaC3IxCKBFtcwvk51W98lNRtMbm
# +oJze5T+dL2wIhyWK58sEIl2paAVfAfWGH3umYL46scLn8BXDFchN1Jgrg07DqY6
# gxCqSdubPhVHZInuVagktWmrnS6N9V/vVLz+OaX4Mkas8n1J1RIR+GV8ZQVmTM49
# l6L+fpv/h95MWLhQOcXanbIY/2cdNEuz5AkhfvDNTQnLxYEMIyMOtW2QIwwZdz92
# vMTU17G9goxXYjSm09yw+iBniH9G/xGz39BV3bwa8ZtKHzDoZ54HT6JT2AraDhrW
# TwFXv8Xrvv2cir+k0h5bIWlDtImH7Jm152edb77f5JI8JrPf6jxcUrhNH4xHxe2k
# Gs8ERA39oYlT0dKQIb0obTN6FOF63hBRFFhGB7NuX2FeFjJsZFCkoJkpsEauObb7
# Rh+C02+fnHfoi6ivKwUC9BOsWlI4xn7GMe27niL6k7wpK0L6MTG5/6gxwosqaMA1
# aukwMYIEOjCCBDYCAQEwgYkwdTELMAkGA1UEBhMCSUwxFjAUBgNVBAoTDVN0YXJ0
# Q29tIEx0ZC4xKTAnBgNVBAsTIFN0YXJ0Q29tIENlcnRpZmljYXRpb24gQXV0aG9y
# aXR5MSMwIQYDVQQDExpTdGFydENvbSBDbGFzcyAyIE9iamVjdCBDQQIQSr/0tccV
# /HqjR6KiPQUqZzAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKA
# ADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYK
# KwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQU1AtEYSLEQneKU0Si1HO+V1bVqakw
# DQYJKoZIhvcNAQEBBQAEggEATRurlA9N/FyHXXuQJ8zqNP7dr8BBiwWMFa2oNfWW
# A2uBzQjN5OoGAP1HFfA3tmXOSKZBzzTXzA4gBNF5owG22+YWlZzTm8y8TnykDBak
# CKmBKzwCpt7wSy9uMbuKSpC1qLBpJrDGntS3BDfRhv/qtrr1k4f5QHni6PGdE+JC
# Okb+4oAUzl1cRCRemYNgZKpnKQenprj6dIHa+jAg8lIlsKbsdvadCU3P/LtlRfYj
# NZNJ66x1l+F63QPhfquLmKVKPb33vArUGGb9PJr/c++Szv+V3U5B7xKbao6hIJUB
# DctFRdi/nkmSXR9NEPkm9Ff1PENXDaiWQCFVcqIi4IyejKGCAgswggIHBgkqhkiG
# 9w0BCQYxggH4MIIB9AIBATByMF4xCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1h
# bnRlYyBDb3Jwb3JhdGlvbjEwMC4GA1UEAxMnU3ltYW50ZWMgVGltZSBTdGFtcGlu
# ZyBTZXJ2aWNlcyBDQSAtIEcyAhAOz/Q4yP6/NW4E2GqYGxpQMAkGBSsOAwIaBQCg
# XTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0xNjAz
# MDgwOTMyMTZaMCMGCSqGSIb3DQEJBDEWBBQynjss5hBob32xwYZocrldFB42IjAN
# BgkqhkiG9w0BAQEFAASCAQA0C8i3DjFV4vllZcGcPtLRKfK0Wzdu9cRQDlDi22pA
# aM3DoXKQ+xHteh/KKyJmxv8fNu7Ru1vTqBANZZUOsN9ihtvYK1qOjboFpTAJqKfN
# uYyNENJ8vHeukGIHuyOpOpeR737qcBIapMFE24pqhKcYo+fO9vcxU1lufIAxtFQD
# YGb3TDUp/CKW8hoaDcr8Wh+RQmx0XK41FqU7bYL9RAEjUSaRsYBnZRzqogABn+8h
# Z8gwWfBWM6Yo1dvm8XPeMfA2DELqS+z33Ak+8PP/t+kpw2yrJNzto3m2N+GCa8+n
# xbjqQIDebvuIFxnb/hquXUAcJvbNKHzhBws6l/af6dCM
# SIG # End signature block
