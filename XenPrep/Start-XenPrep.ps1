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

Start-Transcript -Path "$LogFolder\XenPrep.log" -IncludeInvocationHeader -ErrorAction SilentlyContinue | Out-Null

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
Write-Host "Checking operating system bitness..."
If(((Get-WmiObject -Class Win32_ComputerSystem).SystemType) -match "x64") {
	$Bitness = "x64"
	$ProgramFiles = ${env:ProgramFiles(X86)}
	$ProgramFiles64 = ${env:ProgramFiles}
} Else { 
	$Bitness = "x86"
	$ProgramFiles = ${env:ProgramFiles}
}

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
		Write-Host -NoNewLine "Generalizing TrendMicro Anti Virus..."
		
        # Workaround: Because TrendMicro is deleting the TCacheGenCli_x64.exe after sucessful execution we need to copy it into the TM Folder everytime before running
        # tested with Office Scan 10.6 SP3 - 11.02.2016
        Copy-Item -Path "$AddonFolder\TrendMicro\TCacheGen\TCacheGen*.exe" -Destination "$ProgramFiles\Trend Micro\OfficeScan Client\" -Force -ErrorAction SilentlyContinue
       
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
		
	## Flush DNS cache
	Write-Host -NoNewLine "Flushing DNS cache..."
	Start-Process -FilePath "ipconfig.exe" -ArgumentList "/flushdns" -Wait -WindowStyle Minimized
	Write-Host -ForegroundColor Green " done"
    
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

Stop-Transcript | Out-Null

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
# MIIVcgYJKoZIhvcNAQcCoIIVYzCCFV8CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUdXsAZdbVh4qqv1kve0QiaDnz
# WG+gghKxMIIFBDCCA+ygAwIBAgIQSr/0tccV/HqjR6KiPQUqZzANBgkqhkiG9w0B
# AQsFADB1MQswCQYDVQQGEwJJTDEWMBQGA1UEChMNU3RhcnRDb20gTHRkLjEpMCcG
# A1UECxMgU3RhcnRDb20gQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxIzAhBgNVBAMT
# GlN0YXJ0Q29tIENsYXNzIDIgT2JqZWN0IENBMB4XDTE2MDIxNjEwMDAxMloXDTE4
# MDIxNjEwMDAxMlowcTELMAkGA1UEBhMCREUxGzAZBgNVBAgMEkJhZGVuLVd1ZXJ0
# dGVtYmVyZzERMA8GA1UEBwwITWFubmhlaW0xGDAWBgNVBAoMD0NsYXVzIEphbiBI
# YXJtczEYMBYGA1UEAwwPQ2xhdXMgSmFuIEhhcm1zMIIBIjANBgkqhkiG9w0BAQEF
# AAOCAQ8AMIIBCgKCAQEAuU9b3ZVU3Ru3OG3yHqmQgMm07BFUrihFax0ype3RtaKv
# nkaHB3hgZxUyXGDjieJ+QLpjV6yzcJshOyvnw/up+ghdBWB52JJgN3eEJeM7UaT5
# UlhGb/ijc+7d6jrUSVdnvd2c59G04HWt+fbshvTLjjfzqcDJ7PVrKPlvNeY/+njC
# 2EVN5LA/uoF5qMe6AxpSfwNm5LuvpXG9skjzvs2W7Tgdy540zT4Bz2QPG2aIRSlU
# PQu6y5gUFJ6WZ4R6AEIpqP4SUeaG0ag1Grl89c6dI77ocnuahPJmdiJnfe03idsO
# PC9/ohDAjsVC7K+PbHA2g0vPERqXy3locmm+XRXjywIDAQABo4IBkjCCAY4wDgYD
# VR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMAkGA1UdEwQCMAAwHQYD
# VR0OBBYEFKDLv/q+UEUFC/nT3BqX/fv5OnLQMB8GA1UdIwQYMBaAFD5ik5rXxxnu
# Po9JEIVVFSDjlIQcMG0GCCsGAQUFBwEBBGEwXzAkBggrBgEFBQcwAYYYaHR0cDov
# L29jc3Auc3RhcnRzc2wuY29tMDcGCCsGAQUFBzAChitodHRwOi8vYWlhLnN0YXJ0
# c3NsLmNvbS9jZXJ0cy9zY2EuY29kZTIuY3J0MDYGA1UdHwQvMC0wK6ApoCeGJWh0
# dHA6Ly9jcmwuc3RhcnRzc2wuY29tL3NjYS1jb2RlMi5jcmwwIwYDVR0SBBwwGoYY
# aHR0cDovL3d3dy5zdGFydHNzbC5jb20vMFAGA1UdIARJMEcwCAYGZ4EMAQQBMDsG
# CysGAQQBgbU3AQIEMCwwKgYIKwYBBQUHAgEWHmh0dHA6Ly93d3cuc3RhcnRzc2wu
# Y29tL3BvbGljeTANBgkqhkiG9w0BAQsFAAOCAQEAd5MGTzLeSg8ZSvMifLliu1c0
# eVTHySAE53p5cviRrT2NOikZmqttN0qrpF17tktMhjD6zie8aYpVuakSd1hshJMD
# JCA9UwMCJ4dXv5pV+/c2salW5E3D0D/eiwSuN8e2ap+uX7uyWIpl0s45cDxl2xvk
# iLgCNEf6O4TZTLuMHhum+AzcGDjWvxjdSBZKk9lOJzWz8UOGi6EqSKDqW2aVxNFu
# dCyyKoPAR2fT+QQy22LyfsEfzvj7wFmcGdjqOyPKYRF8lngMeH8JlM7izLDY90ma
# Wfr3ZvflJhQ7NUxCmYtBwi4RlW7wUKgaOgqN1xAXdD0E5ogLye8eYyCvvVmpTTCC
# BdgwggPAoAMCAQICEGw70n7dPJSelY4oqbPHV6AwDQYJKoZIhvcNAQELBQAwfTEL
# MAkGA1UEBhMCSUwxFjAUBgNVBAoTDVN0YXJ0Q29tIEx0ZC4xKzApBgNVBAsTIlNl
# Y3VyZSBEaWdpdGFsIENlcnRpZmljYXRlIFNpZ25pbmcxKTAnBgNVBAMTIFN0YXJ0
# Q29tIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTE1MTIxNjAxMDAwNVoXDTMw
# MTIxNjAxMDAwNVowdTELMAkGA1UEBhMCSUwxFjAUBgNVBAoTDVN0YXJ0Q29tIEx0
# ZC4xKTAnBgNVBAsTIFN0YXJ0Q29tIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MSMw
# IQYDVQQDExpTdGFydENvbSBDbGFzcyAyIE9iamVjdCBDQTCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBALkUBFj3ssWGLAgyYK0IJsCBd7loGdkVKx0YaeTa
# GpYFly5keRqpPVEzWtB3avQCk0HDjrpwG6vYe3RvmOjXuak+aHakiaAirBfWKfi7
# uGGf0gfQZg4wRyArcAIe/nMJHHE0teJ+qayop/GOOkAGdpLK93hs71gFc31/g1Dp
# olUC4wCulqfGwmR74/hYQJUuTXu/3YIA3klVpzMj5tpP+WCjk1VxMSSWgJWJJsh9
# Togt7KE5JBm+miYxiTx4mojSeKY5Mkl+ZdqeA0Oytfyen7eVcPT7qsJmKxdFYhp5
# 9/JMwdnfVCPUPnRZh1G1fnJ6/haBpegolA3eWSBdRzK2/IcCAwEAAaOCAVowggFW
# MA4GA1UdDwEB/wQEAwIBBjATBgNVHSUEDDAKBggrBgEFBQcDAzASBgNVHRMBAf8E
# CDAGAQH/AgEAMDIGA1UdHwQrMCkwJ6AloCOGIWh0dHA6Ly9jcmwuc3RhcnRzc2wu
# Y29tL3Nmc2NhLmNybDBmBggrBgEFBQcBAQRaMFgwJAYIKwYBBQUHMAGGGGh0dHA6
# Ly9vY3NwLnN0YXJ0c3NsLmNvbTAwBggrBgEFBQcwAoYkaHR0cDovL2FpYS5zdGFy
# dHNzbC5jb20vY2VydHMvY2EuY3J0MB0GA1UdDgQWBBQ+YpOa18cZ7j6PSRCFVRUg
# 45SEHDAfBgNVHSMEGDAWgBROC+8apEBbpRdphzDKNGhD0EGu8jA/BgNVHSAEODA2
# MDQGBFUdIAAwLDAqBggrBgEFBQcCARYeaHR0cDovL3d3dy5zdGFydHNzbC5jb20v
# cG9saWN5MA0GCSqGSIb3DQEBCwUAA4ICAQBjpTzVs20nKNjrulOvMAvqSl0S1fma
# ynD6TGOM101UfkbqUueFoSQjGp2m9j9Z3D5R020TGz43x58o9LCHab8HFePZ9J4s
# zBdzAcWiiRJwQRHx7PSq4I3OKio0dpzssJc8SdDNu0bYUeV48o0NaHx5TorGIDM3
# MisjE+2GKccaAtME4AIdAzZhOUPxihTmg3d0uYE6q0fQEMxmgtyMQigRbXML5OdV
# vfJTUbTG5vqCc3uU/nS9sCIcliufLBCJdqWgFXwH1hh97pmC+OrHC5/AVwxXITdS
# YK4NOw6mOoMQqknbmz4VR2SJ7lWoJLVpq50ujfVf71S8/jml+DJGrPJ9SdUSEfhl
# fGUFZkzOPZei/n6b/4feTFi4UDnF2p2yGP9nHTRLs+QJIX7wzU0Jy8WBDCMjDrVt
# kCMMGXc/drzE1NexvYKMV2I0ptPcsPogZ4h/Rv8Rs9/QVd28GvGbSh8w6GeeB0+i
# U9gK2g4a1k8BV7/F6779nIq/pNIeWyFpQ7SJh+yZtednnW++3+SSPCaz3+o8XFK4
# TR+MR8XtpBrPBEQN/aGJU9HSkCG9KG0zehThet4QURRYRgezbl9hXhYybGRQpKCZ
# KbBGrjm2+0YfgtNvn5x36IuorysFAvQTrFpSOMZ+xjHtu54i+pO8KStC+jExuf+o
# McKLKmjANWrpMDCCB8kwggWxoAMCAQICAQEwDQYJKoZIhvcNAQEFBQAwfTELMAkG
# A1UEBhMCSUwxFjAUBgNVBAoTDVN0YXJ0Q29tIEx0ZC4xKzApBgNVBAsTIlNlY3Vy
# ZSBEaWdpdGFsIENlcnRpZmljYXRlIFNpZ25pbmcxKTAnBgNVBAMTIFN0YXJ0Q29t
# IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTA2MDkxNzE5NDYzNloXDTM2MDkx
# NzE5NDYzNlowfTELMAkGA1UEBhMCSUwxFjAUBgNVBAoTDVN0YXJ0Q29tIEx0ZC4x
# KzApBgNVBAsTIlNlY3VyZSBEaWdpdGFsIENlcnRpZmljYXRlIFNpZ25pbmcxKTAn
# BgNVBAMTIFN0YXJ0Q29tIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MIICIjANBgkq
# hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAwYjbCbxsRnx4n5V7tTOQ8nJi1sE2ICIk
# Xs7pd/JDCqIGZKTMjjb4OOYj8G5tsTzdcqOFHKHTPbQzK9Mvr/7qsEFZZ7bEBn0K
# nnSF1nlMgDd63zkFUln39BtGQ6TShYXSw3HzdWI0uiyKfx6P7u000BHHls1SPboz
# 1t1N3gs7SkufwiYv+rUWHHI1d8o8XebK4SaLGjZ2XAHbdBQl/u21oIgP3XjKLR8H
# lzABLXJ5+kbWEyqouaarg0kd5fLv3eQBjhgKj2NTFoViqQ4ZOsy1ZqbCa3QH5Cvh
# dj60bdj2ROFzYh87xL6gU1YlbFEJ96qryr92/W2b853bvz1mvAxWqq+YSJU6S9+n
# WFDZOHWpW+pDDAL/mevobE1wWyllnN2qXcyvATHsDOvSjejqnHvmbvcnZgwaSNdu
# QuM/3iE+e+ENcPtjqqhsGlS0XCV6yaLJixamuyx+F14FTVhuEh0B7hIQDcYyfxj/
# /PT6zW6R6DZJvhpIaYvClk0aErJpF8EKkNb6eSJIv7p7afhwx/p6N9jYDdJ2T1f/
# kLfjkdLd78Jgt2c63f6qnPDUi39yIs7Gn5e2+K+KoBCo2fsYxra1XFI8ibYZKnMB
# Cg8DsxJg8novgdujbv8mMJf1i92JV7atPbOvK8W3dgLwpdYrmoYUKnL24zOMXQlL
# E9+7jHQTUksCAwEAAaOCAlIwggJOMAwGA1UdEwQFMAMBAf8wCwYDVR0PBAQDAgGu
# MB0GA1UdDgQWBBROC+8apEBbpRdphzDKNGhD0EGu8jBkBgNVHR8EXTBbMCygKqAo
# hiZodHRwOi8vY2VydC5zdGFydGNvbS5vcmcvc2ZzY2EtY3JsLmNybDAroCmgJ4Yl
# aHR0cDovL2NybC5zdGFydGNvbS5vcmcvc2ZzY2EtY3JsLmNybDCCAV0GA1UdIASC
# AVQwggFQMIIBTAYLKwYBBAGBtTcBAQEwggE7MC8GCCsGAQUFBwIBFiNodHRwOi8v
# Y2VydC5zdGFydGNvbS5vcmcvcG9saWN5LnBkZjA1BggrBgEFBQcCARYpaHR0cDov
# L2NlcnQuc3RhcnRjb20ub3JnL2ludGVybWVkaWF0ZS5wZGYwgdAGCCsGAQUFBwIC
# MIHDMCcWIFN0YXJ0IENvbW1lcmNpYWwgKFN0YXJ0Q29tKSBMdGQuMAMCAQEagZdM
# aW1pdGVkIExpYWJpbGl0eSwgcmVhZCB0aGUgc2VjdGlvbiAqTGVnYWwgTGltaXRh
# dGlvbnMqIG9mIHRoZSBTdGFydENvbSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSBQ
# b2xpY3kgYXZhaWxhYmxlIGF0IGh0dHA6Ly9jZXJ0LnN0YXJ0Y29tLm9yZy9wb2xp
# Y3kucGRmMBEGCWCGSAGG+EIBAQQEAwIABzA4BglghkgBhvhCAQ0EKxYpU3RhcnRD
# b20gRnJlZSBTU0wgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwDQYJKoZIhvcNAQEF
# BQADggIBABZsmfRmDDT10IVefQrs2hBOOBxe36YlBUuRMsHoO/E93UQJWwdJiinL
# ZgK3sZr3JZgJPI4b4d02hytLu2jTOWY9oCbH8jmRHVGrgnt+1c5a5OIDV3Bplwj5
# XlimCt+MBppFFhY4Cl5X9mLHegIF5rwetfKe9Kkpg/iyFONuKIdEw5Aa3jipPKxD
# TWRFzt0oqVzyc3sE+Bfoq7HzLlxkbnMxOhK4vLMR5H2PgVGaO42J9E2TZns8A+3T
# mh2a82VQ9aDQdZ8vr/DqgkOY+GmciXnEQ45GcuNkNhKv9yUeOImQd37Da2q5w8tE
# S6x4kIvnxyweSxFEyDRSJ80KXZ+FwYnVGnjylRBTMt2AhGZ12bVoKPthLr6EqDjA
# mRKGpR5nZK0GLi+pcIXHlg98iWX1jkNUDqvdpYA5lGDANMmWcCyjEvUfSHu9HH5r
# t52Q9CI7rvj8Ksr6glKg769LVZPrwbXwIousNE4mIgShhyx1SrflfRPXuAxkwDbS
# yS+GEowjCcEbgjtzSaNqV4eU5dZ4xZlDY+NN4Hct4WWZcmkEGkcJ5g8BViT7H78O
# ealYLrnECQF+lbptAAY+supKEDnY0Cv1v+x1v5cCxQkbCNxVN+KB+zeEQ2IgyudW
# S2Xq/mzBJJMkoTTrBf+aIq6bfT/xZVEKpjBqs/SIHIAN/HKK6INeMYICKzCCAicC
# AQEwgYkwdTELMAkGA1UEBhMCSUwxFjAUBgNVBAoTDVN0YXJ0Q29tIEx0ZC4xKTAn
# BgNVBAsTIFN0YXJ0Q29tIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MSMwIQYDVQQD
# ExpTdGFydENvbSBDbGFzcyAyIE9iamVjdCBDQQIQSr/0tccV/HqjR6KiPQUqZzAJ
# BgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0B
# CQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAj
# BgkqhkiG9w0BCQQxFgQUfpTreVuoazHnezN9Pk2pKKeo748wDQYJKoZIhvcNAQEB
# BQAEggEAPhJ3jRIySJGbiHUWUiIvYg5KiXPQD6VbPfNreKLpO3HRUK2iWacpfY37
# fJNAx62tPBOyb4R1W0hpePztmR1ZiVrw8orGg3GhWYmNCLHNzxVVJYkakQTTDo9D
# dfrWoPj8nri4elfolOnFw46uAuOGEcy+HGxh7VjnXO/nsDPGYzLPcZz6n2gk/Pu8
# gEzk6Dbffx/HeTN0smA8nNaHLyYNrmFZJj1S6b98DRU4PPssoO9NWqSoVY82pxKx
# 2pMGvZczYHzSgqWd4WCVCsSiI/GHevOEaHxN6m3paZBrieyghWQDSX8Suf7kAbqA
# jz+qo+P5mAVSJuSe+Gt3vKLeORbtzA==
# SIG # End signature block
