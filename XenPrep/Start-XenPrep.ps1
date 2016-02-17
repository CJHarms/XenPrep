<#
        .SYNOPSIS 
        Prepares the vDisk to be deployed via MCS/PVS.

        .DESCRIPTION
        Prepares the current vDisk to be deployed via MCS/PVS.

        .INPUTS
        None. You cannot pipe objects to this script.

        .EXAMPLE
		C:\PS> Start-XenPrep.ps1 -Mode Seal -CleanupProfiles -CleanupEventlogs -Optimize -Shutdown
		This examples show how Start-XenPrep can be used to generalize and seal a vDisk when using MCS.
		
        C:\PS> Start-XenPrep.ps1 -Mode Seal -CleanupProfiles -CleanupEventlogs -Optimize -VMware -Appsense -Shutdown
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
	[string][ValidateSet("MCS","PVS")]$ProvisioningMode = "MCS",
	
	[parameter(Mandatory = $false, HelpMessage = "Specifiy the Persitent Disk (PVS only) in the following Format n without the :")]
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
$ErrorActionPreference = "Stop"

Clear-Host
Write-Host "------------------------------------------------------------------------------"
Write-Host "-- XenPrep Script"
Write-Host "-- Original Development by Tim Arenz, tarenz@cema.de, cema.de, blog.cema.de"
Write-Host "-- Changes by Claus Jan Harms, mail@cjharms.info, cjharms.info"
Write-Host "------------------------------------------------------------------------------"

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
	Write-Host "Syncing time..."
	Start-Process "w32tm.exe" -ArgumentList "/config /update" -Wait -WindowStyle Minimized
	Start-Process "w32tm.exe" -ArgumentList "/resync" -Wait -WindowStyle Minimized
	
	#Group Policy Update
	Write-Host "Updating group policy..."
	Start-Process "cmd.exe" -ArgumentList "/C echo n | gpupdate.exe /target:computer" -Wait -WindowStyle Minimized
	
}

###
### Custom shut down actions, proccessed only in Seal/Rearm mode
###
 
If ($Mode -eq "Seal") {

    #Put Actions here!

}

###
### Shut down actions, proccessed only in Seal/Rearm mode
### 
If ($Mode -eq "Seal") {
	
	## Delete cached profiles
	If ($CleanupProfiles -eq $true) {
		Write-Host "Cleaning up cached profiles..."
		If ((Test-Path "$AddonFolder\DelProf2\delprof2.exe") -eq $false ) {
			Write-Host ""
			Write-Warning "Profile clean up failed!"
			Write-Warning "delprof2.exe couldn't be found."
			Write-Host ""
		} Else {
			Start-Process -FilePath "$AddonFolder\DelProf2\delprof2.exe" -ArgumentList "/u /i" -Wait -WindowStyle Minimized
		}
	}

    ## Delete Temp Files, Windows installers, Memory Dumps and much more via Cleanup Manager (cleanmgr.exe)
	If ($CleanupWindows -eq $true) {
		Write-Host "Cleaning up Temp Files..."
		# Check if cleanmgr.exe is installed/present on the System
		If ((Get-Command "cleanmgr.exe" -ErrorAction SilentlyContinue) -eq $null ) {
			Write-Host ""
			Write-Warning "Windows Cleanup failed!"
			Write-Warning "cleanmgr.exe couldn't be found."
			Write-Host ""
		} Else {
			# Run Sageset 11, which we created in the First Run Action Part
			Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/sagerun:11" -Wait -WindowStyle Minimized
		}
	}
	
	## Generalize AppSense CCA and EM
	If ($AppSense -eq $true) {
		Write-Host "Generalizing AppSense components..."
		# Here we check if the specific Appsense Service is installed
		Get-Service -Name "AppSense Client Communications Agent" -ErrorAction SilentlyContinue | Out-Null
		If($?) {
			Set-ItemProperty -Path "HKLM:\Software\AppSense Technologies\Communications Agent" -Name "Machine ID" -Value ""
			Set-ItemProperty -Path "HKLM:\Software\AppSense Technologies\Communications Agent" -Name "Group ID" -Value ""
			Get-ChildItem -Path "C:\appsensevirtual" -Recurse | Remove-Item -Force
		} Else {
			Write-Host ""
			Write-Warning "AppSense generalization failed!"
			Write-Warning "AppSense components couldn't be found."
			Write-Host ""
		}
	}
	
    ## Generalize TrendMicro OfficeScan
	If ($TrendMicro -eq $true) {
		Write-Host "Generalizing TrendMicro Anti Virus..."
		
        # Workaround: Because TrendMicro is deleting the TCacheGenCli_x64.exe after sucessful execution we need to copy it into the TM Folder everytime before running
        # tested with Office Scan 10.6 SP3 - 11.02.2016
        Copy-Item -Path "$AddonFolder\TrendMicro\TCacheGen\TCacheGen*.exe" -Destination "$ProgramFiles\Trend Micro\OfficeScan Client\" -Force -ErrorAction SilentlyContinue
       
        If ((Test-Path "$ProgramFiles\Trend Micro\OfficeScan Client\TCacheGenCli_x64.exe") -eq $false) {
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
	    }
    }
	
	## Delete VMware Tools Status Tray Icons
	If ($Optimize -eq $true -and $VMware -eq $true) {
		Write-Host "Disabling VMware Tools Status Tray..."
		# Deleting VMware Tools Status Tray Icons
		Remove-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name "VMware Tools" -Force -ErrorAction SilentlyContinue
		Remove-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name "VMware User Process" -Force -ErrorAction SilentlyContinue		
	}
	
	## Clear event logs
	If ($CleanupEventlog -eq $true) {
		Write-Host "Clearing event logs..."
		Clear-EventLog -LogName Application
		Clear-EventLog -LogName Security
		Clear-EventLog -LogName System
	}

	## Optimize target device
	If ($Optimize -eq $true) {
		Write-Host "Optimizing target device..."
		If ((Test-Path "$ProgramFiles64\Citrix\PvsVm\TargetOSOptimizer\TargetOSOptimizer.exe") -eq $false) {
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
			}
	}
		
	## Flush DNS cache
	Write-Host "Flushing DNS cache..."
	Start-Process -FilePath "ipconfig.exe" -ArgumentList "/flushdns" -Wait -WindowStyle Minimized
	
	## Reclaim Space on vDisk/Harddisk
	If ($Optimize -eq $true) {
		Write-Host "Reclaiming Disk Space..."
		If ((Test-Path "$AddonFolder\sdelete\sdelete.exe") -eq $false ) {
			Write-Host ""
			Write-Warning "Space Reclamation failed!"
			Write-Warning "sdelete.exe couldn't be found."
			Write-Host ""
		} Else {
			Start-Process -FilePath "$AddonFolder\sdelete\sdelete.exe" -ArgumentList "/accepteula -q -z `"$env:SystemDrive`"" -Wait -WindowStyle Minimized
		}
	}
}

###
### Custom start up actions, proccessed only in startup mode
###

#If ($Mode -eq "Startup") {
#
#}

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