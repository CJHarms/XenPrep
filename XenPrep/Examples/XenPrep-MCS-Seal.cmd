@echo off
powershell.exe -ExecutionPolicy Bypass -File "Start-XenPrep.ps1" -Mode Seal -ProvisioningMethod MCS -CleanupProfiles -CleanupWindows -CleanupEventlog -Optimize -Shutdown
pause