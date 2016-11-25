@echo off
powershell.exe -ExecutionPolicy Bypass -File "Start-XenPrep.ps1" -Mode Seal -ProvisioningMethod PVS -PersistentDisk D -CleanupProfiles -CleanupWindows -CleanupEventlog -Optimize -SDelete -Shutdown
pause