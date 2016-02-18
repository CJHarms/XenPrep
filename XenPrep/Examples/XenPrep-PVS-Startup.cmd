@echo off
powershell.exe -ExecutionPolicy Bypass -File "Start-XenPrep.ps1" -Mode Startup -ProvisioningMethod PVS -PersistentDisk D
pause