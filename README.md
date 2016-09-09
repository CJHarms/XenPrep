[![Build Status](https://ci.appveyor.com/api/projects/status/m364htcsmp8xrmkp/branch/master?svg=true)](https://ci.appveyor.com/project/CJHarms/xenprep/branch/master)

# XenPrep
Generalize a Citrix XenApp/XenDesktop 7.x Master Image / Golden Image / vDisk before Rollout.

## Tested Enviroments

Citrix
- [x] XenApp 7.x Server OS Virtual Desktop Agent (VDA)
- [ ] XenDesktop 7.x Client OS Virtual Desktop Agent (VDA)

Microsoft
- [x] Windows Server 2012 R2
- [x] Windows Server 2012
- [x] Windows Server 2008 R2
- [ ] Windows 7

## Installation
Copy the XenPrep Folder (including Subfolders) into the Program Files Folder on the Master Image (Golden Image).

If you want to use the Profile Cleanup Function make sure to download DelProf2 from Helge Klein (https://helgeklein.com) and drop it into the Addons Subfolder.

## Configuration
Edit the XenPrep-Seal.bat with your needed Switches or run the Start-XenPrep.ps1 Script directly with the needed Switches.

A detailed Description of the Parameters / Switches will follow.

## ToDo
- [x] MCS Support 
- [x] PVS Support
- [ ] Implement further Optimizations (Open for Suggestions)

## Misc
Feel free to suggest missing Optimizations or Bugs via Pull Request or Bugtracker here on GitHub
