**cf_warpInstallLatest.ps1**

SYNOPSIS  
Installs the Cloudflare WARP agent silently using a specified Team Name and Display Name
and configures the Zero Trust MDM settings via mdm.xml upon successful installation.

DESCRIPTION  
This script performs five main functions:
1. Checks if it is running with Administrator privileges and terminates if not.
2. Checks and creates the required MDM configuration directory.
3. Defines local paths and configuration variables.
4. Checks if the installer file exists and downloads it if it doesn't, following any redirects.
5. Executes the silent installation (msiexec.exe) using the teamName parameter, enabling autoconnect.
6. If installation is successful (Exit Code 0 or 3010), it writes the mdm.xml
   configuration file to C:\ProgramData\Cloudflare\ and then creates necessary
   Windows firewall rules for WARP executables.

PARAMETER: teamName  
The mandatory Cloudflare Team Name (Organization ID) used for the initial MSI installation
property and the key 'organization' in the mdm.xml file.

PARAMETER: displayName  
The mandatory display name value to be written into the mdm.xml file.

EXAMPLE:  
You must now provide both the teamName and the displayName.  
```.\Install-CloudflareWarp.ps1 -teamName "YourTeamID123" -displayName "MyCompanyWAN"```

NOTES  
- Requires PowerShell 3.0 or later.
- Must be run from a powwershell shell that has been run as Administrator
- The installer file is downloaded to the directory specified by $DownloadDirectory.
- The mdm.xml file is written to C:\ProgramData\Cloudflare\.
