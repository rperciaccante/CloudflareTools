
# Cloudflare WARP Deployment Flextool

## SYNOPSIS  
Installs the **Cloudflare WARP agent** silently, ensuring the **Microsoft WebView2 Runtime** is present and configured.

## DESCRIPTION  
This script performs a multi-step, fully automated installation and configuration:

* **1. Admin Check:** Ensures the script runs with Administrator privileges.
* **2. Directory Prep:** Checks and creates the required **C:\ProgramData\Cloudflare** directory.
* **3. WebView2 Setup:** Checks for and installs the **Microsoft WebView2 Runtime** if missing.
* **4. Registry Configuration:** Adds the **UseWebView2** registry key for the WARP client.
* **5. Installer Source:** Determines the WARP installer file path (local file, specific download, or latest download).
* **6. Execution:** Executes the silent **msiexec.exe** installation, enabling autoconnect.
* **7. Configuration:** If installation succeeds (Exit Code 0 or 3010), it **waits 30 seconds**, writes the **mdm.xml** file, and then creates necessary Windows **firewall rules**.
* **8. Cleanup:** Removes the installer file if it was downloaded during this execution.

### PARAMETER: teamName  
The **mandatory** Cloudflare Team Name (Organization ID) used for the initial MSI installation
property and the key 'organization' in the mdm.xml file.

### PARAMETER displayName  
The **mandatory** display name value to be written into the mdm.xml file.

### PARAMETER InstallerPath  
[Optional] Full path to an already downloaded WARP installer file (e.g., C:\Installers\WARP.msi).
If provided, the download step is skipped.

### PARAMETER Version  
[Optional] The specific WARP version to download (e.g., 2024.11.200.0). Defaults to "latest" (which uses 'ga' endpoint).
Note: If only three parts are provided (e.g., 2025.7.176), a **.0** will be appended automatically.

# EXAMPLES  
## Case 1: Download and install the latest version  
.\Install-CloudflareWarp.ps1 -teamName "YourTeamID123" -displayName "MyCompanyWAN"

## Case 2: Download and install a specific version  
.\Install-CloudflareWarp.ps1 -teamName "YourTeamID123" -displayName "MyCompanyWAN" -Version "2024.11.200.0"

## Case 3: Use a pre-downloaded file  
.\Install-CloudflareWarp.ps1 -teamName "YourTeamID123" -displayName "MyCompanyWAN" -InstallerPath "C:\Installers\WARP_Client.msi"

# NOTES  
* Requires **PowerShell 3.0** or later.
* The **mdm.xml** file is written to **C:\ProgramData\Cloudflare\**.
* A **30-second delay** is enforced post-installation to allow services to start.
#=============================================================================================
