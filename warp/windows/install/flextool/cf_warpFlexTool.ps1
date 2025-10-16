<#
#=============================================================================================
# Cloudflare WARP Deployment Script
#=============================================================================================
.SYNOPSIS
Installs the **Cloudflare WARP agent** silently, ensuring the **Microsoft WebView2 Runtime** is present and configured.

.DESCRIPTION
This script performs a multi-step, fully automated installation and configuration:

* **1. Admin Check:** Ensures the script runs with Administrator privileges.
* **2. Directory Prep:** Checks and creates the required **C:\ProgramData\Cloudflare** directory.
* **3. WebView2 Setup:** Checks for and installs the **Microsoft WebView2 Runtime** if missing.
* **4. Registry Configuration:** Adds the **UseWebView2** registry key for the WARP client.
* **5. Installer Source:** Determines the WARP installer file path (local file, specific download, or latest download).
* **6. Execution:** Executes the silent **msiexec.exe** installation, enabling autoconnect.
* **7. Configuration:** If installation succeeds (Exit Code 0 or 3010), it **waits 30 seconds**, writes the **mdm.xml** file, and then creates necessary Windows **firewall rules**.
* **8. Cleanup:** Removes the installer file if it was downloaded during this execution.

.PARAMETER teamName
The **mandatory** Cloudflare Team Name (Organization ID) used for the initial MSI installation
property and the key 'organization' in the mdm.xml file.

.PARAMETER displayName
The **mandatory** display name value to be written into the mdm.xml file.

.PARAMETER InstallerPath
[Optional] Full path to an already downloaded WARP installer file (e.g., C:\Installers\WARP.msi).
If provided, the download step is skipped.

.PARAMETER Version
[Optional] The specific WARP version to download (e.g., 2024.11.200.0). Defaults to "latest" (which uses 'ga' endpoint).
Note: If only three parts are provided (e.g., 2025.7.176), a **.0** will be appended automatically.

.EXAMPLE
# Case 1: Download and install the latest version
.\Install-CloudflareWarp.ps1 -teamName "YourTeamID123" -displayName "MyCompanyWAN"

.EXAMPLE
# Case 2: Download and install a specific version
.\Install-CloudflareWarp.ps1 -teamName "YourTeamID123" -displayName "MyCompanyWAN" -Version "2024.11.200.0"

.EXAMPLE
# Case 4: Use a pre-downloaded file
.\Install-CloudflareWarp.ps1 -teamName "YourTeamID123" -displayName "MyCompanyWAN" -InstallerPath "C:\Installers\WARP_Client.msi"

.NOTES
* Requires **PowerShell 3.0** or later.
* The **mdm.xml** file is written to **C:\ProgramData\Cloudflare\**.
* A **30-second delay** is enforced post-installation to allow services to start.
#=============================================================================================
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$teamName,
    [Parameter(Mandatory=$true)]
    [string]$displayName,
    [Parameter(Mandatory=$false)]
    [string]$InstallerPath,      # New optional parameter for existing file path
    [Parameter(Mandatory=$false)]
    [string]$Version = "latest"  # New optional parameter for version, defaults to "latest"
)

# --- Configuration Variables ---
$DownloadDirectory = "$env:TEMP" # Location where the MSI is stored temporarily (if downloaded)
$BaseDownloadUrl = "https://downloads.cloudflareclient.com/v1/download/windows"
$FileName = "Cloudflare_WARP_Installer.msi"
$FilePath = Join-Path -Path $DownloadDirectory -ChildPath $FileName
$LogPath = "$env:TEMP\WARP_Installation.log"
$InstallerDownloaded = $false # Flag to track if this script performed the download

# MDM Configuration Path
$MdmFileName = "mdm.xml"
$MdmDirectory = "C:\ProgramData\Cloudflare"
$MdmFilePath = Join-Path -Path $MdmDirectory -ChildPath $MdmFileName

# WebView2 Configuration
$WebView2DownloadUrl = "https://go.microsoft.com/fwlink/?linkid=2124701"
$WebView2FileName = "MicrosoftEdgeWebview2Setup.exe"
$WebView2FilePath = Join-Path -Path $DownloadDirectory -ChildPath $WebView2FileName
$CloudflareRegPath = "HKLM:\SOFTWARE\Cloudflare\CloudflareWARP"
$WebView2RegKey = 'HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BC9-5D88BF0201AA}'


# 1. Check for Administrative Rights
Write-Host "Checking for administrative rights..." -ForegroundColor Yellow
if (-not ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    Write-Error "Error: This script must be run with Administrator privileges."
    Write-Host "Please right-click the PowerShell window and select 'Run as administrator'." -ForegroundColor Red
    exit 1
}
Write-Host "Administrative rights confirmed. Continuing..." -ForegroundColor Green


# 2. Check and Prepare MDM Directory
Write-Host "Checking required directory access for MDM file: $MdmDirectory..." -ForegroundColor Yellow
if (-not (Test-Path -Path $MdmDirectory)) {
    try {
        Write-Host "Directory does not exist. Attempting to create: $MdmDirectory" -ForegroundColor Cyan
        New-Item -Path $MdmDirectory -ItemType Directory -Force | Out-Null
        Write-Host "Directory created successfully." -ForegroundColor Green
    }
    catch {
        Write-Error "Error: Failed to create or access the required MDM directory '$MdmDirectory'. The script cannot proceed without administrative write access to this location. Details: $($_.Exception.Message)"
        exit 1
    }
}
Write-Host "MDM directory access confirmed." -ForegroundColor Green


# 3. Check for and install Microsoft WebView2 Runtime
Write-Host "Checking for Microsoft WebView2 Runtime..." -ForegroundColor Yellow

$WebView2Check = Get-ItemProperty -Path $WebView2RegKey -ErrorAction SilentlyContinue

if (-not $WebView2Check) {
    Write-Host "WebView2 Runtime not found. Attempting download and installation..." -ForegroundColor Cyan
    
    # 3a. Download WebView2 Installer
    try {
        Write-Host "Downloading WebView2 installer from $WebView2DownloadUrl..." -ForegroundColor Cyan
        Invoke-WebRequest -Uri $WebView2DownloadUrl -OutFile $WebView2FilePath -MaximumRedirection 5
        Write-Host "WebView2 installer downloaded successfully." -ForegroundColor Green

        # 3b. Install WebView2 Silently
        Write-Host "Installing WebView2 Runtime silently..." -ForegroundColor Yellow
        # The /wait flag is important to ensure the script pauses until installation is complete
        Start-Process -FilePath $WebView2FilePath -ArgumentList "/install /silent /wait" -Wait -PassThru | Out-Null
        
        Write-Host "WebView2 Runtime installation finished." -ForegroundColor Green

    }
    catch {
        Write-Error "Error: Failed to download or install Microsoft WebView2 Runtime. Cloudflare WARP client may not function correctly. Details: $($_.Exception.Message)"
        Write-Warning "WebView2 installation failed. Continuing with WARP installation."
    }
}
else {
    Write-Host "WebView2 Runtime detected. Skipping installation." -ForegroundColor Green
}


# 4. Add WebView2 Registry Key
Write-Host "Adding UseWebView2 registry key..." -ForegroundColor Yellow
try {
    # Ensure the CloudflareWARP path exists
    if (-not (Test-Path -Path $CloudflareRegPath -ErrorAction SilentlyContinue)) {
        New-Item -Path $CloudflareRegPath -Force | Out-Null
    }
    # Add the UseWebView2 key (REG_SZ type, value 'y')
    Set-ItemProperty -Path $CloudflareRegPath -Name "UseWebView2" -Type String -Value "y" -Force | Out-Null
    Write-Host "Registry key $CloudflareRegPath\UseWebView2 set successfully." -ForegroundColor Green
}
catch {
    Write-Error "Failed to add UseWebView2 registry key: $($_.Exception.Message)"
}


# 5. Determine Installer Path and Handle Download
Write-Host "Starting installer validation and download step..." -ForegroundColor Yellow

# Case A: User provided a specific path to an existing installer file
if (-not [string]::IsNullOrWhiteSpace($InstallerPath)) {
    if (Test-Path -Path $InstallerPath -PathType Leaf) {
        $FilePath = $InstallerPath
        Write-Host "Using pre-existing installer file provided by user: '$FilePath'" -ForegroundColor Cyan
    }
    else {
        Write-Error "Error: The provided installer path '$InstallerPath' does not exist or is not a file. Exiting."
        exit 1
    }
}
# Case B: No path provided, handle download logic
else {
    # --- New Version Normalization and URL Construction ---
    $TargetVersion = $Version
    
    if ($Version -ne "latest") {
        $VersionParts = $Version.Split('.')
        # Check if version has 3 parts and correct it to 4 parts by appending .0
        if ($VersionParts.Count -eq 3) {
            $TargetVersion = "$Version.0"
            Write-Host "Version '$Version' normalized to '$TargetVersion' (four parts) for download." -ForegroundColor Cyan
        }
    }

    # Construct the final download URL
    if ($TargetVersion -eq "latest") {
        # Latest version uses the 'ga' endpoint
        $DownloadTarget = "ga"
        $FinalDownloadUrl = "$BaseDownloadUrl/$DownloadTarget"
    } else {
        # Specific version uses the new '/version/' endpoint and includes the filename
        # Format: https://downloads.cloudflareclient.com/v1/download/windows/version/[version]/Cloudflare_WARP_Installer.msi
        $DownloadTarget = "version/$TargetVersion/$FileName"
        $FinalDownloadUrl = "$BaseDownloadUrl/$DownloadTarget"
    }
    # --- End New Version Normalization and URL Construction ---
    
    Write-Host "Version specified: '$Version'. Target URL: $FinalDownloadUrl" -ForegroundColor Cyan

    if (Test-Path -Path $FilePath) {
        Write-Host "Installer already exists in temp directory: '$FilePath'. Skipping download." -ForegroundColor Cyan
    }
    else {
        # File does not exist, proceed with download
        Write-Host "Installer not found. Downloading Cloudflare WARP installer..." -ForegroundColor Yellow
        try {
            if (-not (Test-Path -Path $DownloadDirectory)) {
                New-Item -Path $DownloadDirectory -ItemType Directory | Out-Null
            }
            
            # Use Invoke-WebRequest to download the file, following redirects up to 5 times.
            Invoke-WebRequest -Uri $FinalDownloadUrl -OutFile $FilePath -MaximumRedirection 5
            Write-Host "Download successful. File saved to: '$FilePath'" -ForegroundColor Green
            $InstallerDownloaded = $true
        }
        catch {
            Write-Error "Error during file download from '$FinalDownloadUrl': $($_.Exception.Message)"
            exit 1
        }
    }
}


# 6. Execute the Silent Installation
$MsiArguments = @(
    "/i",
    "`"$FilePath`"",
    "/qn", # /qn for completely silent installation
    "/l*v", "`"$LogPath`"", # Logging for troubleshooting
    "ORGANIZATION=`"$teamName`"",
    "ONBOARDING=false",
    "AUTOCONNECT=true" # Enables autoconnect after installation
)

Write-Host "Starting silent installation for Team: '$teamName' (Autoconnect enabled)..." -ForegroundColor Yellow
try {
    # Use Start-Process to run msiexec.exe and wait for it to complete
    $Process = Start-Process -FilePath "msiexec.exe" -ArgumentList $MsiArguments -Wait -PassThru
    
    if ($Process.ExitCode -eq 0 -or $Process.ExitCode -eq 3010) {
        Write-Host "Installation completed successfully." -ForegroundColor Green
        
        # Add delay to allow WARP services to fully initialize before configuration
        Write-Host "Waiting 30 seconds to allow WARP services to initialize before applying MDM configuration..." -ForegroundColor Cyan
        Start-Sleep -Seconds 30
        
        # --- Write MDM Configuration XML (Step 7) ---
        Write-Host "Attempting to write MDM configuration to $MdmFilePath..." -ForegroundColor Yellow

        # Use $teamName and $displayName from command line for the MDM configuration
        $XmlContent = @"
<dict>
    <key>organization</key>
    <string>$teamName</string>
    <key>display_name</key>
    <string>$displayName</string>
    <key>onboarding</key>
    <false/>
</dict>
"@

        try {
            # Write the XML content using UTF8 encoding. Directory is already checked/created in Step 2.
            $XmlContent | Out-File -FilePath $MdmFilePath -Encoding UTF8 -Force
            Write-Host "MDM configuration (mdm.xml) written successfully." -ForegroundColor Green
            
            # --- Firewall Rule Creation (Part of Step 7) ---
            Write-Host "Starting creation of necessary firewall rules..." -ForegroundColor Yellow

            $WarpInstallDir = "C:\Program Files\Cloudflare\Cloudflare WARP"
            $WarpExecutables = @(
                @{Name="Warp-Diag"; File="warp-diag.exe"},
                @{Name="Warp-Svc"; File="warp-svc.exe"},
                @{Name="Warp-Dex"; File="warp-dex.exe"}
            )

            try {
                foreach ($Exec in $WarpExecutables) {
                    $ProgramPath = Join-Path -Path $WarpInstallDir -ChildPath $Exec.File
                    $BaseName = $Exec.Name
                    
                    # Create Inbound Rule
                    $DisplayNameIn = "Allow $($BaseName) Inbound"
                    # Using ErrorAction SilentlyContinue to avoid errors if the rule already exists (idempotency)
                    New-NetFirewallRule -DisplayName $DisplayNameIn -Direction Inbound -Program $ProgramPath -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
                    Write-Host "  -> Created/Ensured rule: '$DisplayNameIn'" -ForegroundColor Cyan

                    # Create Outbound Rule
                    $DisplayNameOut = "Allow $($BaseName) Outbound"
                    New-NetFirewallRule -DisplayName $DisplayNameOut -Direction Outbound -Program $ProgramPath -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
                    Write-Host "  -> Created/Ensured rule: '$DisplayNameOut'" -ForegroundColor Cyan
                }
                Write-Host "All required firewall rules created successfully." -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to create one or more firewall rules: $($_.Exception.Message)"
                Write-Warning "The WARP agent is installed and configured, but firewall rules may be missing."
            }
            # --- END Firewall Rule Creation ---
        }
        catch {
            Write-Error "Failed to write MDM configuration file. Please check permissions: $($_.Exception.Message)"
        }

        if ($Process.ExitCode -eq 3010) {
            Write-Host "A system reboot may be required to complete the installation." -ForegroundColor Cyan
        }
    }
    else {
        Write-Error "Installation failed with Exit Code: $($Process.ExitCode). Check log file: $LogPath"
        exit 1
    }
}
catch {
    Write-Error "An unexpected error occurred during installation: $($_.Exception.Message)"
    exit 1
}


# 8. Clean up the downloaded file (Only clean up if the script performed the download)
if ($InstallerDownloaded) {
    Write-Host "Cleaning up installer file: $FileName" -ForegroundColor Yellow
    try {
        Remove-Item -Path $FilePath -Force -ErrorAction Stop
        Write-Host "Cleanup complete." -ForegroundColor Green
    }
    catch {
        # Non-critical error, just log it.
        Write-Warning "Could not remove the installer file. Please delete it manually: $FilePath"
    }
} else {
    Write-Host "Installer was provided by user or already existed; skipping cleanup." -ForegroundColor Cyan
}
