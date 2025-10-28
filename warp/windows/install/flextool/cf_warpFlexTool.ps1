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
    [string]$TeamName,
    [Parameter(Mandatory=$true)]
    [string]$DisplayName,
    [Parameter(Mandatory=$false)]
    [string]$InstallerPath,
    [Parameter(Mandatory=$false)]
    [string]$Version = 'latest'
)

# Configuration Variables
$DownloadDirectory = "$env:TEMP"
$BaseDownloadUrl = 'https://downloads.cloudflareclient.com/v1/download/windows'
$InstallerFileName = 'Cloudflare_WARP_Installer.msi'
$FilePath = Join-Path -Path $DownloadDirectory -ChildPath $InstallerFileName
$LogPath = "$env:TEMP\WARP_Installation.log"
$InstallerDownloaded = $false
$ServiceInitDelaySeconds = 30
$MaxRedirections = 5

# MDM Configuration
$MdmDirectory = 'C:\ProgramData\Cloudflare'
$MdmFilePath = Join-Path -Path $MdmDirectory -ChildPath 'mdm.xml'

# WebView2 Configuration
$WebView2DownloadUrl = 'https://go.microsoft.com/fwlink/?linkid=2124701'
$WebView2FilePath = Join-Path -Path $DownloadDirectory -ChildPath 'MicrosoftEdgeWebview2Setup.exe'
$CloudflareRegPath = 'HKLM:\SOFTWARE\Cloudflare\CloudflareWARP'
$WebView2RegKey = 'HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BC9-5D88BF0201AA}'
$WebView2Downloaded = $false


Write-Host 'Checking for administrative rights...' -ForegroundColor Yellow
if (-not ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    Write-Error 'Error: This script must be run with Administrator privileges.'
    Write-Host 'Please right-click the PowerShell window and select ''Run as administrator''.' -ForegroundColor Red
    exit 1
}
Write-Host 'Administrative rights confirmed. Continuing...' -ForegroundColor Green


Write-Host "Checking required directory access for MDM file: $MdmDirectory..." -ForegroundColor Yellow
if (-not (Test-Path -Path $MdmDirectory -PathType Container)) {
    try {
        Write-Host "Directory does not exist. Attempting to create: $MdmDirectory" -ForegroundColor Cyan
        New-Item -Path $MdmDirectory -ItemType Directory -Force | Out-Null
        Write-Host 'Directory created successfully.' -ForegroundColor Green
    }
    catch {
        Write-Error "Error: Failed to create or access the required MDM directory '$MdmDirectory'. The script cannot proceed without administrative write access to this location. Details: $($_.Exception.Message)"
        exit 1
    }
}
Write-Host 'MDM directory access confirmed.' -ForegroundColor Green


Write-Host 'Checking for Microsoft WebView2 Runtime...' -ForegroundColor Yellow

if (-not (Test-Path -Path $WebView2RegKey)) {
    Write-Host 'WebView2 Runtime not found. Attempting download and installation...' -ForegroundColor Cyan
    
    try {
        Write-Host "Downloading WebView2 installer from $WebView2DownloadUrl..." -ForegroundColor Cyan
        Invoke-WebRequest -Uri $WebView2DownloadUrl -OutFile $WebView2FilePath -MaximumRedirection $MaxRedirections
        Write-Host 'WebView2 installer downloaded successfully.' -ForegroundColor Green
        $WebView2Downloaded = $true

        Write-Host 'Installing WebView2 Runtime silently...' -ForegroundColor Yellow
        $WebView2Process = Start-Process -FilePath $WebView2FilePath -ArgumentList '/install /silent /wait' -Wait -PassThru
        
        if ($WebView2Process.ExitCode -eq 0) {
            Write-Host 'WebView2 Runtime installation completed successfully.' -ForegroundColor Green
        } else {
            Write-Warning "WebView2 installation finished with exit code: $($WebView2Process.ExitCode). Continuing with WARP installation."
        }
    }
    catch {
        Write-Error "Error: Failed to download or install Microsoft WebView2 Runtime. Cloudflare WARP client may not function correctly. Details: $($_.Exception.Message)"
        Write-Warning 'WebView2 installation failed. Continuing with WARP installation.'
    }
}
else {
    Write-Host 'WebView2 Runtime detected. Skipping installation.' -ForegroundColor Green
}


Write-Host 'Adding UseWebView2 registry key...' -ForegroundColor Yellow
try {
    if (-not (Test-Path -Path $CloudflareRegPath)) {
        New-Item -Path $CloudflareRegPath -Force | Out-Null
    }
    Set-ItemProperty -Path $CloudflareRegPath -Name 'UseWebView2' -Type String -Value 'y' -Force
    Write-Host "Registry key $CloudflareRegPath\UseWebView2 set successfully." -ForegroundColor Green
}
catch {
    Write-Error "Failed to add UseWebView2 registry key: $($_.Exception.Message)"
}


Write-Host 'Starting installer validation and download step...' -ForegroundColor Yellow

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
else {
    if ($Version -ne 'latest') {
        $VersionParts = $Version.Split('.')
        if ($VersionParts.Count -eq 3) {
            $Version = "$Version.0"
            Write-Host "Version normalized to '$Version' (four parts) for download." -ForegroundColor Cyan
        }
    }

    if ($Version -eq 'latest') {
        $FinalDownloadUrl = "$BaseDownloadUrl/ga"
    } else {
        $FinalDownloadUrl = "$BaseDownloadUrl/version/$Version/$InstallerFileName"
    }
    
    Write-Host "Version specified: '$Version'. Target URL: $FinalDownloadUrl" -ForegroundColor Cyan

    if (Test-Path -Path $FilePath -PathType Leaf) {
        Write-Host "Installer already exists in temp directory: '$FilePath'. Skipping download." -ForegroundColor Cyan
    }
    else {
        Write-Host 'Installer not found. Downloading Cloudflare WARP installer...' -ForegroundColor Yellow
        try {
            if (-not (Test-Path -Path $DownloadDirectory -PathType Container)) {
                New-Item -Path $DownloadDirectory -ItemType Directory | Out-Null
            }
            
            Invoke-WebRequest -Uri $FinalDownloadUrl -OutFile $FilePath -MaximumRedirection $MaxRedirections
            Write-Host "Download successful. File saved to: '$FilePath'" -ForegroundColor Green
            $InstallerDownloaded = $true
        }
        catch {
            Write-Error "Error during file download from '$FinalDownloadUrl': $($_.Exception.Message)"
            exit 1
        }
    }
}


$MsiArguments = @(
    '/i',
    "`"$FilePath`"",
    '/qn',
    '/l*v', "`"$LogPath`"",
    "ORGANIZATION=`"$TeamName`"",
    'ONBOARDING=false',
    'AUTOCONNECT=true'
)

Write-Host "Starting silent installation for Team: '$TeamName' (Autoconnect enabled)..." -ForegroundColor Yellow
try {
    $Process = Start-Process -FilePath 'msiexec.exe' -ArgumentList $MsiArguments -Wait -PassThru
    
    if ($Process.ExitCode -eq 0 -or $Process.ExitCode -eq 3010) {
        Write-Host 'Installation completed successfully.' -ForegroundColor Green
        
        Write-Host "Waiting $ServiceInitDelaySeconds seconds to allow WARP services to initialize before applying MDM configuration..." -ForegroundColor Cyan
        Start-Sleep -Seconds $ServiceInitDelaySeconds
        
        Write-Host "Attempting to write MDM configuration to $MdmFilePath..." -ForegroundColor Yellow

        $XmlContent = @"
<dict>
    <key>organization</key>
    <string>$TeamName</string>
    <key>display_name</key>
    <string>$DisplayName</string>
    <key>onboarding</key>
    <false/>
</dict>
"@

        try {
            $XmlContent | Out-File -FilePath $MdmFilePath -Encoding UTF8 -Force
            Write-Host 'MDM configuration (mdm.xml) written successfully.' -ForegroundColor Green
            
            Write-Host 'Starting creation of necessary firewall rules...' -ForegroundColor Yellow

            $WarpInstallDir = 'C:\Program Files\Cloudflare\Cloudflare WARP'
            $WarpExecutables = @(
                @{Name='Warp-Diag'; File='warp-diag.exe'},
                @{Name='Warp-Svc'; File='warp-svc.exe'},
                @{Name='Warp-Dex'; File='warp-dex.exe'}
            )

            try {
                foreach ($Exec in $WarpExecutables) {
                    $ProgramPath = Join-Path -Path $WarpInstallDir -ChildPath $Exec.File
                    $BaseName = $Exec.Name
                    
                    foreach ($Direction in @('Inbound', 'Outbound')) {
                        $DisplayName = "Allow $BaseName $Direction"
                        
                        # Check if rule already exists to ensure idempotency
                        $ExistingRule = Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue
                        if (-not $ExistingRule) {
                            New-NetFirewallRule -DisplayName $DisplayName -Direction $Direction -Program $ProgramPath -Action Allow -Profile Any | Out-Null
                            Write-Host "  -> Created rule: '$DisplayName'" -ForegroundColor Cyan
                        } else {
                            Write-Host "  -> Rule already exists: '$DisplayName'" -ForegroundColor Cyan
                        }
                    }
                }
                Write-Host 'All required firewall rules created successfully.' -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to create one or more firewall rules: $($_.Exception.Message)"
                Write-Warning 'The WARP agent is installed and configured, but firewall rules may be missing.'
            }
        }
        catch {
            Write-Error "Failed to write MDM configuration file. Please check permissions: $($_.Exception.Message)"
        }

        if ($Process.ExitCode -eq 3010) {
            Write-Host 'A system reboot may be required to complete the installation.' -ForegroundColor Cyan
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
finally {
    # Clean up WebView2 installer if downloaded
    if ($WebView2Downloaded -and (Test-Path -Path $WebView2FilePath -PathType Leaf)) {
        try {
            Remove-Item -Path $WebView2FilePath -Force -ErrorAction Stop
            Write-Host 'WebView2 installer cleaned up.' -ForegroundColor Green
        }
        catch {
            Write-Warning "Could not remove WebView2 installer. Please delete it manually: $WebView2FilePath"
        }
    }
}


if ($InstallerDownloaded) {
    Write-Host "Cleaning up installer file: $InstallerFileName" -ForegroundColor Yellow
    try {
        Remove-Item -Path $FilePath -Force -ErrorAction Stop
        Write-Host 'Cleanup complete.' -ForegroundColor Green
    }
    catch {
        Write-Warning "Could not remove the installer file. Please delete it manually: $FilePath"
    }
} else {
    Write-Host 'Installer was provided by user or already existed; skipping cleanup.' -ForegroundColor Cyan
}
