<#
.SYNOPSIS
Installs the Cloudflare WARP agent silently using a specified Team Name (Organization ID),
and configures the Zero Trust MDM settings via mdm.xml upon successful installation.

.DESCRIPTION
This script performs five main functions:
1. Checks if it is running with Administrator privileges and terminates if not.
2. Checks and creates the required MDM configuration directory.
3. Defines local paths and configuration variables.
4. Checks if the installer file exists and downloads it if it doesn't, following any redirects.
5. Executes the silent installation (msiexec.exe) using the teamName parameter, enabling autoconnect.
6. If installation is successful (Exit Code 0 or 3010), it writes the mdm.xml
   configuration file to C:\ProgramData\Cloudflare\ and then creates necessary
   Windows firewall rules for WARP executables.

.PARAMETER teamName
The mandatory Cloudflare Team Name (Organization ID) used for the initial MSI installation
property and the key 'organization' in the mdm.xml file.

.PARAMETER displayName
The mandatory display name value to be written into the mdm.xml file.

.EXAMPLE
# You must now provide both the teamName and the displayName.
.\Install-CloudflareWarp.ps1 -teamName "YourTeamID123" -displayName "MyCompanyWAN"

.NOTES
Requires PowerShell 3.0 or later.
The installer file is downloaded to the directory specified by $DownloadDirectory.
The mdm.xml file is written to C:\ProgramData\Cloudflare\.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$teamName,
    [Parameter(Mandatory=$true)]
    [string]$displayName
)

# --- Configuration Variables ---
$DownloadDirectory = "$env:TEMP" # Location where the MSI is stored temporarily
$DownloadUrl = "https://downloads.cloudflareclient.com/v1/download/windows/ga"
$FileName = "Cloudflare_WARP_Installer.msi"
$FilePath = Join-Path -Path $DownloadDirectory -ChildPath $FileName
$LogPath = "$env:TEMP\WARP_Installation.log"

# MDM Configuration Path
$MdmFileName = "mdm.xml"
$MdmDirectory = "C:\ProgramData\Cloudflare"
$MdmFilePath = Join-Path -Path $MdmDirectory -ChildPath $MdmFileName


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
        # Attempt to create the directory; will fail if permissions are insufficient despite Admin check.
        New-Item -Path $MdmDirectory -ItemType Directory -Force | Out-Null
        Write-Host "Directory created successfully." -ForegroundColor Green
    }
    catch {
        Write-Error "Error: Failed to create or access the required MDM directory '$MdmDirectory'. The script cannot proceed without administrative write access to this location. Details: $($_.Exception.Message)"
        exit 1
    }
}
Write-Host "MDM directory access confirmed." -ForegroundColor Green


# 3. Check and Download the Cloudflare WARP Installer
Write-Host "Checking for existing installer at $FilePath..." -ForegroundColor Yellow

if (Test-Path -Path $FilePath) {
    # File exists, skip download
    Write-Host "Installer already exists at $FilePath. Skipping download." -ForegroundColor Cyan
}
else {
    # File does not exist, proceed with download
    Write-Host "Installer not found. Downloading Cloudflare WARP installer from '$DownloadUrl'..." -ForegroundColor Yellow
    try {
        # Ensure the download directory exists before attempting to write the file
        if (-not (Test-Path -Path $DownloadDirectory)) {
            New-Item -Path $DownloadDirectory -ItemType Directory | Out-Null
        }
        
        # Use Invoke-WebRequest to download the file. The -MaximumRedirection parameter
        # ensures the script follows the link to the final MSI file destination.
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $FilePath -MaximumRedirection 5
        Write-Host "Download successful. File saved to: $FilePath" -ForegroundColor Green
    }
    catch {
        Write-Error "Error during file download: $($_.Exception.Message)"
        exit 1
    }
}


# 4. Execute the Silent Installation
$MsiArguments = @(
    "/i",
    "`"$FilePath`"",
    "/qn", # /qn for completely silent installation
    "/l*v", "`"$LogPath`"", # Logging for troubleshooting
    "ORGANIZATION=`"$teamName`"",
    "ONBOARDING=false",
    "AUTOCONNECT=true" # NEW: Enables autoconnect after installation
)

Write-Host "Starting silent installation for Team: '$teamName' (Autoconnect enabled)..." -ForegroundColor Yellow
try {
    # Use Start-Process to run msiexec.exe and wait for it to complete
    $Process = Start-Process -FilePath "msiexec.exe" -ArgumentList $MsiArguments -Wait -PassThru
    
    if ($Process.ExitCode -eq 0 -or $Process.ExitCode -eq 3010) {
        Write-Host "Installation completed successfully." -ForegroundColor Green
        
        # --- Write MDM Configuration XML (Step 5) ---
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
            
            # --- Firewall Rule Creation (Step 6) ---
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


# 7. Clean up the downloaded file
Write-Host "Cleaning up installer file: $FileName" -ForegroundColor Yellow
try {
    Remove-Item -Path $FilePath -Force -ErrorAction Stop
    Write-Host "Cleanup complete." -ForegroundColor Green
}
catch {
    # Non-critical error, just log it.
    Write-Warning "Could not remove the installer file. Please delete it manually: $FilePath"
}
