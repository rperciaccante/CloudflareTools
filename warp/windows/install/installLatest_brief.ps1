# 1. Define Variables
$teamName = "your-team-name" # <--- REPLACE THIS
$url = "https://aka.ms/CloudflareWARP" # Persistent redirect to latest stable MSI
$msiPath = "$env:TEMP\Cloudflare_WARP.msi"

# 2. Download the latest MSI
Write-Host "Downloading latest Cloudflare WARP MSI..." -ForegroundColor Cyan
try {
    Invoke-WebRequest -Uri $url -OutFile $msiPath -ErrorAction Stop
    Write-Host "Download complete: $msiPath" -ForegroundColor Green
} catch {
    Write-Error "Failed to download the installer. Error: $_"
    exit 1
}

# 3. Run the MSI Installer
# /qn = Quiet, no UI
# /norestart = Prevents sudden reboots
# ORGANIZATION = Your Zero Trust team name
# ONBOARDING = false (skips the "Welcome" screens)
Write-Host "Installing Cloudflare WARP for organization: $teamName..." -ForegroundColor Cyan

$installArgs = @(
    "/i", "`"$msiPath`"",
    "/qn",
    "/norestart",
    "ORGANIZATION=`"$teamName`"",
    "ONBOARDING=false"
)

$process = Start-Process -FilePath "msiexec.exe" -ArgumentList $installArgs -Wait -PassThru

# 4. Verification
if ($process.ExitCode -eq 0) {
    Write-Host "Cloudflare WARP installed successfully." -ForegroundColor Green
} elseif ($process.ExitCode -eq 3010) {
    Write-Host "Installation successful, but a reboot is required." -ForegroundColor Yellow
} else {
    Write-Error "Installation failed with Exit Code: $($process.ExitCode)"
}

# Cleanup
Remove-Item -Path $msiPath -Force
