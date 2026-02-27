$ErrorActionPreference = "SilentlyContinue"
$FinalReport = @()
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$Hostname = $env:COMPUTERNAME
$Username = $env:USERNAME
$Timestamp = Get-Date -Format "F"

# Header Information
Write-Host ""
Write-Host "--- Cloudflare WARP Silent Audit Report ---" -ForegroundColor Cyan
Write-Host ""
Write-Host "Hostname: $Hostname"
Write-Host "Timestamp: $Timestamp"
Write-Host "Report run by: $Username"
Write-Host "-------------------------------------------"

function Log-Audit($Comp, $PF, $Stat, $Det, $Imp, $ImpactDesc) {
    $obj = [PSCustomObject]@{
        Component  = $Comp
        'Pass/Fail'= $PF
        Status     = $Stat
        Details    = $Det
        Importance = $Imp
        Impact     = $ImpactDesc
    }
    $script:FinalReport += $obj
}

# 1. WINTUN DRIVER VERSION CHECK
Write-Host "`nChecking Wintun Driver Versions..." -ForegroundColor Yellow
try {
    $WintunDrivers = Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.DeviceName -like "*Wintun*" }
    if ($WintunDrivers) {
        foreach ($drv in $WintunDrivers) {
            Log-Audit "Driver: Wintun" "WARN" "Exists" "Version: $($drv.DriverVersion)" "High" "Existing drivers can conflict with WARP adapter."
            Write-Host "  [!!] Found: $($drv.DeviceName) v$($drv.DriverVersion)" -ForegroundColor Yellow
        }
    } else {
        Log-Audit "Driver: Wintun" "PASS" "Not Found" "Clean state" "Info" "No existing driver conflicts."
        Write-Host "  [OK] No existing Wintun drivers detected." -ForegroundColor Green
    }
} catch {
    Log-Audit "Driver Check" "FAIL" "Error" "Access Denied" "High" "Could not query drivers."
}

# 2. CORE SYSTEM SERVICES (msiserver logic: Manual/Running = PASS)
$Services = @(
    @{N="msiserver"; I="Critical"; E="Handles MSI database/rollback."; F="Disabled state prevents installation."}
    @{N="BFE"; I="High"; E="Manages firewall rules."; F="Installer cannot inject firewall exceptions."}
    @{N="Dnscache"; I="High"; E="Handles name resolution."; F="Handoff to encrypted DNS will fail."}
    @{N="WlanSvc"; I="Dependency"; E="WARP depends on this."; F="The background daemon will fail to start."}
)

Write-Host "`nChecking System Services..." -ForegroundColor Yellow
foreach ($S in $Services) {
    $svcObj = Get-Service -Name $S.N
    if ($svcObj) {
        $PF = "FAIL"
        $Color = "Red"
        if ($S.N -eq "msiserver" -and ($svcObj.StartType -eq 'Manual' -or $svcObj.Status -eq 'Running')) {
            $PF = "PASS"; $Color = "Green"
        } elseif ($S.N -ne "msiserver" -and $svcObj.Status -eq 'Running') {
            $PF = "PASS"; $Color = "Green"
        }
        Log-Audit $S.N $PF $svcObj.Status "StartType: $($svcObj.StartType)" $S.I $S.E
        Write-Host "  [$PF] $($S.N) is $($svcObj.Status)" -ForegroundColor $Color
    } else {
        Log-Audit $S.N "FAIL" "Missing" "Not found" $S.I $S.F
    }
}

# 3. FILESYSTEM & REGISTRY PERMISSIONS
$Targets = @("C:\Program Files\Cloudflare", "C:\ProgramData\Cloudflare", "C:\Windows\Installer")
Write-Host "`nChecking Filesystem Access..." -ForegroundColor Yellow
foreach ($Path in $Targets) {
    try {
        $testFile = Join-Path $Path "warp_audit.tmp"
        if (Test-Path (Split-Path $Path)) {
            $null = New-Item -Path $testFile -ItemType File -Force -ErrorAction Stop
            Remove-Item $testFile -Force
            Log-Audit "Write: $Path" "PASS" "Granted" "Success" "Critical" "Binary/Log placement."
            Write-Host "  [OK] Access: $Path" -ForegroundColor Green
        }
    } catch {
        Log-Audit "Write: $Path" "FAIL" "DENIED" "Access Denied" "Critical" "File placement will fail."
        Write-Host "  [Captured] Denied: $Path" -ForegroundColor Red
    }
}

# 4. CERTIFICATE STORE & DNS API (Based on Installation Log Analysis)
Write-Host "`nChecking Certificate Store & DNS Dependencies..." -ForegroundColor Yellow
$CertStore = "HKLM:\SOFTWARE\Microsoft\SystemCertificates"
try {
    $testKey = Join-Path $CertStore "WARP_Audit"
    $null = New-Item -Path $testKey -Force -ErrorAction Stop
    Remove-Item $testKey -Force
    Log-Audit "Registry: CertStore" "PASS" "Granted" "Write Success" "High" "Required for Root CA installation."
    Write-Host "  [OK] Access: $CertStore" -ForegroundColor Green
} catch {
    Log-Audit "Registry: CertStore" "FAIL" "DENIED" "Access Denied" "High" "SSL inspection and Zero Trust will fail."
    Write-Host "  [Captured] Denied: $CertStore" -ForegroundColor Red
}

$DNSDll = "C:\Windows\System32\dnsapi.dll"
if (Test-Path $DNSDll) {
    Log-Audit "File: dnsapi.dll" "PASS" "Found" "System DLL present" "Critical" "Required for name resolution."
    Write-Host "  [OK] Found: $DNSDll" -ForegroundColor Green
} else {
    Log-Audit "File: dnsapi.dll" "FAIL" "Missing" "DLL Not Found" "Critical" "Resolution will break."
    Write-Host "  [FAIL] Missing: $DNSDll" -ForegroundColor Red
}

# 5. ARM64 TRANSLATION CACHE (Based on Installation Log Analysis)
if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") {
    Write-Host "`nChecking ARM64 xtacache..." -ForegroundColor Yellow
    $XtaPath = "C:\Windows\xtacache"
    try {
        $testFile = Join-Path $XtaPath "warp_arm.tmp"
        $null = New-Item -Path $testFile -ItemType File -Force -ErrorAction Stop
        Remove-Item $testFile -Force
        Log-Audit "Path: xtacache" "PASS" "Granted" "ARM64 Cache OK" "High" "Required for binary translation."
        Write-Host "  [OK] Access: $XtaPath" -ForegroundColor Green
    } catch {
        Log-Audit "Path: xtacache" "FAIL" "DENIED" "Access Denied" "High" "Performance failure on ARM64."
        Write-Host "  [Captured] Denied: $XtaPath" -ForegroundColor Red
    }
}

# 6. NETWORK PORT AUDIT
$Ports = @(53, 500, 4500, 2408)
Write-Host "`nChecking Network Port Conflicts..." -ForegroundColor Yellow
foreach ($P in $Ports) {
    try {
        $conn = Get-NetUDPEndPoint -LocalPort $P -ErrorAction Stop
        $proc = Get-Process -Id $conn.OwningProcess
        Log-Audit "Port:$P" "FAIL" "CONFLICT" "Used by $($proc.Name)" "High" "Critical for DNS/Tunneling."
        Write-Host "  [CONFLICT] Port $P used by $($proc.Name)" -ForegroundColor Red
    } catch {
        Log-Audit "Port:$P" "PASS" "Clear" "Port is free" "Info" "Available for WARP."
        Write-Host "  [OK] Port $P is free." -ForegroundColor Green
    }
}

Write-Host "`n--- FINAL AUDIT REPORT ---" -ForegroundColor Cyan
$FinalReport | Format-Table -AutoSize
