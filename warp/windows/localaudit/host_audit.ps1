$ErrorActionPreference = "SilentlyContinue"
$FinalReport = @()
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$Hostname = $env:COMPUTERNAME
$Username = $env:USERNAME
$Timestamp = Get-Date -Format "F"

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
            Log-Audit "Driver: Wintun" "WARN" "Exists" "Version: $($drv.DriverVersion)" "High" "Existing Wintun drivers can conflict with the WARP adapter."
            Write-Host "  [!!] Found: $($drv.DeviceName) v$($drv.DriverVersion)" -ForegroundColor Yellow
        }
    } else {
        Log-Audit "Driver: Wintun" "PASS" "Not Found" "Clean state" "Informational" "No existing Wintun driver to conflict with."
        Write-Host "  [OK] No existing Wintun drivers detected." -ForegroundColor Green
    }
} catch {
    Log-Audit "Driver Check" "FAIL" "Error" "Access Denied or WMI Failure" "High" "Could not query drivers."
}

# 2. CORE SYSTEM SERVICES
$Services = @(
    @{N="msiserver"; I="Critical"; E="Handles MSI database and rollback."; F="Installation cannot manage cached MSI files."}
    @{N="BFE"; I="High"; E="Manages firewall rules."; F="Installer cannot inject mandatory firewall rules."}
    @{N="Dnscache"; I="High"; E="Handles system name resolution."; F="WARP DNS proxy will fail, leading to no internet."}
    @{N="WlanSvc"; I="Dependency"; E="WARP service depends on this."; F="The CloudflareWARP service will fail to start."}
)

Write-Host "`nChecking System Services..." -ForegroundColor Yellow
foreach ($S in $Services) {
    $svcObj = Get-Service -Name $S.N
    if ($svcObj) {
        $PF = "FAIL"
        $Color = "Red"
        
        if ($S.N -eq "msiserver" -and ($svcObj.StartType -eq 'Manual' -or $svcObj.Status -eq 'Running')) {
            $PF = "PASS"
            $Color = "Green"
        } elseif ($S.N -ne "msiserver" -and $svcObj.Status -eq 'Running') {
            $PF = "PASS"
            $Color = "Green"
        }
        
        Log-Audit $S.N $PF $svcObj.Status "StartType: $($svcObj.StartType)" $S.I $S.E
        Write-Host "  [$PF] $($S.N) is $($svcObj.Status) (StartType: $($svcObj.StartType))" -ForegroundColor $Color
    } else {
        Log-Audit $S.N "FAIL" "Missing" "Not found" $S.I $S.F
    }
}

# 3. FILESYSTEM & REGISTRY TARGETS
$Folders = @("C:\Program Files\Cloudflare", "C:\ProgramData\Cloudflare", "C:\Windows\Installer")
Write-Host "`nChecking Filesystem/Registry Access..." -ForegroundColor Yellow
foreach ($Path in $Folders) {
    try {
        $testFile = Join-Path $Path "warp_audit.tmp"
        if (Test-Path (Split-Path $Path)) {
            $null = New-Item -Path $testFile -ItemType File -Force -ErrorAction Stop
            Remove-Item $testFile -Force
            Log-Audit "Write: $Path" "PASS" "Granted" "Success" "Critical" "Binary and Log placement."
            Write-Host "  [OK] Access: $Path" -ForegroundColor Green
        } else {
            Log-Audit "Write: $Path" "FAIL" "Target Missing" "Parent exists" "High" "Installer will create."
        }
    } catch {
        Log-Audit "Write: $Path" "FAIL" "DENIED" "Access Denied" "Critical" "File placement will fail."
        Write-Host "  [Captured] Denied: $Path" -ForegroundColor Red
    }
}

# 4. NETWORK PORT AUDIT
$Ports = @(53, 500, 4500, 2408)
Write-Host "`nChecking Network Port Conflicts..." -ForegroundColor Yellow
foreach ($P in $Ports) {
    try {
        $conn = Get-NetUDPEndPoint -LocalPort $P -ErrorAction Stop
        $proc = Get-Process -Id $conn.OwningProcess
        Log-Audit "Port:$P" "FAIL" "CONFLICT" "Used by $($proc.Name)" "High" "Port $P is critical for DNS/Tunneling."
        Write-Host "  [CONFLICT] Port $P used by $($proc.Name)" -ForegroundColor Red
    } catch {
        Log-Audit "Port:$P" "PASS" "Clear" "Port is free" "Informational" "Available for WARP."
        Write-Host "  [OK] Port $P is free." -ForegroundColor Green
    }
}

Write-Host "`n--- FINAL AUDIT REPORT ---" -ForegroundColor Cyan
$FinalReport | Format-Table -AutoSize
