$ErrorActionPreference = "SilentlyContinue"
$FinalReport = @()
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$Hostname = $env:COMPUTERNAME
$Username = $env:USERNAME
$DateStamp = Get-Date -Format "yyyyMMdd_HHmm"
$DisplayDate = Get-Date -Format "F"

# Set Folder and ZIP names
$FolderName = "warp_preinstall_audit_$($Hostname)_$($DateStamp)"
$DiagFolder = Join-Path $PSScriptRoot $FolderName
$ZipFile = "$DiagFolder.zip"

if (!(Test-Path $DiagFolder)) { 
    New-Item -Path $DiagFolder -ItemType Directory -Force | Out-Null 
}

# Header Information
Write-Host ""
Write-Host "--- Cloudflare WARP Unified Audit & Diagnostic Report ---" -ForegroundColor Cyan
Write-Host ""
Write-Host "Hostname: $Hostname"
Write-Host "Timestamp: $DisplayDate"
Write-Host "Report run by: $Username"
Write-Host "Run as Admin: $isAdmin"
Write-Host "Output Folder: $DiagFolder"
Write-Host "---------------------------------------------------------"

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

# 2. CORE SYSTEM SERVICES
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

# 3. RUNTIME LOGGING & SNAPSHOTS (From run_Logfile Analysis)
$RuntimePaths = @(
    "C:\ProgramData\Cloudflare\snapshots",
    "C:\ProgramData\Cloudflare\warp-diag-partials"
)

Write-Host "`nChecking Runtime Log & Snapshot Permissions..." -ForegroundColor Yellow
foreach ($RPath in $RuntimePaths) {
    if (!(Test-Path $RPath)) { New-Item -Path $RPath -ItemType Directory -Force | Out-Null }
    try {
        $testFile = Join-Path $RPath "runtime_check.tmp"
        $null = New-Item -Path $testFile -ItemType File -Force -ErrorAction Stop
        Remove-Item $testFile -Force
        Log-Audit "Runtime: $RPath" "PASS" "Full Access" "Modify Success" "High" "Critical for telemetry and logs."
        Write-Host "  [OK] Access: $RPath" -ForegroundColor Green
    } catch {
        Log-Audit "Runtime: $RPath" "FAIL" "DENIED" "Access Denied" "High" "Service logs will fail."
        Write-Host "  [Captured] Denied: $RPath" -ForegroundColor Red
    }
}

# 4. NETWORK TUNING REGISTRY (From run_Logfile Analysis)
$NetRegPaths = @(
    "HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9",
    "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
)

Write-Host "`nChecking Network Tuning Registry Access..." -ForegroundColor Yellow
foreach ($RegPath in $NetRegPaths) {
    try {
        $null = Get-Item -Path $RegPath -ErrorAction Stop
        Log-Audit "Registry: $RegPath" "PASS" "Readable" "Success" "High" "Required for tunnel management."
        Write-Host "  [OK] Readable: $RegPath" -ForegroundColor Green
    } catch {
        Log-Audit "Registry: $RegPath" "FAIL" "RESTRICTED" "Access Denied" "High" "Tunnel negotiation will fail."
        Write-Host "  [Captured] Denied: $RegPath" -ForegroundColor Red
    }
}

# 5. CERTIFICATE STORE & DNS API (From install_Logfile Analysis)
Write-Host "`nChecking Certificate Store & DNS Dependencies..." -ForegroundColor Yellow
$CertStore = "HKLM:\SOFTWARE\Microsoft\SystemCertificates"
try {
    $testKey = Join-Path $CertStore "WARP_Audit"
    $null = New-Item -Path $testKey -Force -ErrorAction Stop
    Remove-Item $testKey -Force
    Log-Audit "Registry: CertStore" "PASS" "Granted" "Write Success" "High" "Required for Root CA installation."
    Write-Host "  [OK] Access: $CertStore" -ForegroundColor Green
} catch {
    Log-Audit "Registry: CertStore" "FAIL" "DENIED" "Access Denied" "High" "SSL inspection will fail."
}

$DNSDll = "C:\Windows\System32\dnsapi.dll"
if (Test-Path $DNSDll) {
    Log-Audit "File: dnsapi.dll" "PASS" "Found" "System DLL present" "Critical" "Required for name resolution."
} else {
    Log-Audit "File: dnsapi.dll" "FAIL" "Missing" "DLL Not Found" "Critical" "Resolution will break."
}

# 6. ARM64 TRANSLATION CACHE
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
        Log-Audit "Path: xtacache" "FAIL" "DENIED" "Access Denied" "High" "Performance failure."
    }
}

# 7. NETWORK PORT AUDIT
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

# 8. SECONDARY DIAGNOSTICS
Write-Host "`nRunning Secondary Diagnostics..." -ForegroundColor Yellow

$SecondaryCommands = @(
    @{Label="Antivirus-check.txt"; Cmd='Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntivirusProduct'}
    @{Label="Com-avi-adapters.txt"; Cmd='Get-WmiObject -class Win32_NetworkAdapterConfiguration | fl *'}
    @{Label="Drivers.txt"; Cmd='Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Sort-Object DeviceName | Format-Table -AutoSize | Out-String -width 9999'}
    @{Label="Registry-interfaces.txt"; Cmd='Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"'}
    @{Label="route.txt"; Cmd='Find-NetRoute -RemoteIPAddress 1.1.1.1'}
    @{Label="routetable.txt"; Cmd='Format-Table -Property ifIndex, DestinationPrefix, NextHop, RouteMetric, ifMetric, InterfaceAlias, State -InputObject (Get-NetRoute | Sort-Object)'}
    @{Label="Services.txt"; Cmd='Get-WmiObject Win32_Service | Select-Object Name, DisplayName, ProcessId, State | Format-Table -AutoSize | Out-String -width 9999'}
    @{Label="bound-dns-ports.txt"; Cmd='netstat -a -n -b'}
    @{Label="Cmdkey.txt"; Cmd='cmdkey.exe /list'}
    @{Label="Dns-client.txt"; Cmd='Get-DnsClient'}
    @{Label="Firewall-rules.txt"; Cmd='netsh.exe wfp show filters file=-'}
    @{Label="Interfaces-config.txt"; Cmd='netsh interface ip show config'}
    @{Label="ipconfig.txt"; Cmd='ipconfig -all'}
    @{Label="pktmon.txt"; Cmd='pktmon.exe status'}
    @{Label="processes.txt"; Cmd='get-process'}
    @{Label="Sleep.txt"; Cmd='powercfg.exe /query SCHEME_CURRENT SUB_SLEEP'}
    @{Label="systeminfo.txt"; Cmd='systeminfo /FO LIST'}
    @{Label="Tracert.txt"; Cmd='tracert.exe -w 1000 -h 20 -d 162.159.197.2'}
    @{Label="user-session.txt"; Cmd='qwinsta.exe'}
    @{Label="v4interfaces.txt"; Cmd='netsh interface ipv4 show interfaces'}
    @{Label="v4subinterfaces.txt"; Cmd='netsh interface ipv4 show subinterfaces'}
    @{Label="V6interfaces.txt"; Cmd='netsh interface ipv6 show interfaces'}
    @{Label="v6subinterfaces.txt"; Cmd='netsh interface ipv6 show subinterfaces'}
)

foreach ($Diag in $SecondaryCommands) {
    $OutPath = Join-Path $DiagFolder $Diag.Label
    Write-Host "  Processing: $($Diag.Label)..." -NoNewline
    try {
        $Error.Clear()
        Invoke-Expression $Diag.Cmd | Out-File -FilePath $OutPath -ErrorAction Stop
        if ($Error.Count -eq 0) {
            Write-Host " [PASS]" -ForegroundColor Green
            Log-Audit "Diag: $($Diag.Label)" "PASS" "Ran Successfully" "Captured" "Info" "Diagnostic successful."
        } else {
            Write-Host " [FAIL]" -ForegroundColor Red
            Log-Audit "Diag: $($Diag.Label)" "FAIL" "Execution Error" "Check File" "Info" "Check output file."
        }
    } catch {
        Write-Host " [ERROR]" -ForegroundColor Red
        Log-Audit "Diag: $($Diag.Label)" "FAIL" "Exception" $_.Exception.Message "Info" "Command failed."
    }
}

# Output Final Summary to Console
Write-Host "`n--- FINAL AUDIT REPORT ---" -ForegroundColor Cyan
$FinalReport | Format-Table -AutoSize

# SAVE REPORT & COMPRESS
$ReportPath = Join-Path $DiagFolder "00_Final_Audit_Report.txt"
$FileHeader = "--- Cloudflare WARP Unified Report ---`nHost: $Hostname`nAdmin: $isAdmin`n"
$FileHeader | Out-File -FilePath $ReportPath
$FinalReport | Format-Table -AutoSize | Out-File -FilePath $ReportPath -Append

Write-Host "`nCompressing diagnostic data..." -ForegroundColor Yellow
if (Test-Path $ZipFile) { Remove-Item $ZipFile -Force }
Compress-Archive -Path $DiagFolder -DestinationPath $ZipFile -Force
Write-Host "Success! ZIP created: $ZipFile" -ForegroundColor Green
