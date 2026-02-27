$ErrorActionPreference = "SilentlyContinue"
$MainReport = @()
$DiagSpecificReport = @()
$DexSpecificReport = @()
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$Hostname = $env:COMPUTERNAME
$Username = $env:USERNAME
$DateStamp = Get-Date -Format "yyyyMMdd_HHmm"
$DisplayDate = Get-Date -Format "F"

# Set Folder and ZIP names (Forced Lowercase)
$FolderName = "warp_preinstall_audit_$($Hostname)_$($DateStamp)".ToLower()
$DiagFolder = Join-Path $PSScriptRoot $FolderName
$ZipFile = "$DiagFolder.zip".ToLower()

if (!(Test-Path $DiagFolder)) { 
    New-Item -Path $DiagFolder -ItemType Directory -Force | Out-Null 
}

# Header Information
Write-Host ""
Write-Host "--- Cloudflare WARP Unified Audit & Investigative Report ---" -ForegroundColor Cyan
Write-Host ""
Write-Host "Hostname: $Hostname"
Write-Host "Timestamp: $DisplayDate"
Write-Host "Report run by: $Username"
Write-Host "Run as Admin: $isAdmin"
Write-Host "Output Folder: $DiagFolder"
Write-Host "---------------------------------------------------------"

function Log-Main($Comp, $PF, $Stat, $Det, $Imp, $ImpactDesc) {
    $obj = [PSCustomObject]@{ Component = $Comp; 'Pass/Fail' = $PF; Status = $Stat; Details = $Det; Importance = $Imp; Impact = $ImpactDesc }
    $script:MainReport += $obj
}

function Log-Diag($Comp, $PF, $Stat, $Det, $Imp, $ImpactDesc) {
    $obj = [PSCustomObject]@{ Component = $Comp; 'Pass/Fail' = $PF; Status = $Stat; Details = $Det; Importance = $Imp; Impact = $ImpactDesc }
    $script:DiagSpecificReport += $obj
}

function Log-Dex($Comp, $PF, $Stat, $Det, $Imp, $ImpactDesc) {
    $obj = [PSCustomObject]@{ Component = $Comp; 'Pass/Fail' = $PF; Status = $Stat; Details = $Det; Importance = $Imp; Impact = $ImpactDesc }
    $script:DexSpecificReport += $obj
}

# PILLAR 1: WINTUN DRIVER VERSION CHECK
Write-Host "`nChecking Wintun Driver Versions..." -ForegroundColor Yellow
try {
    $WintunDrivers = Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.DeviceName -like "*Wintun*" }
    if ($WintunDrivers) {
        foreach ($drv in $WintunDrivers) {
            Log-Main "Driver: Wintun" "WARN" "Exists" "Ver: $($drv.DriverVersion)" "High" "Conflicts with WARP adapter."
            Write-Host "  [!!] Found: $($drv.DeviceName) v$($drv.DriverVersion)" -ForegroundColor Yellow
        }
    } else {
        Log-Main "Driver: Wintun" "PASS" "Not Found" "Clean state" "Info" "No driver conflicts."
        Write-Host "  [OK] No existing Wintun drivers detected." -ForegroundColor Green
    }
} catch { Log-Main "Driver Check" "FAIL" "EXECUTION ERROR" "$($_.Exception.Message)" "High" "Query failed." }

# PILLAR 2: CORE SYSTEM SERVICES
$Services = @(
    @{N="msiserver"; I="Critical"; E="MSI Database Access."}
    @{N="BFE"; I="High"; E="Firewall rules."}
    @{N="Dnscache"; I="High"; E="DNS Proxy support."}
    @{N="WlanSvc"; I="Dependency"; E="Daemon startup."}
)
Write-Host "`nChecking System Services..." -ForegroundColor Yellow
foreach ($S in $Services) {
    try {
        $svcObj = Get-Service -Name $S.N -ErrorAction Stop
        $cimSvc = Get-CimInstance Win32_Service -Filter "Name = '$($S.N)'"
        $PF = if ($S.N -eq "msiserver" -and ($svcObj.StartType -eq 'Manual' -or $svcObj.Status -eq 'Running')) { "PASS" } elseif ($svcObj.Status -eq 'Running') { "PASS" } else { "FAIL" }
        Log-Main $S.N $PF "$($svcObj.Status) ($($svcObj.StartType))" "Path: $($cimSvc.PathName)" $S.I $S.E
        Write-Host "  [$PF] $($S.N) is $($svcObj.Status)" -ForegroundColor (if ($PF -eq "PASS") {"Green"} else {"Red"})
    } catch { Log-Main $S.N "FAIL" "EXECUTION ERROR" "$($_.Exception.Message)" $S.I "Service query failed." }
}

# PILLAR 3: ENVIRONMENT PATH VARIABLES
Write-Host "`nCapturing Environment PATH Variables..." -ForegroundColor Yellow
try {
    $SysPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $UsrPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $PathReport = @("--- SYSTEM PATH ---", ($SysPath -split ";"), "", "--- USER PATH ---", ($UsrPath -split ";"))
    $PathReport | Out-File (Join-Path $DiagFolder "path_variables.txt")
    Log-Main "Env: Path" "PASS" "Captured" "Split-log generated" "Medium" "Required for CLI resolution."
    Write-Host "  [OK] Captured Path Variables." -ForegroundColor Green
} catch { Log-Main "Env: Path" "FAIL" "ERROR" "$($_.Exception.Message)" "Medium" "Path capture failed." }

# PILLAR 4: FILESYSTEM & SPECIALIZED PERMISSIONS
Write-Host "`nChecking Filesystem Access..." -ForegroundColor Yellow
$FSTargets = @("C:\Program Files\Cloudflare", "C:\ProgramData\Cloudflare", "C:\Windows\Installer", "C:\ProgramData\Cloudflare\snapshots", "C:\ProgramData\Cloudflare\warp-diag-partials")
foreach ($Path in $FSTargets) {
    try {
        if (!(Test-Path $Path)) { New-Item -Path $Path -ItemType Directory -Force | Out-Null }
        $testFile = Join-Path $Path "warp_audit.tmp"
        New-Item -Path $testFile -ItemType File -Force | Out-Null; Remove-Item $testFile -Force
        Log-Main "Write: $Path" "PASS" "Granted" "Modify Success" "Critical" "Binary/Data persistence."
        Write-Host "  [OK] Access: $Path" -ForegroundColor Green
    } catch { Log-Main "Write: $Path" "FAIL" "DENIED" "$($_.Exception.Message)" "Critical" "I/O Failure." }
}

# PILLAR 5: NETWORK STACK & SOCKET GOVERNANCE
Write-Host "`nAuditing Network Stack & Socket Governance..." -ForegroundColor Yellow
Get-NetIPInterface | Select-Object InterfaceAlias, AddressFamily, NlMtu | Out-File (Join-Path $DiagFolder "mtu_audit.txt")
& netsh int ipv4 show dynamicport tcp | Out-File (Join-Path $DiagFolder "ephemeral_ports.txt")
Get-DnsClientNrptPolicy -ErrorAction SilentlyContinue | Out-File (Join-Path $DiagFolder "dns_nrpt_policy.txt")
& netsh winhttp show proxy | Out-File (Join-Path $DiagFolder "proxy_settings.txt")
foreach ($NP in (Get-NetConnectionProfile)) {
    $PF = if ($NP.NetworkCategory -eq 'Public') { "WARN" } else { "PASS" }
    Log-Main "Net: Profile" $PF $NP.NetworkCategory "Alias: $($NP.InterfaceAlias)" "High" "Firewall behavior."
}
$HostsContent = Get-Content "C:\Windows\System32\drivers\etc\hosts"
if ($HostsContent -match "^\s*[^#]") { Log-Main "File: Hosts" "WARN" "Modified" "Redirects found" "Medium" "DNS hijacking risk." }
$HostsContent | Out-File (Join-Path $DiagFolder "hosts_file_audit.txt")

# PILLAR 6: DEEP-DIVE FORENSICS
Write-Host "`nRunning Deep-Dive Diagnostics (System & User Scope)..." -ForegroundColor Yellow
$UninstallKeys = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*","HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*")
Get-ItemProperty $UninstallKeys | Where-Object { $_.DisplayName -ne $null } | Select-Object DisplayName, Publisher | Sort-Object DisplayName | Out-File (Join-Path $DiagFolder "installed_applications.txt")
Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, User | Format-List | Out-File (Join-Path $DiagFolder "startup_apps.txt")
Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | Select-Object TaskName, @{N="Triggers";E={$_.Triggers.ToString()}}, @{N="Actions";E={$_.Actions.Execute}} | Format-List | Out-File (Join-Path $DiagFolder "scheduled_tasks.txt")

# --- BLOCK: WARP-DIAG SPECIFIC COMPONENT AUDIT ---
Write-Host "`n--- Performing WARP-DIAG Platform Audit ---" -ForegroundColor Cyan
$DiagStaging = @("C:\ProgramData\Cloudflare\packet_captures", "C:\ProgramData\Cloudflare\qlogs")
foreach ($P in $DiagStaging) {
    try {
        if (!(Test-Path $P)) { New-Item -Path $P -ItemType Directory -Force | Out-Null }
        $test = Join-Path $P "diag_test.tmp"
        New-Item $test -ItemType File -Force | Out-Null; Remove-Item $test -Force
        Log-Diag "Diag Path: $(Split-Path $P -Leaf)" "PASS" "Granted" "Write Success" "Medium" "Diagnostic log staging."
        Write-Host "  [OK] Access: $P" -ForegroundColor Green
    } catch { Log-Diag "Diag Path: $(Split-Path $P -Leaf)" "FAIL" "DENIED" "$($_.Exception.Message)" "Medium" "Capture will fail." }
}
$DiagReg = @{ "NameSpaceCatalog" = "HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5"; "Tcpip6Interfaces" = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces" }
foreach ($K in $DiagReg.Keys) {
    try { $null = Get-Item -Path $DiagReg[$K] -ErrorAction Stop; Log-Diag "Registry: $K" "PASS" "Readable" "Success" "High" "Diag telemetry." }
    catch { Log-Diag "Registry: $K" "FAIL" "DENIED" "$($_.Exception.Message)" "High" "Query failed." }
}

# --- NEW BLOCK: WARP-DEX SPECIFIC COMPONENT AUDIT ---
Write-Host "`n--- Performing WARP-DEX Platform Audit ---" -ForegroundColor Cyan

# 1. Cryptnet URL Cache (Used by DEX for cert validation/telemetry)
$CryptCache = "C:\Windows\System32\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache"
try {
    if (Test-Path $CryptCache) {
        $null = Get-ChildItem -Path $CryptCache -ErrorAction Stop
        Log-Dex "Path: CryptnetUrlCache" "PASS" "Found" "Readable" "Medium" "Required for certificate/experience telemetry."
        Write-Host "  [OK] Readable: $CryptCache" -ForegroundColor Green
    } else {
        Log-Dex "Path: CryptnetUrlCache" "FAIL" "Missing" "Not Found" "Medium" "Profile path missing."
        Write-Host "  [FAIL] Missing: $CryptCache" -ForegroundColor Red
    }
} catch { Log-Dex "Path: CryptnetUrlCache" "FAIL" "DENIED" "$($_.Exception.Message)" "Medium" "Hardened profile restriction." }

# 2. DNS Client Experience Parameters
$DnsParams = "HKLM:\System\CurrentControlSet\Services\Dnscache\Parameters"
try {
    $null = Get-Item -Path $DnsParams -ErrorAction Stop
    Log-Dex "Registry: DnsParameters" "PASS" "Readable" "Success" "High" "Auditing DNS monitoring metadata."
    Write-Host "  [OK] Readable: $DnsParams" -ForegroundColor Green
} catch { Log-Dex "Registry: DnsParameters" "FAIL" "DENIED" "$($_.Exception.Message)" "High" "DNS monitoring disabled." }

# 3. Cryptography Telemetry Config
$CryptoOID = "HKLM:\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CertDllCreateCertificateChainEngine\Config"
try {
    $null = Get-Item -Path $CryptoOID -ErrorAction Stop
    Log-Dex "Registry: CryptoOIDConfig" "PASS" "Readable" "Success" "Medium" "Chain engine monitoring."
    Write-Host "  [OK] Readable: Crypto OID Config" -ForegroundColor Green
} catch { Log-Dex "Registry: CryptoOIDConfig" "FAIL" "DENIED" "$($_.Exception.Message)" "Medium" "Restricted Crypto metadata." }

# --- CONTINUING SECONDARY DIAGNOSTICS ---
Write-Host "`nRunning Secondary Diagnostics Pillar..." -ForegroundColor Yellow
$SecondaryCommands = @(
    @{Label="antivirus-check.txt"; Cmd='Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntivirusProduct'}
    @{Label="com-avi-adapters.txt"; Cmd='Get-WmiObject -class Win32_NetworkAdapterConfiguration | fl *'}
    @{Label="drivers.txt"; Cmd='Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion | Format-Table -AutoSize | Out-String -width 9999'}
    @{Label="registry-interfaces.txt"; Cmd='Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"'}
    @{Label="route.txt"; Cmd='Find-NetRoute -RemoteIPAddress 1.1.1.1'}
    @{Label="routetable.txt"; Cmd='Get-NetRoute | Sort-Object | Format-Table | Out-String -width 9999'}
    @{Label="services.txt"; Cmd='Get-WmiObject Win32_Service | Select-Object Name, State | Format-Table -AutoSize | Out-String -width 9999'}
    @{Label="bound-dns-ports.txt"; Cmd='netstat -a -n -b'}
    @{Label="cmdkey.txt"; Cmd='cmdkey.exe /list'}
    @{Label="dns-client.txt"; Cmd='Get-DnsClient'}
    @{Label="firewall-rules.txt"; Cmd='netsh.exe wfp show filters file=-'}
    @{Label="interfaces-config.txt"; Cmd='netsh interface ip show config'}
    @{Label="ipconfig.txt"; Cmd='ipconfig -all'}
    @{Label="pktmon.txt"; Cmd='pktmon.exe status'}
    @{Label="processes.txt"; Cmd='get-process'}
    @{Label="sleep.txt"; Cmd='powercfg.exe /query SCHEME_CURRENT SUB_SLEEP'}
    @{Label="systeminfo.txt"; Cmd='systeminfo /FO LIST'}
    @{Label="tracert.txt"; Cmd='tracert.exe -w 1000 -h 20 -d 162.159.197.2'}
    @{Label="user-session.txt"; Cmd='qwinsta.exe'}
    @{Label="v4interfaces.txt"; Cmd='netsh interface ipv4 show interfaces'}
    @{Label="v4subinterfaces.txt"; Cmd='netsh interface ipv4 show subinterfaces'}
    @{Label="v6interfaces.txt"; Cmd='netsh interface ipv6 show interfaces'}
    @{Label="v6subinterfaces.txt"; Cmd='netsh interface ipv6 show subinterfaces'}
)
foreach ($Diag in $SecondaryCommands) {
    $LowerLabel = $Diag.Label.ToLower(); $OutPath = Join-Path $DiagFolder $LowerLabel
    Write-Host "  Processing: $LowerLabel..." -NoNewline
    try {
        $Error.Clear(); Invoke-Expression $Diag.Cmd | Out-File -FilePath $OutPath -ErrorAction Stop
        $exitStatus = if ($LASTEXITCODE -eq $null) { "0" } else { $LASTEXITCODE.ToString() }
        if ($Error.Count -eq 0 -and ($exitStatus -eq "0" -or $exitStatus -eq "")) {
            Write-Host " [PASS]" -ForegroundColor Green; Log-Main "Diag: $LowerLabel" "PASS" "Success" "Exit: $exitStatus" "Info" "Diagnostic captured."
        } else { Write-Host " [FAIL]" -ForegroundColor Red; Log-Main "Diag: $LowerLabel" "FAIL" "ERROR" "Exit: $exitStatus" "Info" "Non-zero exit." }
    } catch { Write-Host " [ERROR]" -ForegroundColor Red; Log-Main "Diag: $LowerLabel" "FAIL" "EXCEPTION" "$($_.Exception.Message)" "Info" "Execution failed." }
}

# FINAL REPORT CONSTRUCTION
$ReportPath = Join-Path $DiagFolder "00_final_audit_report.txt"
$Header = "--- Cloudflare WARP Investigative Report ---`nHost: $Hostname | Admin: $isAdmin`nTime: $DisplayDate`n"
$Header | Out-File -FilePath $ReportPath
"--- CORE ENVIRONMENT & READINESS FINDINGS ---" | Out-File -FilePath $ReportPath -Append
$MainReport | Format-Table -AutoSize | Out-File -FilePath $ReportPath -Append
"`n--- WARP-DIAG SPECIFIC COMPONENT FINDINGS ---" | Out-File -FilePath $ReportPath -Append
$DiagSpecificReport | Format-Table -AutoSize | Out-File -FilePath $ReportPath -Append
"`n--- WARP-DEX SPECIFIC COMPONENT FINDINGS ---" | Out-File -FilePath $ReportPath -Append
$DexSpecificReport | Format-Table -AutoSize | Out-File -FilePath $ReportPath -Append

Write-Host "`n--- FINAL AUDIT REPORT ---" -ForegroundColor Cyan
Write-Host "Core Readiness Table:" -ForegroundColor White; $MainReport | Format-Table -AutoSize
Write-Host "WARP-DIAG Table:" -ForegroundColor White; $DiagSpecificReport | Format-Table -AutoSize
Write-Host "WARP-DEX Table:" -ForegroundColor White; $DexSpecificReport | Format-Table -AutoSize

if (Test-Path $ZipFile) { Remove-Item $ZipFile -Force }
Compress-Archive -Path $DiagFolder -DestinationPath $ZipFile -Force
Write-Host "`nProcess Complete. Archive: $ZipFile" -ForegroundColor Cyan
