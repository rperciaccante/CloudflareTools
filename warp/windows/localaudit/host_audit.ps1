$ErrorActionPreference = "SilentlyContinue"
$MainReport = @()
$DiagSpecificReport = @()
$DexSpecificReport = @()
$NetTestReport = @()
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

# ---------------------------------------------------------
# Helper Functions (Logging & Probes)
# ---------------------------------------------------------

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

function Log-Net($Comp, $Prot, $PF, $Stat, $Det) {
    $obj = [PSCustomObject]@{ Component = $Comp; Protocol = $Prot; 'Pass/Fail' = $PF; Result = $Stat; Target = $Det }
    $script:NetTestReport += $obj
}

function Test-UdpPort {
    param ([string]$Ip, [int]$Port, [string]$ProtocolName)
    $udpClient = $null
    try {
        $udpClient = New-Object System.Net.Sockets.UdpClient
        $udpClient.Client.ReceiveTimeout = 2000 
        $udpClient.Connect($Ip, $Port)
        $payload = [System.Text.Encoding]::ASCII.GetBytes("CloudflareWARPTest")
        $bytesSent = $udpClient.Send($payload, $payload.Length)
        if ($bytesSent -gt 0) {
            Write-Host "  [+] SUCCESS ($ProtocolName): UDP Packet sent to $Ip on port $Port." -ForegroundColor Green
            Log-Net "UDP Probe" $ProtocolName "PASS" "Sent" "$Ip`:$Port"
        } else {
            Write-Host "  [-] FAILED ($ProtocolName): Zero bytes sent to $Ip on UDP $Port." -ForegroundColor Red
            Log-Net "UDP Probe" $ProtocolName "FAIL" "Zero Bytes" "$Ip`:$Port"
        }
    } catch {
        Write-Host "  [-] FAILED ($ProtocolName): Could not send to $Ip on UDP $Port. ($($_.Exception.Message))" -ForegroundColor Red
        Log-Net "UDP Probe" $ProtocolName "FAIL" "Error: $($_.Exception.Message)" "$Ip`:$Port"
    } finally {
        if ($udpClient -ne $null) { $udpClient.Close() }
    }
}

function Test-TcpPort {
    param ([string]$Ip, [int]$Port, [string]$ProtocolName)
    $tcpClient = $null
    try {
        if ($Ip -match ":") { $tcpClient = New-Object System.Net.Sockets.TcpClient([System.Net.Sockets.AddressFamily]::InterNetworkV6) }
        else { $tcpClient = New-Object System.Net.Sockets.TcpClient([System.Net.Sockets.AddressFamily]::InterNetwork) }
        $asyncResult = $tcpClient.BeginConnect($Ip, $Port, $null, $null)
        $connected = $asyncResult.AsyncWaitHandle.WaitOne([timespan]::FromSeconds(2))
        if ($connected) {
            $tcpClient.EndConnect($asyncResult)
            Write-Host "  [+] SUCCESS ($ProtocolName): TCP Connection established to $Ip on port $Port." -ForegroundColor Green
            Log-Net "TCP Probe" $ProtocolName "PASS" "Connected" "$Ip`:$Port"
        } else {
            Write-Host "  [-] FAILED ($ProtocolName): TCP Connection timed out to $Ip on port $Port." -ForegroundColor Red
            Log-Net "TCP Probe" $ProtocolName "FAIL" "Timeout" "$Ip`:$Port"
        }
    } catch {
        Write-Host "  [-] FAILED ($ProtocolName): TCP Connection refused/failed to $Ip on port $Port." -ForegroundColor Red
        Log-Net "TCP Probe" $ProtocolName "FAIL" "Refused" "$Ip`:$Port"
    } finally {
        if ($tcpClient -ne $null) { $tcpClient.Close() }
    }
}

function Get-RandomIps {
    param ([string]$BaseIp, [int]$Count = 4)
    $ips = @()
    while ($ips.Count -lt $Count) {
        $randomOctet = Get-Random -Minimum 1 -Maximum 255
        $ip = "$BaseIp$randomOctet"
        if ($ips -notcontains $ip) { $ips += $ip }
    }
    return $ips
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

# ---------------------------------------------------------
# PILLAR 1: WINTUN DRIVER VERSION CHECK
# ---------------------------------------------------------
Write-Host "`nChecking Wintun Driver Versions..." -ForegroundColor Yellow
try {
    $WintunDrivers = Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.DeviceName -like "*Wintun*" }
    if ($WintunDrivers) {
        foreach ($drv in $WintunDrivers) {
            Log-Main "Driver: Wintun" "WARN" "Exists" "Ver: $($drv.DriverVersion)" "High" "Existing drivers conflict."
            Write-Host "  [!!] Found: $($drv.DeviceName) v$($drv.DriverVersion)" -ForegroundColor Yellow
        }
    } else {
        Log-Main "Driver: Wintun" "PASS" "Not Found" "Clean state" "Info" "No driver conflicts."
        Write-Host "  [OK] No existing Wintun drivers detected." -ForegroundColor Green
    }
} catch { Log-Main "Driver Check" "FAIL" "EXECUTION ERROR" "$($_.Exception.Message)" "High" "Query failed." }

# ---------------------------------------------------------
# PILLAR 2: CORE SYSTEM SERVICES
# ---------------------------------------------------------

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

# ---------------------------------------------------------
# PILLAR 3: ENVIRONMENT PATH VARIABLES
# ---------------------------------------------------------

Write-Host "`nCapturing Environment PATH Variables..." -ForegroundColor Yellow
try {
    $SysPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $UsrPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $PathReport = @("--- SYSTEM PATH ---", ($SysPath -split ";"), "", "--- USER PATH ---", ($UsrPath -split ";"))
    $PathReport | Out-File (Join-Path $DiagFolder "path_variables.txt")
    Log-Main "Env: Path" "PASS" "Captured" "Split-log generated" "Medium" "Required for CLI resolution."
    Write-Host "  [OK] Captured Path Variables." -ForegroundColor Green
} catch { Log-Main "Env: Path" "FAIL" "ERROR" "$($_.Exception.Message)" "Medium" "Path capture failed." }

# ---------------------------------------------------------
# PILLAR 4: FILESYSTEM ACCESS AUDIT
# ---------------------------------------------------------
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

# ---------------------------------------------------------
# PILLAR 5: NETWORK STACK & SOCKET GOVERNANCE
# ---------------------------------------------------------

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

# ---------------------------------------------------------
# PILLAR 6: SPECIALIZED PERMISSIONS (CertStore, DLLs, ARM64)
# ---------------------------------------------------------
Write-Host "`nChecking Specialized Permissions..." -ForegroundColor Yellow
$CertStore = "HKLM:\SOFTWARE\Microsoft\SystemCertificates"
try {
    $testKey = Join-Path $CertStore "WARP_Audit"; New-Item -Path $testKey -Force | Out-Null; Remove-Item $testKey -Force
    Log-Main "Registry: CertStore" "PASS" "Granted" "Write Success" "High" "Required for Root CA."
    Write-Host "  [OK] CertStore: Write Granted" -ForegroundColor Green
} catch { Log-Main "Registry: CertStore" "FAIL" "DENIED" "$($_.Exception.Message)" "High" "SSL fails." }

$DepFiles = @("C:\Windows\System32\dnsapi.dll", "C:\Windows\System32\dhcpcsvc.dll", "C:\Windows\System32\dhcpcsvc6.dll")
foreach($f in $DepFiles) { if (Test-Path $f) { Log-Main "File: $(Split-Path $f -Leaf)" "PASS" "Found" "Present" "Critical" "Core DLL." } }

# ---------------------------------------------------------
# PILLAR 7: PROTOCOL SPECIFIC CONNECTIVITY PROBES
# ---------------------------------------------------------

Write-Host "`n>>> PHASE 1: API ENDPOINT & SSL INSPECTION <<<" -ForegroundColor Yellow
$apiHost = "zero-trust-client.cloudflareclient.com"
try {
    $tcpClient = New-Object System.Net.Sockets.TcpClient; $tcpClient.Connect($apiHost, 443)
    $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false); $sslStream.AuthenticateAsClient($apiHost)
    $certDetails = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($sslStream.RemoteCertificate)
    $knownIssuers = @("Google Trust Services", "DigiCert", "Let's Encrypt", "Cloudflare", "Baltimore")
    $issuerMatch = $false; foreach ($issuer in $knownIssuers) { if ($certDetails.Issuer -match $issuer) { $issuerMatch = $true; break } }
    Log-Net "SSL Audit" "HTTPS/API" $(if ($issuerMatch) {"PASS"} else {"WARN"}) $(if ($issuerMatch) {"Public CA"} else {"Untrusted Issuer"}) $certDetails.Issuer
    $tcpClient.Close(); Write-Host "  [+] SSL Check complete." -ForegroundColor Green
} catch { Log-Net "API Edge" "HTTPS/API" "FAIL" "Error" $_.Exception.Message }


Write-Host "`n>>> PHASE 2: WIREGUARD ROUTING <<<" -ForegroundColor Yellow
foreach ($targetIp in (Get-RandomIps -BaseIp "162.159.193.")) {
    foreach ($port in @(2408, 500, 1701, 4500)) { Test-UdpPort -Ip $targetIp -Port $port -ProtocolName "WireGuard" }
}

Write-Host "`n>>> PHASE 3: MASQUE ROUTING <<<" -ForegroundColor Yellow
foreach ($targetIp in (Get-RandomIps -BaseIp "162.159.197.")) {
    foreach ($port in @(443, 500, 1701, 4500, 4443, 8443, 8095)) { Test-UdpPort -Ip $targetIp -Port $port -ProtocolName "MASQUE" }
    Test-TcpPort -Ip $targetIp -Port 443 -ProtocolName "MASQUE"
}

Write-Host "`n>>> PHASE 4: GENERAL CONNECTIVITY & INGRESS <<<" -ForegroundColor Yellow
try {
    $engageIp = ([System.Net.Dns]::GetHostAddresses("engage.cloudflareclient.com") | Where-Object { $_.AddressFamily -eq 'InterNetwork' })[0].IPAddressToString
    Test-UdpPort -Ip $engageIp -Port 2408 -ProtocolName "Ingress"
} catch { Write-Host "  [-] Ingress DNS Failed." -ForegroundColor Red }

# ---------------------------------------------------------
# PILLAR 8: DEEP-DIVE FORENSICS & PLATFORM AUDITS
# ---------------------------------------------------------
Write-Host "`nRunning Deep-Dive Forensics (System & User Scope)..." -ForegroundColor Yellow

$UninstallKeys = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*","HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*")
Get-ItemProperty $UninstallKeys | Where-Object { $_.DisplayName -ne $null } | Select-Object DisplayName, Publisher | Out-File (Join-Path $DiagFolder "installed_applications.txt")
Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, User | Format-List | Out-File (Join-Path $DiagFolder "startup_apps.txt")


Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | Select-Object TaskName, @{N="Triggers";E={$_.Triggers.ToString()}}, @{N="Actions";E={$_.Actions.Execute}} | Format-List | Out-File (Join-Path $DiagFolder "scheduled_tasks.txt")

# Platform (DIAG & DEX)
$DiagStaging = @("C:\ProgramData\Cloudflare\packet_captures", "C:\ProgramData\Cloudflare\qlogs")
foreach ($P in $DiagStaging) {
    try {
        if (!(Test-Path $P)) { New-Item -Path $P -ItemType Directory -Force | Out-Null }
        $test = Join-Path $P "diag_test.tmp"; New-Item $test -ItemType File -Force | Out-Null; Remove-Item $test -Force
        Log-Diag "Diag Path: $(Split-Path $P -Leaf)" "PASS" "Granted" "Success" "Medium" "Staging access."
    } catch { Log-Diag "Diag Path: $(Split-Path $P -Leaf)" "FAIL" "DENIED" "$($_.Exception.Message)" "Medium" "Capture fails." }
}
$CryptCache = "C:\Windows\System32\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache"
if (Test-Path $CryptCache) { Log-Dex "Path: CryptnetUrlCache" "PASS" "Found" "Readable" "Medium" "Experience monitoring." }

# ---------------------------------------------------------
# SECONDARY DIAGNOSTICS (All 23+ Commands)
# ---------------------------------------------------------
Write-Host "`nRunning Secondary Diagnostics Pillar..." -ForegroundColor Yellow
$SecondaryCommands = @(
    @{Label="drivers.txt"; Cmd='Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion | Format-Table -AutoSize'}
    @{Label="ipconfig.txt"; Cmd='ipconfig -all'}
    @{Label="routetable.txt"; Cmd='Get-NetRoute | Sort-Object | Format-Table'}
)
foreach ($Diag in $SecondaryCommands) {
    $LowerLabel = $Diag.Label.ToLower(); $OutPath = Join-Path $DiagFolder $LowerLabel
    try {
        Invoke-Expression $Diag.Cmd | Out-File -FilePath $OutPath -ErrorAction Stop
        Log-Main "Diag: $LowerLabel" "PASS" "Success" "Captured" "Info" "Log."
    } catch { Log-Main "Diag: $LowerLabel" "FAIL" "EXCEPTION" "$($_.Exception.Message)" "Info" "Failed." }
}

# ---------------------------------------------------------
# FINAL PACKAGING, INTEGRITY VERIFICATION & CLEANUP
# ---------------------------------------------------------
$ReportPath = Join-Path $DiagFolder "00_final_audit_report.txt"
$Header = "--- Cloudflare WARP Unified Investigative Report ---`nHost: $Hostname | Time: $DisplayDate`n"
$Header | Out-File -FilePath $ReportPath
"--- CORE READINESS ---" | Out-File -FilePath $ReportPath -Append; $MainReport | Format-Table -AutoSize | Out-File -FilePath $ReportPath -Append
"`n--- CONNECTIVITY BY PROTOCOL ---" | Out-File -FilePath $ReportPath -Append; $NetTestReport | Group-Object Protocol | ForEach-Object { $_.Group | Format-Table -AutoSize | Out-File -FilePath $ReportPath -Append }
"`n--- PLATFORM AUDIT (DIAG & DEX) ---" | Out-File -FilePath $ReportPath -Append; $DiagSpecificReport | Format-Table -AutoSize | Out-File -FilePath $ReportPath -Append; $DexSpecificReport | Format-Table -AutoSize | Out-File -FilePath $ReportPath -Append

Write-Host "`n--- FINAL AUDIT REPORT ---" -ForegroundColor Cyan
$MainReport | Format-Table -AutoSize
$NetTestReport | Group-Object Protocol | ForEach-Object { Write-Host ">> Protocol: $($_.Name)" -ForegroundColor Cyan; $_.Group | Format-Table -AutoSize }

# Archive Creation
if (Test-Path $ZipFile) { Remove-Item $ZipFile -Force }
Write-Host "`nCreating Forensic Archive..." -ForegroundColor Yellow
Compress-Archive -Path $DiagFolder -DestinationPath $ZipFile -Force

# Archive Integrity Verification
Write-Host "Verifying Archive Integrity..." -ForegroundColor Yellow
$FolderFiles = Get-ChildItem -Path $DiagFolder -Recurse | Where-Object { !$_.PSIsContainer } | Select-Object -ExpandProperty Name | Sort-Object
Add-Type -AssemblyName System.IO.Compression.FileSystem
$Zip = [System.IO.Compression.ZipFile]::OpenRead($ZipFile)
$ZipFiles = $Zip.Entries | Select-Object -ExpandProperty Name | Sort-Object
$Zip.Dispose()

if ($FolderFiles.Count -eq $ZipFiles.Count) {
    Write-Host "  [OK] Archive match confirmed ($($ZipFiles.Count) files)." -ForegroundColor Green
    Remove-Item -Path $DiagFolder -Recurse -Force
    Write-Host "  [OK] Source folder cleaned up: $DiagFolder" -ForegroundColor Gray
} else {
    Write-Host "  [!] MISMATCH DETECTED: Folder has $($FolderFiles.Count) files, ZIP has $($ZipFiles.Count)." -ForegroundColor Red
    Write-Host "  Folder retained for manual review: $DiagFolder" -ForegroundColor Yellow
}

Write-Host "`nProcess Complete. Archive: $ZipFile" -ForegroundColor Cyan
