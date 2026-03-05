<#
.SYNOPSIS
    Cloudflare WARP Network Connectivity Tests

.DESCRIPTION
    Standalone script to test network connectivity to Cloudflare WARP endpoints.
    Extracted from localaudit.v2.ps1 to allow isolated network testing.
    
    Tests all Cloudflare firewall requirements per official documentation:
    - Client Orchestration API endpoints
    - WireGuard tunnel ingress (162.159.193.0/24)
    - MASQUE tunnel ingress (162.159.197.0/24)
    - Connectivity check endpoints
    - Captive portal detection
    - Optional features (NTP, NEL)
    
    ANTIVIRUS CONSIDERATIONS:
    This script performs network connectivity tests that may trigger antivirus software:
    - Multiple TCP/UDP/HTTPS connections to external Cloudflare IPs
    - DNS resolution tests
    - TLS/SSL handshakes
    
    All operations are legitimate diagnostic tests - no data exfiltration occurs.

.NOTES
    Version: 1.0
    Requires: PowerShell 5.1+
    No external dependencies - uses native .NET classes only
#>

#Requires -Version 5.1
[CmdletBinding()]
param()

# PowerShell version check
if ($PSVersionTable.PSVersion.Major -lt 5 -or ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -lt 1)) {
    Write-Host "ERROR: This script requires PowerShell 5.1 or higher" -ForegroundColor Red
    Write-Host "Current version: $($PSVersionTable.PSVersion)" -ForegroundColor Yellow
    Write-Host "Please upgrade PowerShell: https://aka.ms/powershell" -ForegroundColor Cyan
    exit 1
}

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

# ============================================================================
# CONFIGURATION
# ============================================================================

$script:Results = @()
$script:Stats = @{
    Total = 0; Passed = 0; Failed = 0; Warnings = 0
}

$script:Env = @{
    Hostname = $env:COMPUTERNAME
    Username = $env:USERNAME
    Timestamp = Get-Date
}

# ============================================================================
# HELPER FUNCTIONS - RESULT MANAGEMENT
# ============================================================================

function Add-TestResult {
    param(
        [string]$Test, [string]$Result, [string]$Severity,
        [string]$Details = "", [string]$Value = "", [string]$Impact = "", [string]$Remediation = ""
    )
    
    $obj = [PSCustomObject]@{
        Test = $Test
        Result = $Result
        Severity = $Severity
        Details = $Details
        Value = $Value
        Impact = $Impact
        Remediation = $Remediation
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    $script:Stats.Total++
    switch ($Result) {
        "PASS" { $script:Stats.Passed++ }
        "FAIL" { $script:Stats.Failed++ }
        "WARN" { $script:Stats.Warnings++ }
    }
    
    return $obj
}

function Write-TestResult {
    param([PSCustomObject]$Result)
    
    $color = switch ($Result.Result) {
        "PASS" { "Green" }
        "FAIL" { "Red" }
        "WARN" { "Yellow" }
        default { "Cyan" }
    }
    $icon = switch ($Result.Result) {
        "PASS" { "[+]" }
        "FAIL" { "[-]" }
        "WARN" { "[!]" }
        default { "[i]" }
    }
    
    Write-Host "  $icon $($Result.Test)" -ForegroundColor $color
    if ($Result.Value) { Write-Host "      → $($Result.Value)" -ForegroundColor Gray }
    if ($Result.Impact) { Write-Host "      Impact: $($Result.Impact)" -ForegroundColor Gray }
    if ($Result.Remediation) { Write-Host "      Fix: $($Result.Remediation)" -ForegroundColor Gray }
}

# ============================================================================
# HELPER FUNCTIONS - NETWORK TESTING
# ============================================================================
# These functions perform network connectivity tests.
# AV WARNING: Network operations to external IPs may trigger behavioral detection.
# These are legitimate diagnostic tests - no data exfiltration occurs.

function Test-TcpPort {
    # AV NOTE: Creates TCP connection to test network reachability.
    # This is a standard diagnostic operation - no malicious payload.
    param([string]$Hostname, [int]$Port, [int]$Timeout = 3)
    $tcp = $null
    try {
        # Creates TCP socket - legitimate connectivity test
        $tcp = New-Object System.Net.Sockets.TcpClient
        $async = $tcp.BeginConnect($Hostname, $Port, $null, $null)
        $wait = $async.AsyncWaitHandle.WaitOne([timespan]::FromSeconds($Timeout))
        if ($wait) { $tcp.EndConnect($async); return @{Success=$true; Msg="Connected"} }
        return @{Success=$false; Msg="Timeout"}
    } catch { return @{Success=$false; Msg=$_.Exception.Message} }
    finally { if ($tcp) { $tcp.Close() } }
}

function Test-HttpsEndpoint {
    # AV NOTE: Performs TLS/SSL handshake to verify HTTPS connectivity.
    # Reads certificate information for validation - no data transmission beyond handshake.
    param([string]$Hostname, [int]$Port = 443, [int]$Timeout = 5)
    $tcp = $null; $ssl = $null
    try {
        # Establish TCP connection
        $tcp = New-Object System.Net.Sockets.TcpClient
        $async = $tcp.BeginConnect($Hostname, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($Timeout * 1000)) { return @{Success=$false; Msg="Timeout"} }
        $tcp.EndConnect($async)
        # Perform TLS handshake to verify SSL/TLS connectivity
        $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false)
        $ssl.AuthenticateAsClient($Hostname)
        # Read certificate for validation purposes only
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate)
        return @{Success=$true; Msg="Connected"; Issuer=$cert.Issuer}
    } catch { return @{Success=$false; Msg=$_.Exception.Message} }
    finally { if ($ssl) { $ssl.Close() }; if ($tcp) { $tcp.Close() } }
}

function Test-UdpPort {
    # AV NOTE: Sends UDP test packet to verify port reachability.
    # UDP is connectionless - packet sent but delivery not confirmed.
    # This is standard network diagnostic behavior.
    param([string]$IP, [int]$Port, [byte[]]$Payload = $null)
    $udp = $null
    try {
        $udp = New-Object System.Net.Sockets.UdpClient
        $udp.Client.ReceiveTimeout = 2000
        $udp.Connect($IP, $Port)
        if (-not $Payload) { $Payload = [Text.Encoding]::ASCII.GetBytes("WARP_TEST") }
        $sent = $udp.Send($Payload, $Payload.Length)
        return @{Success=($sent -gt 0); Msg="Sent $sent bytes"}
    } catch { return @{Success=$false; Msg=$_.Exception.Message} }
    finally { if ($udp) { $udp.Close() } }
}

function Test-DnsResolve {
    param([string]$Hostname)
    try {
        $addrs = [System.Net.Dns]::GetHostAddresses($Hostname)
        $ipv4 = $addrs | Where-Object { $_.AddressFamily -eq 'InterNetwork' }
        if ($ipv4) { return @{Success=$true; IPs=$ipv4.IPAddressToString; Msg="Resolved"} }
        return @{Success=$false; Msg="No IPv4 addresses"}
    } catch { return @{Success=$false; Msg=$_.Exception.Message} }
}

function Get-RandomIPs {
    param([string]$BaseIP, [int]$Count = 4)
    $ips = @()
    $attempts = 0
    while ($ips.Count -lt $Count -and $attempts -lt ($Count * 3)) {
        $ip = "$BaseIP$(Get-Random -Min 1 -Max 255)"
        if ($ips -notcontains $ip) { $ips += $ip }
        $attempts++
    }
    return $ips
}

# ============================================================================
# DISPLAY HEADER
# ============================================================================

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  CLOUDFLARE WARP NETWORK CONNECTIVITY TESTS" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "Hostname:  $($script:Env.Hostname)"
Write-Host "User:      $($script:Env.Username)"
Write-Host "Timestamp: $($script:Env.Timestamp.ToString('F'))"
Write-Host ""

# ============================================================================
# NETWORK CONNECTIVITY TESTS
# ============================================================================
# This section tests network connectivity to Cloudflare endpoints.
# AV WARNING: This is the MOST LIKELY section to trigger antivirus alerts.
# Multiple TCP/UDP/HTTPS connections to external IPs may appear suspicious.
# All connections are legitimate diagnostic tests - no data exfiltration.
# Tests verify firewall rules allow WARP traffic per Cloudflare documentation.

Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "NETWORK CONNECTIVITY TESTS" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "Testing Cloudflare endpoints per official firewall documentation" -ForegroundColor Gray
Write-Host ""
Write-Host "IMPORTANT - TEST METHODOLOGY:" -ForegroundColor Yellow
Write-Host "  • TCP Tests: Establish connection, verify 3-way handshake completes" -ForegroundColor Gray
Write-Host "  • UDP Tests: Send test packet, verify bytes sent (delivery NOT confirmed)" -ForegroundColor Gray
Write-Host "  • HTTPS Tests: TCP + TLS handshake, verify SSL certificate" -ForegroundColor Gray
Write-Host "  • DNS Tests: Resolve hostname to IPv4 address" -ForegroundColor Gray
Write-Host ""
Write-Host "LIMITATIONS - What is NOT tested:" -ForegroundColor Yellow
Write-Host "  ✗ Actual WARP/WireGuard/MASQUE protocol handshakes" -ForegroundColor Gray
Write-Host "  ✗ QUIC protocol negotiation (used by MASQUE)" -ForegroundColor Gray
Write-Host "  ✗ Server responses or protocol validation" -ForegroundColor Gray
Write-Host "  ✗ Tunnel establishment or data transfer" -ForegroundColor Gray
Write-Host "  ✗ UDP packet delivery confirmation (connectionless protocol)" -ForegroundColor Gray
Write-Host ""
Write-Host "PURPOSE: These tests verify network reachability and identify firewall blocks." -ForegroundColor Cyan
Write-Host "They do NOT replicate actual WARP client behavior or protocol operations." -ForegroundColor Cyan
Write-Host ""

# TEST 1: Client Orchestration API
Write-Host "  [1] Client Orchestration API" -ForegroundColor Yellow

$apiEndpoints = @(
    @{Host="zero-trust-client.cloudflareclient.com"; IPs=@("162.159.137.105","162.159.138.105"); Purpose="Registration & Settings"},
    @{Host="notifications.cloudflareclient.com"; IPs=@("162.159.137.105"); Purpose="Push Notifications"}
)

foreach ($endpoint in $apiEndpoints) {
    $dnsResult = Test-DnsResolve -Hostname $endpoint.Host
    $httpsResult = Test-HttpsEndpoint -Hostname $endpoint.Host
    
    $r = Add-TestResult -Test "API: $($endpoint.Purpose)" `
        -Result $(if ($httpsResult.Success) {"PASS"} else {"FAIL"}) -Severity "Critical" `
        -Value "$($endpoint.Host):443" -Details $httpsResult.Msg `
        -Impact $(if (-not $httpsResult.Success) {"WARP cannot $($endpoint.Purpose.ToLower()). Installation will fail"} else {""}) `
        -Remediation $(if (-not $httpsResult.Success) {"Allow HTTPS to $($endpoint.Host) and IPs: $($endpoint.IPs -join ', ')"} else {""})
    
    $script:Results += $r
    Write-TestResult $r
    
    # Test direct IPs
    foreach ($ip in $endpoint.IPs) {
        $ipResult = Test-TcpPort -Hostname $ip -Port 443
        if (-not $ipResult.Success) {
            Write-Host "    [-] Direct IP $ip blocked" -ForegroundColor Red
        }
    }
}

Write-Host ""

# TEST 2: WireGuard Tunnel Ingress
Write-Host "  [2] WireGuard Tunnel (162.159.193.0/24)" -ForegroundColor Yellow

$wgIPs = Get-RandomIPs -BaseIP "162.159.193." -Count 3
$wgPorts = @(2408, 500, 1701, 4500)
$wgSuccess = 0; $wgTotal = 0

foreach ($ip in $wgIPs) {
    foreach ($port in $wgPorts) {
        $wgTotal++
        $udpResult = Test-UdpPort -IP $ip -Port $port
        if ($udpResult.Success) { $wgSuccess++ }
    }
}

$wgHealthy = ($wgSuccess / $wgTotal) -ge 0.5

$r = Add-TestResult -Test "WireGuard Tunnel Ingress" `
    -Result $(if ($wgHealthy) {"PASS"} else {"FAIL"}) -Severity "Critical" `
    -Value "$wgSuccess/$wgTotal UDP tests passed" `
    -Details "Ports 2408,500,1701,4500 on 162.159.193.0/24" `
    -Impact $(if (-not $wgHealthy) {"WARP cannot establish WireGuard tunnel"} else {""}) `
    -Remediation $(if (-not $wgHealthy) {"Allow UDP ports 2408,500,1701,4500 to 162.159.193.0/24"} else {""})

$script:Results += $r
Write-TestResult $r

Write-Host ""

# TEST 3: MASQUE Tunnel Ingress
Write-Host "  [3] MASQUE Tunnel (162.159.197.0/24)" -ForegroundColor Yellow

$mqIPs = Get-RandomIPs -BaseIP "162.159.197." -Count 3
$mqUdpPorts = @(443, 500, 1701, 4500, 4443, 8443, 8095)
$mqSuccess = 0; $mqTotal = 0

foreach ($ip in $mqIPs) {
    foreach ($port in $mqUdpPorts) {
        $mqTotal++
        $udpResult = Test-UdpPort -IP $ip -Port $port
        if ($udpResult.Success) { $mqSuccess++ }
    }
    $mqTotal++
    $tcpResult = Test-TcpPort -Hostname $ip -Port 443
    if ($tcpResult.Success) { $mqSuccess++ }
}

$mqHealthy = ($mqSuccess / $mqTotal) -ge 0.5

$r = Add-TestResult -Test "MASQUE Tunnel Ingress" `
    -Result $(if ($mqHealthy) {"PASS"} else {"FAIL"}) -Severity "Critical" `
    -Value "$mqSuccess/$mqTotal tests passed" `
    -Details "UDP/TCP ports on 162.159.197.0/24" `
    -Impact $(if (-not $mqHealthy) {"WARP cannot establish MASQUE tunnel"} else {""}) `
    -Remediation $(if (-not $mqHealthy) {"Allow UDP 443,500,1701,4500,4443,8443,8095 and TCP 443 to 162.159.197.0/24"} else {""})

$script:Results += $r
Write-TestResult $r

Write-Host ""

# TEST 4: Connectivity Checks
Write-Host "  [4] Connectivity Checks" -ForegroundColor Yellow

$connResult = Test-TcpPort -Hostname "162.159.197.3" -Port 443

$r = Add-TestResult -Test "Connectivity Check Endpoint" `
    -Result $(if ($connResult.Success) {"PASS"} else {"FAIL"}) -Severity "High" `
    -Value "162.159.197.3:443" -Details $connResult.Msg `
    -Impact $(if (-not $connResult.Success) {"WARP connectivity checks will fail"} else {""}) `
    -Remediation $(if (-not $connResult.Success) {"Allow HTTPS to 162.159.197.3"} else {""})

$script:Results += $r
Write-TestResult $r

$engageDns = Test-DnsResolve -Hostname "engage.cloudflareclient.com"
if ($engageDns.Success) {
    $engageUdp = Test-UdpPort -IP $engageDns.IPs[0] -Port 2408
    
    $r = Add-TestResult -Test "Tunnel Establishment" `
        -Result $(if ($engageUdp.Success) {"PASS"} else {"FAIL"}) -Severity "High" `
        -Value "engage.cloudflareclient.com:2408" -Details $engageUdp.Msg `
        -Impact $(if (-not $engageUdp.Success) {"WARP tunnel establishment may fail"} else {""}) `
        -Remediation $(if (-not $engageUdp.Success) {"Allow UDP 2408 to engage.cloudflareclient.com"} else {""})
} else {
    $r = Add-TestResult -Test "Tunnel Establishment" `
        -Result "FAIL" -Severity "High" `
        -Value "engage.cloudflareclient.com" -Details $engageDns.Msg `
        -Impact "Cannot resolve tunnel endpoint" `
        -Remediation "Check DNS settings"
}

$script:Results += $r
Write-TestResult $r

Write-Host ""

# TEST 5: Captive Portal Detection
Write-Host "  [5] Captive Portal Detection" -ForegroundColor Yellow

$captiveDomains = @("cloudflareportal.com", "cloudflareok.com", "cloudflarecp.com", 
                    "www.msftconnecttest.com", "captive.apple.com", "connectivitycheck.gstatic.com")
$captiveSuccess = 0

foreach ($domain in $captiveDomains) {
    $dnsResult = Test-DnsResolve -Hostname $domain
    if ($dnsResult.Success) { $captiveSuccess++ }
}

$r = Add-TestResult -Test "Captive Portal Detection" `
    -Result $(if ($captiveSuccess -ge 3) {"PASS"} else {"WARN"}) -Severity "Low" `
    -Value "$captiveSuccess/$($captiveDomains.Count) domains resolved" `
    -Impact $(if ($captiveSuccess -lt 3) {"Captive portal detection may not work"} else {""}) `
    -Remediation $(if ($captiveSuccess -lt 3) {"Verify DNS resolution"} else {""})

$script:Results += $r
Write-TestResult $r

Write-Host ""

# TEST 6: Additional Endpoints
Write-Host "  [6] Additional Endpoints" -ForegroundColor Yellow

$additionalEndpoints = @(
    @{Host="api.cloudflareclient.com"; Purpose="Registration"; Optional=$false},
    @{Host="client.warp.cloudflare.com"; Purpose="Updates/Telemetry"; Optional=$true}
)

foreach ($endpoint in $additionalEndpoints) {
    $dnsResult = Test-DnsResolve -Hostname $endpoint.Host
    
    if ($dnsResult.Success) {
        $httpsResult = Test-HttpsEndpoint -Hostname $endpoint.Host
        
        $r = Add-TestResult -Test "$($endpoint.Purpose) Endpoint" `
            -Result $(if ($httpsResult.Success) {"PASS"} elseif ($endpoint.Optional) {"WARN"} else {"FAIL"}) `
            -Severity $(if ($endpoint.Optional) {"Low"} else {"High"}) `
            -Value "$($endpoint.Host):443" -Details $httpsResult.Msg `
            -Impact $(if (-not $httpsResult.Success -and -not $endpoint.Optional) {"WARP cannot $($endpoint.Purpose.ToLower())"} elseif (-not $httpsResult.Success) {"Optional feature unavailable"} else {""}) `
            -Remediation $(if (-not $httpsResult.Success -and -not $endpoint.Optional) {"Allow HTTPS to $($endpoint.Host)"} else {""})
    } else {
        $r = Add-TestResult -Test "$($endpoint.Purpose) Endpoint" `
            -Result $(if ($endpoint.Optional) {"WARN"} else {"FAIL"}) `
            -Severity $(if ($endpoint.Optional) {"Low"} else {"High"}) `
            -Value $endpoint.Host -Details $dnsResult.Msg `
            -Impact $(if ($endpoint.Optional) {"Optional endpoint. May not exist or be region-specific"} else {"Cannot reach endpoint"}) `
            -Remediation $(if (-not $endpoint.Optional) {"Check DNS configuration"} else {"N/A - Optional"})
    }
    
    $script:Results += $r
    Write-TestResult $r
}

Write-Host ""

# TEST 7: Optional Features
Write-Host "  [7] Optional Features (NTP, NEL)" -ForegroundColor Yellow

# NTP
$ntpPayload = New-Object byte[] 48
$ntpPayload[0] = 0x1B
$ntpResult = Test-DnsResolve -Hostname "time.cloudflare.com"
if ($ntpResult.Success) {
    $ntpUdp = Test-UdpPort -IP $ntpResult.IPs[0] -Port 123 -Payload $ntpPayload
    $ntpStatus = if ($ntpUdp.Success) {"PASS"} else {"WARN"}
} else {
    $ntpStatus = "WARN"
}

$r = Add-TestResult -Test "NTP Time Sync" `
    -Result $ntpStatus -Severity "Low" `
    -Value "time.cloudflare.com:123" `
    -Impact "Optional feature. WARP can function without it"

$script:Results += $r
Write-TestResult $r

# NEL
$nelResult = Test-DnsResolve -Hostname "a.nel.cloudflare.com"

$r = Add-TestResult -Test "NEL Error Reporting" `
    -Result $(if ($nelResult.Success) {"PASS"} else {"WARN"}) -Severity "Low" `
    -Value "a.nel.cloudflare.com" `
    -Impact "Optional feature. WARP can function without it"

$script:Results += $r
Write-TestResult $r

Write-Host ""
Write-Host "NOTE: UDP tests show packet sent, not delivery confirmed (connectionless protocol)" -ForegroundColor Gray
Write-Host ""

# ============================================================================
# FINAL SUMMARY
# ============================================================================

Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "TEST SUMMARY" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""
Write-Host "Total Tests:  $($script:Stats.Total)"
Write-Host "Passed:       $($script:Stats.Passed)" -ForegroundColor Green
Write-Host "Failed:       $($script:Stats.Failed)" -ForegroundColor Red
Write-Host "Warnings:     $($script:Stats.Warnings)" -ForegroundColor Yellow
Write-Host ""

# Determine overall status
$criticalFailures = $script:Results | Where-Object { $_.Result -eq "FAIL" -and $_.Severity -eq "Critical" }
$highFailures = $script:Results | Where-Object { $_.Result -eq "FAIL" -and $_.Severity -eq "High" }

if ($criticalFailures.Count -gt 0) {
    Write-Host "NETWORK STATUS: " -NoNewline
    Write-Host "BLOCKED" -ForegroundColor Red
    Write-Host ""
    Write-Host "Critical network paths are blocked. WARP will not function." -ForegroundColor Red
    Write-Host ""
    Write-Host "Critical Failures:" -ForegroundColor Red
    foreach ($failure in $criticalFailures) {
        Write-Host "  • $($failure.Test): $($failure.Value)" -ForegroundColor Red
        if ($failure.Remediation) {
            Write-Host "    Fix: $($failure.Remediation)" -ForegroundColor Yellow
        }
    }
} elseif ($highFailures.Count -gt 0) {
    Write-Host "NETWORK STATUS: " -NoNewline
    Write-Host "DEGRADED" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Some network paths are blocked. WARP may have limited functionality." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "High Priority Failures:" -ForegroundColor Yellow
    foreach ($failure in $highFailures) {
        Write-Host "  • $($failure.Test): $($failure.Value)" -ForegroundColor Yellow
        if ($failure.Remediation) {
            Write-Host "    Fix: $($failure.Remediation)" -ForegroundColor Gray
        }
    }
} else {
    Write-Host "NETWORK STATUS: " -NoNewline
    Write-Host "READY" -ForegroundColor Green
    Write-Host ""
    Write-Host "✓ All critical network paths are accessible" -ForegroundColor Green
    Write-Host "✓ WARP should be able to establish connections" -ForegroundColor Green
}

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
