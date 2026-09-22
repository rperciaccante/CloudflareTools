#!/usr/bin/env powershell
<#
.SYNOPSIS
    Test WebRTC port connectivity and diagnose blocking issues
    
.DESCRIPTION
    Comprehensive script to test STUN, TURN, and WebRTC-related port accessibility
    from the local network. Includes DNS resolution, port connectivity, and NAT detection.
    
.PARAMETER TestSTUN
    Test STUN server connectivity (default: $true)
    
.PARAMETER TestTURN
    Test TURN server connectivity (default: $true)
    
.PARAMETER TestDNS
    Test DNS resolution for WebRTC servers (default: $true)
    
.PARAMETER TestNAT
    Detect local NAT/firewall via public IP check (default: $true)
    
.PARAMETER Verbose
    Show detailed diagnostic output
    
.EXAMPLE
    .\Test-WebRTCPorts.ps1
    
.EXAMPLE
    .\Test-WebRTCPorts.ps1 -TestSTUN $true -TestTURN $true -Verbose

.NOTES
    Author: Cloudflare RBI Diagnostics
    Requires: PowerShell 5.0+, Administrator privileges recommended
    Run with: powershell.exe -ExecutionPolicy Bypass -File Test-WebRTCPorts.ps1
#>

param(
    [bool]$TestSTUN = $true,
    [bool]$TestTURN = $true,
    [bool]$TestDNS = $true,
    [bool]$TestNAT = $true,
    [switch]$Verbose
)

# Ensure we can write errors to output
$VerbosePreference = if ($Verbose) { "Continue" } else { "SilentlyContinue" }
$ErrorActionPreference = "Continue"

# Color output functions
function Write-Header {
    param([string]$Text)
    Write-Host "`n===============================================" -ForegroundColor Cyan
    Write-Host $Text -ForegroundColor Cyan
    Write-Host "===============================================`n" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Text)
    Write-Host "✓ $Text" -ForegroundColor Green
}

function Write-Failure {
    param([string]$Text)
    Write-Host "✗ $Text" -ForegroundColor Red
}

function Write-Warning {
    param([string]$Text)
    Write-Host "⚠ $Text" -ForegroundColor Yellow
}

function Write-Info {
    param([string]$Text)
    Write-Host "ℹ $Text" -ForegroundColor Cyan
}

# Define WebRTC servers to test
$STUNServers = @(
    @{ Name = "Google STUN 1"; Host = "stun.l.google.com"; Port = 3478; Protocol = "UDP" },
    @{ Name = "Google STUN 2"; Host = "stun1.l.google.com"; Port = 3478; Protocol = "UDP" },
    @{ Name = "Google STUN 3"; Host = "stun2.l.google.com"; Port = 3478; Protocol = "UDP" },
    @{ Name = "Twilio STUN"; Host = "stun.stunprotocol.org"; Port = 3478; Protocol = "UDP" },
    @{ Name = "Cloudflare STUN"; Host = "stun.cloudflare.com"; Port = 3478; Protocol = "UDP" }
)

$TURNServers = @(
    @{ Name = "Google TURN TCP"; Host = "turn.google.com"; Port = 443; Protocol = "TCP" },
    @{ Name = "Google TURN TCP Alt"; Host = "turn.google.com"; Port = 5349; Protocol = "TCP" },
    @{ Name = "Twilio TURN"; Host = "turn.stunprotocol.org"; Port = 5349; Protocol = "TCP" }
)

$DNSServers = @(
    @{ Name = "CloudFlare DNS"; IP = "1.1.1.1"; Port = 53 },
    @{ Name = "Google DNS"; IP = "8.8.8.8"; Port = 53 },
    @{ Name = "Quad9 DNS"; IP = "9.9.9.9"; Port = 53 }
)

# Results tracking
$results = @{
    STUNTests = @()
    TURNTests = @()
    DNSTests = @()
    NATTests = @()
    Summary = @()
}

# ============================================================================
# DNS Resolution Tests
# ============================================================================
function Test-DNSResolution {
    Write-Header "DNS Resolution Tests"
    
    $allServers = $STUNServers + $TURNServers
    $uniqueHosts = $allServers | Select-Object -ExpandProperty Host -Unique
    
    $dnsSuccess = 0
    $dnsFailure = 0
    
    foreach ($host in $uniqueHosts) {
        try {
            $resolveTimer = [System.Diagnostics.Stopwatch]::StartNew()
            $result = [System.Net.Dns]::GetHostAddresses($host)
            $resolveTimer.Stop()
            
            if ($result -and $result.Count -gt 0) {
                Write-Success "$host → $($result[0]) ($($resolveTimer.ElapsedMilliseconds)ms)"
                $results.DNSTests += @{
                    Host = $host
                    IP = $result[0].IPAddressToString
                    Time = $resolveTimer.ElapsedMilliseconds
                    Status = "Resolved"
                }
                $dnsSuccess++
            } else {
                Write-Failure "$host → No A records found"
                $results.DNSTests += @{
                    Host = $host
                    Status = "No Records"
                }
                $dnsFailure++
            }
        } catch {
            Write-Failure "$host → Resolution failed: $($_.Exception.Message)"
            $results.DNSTests += @{
                Host = $host
                Status = "Failed"
                Error = $_.Exception.Message
            }
            $dnsFailure++
        }
    }
    
    Write-Info "DNS Results: $dnsSuccess resolved, $dnsFailure failed"
    return $dnsSuccess -gt 0
}

# ============================================================================
# UDP Port Connectivity (STUN)
# ============================================================================
function Test-UDPPort {
    param(
        [string]$Host,
        [int]$Port,
        [int]$TimeoutMs = 3000
    )
    
    try {
        $udpClient = New-Object System.Net.Sockets.UdpClient
        $udpClient.Client.ReceiveTimeout = $TimeoutMs
        $udpClient.Client.SendTimeout = $TimeoutMs
        
        # Create a minimal STUN binding request
        # STUN packet format: [header 20 bytes] [optional attributes]
        $stunPacket = New-Object byte[] 20
        $stunPacket[0] = 0x00  # STUN method BINDING
        $stunPacket[1] = 0x01  # Message type BINDING REQUEST
        $stunPacket[2] = 0x00  # Message length (0 for minimal request)
        $stunPacket[3] = 0x00
        # Magic cookie
        $stunPacket[4] = 0x21
        $stunPacket[5] = 0x12
        $stunPacket[6] = 0xA4
        $stunPacket[7] = 0x42
        # Transaction ID (random 12 bytes)
        $random = New-Object System.Random
        for ($i = 8; $i -lt 20; $i++) {
            $stunPacket[$i] = [byte]$random.Next(256)
        }
        
        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $udpClient.Send($stunPacket, $stunPacket.Length, $Host, $Port) | Out-Null
        
        try {
            $remoteEndPoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
            $receivedData = $udpClient.Receive([ref]$remoteEndPoint)
            $timer.Stop()
            
            # Got a response = port is open
            if ($receivedData -and $receivedData.Length -gt 0) {
                return @{
                    Success = $true
                    Time = $timer.ElapsedMilliseconds
                    Response = "Received $(($receivedData).Length) bytes"
                }
            }
        } catch [System.Net.Sockets.SocketException] {
            $timer.Stop()
            # Timeout or connection refused
            return @{
                Success = $false
                Time = $timer.ElapsedMilliseconds
                Error = $_.Exception.Message
            }
        }
    } catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    } finally {
        if ($udpClient) {
            $udpClient.Close()
            $udpClient.Dispose()
        }
    }
}

function Test-STUNConnectivity {
    Write-Header "STUN Server Connectivity (UDP Port 3478)"
    
    $stunSuccess = 0
    $stunFailure = 0
    
    foreach ($server in $STUNServers) {
        Write-Info "Testing $($server.Name) ($($server.Host):$($server.Port) UDP)..."
        
        try {
            $result = Test-UDPPort -Host $server.Host -Port $server.Port
            
            if ($result.Success) {
                Write-Success "$($server.Name) → Open ($($result.Time)ms, $($result.Response))"
                $results.STUNTests += @{
                    Server = $server.Name
                    Host = $server.Host
                    Port = $server.Port
                    Status = "Open"
                    Time = $result.Time
                }
                $stunSuccess++
            } else {
                Write-Failure "$($server.Name) → Blocked/Timeout ($($result.Time)ms)"
                $results.STUNTests += @{
                    Server = $server.Name
                    Host = $server.Host
                    Port = $server.Port
                    Status = "Blocked"
                    Time = $result.Time
                    Error = $result.Error
                }
                $stunFailure++
            }
        } catch {
            Write-Failure "$($server.Name) → Error: $($_.Exception.Message)"
            $results.STUNTests += @{
                Server = $server.Name
                Host = $server.Host
                Port = $server.Port
                Status = "Error"
                Error = $_.Exception.Message
            }
            $stunFailure++
        }
    }
    
    Write-Info "STUN Results: $stunSuccess open, $stunFailure blocked/failed`n"
    
    if ($stunSuccess -eq 0) {
        Write-Warning "CRITICAL: All STUN servers are unreachable!"
        Write-Warning "This will cause WebRTC connection failures (ICE candidate gathering will fail)"
        $results.Summary += "STUN BLOCKED - WebRTC will fail to establish connections"
    } elseif ($stunFailure -gt 0) {
        Write-Warning "Some STUN servers are unreachable (may cause intermittent failures)"
        $results.Summary += "PARTIAL STUN BLOCKING - Some redundancy, but failures may occur"
    } else {
        Write-Success "All STUN servers reachable - NAT traversal should work"
        $results.Summary += "STUN OK - NAT traversal available"
    }
}

# ============================================================================
# TCP Port Connectivity (TURN fallback)
# ============================================================================
function Test-TCPPort {
    param(
        [string]$Host,
        [int]$Port,
        [int]$TimeoutMs = 3000
    )
    
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $asyncConnect = $tcpClient.BeginConnect($Host, $Port, $null, $null)
        
        $timer = [System.Diagnostics.Stopwatch]::StartNew()
        $waitResult = $asyncConnect.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        $timer.Stop()
        
        if ($waitResult -and $tcpClient.Connected) {
            $tcpClient.Close()
            return @{
                Success = $true
                Time = $timer.ElapsedMilliseconds
            }
        } else {
            $tcpClient.Close()
            return @{
                Success = $false
                Time = $timer.ElapsedMilliseconds
                Error = "Connection timeout"
            }
        }
    } catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Test-TURNConnectivity {
    Write-Header "TURN Server Connectivity (TCP Port 443/5349)"
    
    $turnSuccess = 0
    $turnFailure = 0
    
    foreach ($server in $TURNServers) {
        Write-Info "Testing $($server.Name) ($($server.Host):$($server.Port) TCP)..."
        
        try {
            $result = Test-TCPPort -Host $server.Host -Port $server.Port
            
            if ($result.Success) {
                Write-Success "$($server.Name) → Open ($($result.Time)ms)"
                $results.TURNTests += @{
                    Server = $server.Name
                    Host = $server.Host
                    Port = $server.Port
                    Status = "Open"
                    Time = $result.Time
                }
                $turnSuccess++
            } else {
                Write-Failure "$($server.Name) → Blocked/Timeout ($($result.Time)ms)"
                $results.TURNTests += @{
                    Server = $server.Name
                    Host = $server.Host
                    Port = $server.Port
                    Status = "Blocked"
                    Time = $result.Time
                    Error = $result.Error
                }
                $turnFailure++
            }
        } catch {
            Write-Failure "$($server.Name) → Error: $($_.Exception.Message)"
            $results.TURNTests += @{
                Server = $server.Name
                Host = $server.Host
                Port = $server.Port
                Status = "Error"
                Error = $_.Exception.Message
            }
            $turnFailure++
        }
    }
    
    Write-Info "TURN Results: $turnSuccess open, $turnFailure blocked/failed`n"
    
    if ($turnSuccess -eq 0) {
        Write-Warning "CRITICAL: All TURN servers are unreachable!"
        Write-Warning "Combined with STUN failure, this means WebRTC will completely fail"
        $results.Summary += "TURN BLOCKED - No TCP fallback available"
    } elseif ($turnFailure -gt 0) {
        Write-Warning "Some TURN servers blocked (TCP fallback partially working)"
        $results.Summary += "PARTIAL TURN BLOCKING - TCP fallback partially available"
    } else {
        Write-Success "All TURN servers reachable - TCP fallback available"
        $results.Summary += "TURN OK - TCP fallback available"
    }
}

# ============================================================================
# NAT Detection
# ============================================================================
function Test-NATDetection {
    Write-Header "NAT & Public IP Detection"
    
    try {
        Write-Info "Detecting local IP addresses..."
        $localIPs = @()
        
        # Get all network interfaces
        $interfaces = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()
        foreach ($interface in $interfaces) {
            if ($interface.OperationalStatus -eq "Up") {
                $properties = $interface.GetIPProperties()
                foreach ($addr in $properties.UnicastAddresses) {
                    if ($addr.Address.AddressFamily -eq "InterNetwork") {
                        Write-Success "Local IP: $($addr.Address) (Interface: $($interface.Name))"
                        $localIPs += $addr.Address
                    }
                }
            }
        }
        
        $results.NATTests += @{
            LocalIPs = $localIPs
        }
        
        # Try to detect public IP
        Write-Info "Detecting public IP address (this may take a few seconds)..."
        
        $publicIPServices = @(
            "https://api.ipify.org?format=json",
            "https://checkip.amazonaws.com",
            "https://wtfismyip.com/json"
        )
        
        $publicIP = $null
        foreach ($service in $publicIPServices) {
            try {
                $response = Invoke-WebRequest -Uri $service -TimeoutSec 3 -ErrorAction Stop
                if ($service -match "ipify") {
                    $publicIP = ($response.Content | ConvertFrom-Json).ip
                } elseif ($service -match "amazonaws") {
                    $publicIP = $response.Content.Trim()
                } elseif ($service -match "wtfismyip") {
                    $publicIP = ($response.Content | ConvertFrom-Json).YourFuckingIPAddress
                }
                
                if ($publicIP) {
                    Write-Success "Public IP: $publicIP"
                    $results.NATTests += @{ PublicIP = $publicIP }
                    break
                }
            } catch {
                # Try next service
                continue
            }
        }
        
        if (-not $publicIP) {
            Write-Warning "Could not detect public IP (network may block outbound HTTP/HTTPS)"
            $results.NATTests += @{ PublicIP = "Unknown" }
        }
        
        # Check if behind NAT
        if ($localIPs -and $publicIP) {
            if ($localIPs -contains $publicIP) {
                Write-Info "Not behind NAT (public IP matches local IP)"
                $results.NATTests += @{ BehindNAT = $false }
            } else {
                Write-Warning "Behind NAT/Firewall (public IP differs from local IP)"
                Write-Info "  Local: $($localIPs[0]), Public: $publicIP"
                $results.NATTests += @{ BehindNAT = $true }
            }
        }
        
    } catch {
        Write-Warning "NAT detection failed: $($_.Exception.Message)"
    }
}

# ============================================================================
# Firewall & Port Rules Check
# ============================================================================
function Test-FirewallRules {
    Write-Header "Windows Firewall Analysis"
    
    try {
        # Check if Windows Firewall is enabled
        $firewallStatus = Get-MpPreference -ErrorAction SilentlyContinue
        
        if ($firewallStatus) {
            Write-Info "Windows Defender Firewall detected"
            Write-Info "  Network Profile: $(Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object -ExpandProperty Name)"
        }
        
        # Check for outbound rules blocking UDP 3478
        Write-Info "Checking for blocking rules on UDP 3478..."
        $outboundRules = Get-NetFirewallRule -Direction Outbound -ErrorAction SilentlyContinue | `
            Where-Object { $_.Enabled -eq $true -and $_.Action -eq "Block" }
        
        if ($outboundRules) {
            foreach ($rule in $outboundRules) {
                Write-Warning "Found blocking rule: $($rule.DisplayName)"
                $results.Summary += "FIREWALL RULE: $($rule.DisplayName) may be blocking WebRTC"
            }
        } else {
            Write-Success "No obvious outbound blocking rules found"
        }
        
        # Check third-party firewalls
        Write-Info "Checking for third-party firewall products..."
        try {
            $antivirus = Get-MpComputerStatus -ErrorAction SilentlyContinue
            if ($antivirus) {
                Write-Info "  Antivirus: $($antivirus.AntivirusSignatureVersion)"
            }
        } catch {}
        
    } catch {
        Write-Warning "Could not check firewall rules (may require elevation)"
    }
}

# ============================================================================
# Generate Report
# ============================================================================
function Write-Report {
    Write-Header "Test Summary & Recommendations"
    
    Write-Host "STUN Servers (NAT Traversal):`n"
    foreach ($test in $results.STUNTests) {
        $status = if ($test.Status -eq "Open") { "✓ OPEN" } else { "✗ BLOCKED" }
        Write-Host "  $status - $($test.Server) ($($test.Host):$($test.Port))"
    }
    
    Write-Host "`nTURN Servers (TCP Fallback):`n"
    foreach ($test in $results.TURNTests) {
        $status = if ($test.Status -eq "Open") { "✓ OPEN" } else { "✗ BLOCKED" }
        Write-Host "  $status - $($test.Server) ($($test.Host):$($test.Port))"
    }
    
    Write-Host "`nNetwork Status:`n"
    foreach ($test in $results.DNSTests) {
        $status = if ($test.Status -eq "Resolved") { "✓ RESOLVED" } else { "✗ FAILED" }
        Write-Host "  $status - $($test.Host)"
    }
    
    Write-Host "`nDiagnosis:`n"
    $stunBlocked = $results.STUNTests | Where-Object { $_.Status -eq "Blocked" } | Measure-Object | Select-Object -ExpandProperty Count
    $turnBlocked = $results.TURNTests | Where-Object { $_.Status -eq "Blocked" } | Measure-Object | Select-Object -ExpandProperty Count
    
    if ($stunBlocked -eq $results.STUNTests.Count -and $turnBlocked -eq $results.TURNTests.Count) {
        Write-Failure "CRITICAL: WebRTC is completely blocked on this network"
        Write-Host "`nAction Items:"
        Write-Host "  1. Contact your network administrator"
        Write-Host "  2. Request opening UDP 3478 outbound to STUN servers"
        Write-Host "  3. Request opening TCP 443/5349 outbound as fallback to TURN servers"
        Write-Host "  4. Re-run this test after firewall changes"
    } elseif ($stunBlocked -gt 0) {
        Write-Warning "PARTIAL BLOCKING: Some WebRTC connections may fail"
        Write-Host "`nAction Items:"
        Write-Host "  1. Request opening all STUN servers (UDP 3478)"
        Write-Host "  2. Ensure TCP 443/5349 is open for TURN fallback"
        Write-Host "  3. Test with multiple connection attempts"
    } else {
        Write-Success "WebRTC ports appear to be accessible"
        Write-Host "`nNo immediate action needed. If WebRTC still fails:"
        Write-Host "  1. Check browser console for specific errors"
        Write-Host "  2. Collect HAR files during failures"
        Write-Host "  3. Contact Cloudflare support with HAR logs"
    }
    
    Write-Host "`nDetailed Results:`n"
    foreach ($item in $results.Summary) {
        Write-Host "  • $item"
    }
}

# ============================================================================
# Main Execution
# ============================================================================

Write-Host "`n" -ForegroundColor Cyan
Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║        WebRTC Port Connectivity Diagnostic Tool               ║" -ForegroundColor Cyan
Write-Host "║              Cloudflare RBI / Browser Isolation              ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host "`n"

Write-Info "Starting WebRTC connectivity diagnostics..."
Write-Info "Test timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Info "Computer: $env:COMPUTERNAME | User: $env:USERNAME`n"

# Run tests
if ($TestDNS) { Test-DNSResolution }
if ($TestSTUN) { Test-STUNConnectivity }
if ($TestTURN) { Test-TURNConnectivity }
if ($TestNAT) { Test-NATDetection; Test-FirewallRules }

# Generate final report
Write-Report

Write-Host "`n" -ForegroundColor Cyan
Write-Host "═════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Diagnostic complete. See results above for detailed analysis." -ForegroundColor Cyan
Write-Host "═════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "`n"
