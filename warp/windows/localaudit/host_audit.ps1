<#
.SYNOPSIS
    Cloudflare WARP Pre-Installation Readiness Assessment v2.0

.DESCRIPTION
    Comprehensive system audit with improved structure and reporting.
    Tests all Cloudflare firewall requirements from official documentation.

.NOTES
    Version: 2.0
    Single-file architecture for easy distribution
    Enhanced reporting with severity-based recommendations
#>

#Requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

# ============================================================================
# CONFIGURATION & INITIALIZATION
# ============================================================================

$script:Config = @{
    Version = "2.0"
    MinWindowsVersion = [Version]"6.2"
    MinDiskSpaceMB = 200
    RequiredArchitectures = @("AMD64", "ARM64")
}

$script:Results = @{
    SystemRequirements = @()
    Services = @()
    Permissions = @()
    NetworkTests = @()
    ProxyConfig = @()
    Diagnostics = @()
}

$script:Stats = @{
    Total = 0; Passed = 0; Failed = 0; Warnings = 0
    CriticalFailures = 0; HighPriorityFailures = 0
}

$script:Env = @{
    IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Hostname = $env:COMPUTERNAME
    Username = $env:USERNAME
    Timestamp = Get-Date
    DateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
}

$script:OutputFolder = Join-Path $PSScriptRoot "warp_audit_$($script:Env.Hostname)_$($script:Env.DateStamp)".ToLower()
$script:CreatedDirs = @()

if (-not (Test-Path $script:OutputFolder)) {
    New-Item -Path $script:OutputFolder -ItemType Directory -Force | Out-Null
}

# ============================================================================
# HELPER FUNCTIONS - TEST RESULT MANAGEMENT
# ============================================================================

function Add-TestResult {
    param(
        [string]$Category, [string]$Test, [string]$Result, [string]$Severity,
        [string]$Details = "", [string]$Value = "", [string]$Impact = "", [string]$Remediation = ""
    )
    
    $obj = [PSCustomObject]@{
        Category = $Category; Test = $Test; Result = $Result; Severity = $Severity
        Details = $Details; Value = $Value; Impact = $Impact; Remediation = $Remediation
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    $script:Stats.Total++
    switch ($Result) {
        "PASS" { $script:Stats.Passed++ }
        "FAIL" { 
            $script:Stats.Failed++
            if ($Severity -eq "Critical") { $script:Stats.CriticalFailures++ }
            if ($Severity -eq "High") { $script:Stats.HighPriorityFailures++ }
        }
        "WARN" { $script:Stats.Warnings++ }
    }
    
    return $obj
}

function Write-TestResult {
    param([PSCustomObject]$Result)
    
    $color = switch ($Result.Result) {
        "PASS" { "Green" }; "FAIL" { "Red" }; "WARN" { "Yellow" }; default { "Cyan" }
    }
    $icon = switch ($Result.Result) {
        "PASS" { "[+]" }; "FAIL" { "[-]" }; "WARN" { "[!]" }; default { "[i]" }
    }
    
    Write-Host "  $icon $($Result.Test)" -ForegroundColor $color
    if ($Result.Value) { Write-Host "      → $($Result.Value)" -ForegroundColor Gray }
    if ($Result.Impact) { Write-Host "      Impact: $($Result.Impact)" -ForegroundColor Gray }
    if ($Result.Remediation) { Write-Host "      Fix: $($Result.Remediation)" -ForegroundColor Gray }
}

# ============================================================================
# HELPER FUNCTIONS - NETWORK TESTING
# ============================================================================

function Test-TcpPort {
    param([string]$Hostname, [int]$Port, [int]$Timeout = 3)
    $tcp = $null
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $async = $tcp.BeginConnect($Hostname, $Port, $null, $null)
        $wait = $async.AsyncWaitHandle.WaitOne([timespan]::FromSeconds($Timeout))
        if ($wait) { $tcp.EndConnect($async); return @{Success=$true; Msg="Connected"} }
        return @{Success=$false; Msg="Timeout"}
    } catch { return @{Success=$false; Msg=$_.Exception.Message} }
    finally { if ($tcp) { $tcp.Close() } }
}

function Test-HttpsEndpoint {
    param([string]$Hostname, [int]$Port = 443, [int]$Timeout = 5)
    $tcp = $null; $ssl = $null
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $async = $tcp.BeginConnect($Hostname, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($Timeout * 1000)) { return @{Success=$false; Msg="Timeout"} }
        $tcp.EndConnect($async)
        $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false)
        $ssl.AuthenticateAsClient($Hostname)
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate)
        return @{Success=$true; Msg="Connected"; Issuer=$cert.Issuer}
    } catch { return @{Success=$false; Msg=$_.Exception.Message} }
    finally { if ($ssl) { $ssl.Close() }; if ($tcp) { $tcp.Close() } }
}

function Test-UdpPort {
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
Write-Host "  CLOUDFLARE WARP READINESS ASSESSMENT v$($script:Config.Version)" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "Hostname:      $($script:Env.Hostname)"
Write-Host "User:          $($script:Env.Username)"
Write-Host "Administrator: $($script:Env.IsAdmin)"
Write-Host "Timestamp:     $($script:Env.Timestamp.ToString('F'))"
Write-Host "Output:        $script:OutputFolder"
Write-Host ""

if (-not $script:Env.IsAdmin) {
    Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
    Write-Host "║  WARNING: Not running as Administrator                    ║" -ForegroundColor Yellow
    Write-Host "║  Some tests may fail. Run as admin for full assessment.   ║" -ForegroundColor Yellow
    Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
    Write-Host ""
}

# ============================================================================
# CATEGORY 1: SYSTEM REQUIREMENTS
# ============================================================================

Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "CATEGORY 1: SYSTEM REQUIREMENTS" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""

# OS Version
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $osVer = [Version]$os.Version
    $meets = $osVer -ge $script:Config.MinWindowsVersion
    
    $r = Add-TestResult -Category "System" -Test "Operating System" `
        -Result $(if ($meets) {"PASS"} else {"FAIL"}) -Severity "Critical" `
        -Value "$($os.Caption) v$osVer Build $($os.BuildNumber)" `
        -Impact $(if (-not $meets) {"WARP requires Windows 8+. Installation will fail"} else {""}) `
        -Remediation $(if (-not $meets) {"Upgrade to Windows 8/10/11"} else {""})
    
    $script:Results.SystemRequirements += $r
    Write-TestResult $r
} catch {
    $r = Add-TestResult -Category "System" -Test "Operating System" -Result "FAIL" -Severity "Critical" `
        -Impact "Cannot determine OS version" -Remediation "Check WMI service"
    $script:Results.SystemRequirements += $r
    Write-TestResult $r
}

# Architecture
$arch = $env:PROCESSOR_ARCHITECTURE
$valid = $arch -in $script:Config.RequiredArchitectures

$r = Add-TestResult -Category "System" -Test "Architecture" `
    -Result $(if ($valid) {"PASS"} else {"FAIL"}) -Severity "Critical" `
    -Value $arch `
    -Impact $(if (-not $valid) {"WARP requires 64-bit Windows"} else {""}) `
    -Remediation $(if (-not $valid) {"Reinstall as 64-bit or use different device"} else {""})

$script:Results.SystemRequirements += $r
Write-TestResult $r

# Disk Space
try {
    $drive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction Stop
    $freeMB = [math]::Round($drive.FreeSpace / 1MB, 2)
    $enough = $freeMB -ge $script:Config.MinDiskSpaceMB
    
    $r = Add-TestResult -Category "System" -Test "Disk Space (C:)" `
        -Result $(if ($enough) {"PASS"} else {"FAIL"}) -Severity "Critical" `
        -Value "$freeMB MB free (need $($script:Config.MinDiskSpaceMB) MB)" `
        -Impact $(if (-not $enough) {"Insufficient space. Installation will fail"} else {""}) `
        -Remediation $(if (-not $enough) {"Free up $($script:Config.MinDiskSpaceMB) MB on C:"} else {""})
    
    $script:Results.SystemRequirements += $r
    Write-TestResult $r
} catch {
    $r = Add-TestResult -Category "System" -Test "Disk Space" -Result "FAIL" -Severity "Critical" `
        -Impact "Cannot check disk space"
    $script:Results.SystemRequirements += $r
    Write-TestResult $r
}

# Existing WARP
$warpReg = "HKLM:\SOFTWARE\Cloudflare\Cloudflare WARP"
$warpSvc = Get-Service -Name "CloudflareWARP" -ErrorAction SilentlyContinue

if (Test-Path $warpReg) {
    $ver = (Get-ItemProperty -Path $warpReg -Name "CurrentVersion" -ErrorAction SilentlyContinue).CurrentVersion
    $r = Add-TestResult -Category "System" -Test "Existing WARP Installation" -Result "WARN" -Severity "Info" `
        -Value $(if ($ver) {"Version $ver"} else {"Installed"}) -Impact "Upgrade scenario"
} elseif ($warpSvc) {
    $r = Add-TestResult -Category "System" -Test "Existing WARP Installation" -Result "WARN" -Severity "Info" `
        -Value "Service: $($warpSvc.Status)" -Impact "Upgrade scenario"
} else {
    $r = Add-TestResult -Category "System" -Test "Existing WARP Installation" -Result "PASS" -Severity "Info" `
        -Value "Not installed" -Impact "Fresh install"
}

$script:Results.SystemRequirements += $r
Write-TestResult $r

# Wintun Driver
try {
    $wintun = Get-CimInstance Win32_PnPSignedDriver -ErrorAction Stop | Where-Object { $_.DeviceName -like "*Wintun*" }
    if ($wintun) {
        $r = Add-TestResult -Category "System" -Test "Wintun Driver" -Result "WARN" -Severity "Medium" `
            -Value "$($wintun.DeviceName) v$($wintun.DriverVersion)" `
            -Impact "Existing driver may conflict" -Remediation "WARP installer will handle updates"
    } else {
        $r = Add-TestResult -Category "System" -Test "Wintun Driver" -Result "PASS" -Severity "Info" `
            -Value "Not installed" -Impact "Clean state"
    }
    $script:Results.SystemRequirements += $r
    Write-TestResult $r
} catch {
    Write-Host "  [!] Could not check Wintun drivers" -ForegroundColor Yellow
}

# PowerShell Version
$psVersion = $PSVersionTable.PSVersion
$psMinVersion = [Version]"5.1"
$psMeets = $psVersion -ge $psMinVersion

$r = Add-TestResult -Category "System" -Test "PowerShell Version" `
    -Result $(if ($psMeets) {"PASS"} else {"FAIL"}) -Severity "High" `
    -Value "v$psVersion" `
    -Impact $(if (-not $psMeets) {"WARP installer may require PowerShell 5.1+"} else {""}) `
    -Remediation $(if (-not $psMeets) {"Update PowerShell to 5.1 or later"} else {""})

$script:Results.SystemRequirements += $r
Write-TestResult $r

# .NET Framework Version
try {
    $dotNetVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -ErrorAction Stop).Release
    $dotNetReadable = switch ($dotNetVersion) {
        {$_ -ge 533320} {"4.8.1 or later"}
        {$_ -ge 528040} {"4.8"}
        {$_ -ge 461808} {"4.7.2"}
        {$_ -ge 461308} {"4.7.1"}
        {$_ -ge 460798} {"4.7"}
        {$_ -ge 394802} {"4.6.2"}
        {$_ -ge 394254} {"4.6.1"}
        {$_ -ge 393295} {"4.6"}
        default {"4.5 or earlier"}
    }
    
    $dotNetOk = $dotNetVersion -ge 394802  # 4.6.2 or later
    
    $r = Add-TestResult -Category "System" -Test ".NET Framework" `
        -Result $(if ($dotNetOk) {"PASS"} else {"WARN"}) -Severity "Medium" `
        -Value "$dotNetReadable (Release: $dotNetVersion)" `
        -Impact $(if (-not $dotNetOk) {"WARP installer may require .NET 4.6.2+"} else {""}) `
        -Remediation $(if (-not $dotNetOk) {"Update .NET Framework to 4.6.2 or later"} else {""})
    
    $script:Results.SystemRequirements += $r
    Write-TestResult $r
} catch {
    $r = Add-TestResult -Category "System" -Test ".NET Framework" -Result "WARN" -Severity "Medium" `
        -Value "Could not determine version" -Impact "May affect installer"
    $script:Results.SystemRequirements += $r
    Write-TestResult $r
}

# TLS 1.2/1.3 Support
try {
    $tls12Enabled = $false
    $tls13Enabled = $false
    
    # Check TLS 1.2
    $tls12Client = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -ErrorAction SilentlyContinue).Enabled
    $tls12ClientDefault = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -ErrorAction SilentlyContinue).DisabledByDefault
    $tls12Enabled = ($tls12Client -eq 1) -or ($tls12Client -eq $null -and $tls12ClientDefault -ne 1)
    
    # Check TLS 1.3
    $tls13Client = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" -ErrorAction SilentlyContinue).Enabled
    $tls13Enabled = ($tls13Client -eq 1)
    
    $tlsStatus = if ($tls13Enabled) {"TLS 1.3 enabled"} elseif ($tls12Enabled) {"TLS 1.2 enabled"} else {"TLS 1.2/1.3 may be disabled"}
    
    $r = Add-TestResult -Category "System" -Test "TLS Protocol Support" `
        -Result $(if ($tls12Enabled) {"PASS"} else {"FAIL"}) -Severity "Critical" `
        -Value $tlsStatus `
        -Impact $(if (-not $tls12Enabled) {"HTTPS connections to Cloudflare will fail"} else {""}) `
        -Remediation $(if (-not $tls12Enabled) {"Enable TLS 1.2 in registry or via Group Policy"} else {""})
    
    $script:Results.SystemRequirements += $r
    Write-TestResult $r
} catch {
    $r = Add-TestResult -Category "System" -Test "TLS Protocol Support" -Result "WARN" -Severity "High" `
        -Value "Could not verify" -Impact "TLS configuration unknown"
    $script:Results.SystemRequirements += $r
    Write-TestResult $r
}

# IPv6 Configuration
try {
    $ipv6Adapters = Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction Stop | Where-Object {$_.Enabled -eq $true}
    $ipv6Enabled = $ipv6Adapters.Count -gt 0
    
    $r = Add-TestResult -Category "System" -Test "IPv6 Configuration" `
        -Result "INFO" -Severity "Info" `
        -Value $(if ($ipv6Enabled) {"Enabled on $($ipv6Adapters.Count) adapter(s)"} else {"Disabled"}) `
        -Impact $(if ($ipv6Enabled) {"WARP can use IPv6"} else {"WARP will use IPv4 only"})
    
    $script:Results.SystemRequirements += $r
    Write-TestResult $r
} catch {
    Write-Host "  [!] Could not check IPv6 configuration" -ForegroundColor Yellow
}

Write-Host ""

# ============================================================================
# CATEGORY 2: REQUIRED SERVICES
# ============================================================================

Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "CATEGORY 2: REQUIRED SERVICES" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""

$services = @(
    @{Name="msiserver"; Display="Windows Installer"; Severity="Critical"; RequiredState="Manual"; 
      Impact="MSI installation will fail"; Remediation="Set-Service msiserver -StartupType Manual"},
    @{Name="BFE"; Display="Base Filtering Engine"; Severity="High"; RequiredState="Running";
      Impact="WARP cannot create firewall rules"; Remediation="Start-Service BFE; Set-Service BFE -StartupType Automatic"},
    @{Name="Dnscache"; Display="DNS Client"; Severity="High"; RequiredState="Running";
      Impact="DNS resolution may fail"; Remediation="Start-Service Dnscache; Set-Service Dnscache -StartupType Automatic"},
    @{Name="NlaSvc"; Display="Network Location Awareness"; Severity="Critical"; RequiredState="Manual";
      Impact="WARP cannot detect network changes"; Remediation="Set-Service NlaSvc -StartupType Automatic"},
    @{Name="nsi"; Display="Network Store Interface Service"; Severity="Critical"; RequiredState="Running";
      Impact="Network stack will not function"; Remediation="Start-Service nsi; Set-Service nsi -StartupType Automatic"},
    @{Name="CryptSvc"; Display="Cryptographic Services"; Severity="High"; RequiredState="Running";
      Impact="Certificate validation will fail"; Remediation="Start-Service CryptSvc; Set-Service CryptSvc -StartupType Automatic"},
    @{Name="W32Time"; Display="Windows Time"; Severity="High"; RequiredState="Running";
      Impact="Time sync issues may break TLS/certificates"; Remediation="Start-Service W32Time; Set-Service W32Time -StartupType Automatic"},
    @{Name="RpcSs"; Display="Remote Procedure Call (RPC)"; Severity="Critical"; RequiredState="Running";
      Impact="Core Windows functionality will fail"; Remediation="Start-Service RpcSs"},
    @{Name="Dhcp"; Display="DHCP Client"; Severity="High"; RequiredState="Running";
      Impact="Network configuration may fail"; Remediation="Start-Service Dhcp; Set-Service Dhcp -StartupType Automatic"},
    @{Name="WlanSvc"; Display="WLAN AutoConfig"; Severity="Low"; RequiredState="Running"; Optional=$true;
      Impact="WARP daemon may not start (affects laptops)"; Remediation="Start-Service WlanSvc"}
)

foreach ($svc in $services) {
    try {
        $service = Get-Service -Name $svc.Name -ErrorAction Stop
        $status = $service.Status.ToString()
        $startType = $service.StartType.ToString()
        
        $healthy = if ($svc.Name -in @("msiserver", "NlaSvc")) {
            $startType -in @("Manual", "Automatic") -or $status -eq "Running"
        } else {
            $status -eq "Running"
        }
        
        $r = Add-TestResult -Category "Services" -Test $svc.Display `
            -Result $(if ($healthy) {"PASS"} else {"FAIL"}) -Severity $svc.Severity `
            -Value "$status ($startType)" `
            -Impact $(if (-not $healthy) {$svc.Impact} else {""}) `
            -Remediation $(if (-not $healthy) {$svc.Remediation} else {""})
        
        $script:Results.Services += $r
        Write-TestResult $r
        
    } catch {
        if ($svc.Optional) {
            $r = Add-TestResult -Category "Services" -Test $svc.Display -Result "WARN" -Severity "Low" `
                -Value "Not installed (optional)" -Impact "May affect laptops"
        } else {
            $r = Add-TestResult -Category "Services" -Test $svc.Display -Result "FAIL" -Severity $svc.Severity `
                -Value "Not found" -Impact $svc.Impact -Remediation "Verify Windows installation"
        }
        $script:Results.Services += $r
        Write-TestResult $r
    }
}

Write-Host ""

# ============================================================================
# CATEGORY 3: FILESYSTEM & REGISTRY PERMISSIONS
# ============================================================================

Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "CATEGORY 3: PERMISSIONS" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""

$paths = @(
    @{Path="C:\Program Files\Cloudflare"; Purpose="Application binaries"},
    @{Path="C:\ProgramData\Cloudflare"; Purpose="Configuration and logs"},
    @{Path="C:\Windows\Installer"; Purpose="MSI installation"}
)

foreach ($pathInfo in $paths) {
    $existed = Test-Path $pathInfo.Path
    try {
        if (-not $existed) {
            New-Item -Path $pathInfo.Path -ItemType Directory -Force -ErrorAction Stop | Out-Null
            $script:CreatedDirs += $pathInfo.Path
        }
        
        $testFile = Join-Path $pathInfo.Path "warp_test_$(Get-Random).tmp"
        New-Item -Path $testFile -ItemType File -Force -ErrorAction Stop | Out-Null
        Remove-Item -Path $testFile -Force -ErrorAction Stop
        
        $r = Add-TestResult -Category "Permissions" -Test "Filesystem Write" `
            -Result "PASS" -Severity "Critical" `
            -Value $pathInfo.Path -Details $pathInfo.Purpose
        
        $script:Results.Permissions += $r
        Write-TestResult $r
        
    } catch {
        $r = Add-TestResult -Category "Permissions" -Test "Filesystem Write" `
            -Result "FAIL" -Severity "Critical" `
            -Value $pathInfo.Path -Details $pathInfo.Purpose `
            -Impact "WARP cannot install files in this location" `
            -Remediation "Run as Administrator or check folder permissions"
        
        $script:Results.Permissions += $r
        Write-TestResult $r
    }
}

# Registry Access
$certStore = "HKLM:\SOFTWARE\Microsoft\SystemCertificates"
$testKey = Join-Path $certStore "WARP_Test_$(Get-Random)"

try {
    New-Item -Path $testKey -Force -ErrorAction Stop | Out-Null
    Remove-Item -Path $testKey -Force -ErrorAction SilentlyContinue
    
    $r = Add-TestResult -Category "Permissions" -Test "Registry Write (Cert Store)" `
        -Result "PASS" -Severity "High" -Value $certStore
    
    $script:Results.Permissions += $r
    Write-TestResult $r
    
} catch {
    $r = Add-TestResult -Category "Permissions" -Test "Registry Write (Cert Store)" `
        -Result "FAIL" -Severity "High" -Value $certStore `
        -Impact "WARP cannot install root CA certificates" `
        -Remediation "Run as Administrator"
    
    $script:Results.Permissions += $r
    Write-TestResult $r
}

# Critical DLLs
$dlls = @("dnsapi.dll", "dhcpcsvc.dll", "dhcpcsvc6.dll")
foreach ($dll in $dlls) {
    $path = "C:\Windows\System32\$dll"
    $exists = Test-Path $path
    
    $r = Add-TestResult -Category "Permissions" -Test "System DLL" `
        -Result $(if ($exists) {"PASS"} else {"FAIL"}) -Severity "Critical" `
        -Value $dll -Details $(if ($exists) {"Found"} else {"Missing"}) `
        -Impact $(if (-not $exists) {"Critical system file missing"} else {""}) `
        -Remediation $(if (-not $exists) {"Run: sfc /scannow"} else {""})
    
    $script:Results.Permissions += $r
    Write-TestResult $r
}

Write-Host ""

# ============================================================================
# CATEGORY 4: PROXY CONFIGURATION
# ============================================================================

Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "CATEGORY 4: PROXY CONFIGURATION" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""

$proxyReport = @()

# System Proxy (WinHTTP)
try {
    $winHttp = & netsh winhttp show proxy 2>$null
    $proxyReport += "=== SYSTEM PROXY (WinHTTP) ==="
    $proxyReport += $winHttp
    $proxyReport += ""
    
    if ($winHttp -match "Proxy Server\(s\)\s*:\s*(.+)") {
        $proxyServer = $matches[1].Trim()
        if ($proxyServer -and $proxyServer -notmatch "Direct access") {
            $r = Add-TestResult -Category "Proxy" -Test "System Proxy (WinHTTP)" `
                -Result "WARN" -Severity "High" `
                -Value $proxyServer `
                -Impact "WARP traffic may be routed through proxy. Installation may fail if proxy blocks Cloudflare" `
                -Remediation "Disable system proxy or configure WARP split tunneling"
            
            $script:Results.ProxyConfig += $r
            Write-TestResult $r
        } else {
            $r = Add-TestResult -Category "Proxy" -Test "System Proxy (WinHTTP)" `
                -Result "PASS" -Severity "Info" -Value "Direct connection"
            $script:Results.ProxyConfig += $r
            Write-TestResult $r
        }
    }
} catch {
    Write-Host "  [!] Could not check system proxy" -ForegroundColor Yellow
}

# User Proxy (Internet Settings)
try {
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    $proxyEnable = (Get-ItemProperty -Path $regPath -Name ProxyEnable -ErrorAction SilentlyContinue).ProxyEnable
    $proxyServer = (Get-ItemProperty -Path $regPath -Name ProxyServer -ErrorAction SilentlyContinue).ProxyServer
    $autoConfigURL = (Get-ItemProperty -Path $regPath -Name AutoConfigURL -ErrorAction SilentlyContinue).AutoConfigURL
    
    $proxyReport += "=== WINDOWS INTERNET SETTINGS (User-Level) ==="
    $proxyReport += "Registry: HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    $proxyReport += "Affects: IE, Edge (when using system proxy), WinINet apps, .NET apps"
    $proxyReport += "ProxyEnable: $proxyEnable"
    $proxyReport += "ProxyServer: $proxyServer"
    $proxyReport += "AutoConfigURL: $autoConfigURL"
    $proxyReport += ""
    
    if ($proxyEnable -eq 1 -and $proxyServer) {
        $r = Add-TestResult -Category "Proxy" -Test "Windows Internet Settings Proxy" `
            -Result "WARN" -Severity "High" `
            -Value $proxyServer `
            -Impact "System-wide proxy affects IE, Edge (system mode), and WinINet apps. May bypass WARP tunnel" `
            -Remediation "Disable proxy in Internet Options (inetcpl.cpl) or Windows Settings"
        
        $script:Results.ProxyConfig += $r
        Write-TestResult $r
        
    } elseif ($autoConfigURL) {
        $r = Add-TestResult -Category "Proxy" -Test "Windows Internet Settings PAC" `
            -Result "WARN" -Severity "High" `
            -Value $autoConfigURL `
            -Impact "System-wide PAC file affects IE, Edge (system mode), and WinINet apps. May route traffic around WARP" `
            -Remediation "Review PAC file or disable auto-config in Internet Options"
        
        $script:Results.ProxyConfig += $r
        Write-TestResult $r
        
    } else {
        $r = Add-TestResult -Category "Proxy" -Test "Windows Internet Settings Proxy" `
            -Result "PASS" -Severity "Info" -Value "Direct connection"
        $script:Results.ProxyConfig += $r
        Write-TestResult $r
    }
} catch {
    Write-Host "  [!] Could not check user proxy" -ForegroundColor Yellow
}

# Microsoft Edge (Chromium) Browser Proxy
try {
    $edgeProxyFound = $false
    $edgeProxyDetails = @()
    
    # Edge stores proxy settings in Preferences file (JSON)
    $edgePaths = @(
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Preferences",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Profile 1\Preferences"
    )
    
    $proxyReport += "=== MICROSOFT EDGE (CHROMIUM) PROXY ==="
    
    foreach ($edgePath in $edgePaths) {
        if (Test-Path $edgePath) {
            try {
                $edgePrefs = Get-Content $edgePath -Raw -ErrorAction Stop | ConvertFrom-Json
                
                if ($edgePrefs.proxy) {
                    $proxyMode = $edgePrefs.proxy.mode
                    $proxyServer = $edgePrefs.proxy.server
                    $proxyPacUrl = $edgePrefs.proxy.pac_url
                    
                    if ($proxyMode -and $proxyMode -ne "direct" -and $proxyMode -ne "system") {
                        $edgeProxyFound = $true
                        $edgeProxyDetails += "Profile: $(Split-Path (Split-Path $edgePath) -Leaf)"
                        $edgeProxyDetails += "Mode: $proxyMode"
                        if ($proxyServer) { $edgeProxyDetails += "Server: $proxyServer" }
                        if ($proxyPacUrl) { $edgeProxyDetails += "PAC URL: $proxyPacUrl" }
                    }
                }
            } catch {
                # JSON parsing may fail, continue
            }
        }
    }
    
    # Check Edge policy-based proxy (enterprise deployments)
    $edgePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    if (Test-Path $edgePolicyPath) {
        $proxyMode = (Get-ItemProperty -Path $edgePolicyPath -Name ProxyMode -ErrorAction SilentlyContinue).ProxyMode
        $proxyServer = (Get-ItemProperty -Path $edgePolicyPath -Name ProxyServer -ErrorAction SilentlyContinue).ProxyServer
        $proxyPacUrl = (Get-ItemProperty -Path $edgePolicyPath -Name ProxyPacUrl -ErrorAction SilentlyContinue).ProxyPacUrl
        
        if ($proxyMode -and $proxyMode -ne "direct" -and $proxyMode -ne "system") {
            $edgeProxyFound = $true
            $edgeProxyDetails += "Policy-enforced proxy detected"
            $edgeProxyDetails += "Mode: $proxyMode"
            if ($proxyServer) { $edgeProxyDetails += "Server: $proxyServer" }
            if ($proxyPacUrl) { $edgeProxyDetails += "PAC URL: $proxyPacUrl" }
        }
    }
    
    if ($edgeProxyFound) {
        $proxyReport += $edgeProxyDetails
        
        $r = Add-TestResult -Category "Proxy" -Test "Edge Browser Proxy" `
            -Result "WARN" -Severity "High" `
            -Value ($edgeProxyDetails -join "; ") `
            -Impact "Edge traffic may bypass WARP tunnel or conflict with WARP settings" `
            -Remediation "Review Edge proxy settings (edge://settings/system) or Group Policy"
        
        $script:Results.ProxyConfig += $r
        Write-TestResult $r
    } else {
        $proxyReport += "No Edge-specific proxy detected (may use system settings)"
        
        $r = Add-TestResult -Category "Proxy" -Test "Edge Browser Proxy" `
            -Result "PASS" -Severity "Info" -Value "Using system settings or direct connection"
        $script:Results.ProxyConfig += $r
        Write-TestResult $r
    }
    $proxyReport += ""
} catch {
    Write-Host "  [!] Could not check Edge proxy settings" -ForegroundColor Yellow
    $proxyReport += "Error checking Edge proxy"
    $proxyReport += ""
}

# Chrome Browser Proxy
try {
    $chromeProxyFound = $false
    $chromeProxyDetails = @()
    
    # Chrome stores proxy settings in Preferences file (JSON)
    $chromePaths = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Preferences",
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Profile 1\Preferences"
    )
    
    $proxyReport += "=== CHROME BROWSER PROXY ==="
    
    foreach ($chromePath in $chromePaths) {
        if (Test-Path $chromePath) {
            try {
                $chromePrefs = Get-Content $chromePath -Raw -ErrorAction Stop | ConvertFrom-Json
                
                # Check proxy settings in Chrome preferences
                if ($chromePrefs.proxy) {
                    $proxyMode = $chromePrefs.proxy.mode
                    $proxyServer = $chromePrefs.proxy.server
                    $proxyPacUrl = $chromePrefs.proxy.pac_url
                    
                    if ($proxyMode -and $proxyMode -ne "direct" -and $proxyMode -ne "system") {
                        $chromeProxyFound = $true
                        $chromeProxyDetails += "Profile: $(Split-Path (Split-Path $chromePath) -Leaf)"
                        $chromeProxyDetails += "Mode: $proxyMode"
                        if ($proxyServer) { $chromeProxyDetails += "Server: $proxyServer" }
                        if ($proxyPacUrl) { $chromeProxyDetails += "PAC URL: $proxyPacUrl" }
                    }
                }
            } catch {
                # JSON parsing may fail, continue
            }
        }
    }
    
    # Also check Chrome policy-based proxy (enterprise deployments)
    $chromePolicyPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
    if (Test-Path $chromePolicyPath) {
        $proxyMode = (Get-ItemProperty -Path $chromePolicyPath -Name ProxyMode -ErrorAction SilentlyContinue).ProxyMode
        $proxyServer = (Get-ItemProperty -Path $chromePolicyPath -Name ProxyServer -ErrorAction SilentlyContinue).ProxyServer
        $proxyPacUrl = (Get-ItemProperty -Path $chromePolicyPath -Name ProxyPacUrl -ErrorAction SilentlyContinue).ProxyPacUrl
        
        if ($proxyMode -and $proxyMode -ne "direct" -and $proxyMode -ne "system") {
            $chromeProxyFound = $true
            $chromeProxyDetails += "Policy-enforced proxy detected"
            $chromeProxyDetails += "Mode: $proxyMode"
            if ($proxyServer) { $chromeProxyDetails += "Server: $proxyServer" }
            if ($proxyPacUrl) { $chromeProxyDetails += "PAC URL: $proxyPacUrl" }
        }
    }
    
    if ($chromeProxyFound) {
        $proxyReport += $chromeProxyDetails
        
        $r = Add-TestResult -Category "Proxy" -Test "Chrome Browser Proxy" `
            -Result "WARN" -Severity "High" `
            -Value ($chromeProxyDetails -join "; ") `
            -Impact "Chrome traffic may bypass WARP tunnel or conflict with WARP settings" `
            -Remediation "Review Chrome proxy settings (chrome://settings/system) or Group Policy"
        
        $script:Results.ProxyConfig += $r
        Write-TestResult $r
    } else {
        $proxyReport += "No Chrome-specific proxy detected (may use system settings)"
        
        $r = Add-TestResult -Category "Proxy" -Test "Chrome Browser Proxy" `
            -Result "PASS" -Severity "Info" -Value "Using system settings or direct connection"
        $script:Results.ProxyConfig += $r
        Write-TestResult $r
    }
    $proxyReport += ""
} catch {
    Write-Host "  [!] Could not check Chrome proxy settings" -ForegroundColor Yellow
    $proxyReport += "Error checking Chrome proxy"
    $proxyReport += ""
}

# Firefox Browser Proxy
try {
    $firefoxProxyFound = $false
    $firefoxProxyDetails = @()
    
    $firefoxProfilePath = "$env:APPDATA\Mozilla\Firefox\Profiles"
    $proxyReport += "=== FIREFOX BROWSER PROXY ==="
    
    if (Test-Path $firefoxProfilePath) {
        $profiles = Get-ChildItem $firefoxProfilePath -Directory -ErrorAction SilentlyContinue
        foreach ($profile in $profiles) {
            $prefsFile = Join-Path $profile.FullName "prefs.js"
            if (Test-Path $prefsFile) {
                $prefsContent = Get-Content $prefsFile -ErrorAction SilentlyContinue
                $proxyType = $prefsContent | Select-String 'user_pref\("network.proxy.type",\s*(\d+)\)' | ForEach-Object {$_.Matches.Groups[1].Value}
                
                if ($proxyType -and $proxyType -ne "0" -and $proxyType -ne "5") {
                    $firefoxProxyFound = $true
                    $firefoxProxyDetails += "Profile: $($profile.Name)"
                    $firefoxProxyDetails += "Type: $(switch($proxyType){'1'{'Manual'};'2'{'PAC'};'4'{'WPAD'};default{$proxyType}})"
                    
                    if ($proxyType -eq "1") {
                        $httpProxy = $prefsContent | Select-String 'user_pref\("network.proxy.http",\s*"([^"]+)"\)' | ForEach-Object {$_.Matches.Groups[1].Value}
                        if ($httpProxy) { $firefoxProxyDetails += "HTTP Proxy: $httpProxy" }
                    }
                }
            }
        }
    }
    
    if ($firefoxProxyFound) {
        $proxyReport += $firefoxProxyDetails
        
        $r = Add-TestResult -Category "Proxy" -Test "Firefox Browser Proxy" `
            -Result "WARN" -Severity "High" `
            -Value ($firefoxProxyDetails -join "; ") `
            -Impact "Firefox traffic may bypass WARP tunnel" `
            -Remediation "Review Firefox proxy settings (about:preferences#general > Network Settings)"
        
        $script:Results.ProxyConfig += $r
        Write-TestResult $r
    } else {
        $proxyReport += "No Firefox-specific proxy detected"
        
        $r = Add-TestResult -Category "Proxy" -Test "Firefox Browser Proxy" `
            -Result "PASS" -Severity "Info" -Value "No custom proxy or Firefox not installed"
        $script:Results.ProxyConfig += $r
        Write-TestResult $r
    }
    $proxyReport += ""
} catch {
    Write-Host "  [!] Could not check Firefox proxy settings" -ForegroundColor Yellow
    $proxyReport += "Error checking Firefox proxy"
    $proxyReport += ""
}

# VPN Client Detection
try {
    $vpnDetected = @()
    $proxyReport += "=== VPN CLIENT DETECTION ==="
    
    # Check for common VPN network adapters
    $vpnAdapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
        $_.InterfaceDescription -match "VPN|TAP|TUN|WireGuard|OpenVPN|Cisco|FortiClient|Pulse|GlobalProtect|NordVPN|ExpressVPN|ProtonVPN"
    }
    
    if ($vpnAdapters) {
        foreach ($adapter in $vpnAdapters) {
            $vpnDetected += "$($adapter.Name) ($($adapter.InterfaceDescription))"
        }
    }
    
    # Check for common VPN services
    $vpnServices = @("OpenVPNService", "CiscoVPN", "FortiClient", "PulseSecureService", "NordVPN", "ExpressVPN")
    foreach ($svcName in $vpnServices) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc) {
            $vpnDetected += "$($svc.DisplayName) service ($($svc.Status))"
        }
    }
    
    if ($vpnDetected.Count -gt 0) {
        $proxyReport += $vpnDetected
        
        $r = Add-TestResult -Category "Proxy" -Test "VPN Client Detection" `
            -Result "WARN" -Severity "High" `
            -Value "$($vpnDetected.Count) VPN client(s) detected" `
            -Details ($vpnDetected -join "; ") `
            -Impact "VPN may conflict with WARP tunnel. Only one VPN can be active at a time" `
            -Remediation "Disable other VPN clients before using WARP"
        
        $script:Results.ProxyConfig += $r
        Write-TestResult $r
    } else {
        $proxyReport += "No VPN clients detected"
        
        $r = Add-TestResult -Category "Proxy" -Test "VPN Client Detection" `
            -Result "PASS" -Severity "Info" -Value "No conflicting VPN clients"
        $script:Results.ProxyConfig += $r
        Write-TestResult $r
    }
    $proxyReport += ""
} catch {
    Write-Host "  [!] Could not check for VPN clients" -ForegroundColor Yellow
    $proxyReport += "Error checking VPN clients"
    $proxyReport += ""
}

# Environment Variables
$envProxies = @()
if ($env:HTTP_PROXY) { $envProxies += "HTTP_PROXY=$($env:HTTP_PROXY)" }
if ($env:HTTPS_PROXY) { $envProxies += "HTTPS_PROXY=$($env:HTTPS_PROXY)" }
if ($env:NO_PROXY) { $envProxies += "NO_PROXY=$($env:NO_PROXY)" }

$proxyReport += "=== ENVIRONMENT PROXY VARIABLES ==="
if ($envProxies.Count -gt 0) {
    $proxyReport += $envProxies
    
    $r = Add-TestResult -Category "Proxy" -Test "Environment Variables" `
        -Result "WARN" -Severity "Medium" `
        -Value ($envProxies -join "; ") `
        -Impact "CLI tools may use these proxies" `
        -Remediation "Unset environment variables if not needed"
    
    $script:Results.ProxyConfig += $r
    Write-TestResult $r
} else {
    $proxyReport += "None detected"
    
    $r = Add-TestResult -Category "Proxy" -Test "Environment Variables" `
        -Result "PASS" -Severity "Info" -Value "None"
    $script:Results.ProxyConfig += $r
    Write-TestResult $r
}

# Save proxy report
$proxyReport | Out-File (Join-Path $script:OutputFolder "proxy_configuration.txt") -ErrorAction SilentlyContinue

Write-Host ""

# ============================================================================
# CATEGORY 5: CERTIFICATE & SECURITY
# ============================================================================

Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "CATEGORY 5: CERTIFICATE & SECURITY" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""

# Windows Certificate Store Health
try {
    $certStores = @("Root", "CA", "My")
    $certCounts = @{}
    $storeHealthy = $true
    
    foreach ($storeName in $certStores) {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, "LocalMachine")
        $store.Open("ReadOnly")
        $certCounts[$storeName] = $store.Certificates.Count
        $store.Close()
        
        if ($certCounts[$storeName] -eq 0 -and $storeName -eq "Root") {
            $storeHealthy = $false
        }
    }
    
    $r = Add-TestResult -Category "Security" -Test "Certificate Store Health" `
        -Result $(if ($storeHealthy) {"PASS"} else {"FAIL"}) -Severity "Critical" `
        -Value "Root: $($certCounts['Root']), CA: $($certCounts['CA']), Personal: $($certCounts['My'])" `
        -Impact $(if (-not $storeHealthy) {"TLS/SSL connections will fail"} else {""}) `
        -Remediation $(if (-not $storeHealthy) {"Reinstall root certificates or repair Windows"} else {""})
    
    $script:Results.Permissions += $r
    Write-TestResult $r
} catch {
    $r = Add-TestResult -Category "Security" -Test "Certificate Store Health" -Result "FAIL" -Severity "Critical" `
        -Value "Cannot access certificate store" -Impact "TLS/SSL will not function"
    $script:Results.Permissions += $r
    Write-TestResult $r
}

# Cloudflare Root CA Check
try {
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
    $store.Open("ReadOnly")
    $cloudflareCA = $store.Certificates | Where-Object {
        $_.Subject -like "*Cloudflare*" -or $_.Issuer -like "*DigiCert*" -or $_.Issuer -like "*Baltimore*"
    }
    $store.Close()
    
    $hasTrustedRoots = $cloudflareCA.Count -gt 0
    
    $r = Add-TestResult -Category "Security" -Test "Trusted Root CAs" `
        -Result $(if ($hasTrustedRoots) {"PASS"} else {"WARN"}) -Severity "Medium" `
        -Value "$($cloudflareCA.Count) relevant root CA(s) found" `
        -Impact $(if (-not $hasTrustedRoots) {"May need to install Cloudflare root CA"} else {""}) `
        -Remediation $(if (-not $hasTrustedRoots) {"WARP installer will add required certificates"} else {""})
    
    $script:Results.Permissions += $r
    Write-TestResult $r
} catch {
    Write-Host "  [!] Could not check root CAs" -ForegroundColor Yellow
}

# Certificate Revocation Checking
try {
    $crlCheck = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CertDllCreateCertificateChainEngine\Config" -ErrorAction SilentlyContinue).MaxUrlRetrievalByteCount
    $ocspEnabled = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\ChainEngine\Config" -ErrorAction SilentlyContinue).EnableOcspStaplingForSni
    
    $revocationEnabled = ($crlCheck -ne 0) -or ($ocspEnabled -eq $null)
    
    $r = Add-TestResult -Category "Security" -Test "Certificate Revocation Checking" `
        -Result "INFO" -Severity "Info" `
        -Value $(if ($revocationEnabled) {"Enabled"} else {"Disabled"}) `
        -Impact "Affects certificate validation security"
    
    $script:Results.Permissions += $r
    Write-TestResult $r
} catch {
    Write-Host "  [!] Could not check revocation settings" -ForegroundColor Yellow
}

# Windows Defender Status
try {
    $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
    $defenderEnabled = $defenderStatus.AntivirusEnabled
    $realtimeEnabled = $defenderStatus.RealTimeProtectionEnabled
    
    $r = Add-TestResult -Category "Security" -Test "Windows Defender" `
        -Result "INFO" -Severity "Info" `
        -Value $(if ($defenderEnabled) {"Enabled (Realtime: $realtimeEnabled)"} else {"Disabled"}) `
        -Impact "Antivirus may scan WARP traffic"
    
    $script:Results.Permissions += $r
    Write-TestResult $r
} catch {
    $r = Add-TestResult -Category "Security" -Test "Windows Defender" -Result "INFO" -Severity "Info" `
        -Value "Status unknown or third-party AV installed"
    $script:Results.Permissions += $r
    Write-TestResult $r
}

# Windows Firewall Status
try {
    $fwProfiles = Get-NetFirewallProfile -ErrorAction Stop
    $fwStatus = @()
    foreach ($profile in $fwProfiles) {
        $fwStatus += "$($profile.Name): $(if ($profile.Enabled) {'ON'} else {'OFF'})"
    }
    
    $r = Add-TestResult -Category "Security" -Test "Windows Firewall" `
        -Result "INFO" -Severity "Info" `
        -Value ($fwStatus -join ", ") `
        -Impact "Firewall rules may need WARP exceptions"
    
    $script:Results.Permissions += $r
    Write-TestResult $r
} catch {
    Write-Host "  [!] Could not check firewall status" -ForegroundColor Yellow
}

# Time Synchronization
try {
    $w32tm = & w32tm /query /status 2>&1
    $timeSource = $w32tm | Select-String "Source:" | ForEach-Object {$_.ToString().Split(':')[1].Trim()}
    $lastSync = $w32tm | Select-String "Last Successful Sync Time:" | ForEach-Object {$_.ToString().Split(':', 2)[1].Trim()}
    
    $timeSynced = $timeSource -and $timeSource -ne "Local CMOS Clock" -and $timeSource -ne "Free-Running System Clock"
    
    $r = Add-TestResult -Category "Security" -Test "Time Synchronization" `
        -Result $(if ($timeSynced) {"PASS"} else {"WARN"}) -Severity "High" `
        -Value "Source: $timeSource" `
        -Details "Last sync: $lastSync" `
        -Impact $(if (-not $timeSynced) {"Clock skew will break TLS certificate validation"} else {""}) `
        -Remediation $(if (-not $timeSynced) {"Enable Windows Time service and sync with time server"} else {""})
    
    $script:Results.Permissions += $r
    Write-TestResult $r
} catch {
    $r = Add-TestResult -Category "Security" -Test "Time Synchronization" -Result "WARN" -Severity "High" `
        -Value "Could not verify time sync" -Impact "Time sync issues may affect TLS"
    $script:Results.Permissions += $r
    Write-TestResult $r
}

Write-Host ""

# ============================================================================
# CATEGORY 6: NETWORK CONNECTIVITY (CLOUDFLARE ENDPOINTS)
# ============================================================================

Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "CATEGORY 6: NETWORK CONNECTIVITY" -ForegroundColor Cyan
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

# TEST 5.1: Client Orchestration API
Write-Host "  [5.1] Client Orchestration API" -ForegroundColor Yellow

$apiEndpoints = @(
    @{Host="zero-trust-client.cloudflareclient.com"; IPs=@("162.159.137.105","162.159.138.105"); Purpose="Registration & Settings"},
    @{Host="notifications.cloudflareclient.com"; IPs=@("162.159.137.105"); Purpose="Push Notifications"}
)

foreach ($endpoint in $apiEndpoints) {
    $dnsResult = Test-DnsResolve -Hostname $endpoint.Host
    $httpsResult = Test-HttpsEndpoint -Hostname $endpoint.Host
    
    $r = Add-TestResult -Category "Network" -Test "API: $($endpoint.Purpose)" `
        -Result $(if ($httpsResult.Success) {"PASS"} else {"FAIL"}) -Severity "Critical" `
        -Value "$($endpoint.Host):443" -Details $httpsResult.Msg `
        -Impact $(if (-not $httpsResult.Success) {"WARP cannot $($endpoint.Purpose.ToLower()). Installation will fail"} else {""}) `
        -Remediation $(if (-not $httpsResult.Success) {"Allow HTTPS to $($endpoint.Host) and IPs: $($endpoint.IPs -join ', ')"} else {""})
    
    $script:Results.NetworkTests += $r
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

# TEST 5.2: WireGuard Tunnel Ingress
Write-Host "  [5.2] WireGuard Tunnel (162.159.193.0/24)" -ForegroundColor Yellow

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

$r = Add-TestResult -Category "Network" -Test "WireGuard Tunnel Ingress" `
    -Result $(if ($wgHealthy) {"PASS"} else {"FAIL"}) -Severity "Critical" `
    -Value "$wgSuccess/$wgTotal UDP tests passed" `
    -Details "Ports 2408,500,1701,4500 on 162.159.193.0/24" `
    -Impact $(if (-not $wgHealthy) {"WARP cannot establish WireGuard tunnel"} else {""}) `
    -Remediation $(if (-not $wgHealthy) {"Allow UDP ports 2408,500,1701,4500 to 162.159.193.0/24"} else {""})

$script:Results.NetworkTests += $r
Write-TestResult $r

Write-Host ""

# TEST 5.3: MASQUE Tunnel Ingress
Write-Host "  [5.3] MASQUE Tunnel (162.159.197.0/24)" -ForegroundColor Yellow

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

$r = Add-TestResult -Category "Network" -Test "MASQUE Tunnel Ingress" `
    -Result $(if ($mqHealthy) {"PASS"} else {"FAIL"}) -Severity "Critical" `
    -Value "$mqSuccess/$mqTotal tests passed" `
    -Details "UDP/TCP ports on 162.159.197.0/24" `
    -Impact $(if (-not $mqHealthy) {"WARP cannot establish MASQUE tunnel"} else {""}) `
    -Remediation $(if (-not $mqHealthy) {"Allow UDP 443,500,1701,4500,4443,8443,8095 and TCP 443 to 162.159.197.0/24"} else {""})

$script:Results.NetworkTests += $r
Write-TestResult $r

Write-Host ""

# TEST 5.4: Connectivity Checks
Write-Host "  [5.4] Connectivity Checks" -ForegroundColor Yellow

$connResult = Test-TcpPort -Hostname "162.159.197.3" -Port 443

$r = Add-TestResult -Category "Network" -Test "Connectivity Check Endpoint" `
    -Result $(if ($connResult.Success) {"PASS"} else {"FAIL"}) -Severity "High" `
    -Value "162.159.197.3:443" -Details $connResult.Msg `
    -Impact $(if (-not $connResult.Success) {"WARP connectivity checks will fail"} else {""}) `
    -Remediation $(if (-not $connResult.Success) {"Allow HTTPS to 162.159.197.3"} else {""})

$script:Results.NetworkTests += $r
Write-TestResult $r

$engageDns = Test-DnsResolve -Hostname "engage.cloudflareclient.com"
if ($engageDns.Success) {
    $engageUdp = Test-UdpPort -IP $engageDns.IPs[0] -Port 2408
    
    $r = Add-TestResult -Category "Network" -Test "Tunnel Establishment" `
        -Result $(if ($engageUdp.Success) {"PASS"} else {"FAIL"}) -Severity "High" `
        -Value "engage.cloudflareclient.com:2408" -Details $engageUdp.Msg `
        -Impact $(if (-not $engageUdp.Success) {"WARP tunnel establishment may fail"} else {""}) `
        -Remediation $(if (-not $engageUdp.Success) {"Allow UDP 2408 to engage.cloudflareclient.com"} else {""})
} else {
    $r = Add-TestResult -Category "Network" -Test "Tunnel Establishment" `
        -Result "FAIL" -Severity "High" `
        -Value "engage.cloudflareclient.com" -Details $engageDns.Msg `
        -Impact "Cannot resolve tunnel endpoint" `
        -Remediation "Check DNS settings"
}

$script:Results.NetworkTests += $r
Write-TestResult $r

Write-Host ""

# TEST 5.5: Captive Portal Detection
Write-Host "  [5.5] Captive Portal Detection" -ForegroundColor Yellow

$captiveDomains = @("cloudflareportal.com", "cloudflareok.com", "cloudflarecp.com", 
                    "www.msftconnecttest.com", "captive.apple.com", "connectivitycheck.gstatic.com")
$captiveSuccess = 0

foreach ($domain in $captiveDomains) {
    $dnsResult = Test-DnsResolve -Hostname $domain
    if ($dnsResult.Success) { $captiveSuccess++ }
}

$r = Add-TestResult -Category "Network" -Test "Captive Portal Detection" `
    -Result $(if ($captiveSuccess -ge 3) {"PASS"} else {"WARN"}) -Severity "Low" `
    -Value "$captiveSuccess/$($captiveDomains.Count) domains resolved" `
    -Impact $(if ($captiveSuccess -lt 3) {"Captive portal detection may not work"} else {""}) `
    -Remediation $(if ($captiveSuccess -lt 3) {"Verify DNS resolution"} else {""})

$script:Results.NetworkTests += $r
Write-TestResult $r

Write-Host ""

# TEST 5.6: Additional Endpoints
Write-Host "  [5.6] Additional Endpoints" -ForegroundColor Yellow

$additionalEndpoints = @(
    @{Host="api.cloudflareclient.com"; Purpose="Registration"; Optional=$false},
    @{Host="client.warp.cloudflare.com"; Purpose="Updates/Telemetry"; Optional=$true}
)

foreach ($endpoint in $additionalEndpoints) {
    $dnsResult = Test-DnsResolve -Hostname $endpoint.Host
    
    if ($dnsResult.Success) {
        $httpsResult = Test-HttpsEndpoint -Hostname $endpoint.Host
        
        $r = Add-TestResult -Category "Network" -Test "$($endpoint.Purpose) Endpoint" `
            -Result $(if ($httpsResult.Success) {"PASS"} elseif ($endpoint.Optional) {"WARN"} else {"FAIL"}) `
            -Severity $(if ($endpoint.Optional) {"Low"} else {"High"}) `
            -Value "$($endpoint.Host):443" -Details $httpsResult.Msg `
            -Impact $(if (-not $httpsResult.Success -and -not $endpoint.Optional) {"WARP cannot $($endpoint.Purpose.ToLower())"} elseif (-not $httpsResult.Success) {"Optional feature unavailable"} else {""}) `
            -Remediation $(if (-not $httpsResult.Success -and -not $endpoint.Optional) {"Allow HTTPS to $($endpoint.Host)"} else {""})
    } else {
        $r = Add-TestResult -Category "Network" -Test "$($endpoint.Purpose) Endpoint" `
            -Result $(if ($endpoint.Optional) {"WARN"} else {"FAIL"}) `
            -Severity $(if ($endpoint.Optional) {"Low"} else {"High"}) `
            -Value $endpoint.Host -Details $dnsResult.Msg `
            -Impact $(if ($endpoint.Optional) {"Optional endpoint. May not exist or be region-specific"} else {"Cannot reach endpoint"}) `
            -Remediation $(if (-not $endpoint.Optional) {"Check DNS configuration"} else {"N/A - Optional"})
    }
    
    $script:Results.NetworkTests += $r
    Write-TestResult $r
}

Write-Host ""

# TEST 5.7: Optional Features
Write-Host "  [5.7] Optional Features (NTP, NEL)" -ForegroundColor Yellow

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

$r = Add-TestResult -Category "Network" -Test "NTP Time Sync" `
    -Result $ntpStatus -Severity "Low" `
    -Value "time.cloudflare.com:123" `
    -Impact "Optional feature. WARP can function without it"

$script:Results.NetworkTests += $r
Write-TestResult $r

# NEL
$nelResult = Test-DnsResolve -Hostname "a.nel.cloudflare.com"

$r = Add-TestResult -Category "Network" -Test "NEL Error Reporting" `
    -Result $(if ($nelResult.Success) {"PASS"} else {"WARN"}) -Severity "Low" `
    -Value "a.nel.cloudflare.com" `
    -Impact "Optional feature. WARP can function without it"

$script:Results.NetworkTests += $r
Write-TestResult $r

Write-Host ""
Write-Host "NOTE: UDP tests show packet sent, not delivery confirmed (connectionless protocol)" -ForegroundColor Gray
Write-Host ""

# ============================================================================
# CATEGORY 6: SYSTEM DIAGNOSTICS COLLECTION
# ============================================================================

Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "CATEGORY 6: DIAGNOSTICS COLLECTION" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""

$diagnostics = @(
    @{Name="network_interfaces"; Cmd={Get-NetIPInterface | Select-Object InterfaceAlias,AddressFamily,ConnectionState,NlMtu | Format-Table -AutoSize}},
    @{Name="route_table"; Cmd={Get-NetRoute | Select-Object DestinationPrefix,NextHop,InterfaceAlias,RouteMetric | Sort-Object DestinationPrefix | Format-Table -AutoSize}},
    @{Name="dns_config"; Cmd={Get-DnsClientServerAddress | Format-Table -AutoSize}},
    @{Name="firewall_profiles"; Cmd={Get-NetConnectionProfile | Format-Table -AutoSize}},
    @{Name="hosts_file"; Cmd={Get-Content "C:\Windows\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue}},
    @{Name="installed_apps"; Cmd={
        Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
                        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
        Where-Object {$_.DisplayName} | Select-Object DisplayName,DisplayVersion,Publisher | Sort-Object DisplayName | Format-Table -AutoSize
    }}
)

foreach ($diag in $diagnostics) {
    try {
        $output = & $diag.Cmd
        $path = Join-Path $script:OutputFolder "$($diag.Name).txt"
        $output | Out-File -FilePath $path -ErrorAction Stop
        Write-Host "  [+] Collected: $($diag.Name)" -ForegroundColor Green
    } catch {
        Write-Host "  [!] Failed: $($diag.Name)" -ForegroundColor Yellow
    }
}

# Path Variables
try {
    $sysPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $usrPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $pathReport = @("=== SYSTEM PATH ===", ($sysPath -split ";"), "", "=== USER PATH ===", ($usrPath -split ";"))
    $pathReport | Out-File (Join-Path $script:OutputFolder "path_variables.txt") -ErrorAction Stop
    Write-Host "  [+] Collected: path_variables" -ForegroundColor Green
} catch {
    Write-Host "  [!] Failed: path_variables" -ForegroundColor Yellow
}

# MTU Audit
try {
    Get-NetIPInterface -ErrorAction Continue | Select-Object InterfaceAlias,AddressFamily,NlMtu | 
        Out-File (Join-Path $script:OutputFolder "mtu_audit.txt") -ErrorAction Stop
    Write-Host "  [+] Collected: mtu_audit" -ForegroundColor Green
} catch {
    Write-Host "  [!] Failed: mtu_audit" -ForegroundColor Yellow
}

# Ephemeral Ports
try {
    & netsh int ipv4 show dynamicport tcp | Out-File (Join-Path $script:OutputFolder "ephemeral_ports.txt") -ErrorAction Stop
    Write-Host "  [+] Collected: ephemeral_ports" -ForegroundColor Green
} catch {
    Write-Host "  [!] Failed: ephemeral_ports" -ForegroundColor Yellow
}

# DNS NRPT Policy
try {
    Get-DnsClientNrptPolicy -ErrorAction SilentlyContinue | 
        Out-File (Join-Path $script:OutputFolder "dns_nrpt_policy.txt") -ErrorAction Stop
    Write-Host "  [+] Collected: dns_nrpt_policy" -ForegroundColor Green
} catch {
    Write-Host "  [!] Failed: dns_nrpt_policy" -ForegroundColor Yellow
}

# Startup Applications
try {
    Get-CimInstance Win32_StartupCommand -ErrorAction Continue | 
        Select-Object Name,Command,User | Format-List | 
        Out-File (Join-Path $script:OutputFolder "startup_apps.txt") -ErrorAction Stop
    Write-Host "  [+] Collected: startup_apps" -ForegroundColor Green
} catch {
    Write-Host "  [!] Failed: startup_apps" -ForegroundColor Yellow
}

# Scheduled Tasks
try {
    Get-ScheduledTask -ErrorAction Continue | Where-Object {$_.State -ne 'Disabled'} | 
        Select-Object TaskName,@{N="Triggers";E={$_.Triggers.ToString()}},@{N="Actions";E={$_.Actions.Execute}} | 
        Format-List | Out-File (Join-Path $script:OutputFolder "scheduled_tasks.txt") -ErrorAction Stop
    Write-Host "  [+] Collected: scheduled_tasks" -ForegroundColor Green
} catch {
    Write-Host "  [!] Failed: scheduled_tasks" -ForegroundColor Yellow
}

# Additional System Diagnostics
$secondaryDiagnostics = @(
    @{Label="ipconfig_all.txt"; Cmd="ipconfig /all"},
    @{Label="netstat_ano.txt"; Cmd="netstat -ano"},
    @{Label="arp_table.txt"; Cmd="arp -a"},
    @{Label="dns_cache.txt"; Cmd="ipconfig /displaydns"},
    @{Label="firewall_rules.txt"; Cmd="netsh advfirewall firewall show rule name=all"},
    @{Label="wlan_profiles.txt"; Cmd="netsh wlan show profiles"},
    @{Label="network_adapters.txt"; Cmd="Get-NetAdapter | Format-List"},
    @{Label="tcp_connections.txt"; Cmd="Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | Format-Table -AutoSize"},
    @{Label="udp_endpoints.txt"; Cmd="Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess | Format-Table -AutoSize"},
    @{Label="dns_client_cache.txt"; Cmd="Get-DnsClientCache | Format-Table -AutoSize"},
    @{Label="network_statistics.txt"; Cmd="netstat -s"},
    @{Label="routing_table_detailed.txt"; Cmd="route print"},
    @{Label="interface_statistics.txt"; Cmd="netsh interface ipv4 show interfaces"}
)

foreach ($diag in $secondaryDiagnostics) {
    $outPath = Join-Path $script:OutputFolder $diag.Label
    try {
        if ($diag.Cmd -like "Get-*" -or $diag.Cmd -like "*|*") {
            Invoke-Expression $diag.Cmd | Out-File -FilePath $outPath -ErrorAction Stop
        } else {
            & cmd /c $diag.Cmd 2>&1 | Out-File -FilePath $outPath -ErrorAction Stop
        }
        Write-Host "  [+] Collected: $($diag.Label)" -ForegroundColor Green
    } catch {
        Write-Host "  [!] Failed: $($diag.Label)" -ForegroundColor Yellow
    }
}

Write-Host ""

# ============================================================================
# FINAL REPORTING
# ============================================================================

Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "GENERATING FINAL REPORT" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""

# Save all test results to CSV
$allResults = @()
$allResults += $script:Results.SystemRequirements
$allResults += $script:Results.Services
$allResults += $script:Results.Permissions
$allResults += $script:Results.ProxyConfig
$allResults += $script:Results.NetworkTests
$allResults += $script:Results.Diagnostics

$allResults | Export-Csv -Path (Join-Path $script:OutputFolder "all_test_results.csv") -NoTypeInformation -ErrorAction SilentlyContinue

# Generate comprehensive text report
$report = @()
$report += "═══════════════════════════════════════════════════════════════"
$report += "  CLOUDFLARE WARP PRE-INSTALLATION READINESS ASSESSMENT"
$report += "  Version $($script:Config.Version)"
$report += "═══════════════════════════════════════════════════════════════"
$report += ""
$report += "ASSESSMENT SUMMARY"
$report += "─────────────────────────────────────────────────────────────"
$report += "Hostname:           $($script:Env.Hostname)"
$report += "User:               $($script:Env.Username)"
$report += "Administrator:      $($script:Env.IsAdmin)"
$report += "Timestamp:          $($script:Env.Timestamp.ToString('F'))"
$report += "PowerShell Version: $($PSVersionTable.PSVersion)"
$report += ""
$report += "TEST STATISTICS"
$report += "─────────────────────────────────────────────────────────────"
$report += "Total Tests:        $($script:Stats.Total)"
$report += "Passed:             $($script:Stats.Passed) ($([math]::Round(($script:Stats.Passed/$script:Stats.Total)*100,1))%)"
$report += "Failed:             $($script:Stats.Failed)"
$report += "Warnings:           $($script:Stats.Warnings)"
$report += "Critical Failures:  $($script:Stats.CriticalFailures)"
$report += "High Priority Failures: $($script:Stats.HighPriorityFailures)"
$report += ""
$report += ""
$report += "NEW TESTS IN VERSION 2.0"
$report += "═══════════════════════════════════════════════════════════════"
$report += ""
$report += "SYSTEM REQUIREMENTS (Enhanced):"
$report += "  ✓ PowerShell version check (5.1+ required)"
$report += "  ✓ .NET Framework version (4.6.2+ recommended)"
$report += "  ✓ TLS 1.2/1.3 protocol support verification"
$report += "  ✓ IPv6 configuration status"
$report += ""
$report += "SERVICES (7 New Critical Services Added):"
$report += "  ✓ Network Location Awareness (NlaSvc)"
$report += "  ✓ Network Store Interface Service (nsi)"
$report += "  ✓ Cryptographic Services (CryptSvc)"
$report += "  ✓ Windows Time (W32Time)"
$report += "  ✓ Remote Procedure Call (RpcSs)"
$report += "  ✓ DHCP Client (Dhcp)"
$report += ""
$report += "PROXY CONFIGURATION (Enhanced):"
$report += "  ✓ Windows Internet Settings (system-wide proxy)"
$report += "  ✓ Microsoft Edge (Chromium) browser proxy"
$report += "  ✓ Google Chrome browser proxy"
$report += "  ✓ Firefox browser proxy"
$report += "  ✓ VPN client detection (conflicts with WARP)"
$report += "  ✓ Environment proxy variables"
$report += ""
$report += "CERTIFICATE & SECURITY (New Category):"
$report += "  ✓ Windows Certificate Store health check"
$report += "  ✓ Trusted root CA verification"
$report += "  ✓ Certificate revocation checking status"
$report += "  ✓ Windows Defender status"
$report += "  ✓ Windows Firewall profile status"
$report += "  ✓ Time synchronization verification (critical for TLS)"
$report += ""
$report += "DIAGNOSTICS COLLECTION (28+ Files):"
$report += "  ✓ All files from v1 plus enhanced proxy detection"
$report += "  ✓ Path variables, MTU audit, ephemeral ports"
$report += "  ✓ DNS NRPT policy, startup apps, scheduled tasks"
$report += "  ✓ Complete network stack diagnostics"
$report += ""
$report += ""
$report += "TEST METHODOLOGY & LIMITATIONS"
$report += "═══════════════════════════════════════════════════════════════"
$report += ""
$report += "NETWORK CONNECTIVITY TEST METHODS:"
$report += "─────────────────────────────────────────────────────────────"
$report += ""
$report += "TCP Connection Tests:"
$report += "  • Method: Establish TCP connection using .NET TcpClient"
$report += "  • Validation: 3-way handshake completion (SYN, SYN-ACK, ACK)"
$report += "  • Timeout: 3 seconds"
$report += "  • What this tests: Network reachability, firewall rules, port availability"
$report += "  • What this does NOT test: Application-layer protocols, data transfer"
$report += ""
$report += "UDP Connection Tests:"
$report += "  • Method: Send UDP packet using .NET UdpClient"
$report += "  • Validation: Bytes successfully sent to socket"
$report += "  • Payload: 'WARP_TEST' ASCII string (9 bytes)"
$report += "  • What this tests: Ability to send UDP packets to destination"
$report += "  • What this does NOT test: Packet delivery, server response, protocol handshake"
$report += "  • IMPORTANT: UDP is connectionless - successful send does NOT confirm delivery"
$report += ""
$report += "HTTPS Connection Tests:"
$report += "  • Method: TCP connection + TLS/SSL handshake"
$report += "  • Validation: SSL certificate exchange and authentication"
$report += "  • What this tests: HTTPS reachability, certificate validity, TLS support"
$report += "  • What this does NOT test: HTTP request/response, API functionality"
$report += ""
$report += "DNS Resolution Tests:"
$report += "  • Method: Query DNS for IPv4 addresses using .NET Dns.GetHostAddresses"
$report += "  • Validation: At least one IPv4 address returned"
$report += "  • What this tests: DNS resolution, DNS server availability"
$report += "  • What this does NOT test: DNS security (DNSSEC), DNS over HTTPS"
$report += ""
$report += ""
$report += "CRITICAL LIMITATIONS - WHAT IS NOT TESTED:"
$report += "─────────────────────────────────────────────────────────────"
$report += ""
$report += "WireGuard Tunnel Tests:"
$report += "  ✗ Actual WireGuard protocol handshake (Noise protocol)"
$report += "  ✗ Cryptographic key exchange"
$report += "  ✗ Tunnel establishment and data encapsulation"
$report += "  ✓ Only tests: UDP packet reachability to WireGuard ports"
$report += ""
$report += "MASQUE Tunnel Tests:"
$report += "  ✗ QUIC protocol negotiation and handshake"
$report += "  ✗ MASQUE CONNECT-UDP method"
$report += "  ✗ HTTP/3 over QUIC"
$report += "  ✗ Tunnel establishment and proxying"
$report += "  ✓ Only tests: UDP/TCP packet reachability to MASQUE ports"
$report += ""
$report += "API Endpoint Tests:"
$report += "  ✗ API authentication and authorization"
$report += "  ✗ API request/response validation"
$report += "  ✗ JSON payload parsing"
$report += "  ✓ Only tests: HTTPS connectivity and SSL certificate validation"
$report += ""
$report += "General Limitations:"
$report += "  ✗ No actual WARP client behavior simulation"
$report += "  ✗ No protocol-level validation (WireGuard, MASQUE, QUIC)"
$report += "  ✗ No server response validation"
$report += "  ✗ No data transfer or throughput testing"
$report += "  ✗ No tunnel establishment or teardown"
$report += "  ✗ No authentication or credential validation"
$report += ""
$report += ""
$report += "PURPOSE OF THESE TESTS:"
$report += "─────────────────────────────────────────────────────────────"
$report += "This audit performs PRE-INSTALLATION READINESS checks to identify:"
$report += "  • Firewall blocks preventing WARP connectivity"
$report += "  • Network routing issues"
$report += "  • DNS resolution problems"
$report += "  • Missing system requirements"
$report += "  • Service configuration issues"
$report += ""
$report += "These tests do NOT replicate actual WARP client operations."
$report += "They verify that the NETWORK PATH is available for WARP to use."
$report += ""
$report += "Successful tests indicate the network allows connectivity to required"
$report += "endpoints. The actual WARP client will perform full protocol handshakes"
$report += "and establish encrypted tunnels using WireGuard or MASQUE protocols."
$report += ""
$report += ""

# GO/NO-GO Decision
$goNoGo = if ($script:Stats.CriticalFailures -eq 0 -and $script:Stats.HighPriorityFailures -le 2) {
    "GO"
} elseif ($script:Stats.CriticalFailures -le 2) {
    "CAUTION"
} else {
    "NO-GO"
}

$report += "═══════════════════════════════════════════════════════════════"
$report += "  RECOMMENDATION: $goNoGo"
$report += "═══════════════════════════════════════════════════════════════"
$report += ""

if ($goNoGo -eq "GO") {
    $report += "✓ System meets WARP installation requirements"
    $report += "✓ Proceed with installation"
} elseif ($goNoGo -eq "CAUTION") {
    $report += "⚠ System has some issues but may support WARP"
    $report += "⚠ Review failures below and remediate if possible"
    $report += "⚠ Installation may succeed but functionality could be limited"
} else {
    $report += "✗ System does NOT meet WARP installation requirements"
    $report += "✗ DO NOT proceed with installation until issues are resolved"
    $report += "✗ Review critical failures below"
}

$report += ""
$report += ""

# Critical and High Priority Failures
$criticalFailures = $allResults | Where-Object {$_.Result -eq "FAIL" -and $_.Severity -in @("Critical","High")}
if ($criticalFailures) {
    $report += "CRITICAL & HIGH PRIORITY FAILURES"
    $report += "═══════════════════════════════════════════════════════════════"
    foreach ($failure in $criticalFailures) {
        $report += ""
        $report += "[$($failure.Severity)] $($failure.Test)"
        $report += "  Category:     $($failure.Category)"
        $report += "  Value:        $($failure.Value)"
        if ($failure.Details) { $report += "  Details:      $($failure.Details)" }
        if ($failure.Impact) { $report += "  Impact:       $($failure.Impact)" }
        if ($failure.Remediation) { $report += "  Remediation:  $($failure.Remediation)" }
    }
    $report += ""
    $report += ""
}

# Warnings
$warnings = $allResults | Where-Object {$_.Result -eq "WARN"}
if ($warnings) {
    $report += "WARNINGS"
    $report += "═══════════════════════════════════════════════════════════════"
    foreach ($warning in $warnings) {
        $report += ""
        $report += "[$($warning.Severity)] $($warning.Test)"
        $report += "  Category:     $($warning.Category)"
        $report += "  Value:        $($warning.Value)"
        if ($warning.Impact) { $report += "  Impact:       $($warning.Impact)" }
    }
    $report += ""
    $report += ""
}

# All Test Results by Category
$report += "DETAILED TEST RESULTS BY CATEGORY"
$report += "═══════════════════════════════════════════════════════════════"
$report += ""

foreach ($category in @("System","Services","Permissions","Proxy","Security","Network")) {
    $categoryResults = $allResults | Where-Object {$_.Category -eq $category}
    if ($categoryResults) {
        $report += "CATEGORY: $category"
        $report += "─────────────────────────────────────────────────────────────"
        foreach ($result in $categoryResults) {
            $icon = switch ($result.Result) {
                "PASS" {"✓"}; "FAIL" {"✗"}; "WARN" {"⚠"}; "INFO" {"ℹ"}; default {"•"}
            }
            $report += "  $icon [$($result.Result)] $($result.Test)"
            if ($result.Value) { $report += "      Value: $($result.Value)" }
        }
        $report += ""
    }
}

$report += ""
$report += "═══════════════════════════════════════════════════════════════"
$report += "END OF REPORT"
$report += "═══════════════════════════════════════════════════════════════"

# Save report
$report | Out-File (Join-Path $script:OutputFolder "00_audit_report.txt") -ErrorAction SilentlyContinue

# Display summary to console
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  ASSESSMENT COMPLETE" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "Test Statistics:" -ForegroundColor White
Write-Host "  Total:    $($script:Stats.Total)"
Write-Host "  Passed:   $($script:Stats.Passed)" -ForegroundColor Green
Write-Host "  Failed:   $($script:Stats.Failed)" -ForegroundColor Red
Write-Host "  Warnings: $($script:Stats.Warnings)" -ForegroundColor Yellow
Write-Host ""

$color = switch ($goNoGo) {
    "GO" {"Green"}; "CAUTION" {"Yellow"}; "NO-GO" {"Red"}
}
Write-Host "RECOMMENDATION: $goNoGo" -ForegroundColor $color
Write-Host ""

if ($goNoGo -eq "GO") {
    Write-Host "✓ System is ready for WARP installation" -ForegroundColor Green
} elseif ($goNoGo -eq "CAUTION") {
    Write-Host "⚠ Review failures before proceeding" -ForegroundColor Yellow
} else {
    Write-Host "✗ Resolve critical issues before installation" -ForegroundColor Red
}

Write-Host ""
Write-Host "Results saved to: $script:OutputFolder" -ForegroundColor Cyan
Write-Host "  - 00_audit_report.txt (comprehensive assessment report)" -ForegroundColor Gray
Write-Host "  - all_test_results.csv (detailed test data)" -ForegroundColor Gray
Write-Host "  - proxy_configuration.txt (proxy settings)" -ForegroundColor Gray
Write-Host "  - network_interfaces.txt, route_table.txt, dns_config.txt" -ForegroundColor Gray
Write-Host "  - path_variables.txt, mtu_audit.txt, ephemeral_ports.txt" -ForegroundColor Gray
Write-Host "  - dns_nrpt_policy.txt, startup_apps.txt, scheduled_tasks.txt" -ForegroundColor Gray
Write-Host "  - ipconfig_all.txt, netstat_ano.txt, firewall_rules.txt" -ForegroundColor Gray
Write-Host "  - tcp_connections.txt, udp_endpoints.txt, dns_cache.txt" -ForegroundColor Gray
Write-Host "  - Plus 20+ additional diagnostic files for troubleshooting" -ForegroundColor Gray
Write-Host ""

# ============================================================================
# CLEANUP
# ============================================================================

Write-Host "Cleaning up test artifacts..." -ForegroundColor Yellow

# Remove test directories we created
foreach ($dir in $script:CreatedDirs) {
    try {
        if (Test-Path $dir) {
            Remove-Item -Path $dir -Recurse -Force -ErrorAction Stop
            Write-Host "  [+] Removed: $dir" -ForegroundColor Green
        }
    } catch {
        Write-Host "  [!] Could not remove: $dir" -ForegroundColor Yellow
    }
}

# Create ZIP archive
$zipCreated = $false
$zipPath = "$script:OutputFolder.zip"

try {
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    
    Add-Type -Assembly "System.IO.Compression.FileSystem"
    [System.IO.Compression.ZipFile]::CreateFromDirectory($script:OutputFolder, $zipPath)
    
    # Verify ZIP was created and has content
    if (Test-Path $zipPath) {
        $zipInfo = Get-Item $zipPath
        if ($zipInfo.Length -gt 1KB) {
            $zipCreated = $true
            Write-Host ""
            Write-Host "✓ Archive created: $zipPath ($([math]::Round($zipInfo.Length/1MB,2)) MB)" -ForegroundColor Green
        } else {
            Write-Host ""
            Write-Host "✗ ZIP archive created but appears empty" -ForegroundColor Red
        }
    }
} catch {
    Write-Host ""
    Write-Host "✗ Could not create ZIP archive: $($_.Exception.Message)" -ForegroundColor Red
}

# Only remove output folder if ZIP was successfully created
if ($zipCreated) {
    try {
        Remove-Item -Path $script:OutputFolder -Recurse -Force -ErrorAction Stop
        Write-Host "✓ Removed output folder (contents preserved in ZIP)" -ForegroundColor Green
    } catch {
        Write-Host "⚠ Could not remove output folder: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "  Both folder and ZIP are available" -ForegroundColor Gray
    }
} else {
    Write-Host "⚠ Output folder preserved due to ZIP creation issue" -ForegroundColor Yellow
    Write-Host "  Folder location: $script:OutputFolder" -ForegroundColor Gray
}

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  AUDIT COMPLETE" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
