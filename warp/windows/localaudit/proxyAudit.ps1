<#
.SYNOPSIS
    Cloudflare WARP Proxy Configuration Detector

.DESCRIPTION
    Standalone script to detect all proxy configurations that may interfere with WARP.
    Extracted from localaudit.v2.ps1 for focused proxy troubleshooting.
    
    Detects:
    - System proxy (WinHTTP)
    - Windows Internet Settings proxy (affects IE, Edge, WinINet apps)
    - Microsoft Edge browser proxy
    - Google Chrome browser proxy
    - Mozilla Firefox browser proxy
    - Environment proxy variables (HTTP_PROXY, HTTPS_PROXY)
    - VPN client detection
    
    ANTIVIRUS CONSIDERATIONS:
    This script reads proxy settings from registry and configuration files.
    All operations are READ-ONLY - no proxy settings are modified.

.NOTES
    Version: 1.0
    Requires: PowerShell 5.1+
    No external dependencies
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
    Total = 0; Passed = 0; Warnings = 0
}

$script:Env = @{
    Hostname = $env:COMPUTERNAME
    Username = $env:USERNAME
    Timestamp = Get-Date
}

$script:ProxyReport = @()

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Add-TestResult {
    param(
        [string]$Test, [string]$Result, [string]$Severity,
        [string]$Value = "", [string]$Details = "", [string]$Impact = "", [string]$Remediation = ""
    )
    
    $obj = [PSCustomObject]@{
        Test = $Test
        Result = $Result
        Severity = $Severity
        Value = $Value
        Details = $Details
        Impact = $Impact
        Remediation = $Remediation
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    $script:Stats.Total++
    if ($Result -eq "PASS") { $script:Stats.Passed++ }
    if ($Result -eq "WARN") { $script:Stats.Warnings++ }
    
    return $obj
}

function Write-TestResult {
    param([PSCustomObject]$Result)
    
    $color = switch ($Result.Result) {
        "PASS" { "Green" }
        "WARN" { "Yellow" }
        default { "Cyan" }
    }
    $icon = switch ($Result.Result) {
        "PASS" { "[+]" }
        "WARN" { "[!]" }
        default { "[i]" }
    }
    
    Write-Host "  $icon $($Result.Test)" -ForegroundColor $color
    if ($Result.Value) { Write-Host "      → $($Result.Value)" -ForegroundColor Gray }
    if ($Result.Impact) { Write-Host "      Impact: $($Result.Impact)" -ForegroundColor Gray }
    if ($Result.Remediation) { Write-Host "      Fix: $($Result.Remediation)" -ForegroundColor Gray }
}

# ============================================================================
# DISPLAY HEADER
# ============================================================================

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  CLOUDFLARE WARP PROXY CONFIGURATION DETECTOR" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "Hostname:  $($script:Env.Hostname)"
Write-Host "User:      $($script:Env.Username)"
Write-Host "Timestamp: $($script:Env.Timestamp.ToString('F'))"
Write-Host ""

# ============================================================================
# PROXY DETECTION TESTS
# ============================================================================
# This section detects proxy configurations that may interfere with WARP.
# AV NOTE: Reading proxy settings from registry and netsh is standard diagnostic practice.
# This is READ-ONLY - no proxy settings are modified.

Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "PROXY CONFIGURATION DETECTION" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""

# TEST 1: System Proxy (WinHTTP)
Write-Host "  [1] System Proxy (WinHTTP)" -ForegroundColor Yellow

try {
    $winHttp = & netsh winhttp show proxy 2>$null
    $script:ProxyReport += "=== SYSTEM PROXY (WinHTTP) ==="
    $script:ProxyReport += $winHttp
    $script:ProxyReport += ""
    
    if ($winHttp -match "Proxy Server\(s\)\s*:\s*(.+)") {
        $proxyServer = $matches[1].Trim()
        if ($proxyServer -and $proxyServer -notmatch "Direct access") {
            $r = Add-TestResult -Test "System Proxy (WinHTTP)" `
                -Result "WARN" -Severity "High" `
                -Value $proxyServer `
                -Impact "WARP traffic may be routed through proxy. Installation may fail if proxy blocks Cloudflare" `
                -Remediation "Disable system proxy or configure WARP split tunneling"
            
            $script:Results += $r
            Write-TestResult $r
        } else {
            $r = Add-TestResult -Test "System Proxy (WinHTTP)" `
                -Result "PASS" -Severity "Info" -Value "Direct connection"
            $script:Results += $r
            Write-TestResult $r
        }
    }
} catch {
    Write-Host "  [!] Could not check system proxy" -ForegroundColor Yellow
}

Write-Host ""

# TEST 2: Windows Internet Settings Proxy
Write-Host "  [2] Windows Internet Settings Proxy" -ForegroundColor Yellow

try {
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    $proxyEnable = (Get-ItemProperty -Path $regPath -Name ProxyEnable -ErrorAction SilentlyContinue).ProxyEnable
    $proxyServer = (Get-ItemProperty -Path $regPath -Name ProxyServer -ErrorAction SilentlyContinue).ProxyServer
    $autoConfigURL = (Get-ItemProperty -Path $regPath -Name AutoConfigURL -ErrorAction SilentlyContinue).AutoConfigURL
    
    $script:ProxyReport += "=== WINDOWS INTERNET SETTINGS (User-Level) ==="
    $script:ProxyReport += "Registry: HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    $script:ProxyReport += "Affects: IE, Edge (when using system proxy), WinINet apps, .NET apps"
    $script:ProxyReport += "ProxyEnable: $proxyEnable"
    $script:ProxyReport += "ProxyServer: $proxyServer"
    $script:ProxyReport += "AutoConfigURL: $autoConfigURL"
    $script:ProxyReport += ""
    
    if ($proxyEnable -eq 1 -and $proxyServer) {
        $r = Add-TestResult -Test "Windows Internet Settings Proxy" `
            -Result "WARN" -Severity "High" `
            -Value $proxyServer `
            -Impact "System-wide proxy affects IE, Edge (system mode), and WinINet apps. May bypass WARP tunnel" `
            -Remediation "Disable proxy in Internet Options (inetcpl.cpl) or Windows Settings"
        
        $script:Results += $r
        Write-TestResult $r
        
    } elseif ($autoConfigURL) {
        $r = Add-TestResult -Test "Windows Internet Settings PAC" `
            -Result "WARN" -Severity "High" `
            -Value $autoConfigURL `
            -Impact "System-wide PAC file affects IE, Edge (system mode), and WinINet apps. May route traffic around WARP" `
            -Remediation "Review PAC file or disable auto-config in Internet Options"
        
        $script:Results += $r
        Write-TestResult $r
        
    } else {
        $r = Add-TestResult -Test "Windows Internet Settings Proxy" `
            -Result "PASS" -Severity "Info" -Value "Direct connection"
        $script:Results += $r
        Write-TestResult $r
    }
} catch {
    Write-Host "  [!] Could not check user proxy" -ForegroundColor Yellow
}

Write-Host ""

# TEST 3: Microsoft Edge Browser Proxy
Write-Host "  [3] Microsoft Edge Browser Proxy" -ForegroundColor Yellow

try {
    $edgeProxyFound = $false
    $edgeProxyDetails = @()
    
    $edgePaths = @(
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Preferences",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Profile 1\Preferences"
    )
    
    $script:ProxyReport += "=== MICROSOFT EDGE (CHROMIUM) PROXY ==="
    
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
            } catch {}
        }
    }
    
    # Check Edge policy-based proxy
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
        $script:ProxyReport += $edgeProxyDetails
        
        $r = Add-TestResult -Test "Edge Browser Proxy" `
            -Result "WARN" -Severity "High" `
            -Value ($edgeProxyDetails -join "; ") `
            -Impact "Edge traffic may bypass WARP tunnel or conflict with WARP settings" `
            -Remediation "Review Edge proxy settings (edge://settings/system) or Group Policy"
        
        $script:Results += $r
        Write-TestResult $r
    } else {
        $script:ProxyReport += "No Edge-specific proxy detected (may use system settings)"
        
        $r = Add-TestResult -Test "Edge Browser Proxy" `
            -Result "PASS" -Severity "Info" -Value "Using system settings or direct connection"
        $script:Results += $r
        Write-TestResult $r
    }
    $script:ProxyReport += ""
} catch {
    Write-Host "  [!] Could not check Edge proxy settings" -ForegroundColor Yellow
}

Write-Host ""

# TEST 4: Google Chrome Browser Proxy
Write-Host "  [4] Google Chrome Browser Proxy" -ForegroundColor Yellow

try {
    $chromeProxyFound = $false
    $chromeProxyDetails = @()
    
    $chromePaths = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Preferences",
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Profile 1\Preferences"
    )
    
    $script:ProxyReport += "=== CHROME BROWSER PROXY ==="
    
    foreach ($chromePath in $chromePaths) {
        if (Test-Path $chromePath) {
            try {
                $chromePrefs = Get-Content $chromePath -Raw -ErrorAction Stop | ConvertFrom-Json
                
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
            } catch {}
        }
    }
    
    # Check Chrome policy-based proxy
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
        $script:ProxyReport += $chromeProxyDetails
        
        $r = Add-TestResult -Test "Chrome Browser Proxy" `
            -Result "WARN" -Severity "High" `
            -Value ($chromeProxyDetails -join "; ") `
            -Impact "Chrome traffic may bypass WARP tunnel or conflict with WARP settings" `
            -Remediation "Review Chrome proxy settings (chrome://settings/system) or Group Policy"
        
        $script:Results += $r
        Write-TestResult $r
    } else {
        $script:ProxyReport += "No Chrome-specific proxy detected (may use system settings)"
        
        $r = Add-TestResult -Test "Chrome Browser Proxy" `
            -Result "PASS" -Severity "Info" -Value "Using system settings or direct connection"
        $script:Results += $r
        Write-TestResult $r
    }
    $script:ProxyReport += ""
} catch {
    Write-Host "  [!] Could not check Chrome proxy settings" -ForegroundColor Yellow
}

Write-Host ""

# TEST 5: Mozilla Firefox Browser Proxy
Write-Host "  [5] Mozilla Firefox Browser Proxy" -ForegroundColor Yellow

try {
    $firefoxProxyFound = $false
    $firefoxProxyDetails = @()
    
    $firefoxProfilePath = "$env:APPDATA\Mozilla\Firefox\Profiles"
    $script:ProxyReport += "=== FIREFOX BROWSER PROXY ==="
    
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
        $script:ProxyReport += $firefoxProxyDetails
        
        $r = Add-TestResult -Test "Firefox Browser Proxy" `
            -Result "WARN" -Severity "High" `
            -Value ($firefoxProxyDetails -join "; ") `
            -Impact "Firefox traffic may bypass WARP tunnel" `
            -Remediation "Review Firefox proxy settings (about:preferences#general > Network Settings)"
        
        $script:Results += $r
        Write-TestResult $r
    } else {
        $script:ProxyReport += "No Firefox-specific proxy detected"
        
        $r = Add-TestResult -Test "Firefox Browser Proxy" `
            -Result "PASS" -Severity "Info" -Value "No custom proxy or Firefox not installed"
        $script:Results += $r
        Write-TestResult $r
    }
    $script:ProxyReport += ""
} catch {
    Write-Host "  [!] Could not check Firefox proxy settings" -ForegroundColor Yellow
}

Write-Host ""

# TEST 6: Environment Proxy Variables
Write-Host "  [6] Environment Proxy Variables" -ForegroundColor Yellow

$envProxies = @()
if ($env:HTTP_PROXY) { $envProxies += "HTTP_PROXY=$($env:HTTP_PROXY)" }
if ($env:HTTPS_PROXY) { $envProxies += "HTTPS_PROXY=$($env:HTTPS_PROXY)" }
if ($env:NO_PROXY) { $envProxies += "NO_PROXY=$($env:NO_PROXY)" }

$script:ProxyReport += "=== ENVIRONMENT PROXY VARIABLES ==="
if ($envProxies.Count -gt 0) {
    $script:ProxyReport += $envProxies
    
    $r = Add-TestResult -Test "Environment Variables" `
        -Result "WARN" -Severity "Medium" `
        -Value ($envProxies -join "; ") `
        -Impact "CLI tools may use these proxies" `
        -Remediation "Unset environment variables if not needed"
    
    $script:Results += $r
    Write-TestResult $r
} else {
    $script:ProxyReport += "None detected"
    
    $r = Add-TestResult -Test "Environment Variables" `
        -Result "PASS" -Severity "Info" -Value "None"
    $script:Results += $r
    Write-TestResult $r
}

Write-Host ""

# TEST 7: VPN Client Detection
Write-Host "  [7] VPN Client Detection" -ForegroundColor Yellow

try {
    $vpnDetected = @()
    $script:ProxyReport += "=== VPN CLIENT DETECTION ==="
    
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
        $script:ProxyReport += $vpnDetected
        
        $r = Add-TestResult -Test "VPN Client Detection" `
            -Result "WARN" -Severity "High" `
            -Value "$($vpnDetected.Count) VPN client(s) detected" `
            -Details ($vpnDetected -join "; ") `
            -Impact "VPN may conflict with WARP tunnel. Only one VPN can be active at a time" `
            -Remediation "Disable other VPN clients before using WARP"
        
        $script:Results += $r
        Write-TestResult $r
    } else {
        $script:ProxyReport += "No VPN clients detected"
        
        $r = Add-TestResult -Test "VPN Client Detection" `
            -Result "PASS" -Severity "Info" -Value "No conflicting VPN clients"
        $script:Results += $r
        Write-TestResult $r
    }
    $script:ProxyReport += ""
} catch {
    Write-Host "  [!] Could not check for VPN clients" -ForegroundColor Yellow
}

Write-Host ""

# ============================================================================
# SUMMARY
# ============================================================================

Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "SUMMARY" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""
Write-Host "Total Checks: $($script:Stats.Total)"
Write-Host "Clean:        $($script:Stats.Passed)" -ForegroundColor Green
Write-Host "Warnings:     $($script:Stats.Warnings)" -ForegroundColor Yellow
Write-Host ""

$warnings = $script:Results | Where-Object { $_.Result -eq "WARN" }
if ($warnings.Count -gt 0) {
    Write-Host "PROXY STATUS: " -NoNewline
    Write-Host "DETECTED" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Proxy configurations detected that may interfere with WARP:" -ForegroundColor Yellow
    Write-Host ""
    foreach ($warning in $warnings) {
        Write-Host "  • $($warning.Test)" -ForegroundColor Yellow
        if ($warning.Value) {
            Write-Host "    $($warning.Value)" -ForegroundColor Gray
        }
        if ($warning.Remediation) {
            Write-Host "    Fix: $($warning.Remediation)" -ForegroundColor Cyan
        }
    }
} else {
    Write-Host "PROXY STATUS: " -NoNewline
    Write-Host "CLEAN" -ForegroundColor Green
    Write-Host ""
    Write-Host "✓ No proxy configurations detected" -ForegroundColor Green
    Write-Host "✓ Direct connection to internet" -ForegroundColor Green
}

Write-Host ""

# Save detailed report
$reportPath = Join-Path $PSScriptRoot "proxy_configuration_report.txt"
$script:ProxyReport | Out-File $reportPath -ErrorAction SilentlyContinue
if (Test-Path $reportPath) {
    Write-Host "Detailed report saved to: $reportPath" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
