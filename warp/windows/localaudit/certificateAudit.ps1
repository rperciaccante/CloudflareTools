<#
.SYNOPSIS
    Cloudflare WARP Certificate & Security Validator

.DESCRIPTION
    Standalone script to validate certificate infrastructure and security settings for WARP.
    Extracted from localaudit.v2.ps1 for focused TLS/certificate troubleshooting.
    
    Checks:
    - Windows Certificate Store health (Root, CA, Personal)
    - Trusted Root CAs for Cloudflare
    - Certificate revocation checking settings
    - Windows Defender status
    - Windows Firewall status
    - Time synchronization (critical for TLS)
    
    ANTIVIRUS CONSIDERATIONS:
    This script enumerates certificate stores in READ-ONLY mode.
    No certificates are installed, modified, or removed.

.NOTES
    Version: 1.0
    Requires: PowerShell 5.1+
    Administrator rights recommended for full information
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
    Total = 0; Passed = 0; Failed = 0; Warnings = 0; Info = 0
}

$script:Env = @{
    IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Hostname = $env:COMPUTERNAME
    Username = $env:USERNAME
    Timestamp = Get-Date
}

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
    switch ($Result) {
        "PASS" { $script:Stats.Passed++ }
        "FAIL" { $script:Stats.Failed++ }
        "WARN" { $script:Stats.Warnings++ }
        "INFO" { $script:Stats.Info++ }
    }
    
    return $obj
}

function Write-TestResult {
    param([PSCustomObject]$Result)
    
    $color = switch ($Result.Result) {
        "PASS" { "Green" }
        "FAIL" { "Red" }
        "WARN" { "Yellow" }
        "INFO" { "Cyan" }
        default { "Gray" }
    }
    $icon = switch ($Result.Result) {
        "PASS" { "[+]" }
        "FAIL" { "[-]" }
        "WARN" { "[!]" }
        "INFO" { "[i]" }
        default { "[?]" }
    }
    
    Write-Host "  $icon $($Result.Test)" -ForegroundColor $color
    if ($Result.Value) { Write-Host "      → $($Result.Value)" -ForegroundColor Gray }
    if ($Result.Details) { Write-Host "      Details: $($Result.Details)" -ForegroundColor Gray }
    if ($Result.Impact) { Write-Host "      Impact: $($Result.Impact)" -ForegroundColor Gray }
    if ($Result.Remediation) { Write-Host "      Fix: $($Result.Remediation)" -ForegroundColor Gray }
}

# ============================================================================
# DISPLAY HEADER
# ============================================================================

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  CLOUDFLARE WARP CERTIFICATE & SECURITY VALIDATOR" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "Hostname:      $($script:Env.Hostname)"
Write-Host "User:          $($script:Env.Username)"
Write-Host "Administrator: $($script:Env.IsAdmin)"
Write-Host "Timestamp:     $($script:Env.Timestamp.ToString('F'))"
Write-Host ""

# ============================================================================
# CERTIFICATE & SECURITY TESTS
# ============================================================================
# This section validates certificate infrastructure and security settings.
# AV NOTE: Certificate store enumeration is standard for TLS diagnostics.
# This is READ-ONLY - no certificates are installed, modified, or removed.

Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "CERTIFICATE & SECURITY VALIDATION" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""

# TEST 1: Windows Certificate Store Health
Write-Host "  [1] Certificate Store Health" -ForegroundColor Yellow

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
    
    $r = Add-TestResult -Test "Certificate Store Health" `
        -Result $(if ($storeHealthy) {"PASS"} else {"FAIL"}) -Severity "Critical" `
        -Value "Root: $($certCounts['Root']), CA: $($certCounts['CA']), Personal: $($certCounts['My'])" `
        -Impact $(if (-not $storeHealthy) {"TLS/SSL connections will fail"} else {""}) `
        -Remediation $(if (-not $storeHealthy) {"Reinstall root certificates or repair Windows"} else {""})
    
    $script:Results += $r
    Write-TestResult $r
} catch {
    $r = Add-TestResult -Test "Certificate Store Health" -Result "FAIL" -Severity "Critical" `
        -Value "Cannot access certificate store" -Impact "TLS/SSL will not function"
    $script:Results += $r
    Write-TestResult $r
}

Write-Host ""

# TEST 2: Cloudflare Root CA Check
Write-Host "  [2] Trusted Root CAs" -ForegroundColor Yellow

try {
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
    $store.Open("ReadOnly")
    $cloudflareCA = $store.Certificates | Where-Object {
        $_.Subject -like "*Cloudflare*" -or $_.Issuer -like "*DigiCert*" -or $_.Issuer -like "*Baltimore*"
    }
    $store.Close()
    
    $hasTrustedRoots = $cloudflareCA.Count -gt 0
    
    $r = Add-TestResult -Test "Trusted Root CAs" `
        -Result $(if ($hasTrustedRoots) {"PASS"} else {"WARN"}) -Severity "Medium" `
        -Value "$($cloudflareCA.Count) relevant root CA(s) found" `
        -Impact $(if (-not $hasTrustedRoots) {"May need to install Cloudflare root CA"} else {""}) `
        -Remediation $(if (-not $hasTrustedRoots) {"WARP installer will add required certificates"} else {""})
    
    $script:Results += $r
    Write-TestResult $r
} catch {
    Write-Host "  [!] Could not check root CAs" -ForegroundColor Yellow
}

Write-Host ""

# TEST 3: Certificate Revocation Checking
Write-Host "  [3] Certificate Revocation Checking" -ForegroundColor Yellow

try {
    $crlCheck = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CertDllCreateCertificateChainEngine\Config" -ErrorAction SilentlyContinue).MaxUrlRetrievalByteCount
    $ocspEnabled = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\ChainEngine\Config" -ErrorAction SilentlyContinue).EnableOcspStaplingForSni
    
    $revocationEnabled = ($crlCheck -ne 0) -or ($ocspEnabled -eq $null)
    
    $r = Add-TestResult -Test "Certificate Revocation Checking" `
        -Result "INFO" -Severity "Info" `
        -Value $(if ($revocationEnabled) {"Enabled"} else {"Disabled"}) `
        -Impact "Affects certificate validation security"
    
    $script:Results += $r
    Write-TestResult $r
} catch {
    Write-Host "  [!] Could not check revocation settings" -ForegroundColor Yellow
}

Write-Host ""

# TEST 4: Windows Defender Status
Write-Host "  [4] Windows Defender" -ForegroundColor Yellow

try {
    $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
    $defenderEnabled = $defenderStatus.AntivirusEnabled
    $realtimeEnabled = $defenderStatus.RealTimeProtectionEnabled
    
    $r = Add-TestResult -Test "Windows Defender" `
        -Result "INFO" -Severity "Info" `
        -Value $(if ($defenderEnabled) {"Enabled (Realtime: $realtimeEnabled)"} else {"Disabled"}) `
        -Impact "Antivirus may scan WARP traffic"
    
    $script:Results += $r
    Write-TestResult $r
} catch {
    $r = Add-TestResult -Test "Windows Defender" -Result "INFO" -Severity "Info" `
        -Value "Status unknown or third-party AV installed"
    $script:Results += $r
    Write-TestResult $r
}

Write-Host ""

# TEST 5: Windows Firewall Status
Write-Host "  [5] Windows Firewall" -ForegroundColor Yellow

try {
    $fwProfiles = Get-NetFirewallProfile -ErrorAction Stop
    $fwStatus = @()
    foreach ($profile in $fwProfiles) {
        $fwStatus += "$($profile.Name): $(if ($profile.Enabled) {'ON'} else {'OFF'})"
    }
    
    $r = Add-TestResult -Test "Windows Firewall" `
        -Result "INFO" -Severity "Info" `
        -Value ($fwStatus -join ", ") `
        -Impact "Firewall rules may need WARP exceptions"
    
    $script:Results += $r
    Write-TestResult $r
} catch {
    Write-Host "  [!] Could not check firewall status" -ForegroundColor Yellow
}

Write-Host ""

# TEST 6: Time Synchronization
Write-Host "  [6] Time Synchronization" -ForegroundColor Yellow

try {
    $w32tm = & w32tm /query /status 2>&1
    $timeSource = $w32tm | Select-String "Source:" | ForEach-Object {$_.ToString().Split(':')[1].Trim()}
    $lastSync = $w32tm | Select-String "Last Successful Sync Time:" | ForEach-Object {$_.ToString().Split(':', 2)[1].Trim()}
    
    $timeSynced = $timeSource -and $timeSource -ne "Local CMOS Clock" -and $timeSource -ne "Free-Running System Clock"
    
    $r = Add-TestResult -Test "Time Synchronization" `
        -Result $(if ($timeSynced) {"PASS"} else {"WARN"}) -Severity "High" `
        -Value "Source: $timeSource" `
        -Details "Last sync: $lastSync" `
        -Impact $(if (-not $timeSynced) {"Clock skew will break TLS certificate validation"} else {""}) `
        -Remediation $(if (-not $timeSynced) {"Enable Windows Time service and sync with time server"} else {""})
    
    $script:Results += $r
    Write-TestResult $r
} catch {
    $r = Add-TestResult -Test "Time Synchronization" -Result "WARN" -Severity "High" `
        -Value "Could not verify time sync" -Impact "Time sync issues may affect TLS"
    $script:Results += $r
    Write-TestResult $r
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
Write-Host "Passed:       $($script:Stats.Passed)" -ForegroundColor Green
Write-Host "Failed:       $($script:Stats.Failed)" -ForegroundColor Red
Write-Host "Warnings:     $($script:Stats.Warnings)" -ForegroundColor Yellow
Write-Host "Info:         $($script:Stats.Info)" -ForegroundColor Cyan
Write-Host ""

$criticalFailures = $script:Results | Where-Object { $_.Result -eq "FAIL" -and $_.Severity -eq "Critical" }
$warnings = $script:Results | Where-Object { $_.Result -eq "WARN" }

if ($criticalFailures.Count -gt 0) {
    Write-Host "CERTIFICATE STATUS: " -NoNewline
    Write-Host "CRITICAL FAILURE" -ForegroundColor Red
    Write-Host ""
    Write-Host "Critical certificate/security issues detected. TLS connections will fail." -ForegroundColor Red
    Write-Host ""
    Write-Host "Critical Failures:" -ForegroundColor Red
    foreach ($failure in $criticalFailures) {
        Write-Host "  • $($failure.Test): $($failure.Value)" -ForegroundColor Red
        if ($failure.Remediation) {
            Write-Host "    Fix: $($failure.Remediation)" -ForegroundColor Yellow
        }
    }
} elseif ($warnings.Count -gt 0) {
    Write-Host "CERTIFICATE STATUS: " -NoNewline
    Write-Host "WARNINGS DETECTED" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Some certificate/security issues detected. May affect WARP functionality." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Warnings:" -ForegroundColor Yellow
    foreach ($warning in $warnings) {
        Write-Host "  • $($warning.Test): $($warning.Value)" -ForegroundColor Yellow
        if ($warning.Remediation) {
            Write-Host "    Fix: $($warning.Remediation)" -ForegroundColor Gray
        }
    }
} else {
    Write-Host "CERTIFICATE STATUS: " -NoNewline
    Write-Host "HEALTHY" -ForegroundColor Green
    Write-Host ""
    Write-Host "✓ Certificate stores are healthy" -ForegroundColor Green
    Write-Host "✓ Time synchronization is working" -ForegroundColor Green
    Write-Host "✓ TLS/SSL connections should function properly" -ForegroundColor Green
}

Write-Host ""

# Additional information
$infoItems = $script:Results | Where-Object { $_.Result -eq "INFO" }
if ($infoItems.Count -gt 0) {
    Write-Host "SECURITY INFORMATION:" -ForegroundColor Cyan
    foreach ($info in $infoItems) {
        Write-Host "  • $($info.Test): $($info.Value)" -ForegroundColor Gray
    }
    Write-Host ""
}

Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
