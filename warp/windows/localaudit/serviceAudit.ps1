<#
.SYNOPSIS
    Cloudflare WARP Required Services Validator

.DESCRIPTION
    Standalone script to validate Windows services required for WARP to function.
    Extracted from localaudit.v2.ps1 for focused service troubleshooting.
    
    Checks:
    - Windows Installer (msiserver)
    - Base Filtering Engine (BFE)
    - DNS Client (Dnscache)
    - Network Location Awareness (NlaSvc)
    - Network Store Interface Service (nsi)
    - Cryptographic Services (CryptSvc)
    - Windows Time (W32Time)
    - Remote Procedure Call (RpcSs)
    - DHCP Client (Dhcp)
    - WLAN AutoConfig (WlanSvc) - optional
    
    ANTIVIRUS CONSIDERATIONS:
    This script enumerates Windows services using Get-Service.
    All operations are READ-ONLY - no services are started, stopped, or modified.

.NOTES
    Version: 1.0
    Requires: PowerShell 5.1+
    Administrator rights recommended for full service information
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
        [string]$Value = "", [string]$Impact = "", [string]$Remediation = ""
    )
    
    $obj = [PSCustomObject]@{
        Test = $Test
        Result = $Result
        Severity = $Severity
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
# DISPLAY HEADER
# ============================================================================

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  CLOUDFLARE WARP REQUIRED SERVICES VALIDATOR" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "Hostname:      $($script:Env.Hostname)"
Write-Host "User:          $($script:Env.Username)"
Write-Host "Administrator: $($script:Env.IsAdmin)"
Write-Host "Timestamp:     $($script:Env.Timestamp.ToString('F'))"
Write-Host ""

if (-not $script:Env.IsAdmin) {
    Write-Host "⚠ WARNING: Not running as Administrator" -ForegroundColor Yellow
    Write-Host "  Some service information may be limited" -ForegroundColor Yellow
    Write-Host ""
}

# ============================================================================
# SERVICE VALIDATION TESTS
# ============================================================================
# This section checks Windows services required for WARP to function.
# AV NOTE: Service enumeration via Get-Service is standard administrative practice.
# This is READ-ONLY - no services are started, stopped, or modified.

Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "REQUIRED SERVICES VALIDATION" -ForegroundColor Cyan
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
        
        # Special handling for trigger-start services (msiserver, NlaSvc)
        $healthy = if ($svc.Name -in @("msiserver", "NlaSvc")) {
            $startType -in @("Manual", "Automatic") -or $status -eq "Running"
        } else {
            $status -eq "Running"
        }
        
        $r = Add-TestResult -Test $svc.Display `
            -Result $(if ($healthy) {"PASS"} else {"FAIL"}) -Severity $svc.Severity `
            -Value "$status ($startType)" `
            -Impact $(if (-not $healthy) {$svc.Impact} else {""}) `
            -Remediation $(if (-not $healthy) {$svc.Remediation} else {""})
        
        $script:Results += $r
        Write-TestResult $r
        
    } catch {
        if ($svc.Optional) {
            $r = Add-TestResult -Test $svc.Display -Result "WARN" -Severity "Low" `
                -Value "Not installed (optional)" -Impact "May affect laptops"
        } else {
            $r = Add-TestResult -Test $svc.Display -Result "FAIL" -Severity $svc.Severity `
                -Value "Not found" -Impact $svc.Impact -Remediation "Verify Windows installation"
        }
        $script:Results += $r
        Write-TestResult $r
    }
}

Write-Host ""

# ============================================================================
# SUMMARY
# ============================================================================

Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "SUMMARY" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""
Write-Host "Total Services: $($script:Stats.Total)"
Write-Host "Healthy:        $($script:Stats.Passed)" -ForegroundColor Green
Write-Host "Failed:         $($script:Stats.Failed)" -ForegroundColor Red
Write-Host "Warnings:       $($script:Stats.Warnings)" -ForegroundColor Yellow
Write-Host ""

$criticalFailures = $script:Results | Where-Object { $_.Result -eq "FAIL" -and $_.Severity -eq "Critical" }
$highFailures = $script:Results | Where-Object { $_.Result -eq "FAIL" -and $_.Severity -eq "High" }

if ($criticalFailures.Count -gt 0) {
    Write-Host "SERVICE STATUS: " -NoNewline
    Write-Host "CRITICAL FAILURE" -ForegroundColor Red
    Write-Host ""
    Write-Host "Critical services are not running. WARP will not function." -ForegroundColor Red
    Write-Host ""
    Write-Host "Critical Failures:" -ForegroundColor Red
    foreach ($failure in $criticalFailures) {
        Write-Host "  • $($failure.Test): $($failure.Value)" -ForegroundColor Red
        if ($failure.Remediation) {
            Write-Host "    Fix: $($failure.Remediation)" -ForegroundColor Yellow
        }
    }
} elseif ($highFailures.Count -gt 0) {
    Write-Host "SERVICE STATUS: " -NoNewline
    Write-Host "DEGRADED" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Some important services are not running. WARP may have issues." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "High Priority Failures:" -ForegroundColor Yellow
    foreach ($failure in $highFailures) {
        Write-Host "  • $($failure.Test): $($failure.Value)" -ForegroundColor Yellow
        if ($failure.Remediation) {
            Write-Host "    Fix: $($failure.Remediation)" -ForegroundColor Gray
        }
    }
} else {
    Write-Host "SERVICE STATUS: " -NoNewline
    Write-Host "READY" -ForegroundColor Green
    Write-Host ""
    Write-Host "✓ All required services are running" -ForegroundColor Green
    Write-Host "✓ System is ready for WARP installation" -ForegroundColor Green
}

Write-Host ""

# Additional recommendations
if ($script:Stats.Failed -gt 0 -and $script:Env.IsAdmin) {
    Write-Host "RECOMMENDED ACTIONS:" -ForegroundColor Cyan
    Write-Host "  1. Review failed services above" -ForegroundColor Gray
    Write-Host "  2. Run the remediation commands as Administrator" -ForegroundColor Gray
    Write-Host "  3. Re-run this script to verify fixes" -ForegroundColor Gray
    Write-Host ""
} elseif ($script:Stats.Failed -gt 0 -and -not $script:Env.IsAdmin) {
    Write-Host "RECOMMENDED ACTIONS:" -ForegroundColor Cyan
    Write-Host "  1. Run PowerShell as Administrator" -ForegroundColor Gray
    Write-Host "  2. Execute the remediation commands shown above" -ForegroundColor Gray
    Write-Host "  3. Re-run this script to verify fixes" -ForegroundColor Gray
    Write-Host ""
}

Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
