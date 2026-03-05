<#
.SYNOPSIS
    Cloudflare WARP System Diagnostics Collector

.DESCRIPTION
    Standalone script to collect comprehensive system diagnostics for troubleshooting.
    Extracted from localaudit.v2.ps1 for focused diagnostic gathering without running tests.
    
    Collects:
    - Network interfaces, routes, DNS configuration
    - Firewall profiles and rules
    - Hosts file, installed applications
    - Path variables, MTU settings, ephemeral ports
    - DNS NRPT policy, startup apps, scheduled tasks
    - ipconfig, netstat, ARP table, DNS cache
    - TCP/UDP connections, network statistics
    - And 20+ additional diagnostic files
    
    ANTIVIRUS CONSIDERATIONS:
    This script performs system enumeration that may trigger behavioral detection:
    - Process enumeration (netstat -ano)
    - Network connection enumeration (Get-NetTCPConnection)
    - Firewall rule reading (netsh advfirewall)
    All data is saved LOCALLY - no external transmission.

.NOTES
    Version: 1.0
    Requires: PowerShell 5.1+
    Administrator rights recommended for complete diagnostics
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

$script:Env = @{
    IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Hostname = $env:COMPUTERNAME
    Username = $env:USERNAME
    Timestamp = Get-Date
    DateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
}

$script:OutputFolder = Join-Path $PSScriptRoot "warp_diagnostics_$($script:Env.Hostname)_$($script:Env.DateStamp)".ToLower()
$script:CollectedCount = 0
$script:FailedCount = 0

# ============================================================================
# DISPLAY HEADER
# ============================================================================

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  CLOUDFLARE WARP SYSTEM DIAGNOSTICS COLLECTOR" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "Hostname:      $($script:Env.Hostname)"
Write-Host "User:          $($script:Env.Username)"
Write-Host "Administrator: $($script:Env.IsAdmin)"
Write-Host "Timestamp:     $($script:Env.Timestamp.ToString('F'))"
Write-Host "Output:        $script:OutputFolder"
Write-Host ""

if (-not $script:Env.IsAdmin) {
    Write-Host "⚠ WARNING: Not running as Administrator" -ForegroundColor Yellow
    Write-Host "  Some diagnostic information may be limited" -ForegroundColor Yellow
    Write-Host ""
}

# Create output folder
if (-not (Test-Path $script:OutputFolder)) {
    New-Item -Path $script:OutputFolder -ItemType Directory -Force | Out-Null
}

# ============================================================================
# DIAGNOSTICS COLLECTION
# ============================================================================
# This section collects system diagnostic information for troubleshooting.
# AV WARNING: System enumeration (processes, network connections, installed apps)
# may trigger behavioral detection as these are reconnaissance techniques.
# All data is saved LOCALLY in the output folder - no external transmission.
# This is standard IT diagnostic practice for troubleshooting network issues.

Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "COLLECTING SYSTEM DIAGNOSTICS" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""

# PowerShell-based diagnostics
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
        $script:CollectedCount++
    } catch {
        Write-Host "  [!] Failed: $($diag.Name)" -ForegroundColor Yellow
        $script:FailedCount++
    }
}

# Path Variables
try {
    $sysPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $usrPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $pathReport = @("=== SYSTEM PATH ===", ($sysPath -split ";"), "", "=== USER PATH ===", ($usrPath -split ";"))
    $pathReport | Out-File (Join-Path $script:OutputFolder "path_variables.txt") -ErrorAction Stop
    Write-Host "  [+] Collected: path_variables" -ForegroundColor Green
    $script:CollectedCount++
} catch {
    Write-Host "  [!] Failed: path_variables" -ForegroundColor Yellow
    $script:FailedCount++
}

# MTU Audit
try {
    Get-NetIPInterface -ErrorAction Continue | Select-Object InterfaceAlias,AddressFamily,NlMtu | 
        Out-File (Join-Path $script:OutputFolder "mtu_audit.txt") -ErrorAction Stop
    Write-Host "  [+] Collected: mtu_audit" -ForegroundColor Green
    $script:CollectedCount++
} catch {
    Write-Host "  [!] Failed: mtu_audit" -ForegroundColor Yellow
    $script:FailedCount++
}

# Ephemeral Ports
try {
    & netsh int ipv4 show dynamicport tcp | Out-File (Join-Path $script:OutputFolder "ephemeral_ports.txt") -ErrorAction Stop
    Write-Host "  [+] Collected: ephemeral_ports" -ForegroundColor Green
    $script:CollectedCount++
} catch {
    Write-Host "  [!] Failed: ephemeral_ports" -ForegroundColor Yellow
    $script:FailedCount++
}

# DNS NRPT Policy
try {
    Get-DnsClientNrptPolicy -ErrorAction SilentlyContinue | 
        Out-File (Join-Path $script:OutputFolder "dns_nrpt_policy.txt") -ErrorAction Stop
    Write-Host "  [+] Collected: dns_nrpt_policy" -ForegroundColor Green
    $script:CollectedCount++
} catch {
    Write-Host "  [!] Failed: dns_nrpt_policy" -ForegroundColor Yellow
    $script:FailedCount++
}

# Startup Applications
try {
    Get-CimInstance Win32_StartupCommand -ErrorAction Continue | 
        Select-Object Name,Command,User | Format-List | 
        Out-File (Join-Path $script:OutputFolder "startup_apps.txt") -ErrorAction Stop
    Write-Host "  [+] Collected: startup_apps" -ForegroundColor Green
    $script:CollectedCount++
} catch {
    Write-Host "  [!] Failed: startup_apps" -ForegroundColor Yellow
    $script:FailedCount++
}

# Scheduled Tasks
try {
    Get-ScheduledTask -ErrorAction Continue | Where-Object {$_.State -ne 'Disabled'} | 
        Select-Object TaskName,@{N="Triggers";E={$_.Triggers.ToString()}},@{N="Actions";E={$_.Actions.Execute}} | 
        Format-List | Out-File (Join-Path $script:OutputFolder "scheduled_tasks.txt") -ErrorAction Stop
    Write-Host "  [+] Collected: scheduled_tasks" -ForegroundColor Green
    $script:CollectedCount++
} catch {
    Write-Host "  [!] Failed: scheduled_tasks" -ForegroundColor Yellow
    $script:FailedCount++
}

Write-Host ""
Write-Host "Collecting additional network diagnostics..." -ForegroundColor Cyan
Write-Host ""

# Additional System Diagnostics
# AV WARNING: The following commands may trigger alerts:
# - netstat -ano: Lists all network connections with process IDs (reconnaissance)
# - Get-NetTCPConnection/Get-NetUDPEndpoint: Enumerates active connections (reconnaissance)
# - netsh advfirewall: Reads firewall rules (security enumeration)
# These are standard network diagnostic commands - all output saved locally
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
        $script:CollectedCount++
    } catch {
        Write-Host "  [!] Failed: $($diag.Label)" -ForegroundColor Yellow
        $script:FailedCount++
    }
}

Write-Host ""

# ============================================================================
# CREATE ZIP ARCHIVE
# ============================================================================

Write-Host "Creating ZIP archive..." -ForegroundColor Cyan

$zipCreated = $false
$zipPath = "$script:OutputFolder.zip"

try {
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    
    Add-Type -Assembly "System.IO.Compression.FileSystem"
    [System.IO.Compression.ZipFile]::CreateFromDirectory($script:OutputFolder, $zipPath)
    
    if (Test-Path $zipPath) {
        $zipInfo = Get-Item $zipPath
        if ($zipInfo.Length -gt 1KB) {
            $zipCreated = $true
            Write-Host "✓ Archive created: $zipPath ($([math]::Round($zipInfo.Length/1MB,2)) MB)" -ForegroundColor Green
        }
    }
} catch {
    Write-Host "✗ Could not create ZIP archive: $($_.Exception.Message)" -ForegroundColor Red
}

# Remove output folder if ZIP was successfully created
if ($zipCreated) {
    try {
        Remove-Item -Path $script:OutputFolder -Recurse -Force -ErrorAction Stop
        Write-Host "✓ Removed output folder (contents preserved in ZIP)" -ForegroundColor Green
    } catch {
        Write-Host "⚠ Could not remove output folder" -ForegroundColor Yellow
    }
}

Write-Host ""

# ============================================================================
# SUMMARY
# ============================================================================

Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "COLLECTION SUMMARY" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host ""
Write-Host "Files Collected: $script:CollectedCount" -ForegroundColor Green
Write-Host "Files Failed:    $script:FailedCount" -ForegroundColor $(if ($script:FailedCount -gt 0) {"Yellow"} else {"Green"})
Write-Host ""

if ($zipCreated) {
    Write-Host "DIAGNOSTICS STATUS: " -NoNewline
    Write-Host "COMPLETE" -ForegroundColor Green
    Write-Host ""
    Write-Host "✓ Diagnostics collected and archived" -ForegroundColor Green
    Write-Host "✓ Archive: $zipPath" -ForegroundColor Green
    Write-Host ""
    Write-Host "NEXT STEPS:" -ForegroundColor Cyan
    Write-Host "  1. Review diagnostic files in the ZIP archive" -ForegroundColor Gray
    Write-Host "  2. Share with support team if needed" -ForegroundColor Gray
    Write-Host "  3. Look for anomalies in network configuration" -ForegroundColor Gray
} else {
    Write-Host "DIAGNOSTICS STATUS: " -NoNewline
    Write-Host "PARTIAL" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "⚠ Diagnostics collected but ZIP creation failed" -ForegroundColor Yellow
    Write-Host "⚠ Files available in: $script:OutputFolder" -ForegroundColor Yellow
}

Write-Host ""

if ($script:FailedCount -gt 0) {
    Write-Host "NOTE: Some diagnostics failed to collect." -ForegroundColor Yellow
    Write-Host "This is usually due to:" -ForegroundColor Gray
    Write-Host "  • Missing Administrator privileges" -ForegroundColor Gray
    Write-Host "  • Services not installed (e.g., WLAN on desktops)" -ForegroundColor Gray
    Write-Host "  • Security policies blocking enumeration" -ForegroundColor Gray
    Write-Host ""
}

Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
