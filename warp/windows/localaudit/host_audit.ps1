$ErrorActionPreference = "SilentlyContinue"
$FinalReport = @()
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$Hostname = $env:COMPUTERNAME
$Username = $env:USERNAME
$DateStamp = Get-Date -Format "yyyyMMdd_HHmm"
$DisplayDate = Get-Date -Format "F"

# Set Folder and ZIP names (Lowercased)
$FolderName = "warp_preinstall_audit_$($Hostname)_$($DateStamp)".ToLower()
$DiagFolder = Join-Path $PSScriptRoot $FolderName
$ZipFile = "$DiagFolder.zip".ToLower()

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

# 2. CORE SYSTEM SERVICES (Includes Process Paths)

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
        $cimSvc = Get-CimInstance Win32_Service -Filter "Name = '$($S.N)'"
        $ProcPath = $cimSvc.PathName

        if ($S.N -eq "msiserver" -and ($svcObj.StartType -eq 'Manual' -or $svcObj.Status -eq 'Running')) {
            $PF = "PASS"; $Color = "Green"
        } elseif ($S.N -ne "msiserver" -and $svcObj.Status -eq 'Running') {
            $PF = "PASS"; $Color = "Green"
        }
        
        Log-Audit $S.N $PF "$($svcObj.Status) ($($svcObj.StartType))" "Path: $ProcPath" $S.I $S.E
        Write-Host "  [$PF] $($S.N) is $($svcObj.Status)" -ForegroundColor $Color
    } else {
        Log-Audit $S.N "FAIL" "Missing" "Not found" $S.I $S.F
    }
}

# 3. RUNTIME LOGGING & REGISTRY
$RuntimePaths = @("C:\ProgramData\Cloudflare\snapshots", "C:\ProgramData\Cloudflare\warp-diag-partials")
foreach ($RPath in $RuntimePaths) {
    if (!(Test-Path $RPath)) { New-Item -Path $RPath -ItemType Directory -Force | Out-Null }
    try {
        $testFile = Join-Path $RPath "runtime_check.tmp"
        New-Item -Path $testFile -ItemType File -Force | Out-Null
        Remove-Item $testFile -Force
        Log-Audit "Runtime: $RPath" "PASS" "Full Access" "Modify Success" "High" "Critical for telemetry."
    } catch {
        Log-Audit "Runtime: $RPath" "FAIL" "DENIED" "Access Denied" "High" "Logs will fail."
    }
}

# 4. NETWORK PORT AUDIT

$Ports = @(53, 500, 4500, 2408)
foreach ($P in $Ports) {
    try {
        $conn = Get-NetUDPEndPoint -LocalPort $P -ErrorAction Stop
        $proc = Get-Process -Id $conn.OwningProcess
        Log-Audit "Port:$P" "FAIL" "CONFLICT" "Used by $($proc.Name)" "High" "Critical for Tunneling."
    } catch {
        Log-Audit "Port:$P" "PASS" "Clear" "Port is free" "Info" "Available for WARP."
    }
}

# 5. DEEP-DIVE DIAGNOSTICS (Lowercased filenames)
Write-Host "`nRunning Deep-Dive Diagnostics (System & User Scope)..." -ForegroundColor Yellow

# A. Comprehensive Installed Applications (System + User)
Write-Host "  Processing: installed_applications.txt..." -NoNewline
$UninstallKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
)
Get-ItemProperty $UninstallKeys | Where-Object { $_.DisplayName -ne $null } | 
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | 
    Sort-Object DisplayName | Format-Table -AutoSize | 
    Out-File (Join-Path $DiagFolder "installed_applications.txt")
Write-Host " Done." -ForegroundColor Green

# B. Comprehensive Startup Apps (Registry + Startup Folders + WMI)

Write-Host "  Processing: startup_apps.txt..." -NoNewline
$StartupData = Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User
$StartupData | Format-List | Out-File (Join-Path $DiagFolder "startup_apps.txt")
Write-Host " Done." -ForegroundColor Green

# C. Scheduled Tasks
Write-Host "  Processing: scheduled_tasks.txt..." -NoNewline
Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | 
    Select-Object TaskName, TaskPath, State, 
    @{Name="Triggers";Expression={$_.Triggers.ToString()}}, 
    @{Name="Actions";Expression={$_.Actions.Execute}} | 
    Format-List | Out-File (Join-Path $DiagFolder "scheduled_tasks.txt")
Write-Host " Done." -ForegroundColor Green

# 6. SECONDARY DIAGNOSTICS (Forced Lowercase)
$SecondaryCommands = @(
    @{Label="antivirus-check.txt"; Cmd='Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntivirusProduct'}
    @{Label="com-avi-adapters.txt"; Cmd='Get-WmiObject -class Win32_NetworkAdapterConfiguration | fl *'}
    @{Label="drivers.txt"; Cmd='Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Sort-Object DeviceName | Format-Table -AutoSize | Out-String -width 9999'}
    @{Label="registry-interfaces.txt"; Cmd='Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"'}
    @{Label="route.txt"; Cmd='Find-NetRoute -RemoteIPAddress 1.1.1.1'}
    @{Label="routetable.txt"; Cmd='Format-Table -Property ifIndex, DestinationPrefix, NextHop, RouteMetric, ifMetric, InterfaceAlias, State -InputObject (Get-NetRoute | Sort-Object)'}
    @{Label="services.txt"; Cmd='Get-WmiObject Win32_Service | Select-Object Name, DisplayName, ProcessId, State | Format-Table -AutoSize | Out-String -width 9999'}
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
    # Force filename to lowercase
    $LowerLabel = $Diag.Label.ToLower()
    $OutPath = Join-Path $DiagFolder $LowerLabel
    Write-Host "  Processing: $LowerLabel..." -NoNewline
    try {
        $Error.Clear()
        Invoke-Expression $Diag.Cmd | Out-File -FilePath $OutPath -ErrorAction Stop
        if ($Error.Count -eq 0) { Write-Host " [PASS]" -ForegroundColor Green } 
        else { Write-Host " [FAIL]" -ForegroundColor Red }
    } catch {
        Write-Host " [ERROR]" -ForegroundColor Red
    }
}

# FINAL REPORT & ZIP
$ReportPath = Join-Path $DiagFolder "00_final_audit_report.txt"
$FileHeader = "--- Cloudflare WARP Unified Report ---`nHost: $Hostname`nAdmin: $isAdmin`nTime: $DisplayDate`n"
$FileHeader | Out-File -FilePath $ReportPath
$FinalReport | Format-Table -AutoSize | Out-File -FilePath $ReportPath -Append

Write-Host "`n--- FINAL AUDIT REPORT ---" -ForegroundColor Cyan
$FinalReport | Format-Table -AutoSize

Write-Host "`nCompressing results into: $ZipFile" -ForegroundColor Yellow
if (Test-Path $ZipFile) { Remove-Item $ZipFile -Force }
Compress-Archive -Path $DiagFolder -DestinationPath $ZipFile -Force
Write-Host "Process Complete." -ForegroundColor Cyan
