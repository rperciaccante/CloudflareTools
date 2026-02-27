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
Write-Host "--- Cloudflare WARP Unified Audit & Investigative Report ---" -ForegroundColor Cyan
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

# 1. WINTUN DRIVER AUDIT (RESTORED)
Write-Host "`nChecking Wintun Driver Versions..." -ForegroundColor Yellow
try {
    $WintunDrivers = Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.DeviceName -like "*Wintun*" }
    if ($WintunDrivers) {
        foreach ($drv in $WintunDrivers) {
            Log-Audit "Driver: Wintun" "WARN" "Exists" "Ver: $($drv.DriverVersion) - $($drv.Manufacturer)" "High" "Existing drivers can conflict with WARP adapter."
            Write-Host "  [!!] Found: $($drv.DeviceName) v$($drv.DriverVersion)" -ForegroundColor Yellow
        }
    } else {
        Log-Audit "Driver: Wintun" "PASS" "Not Found" "Clean state" "Info" "No existing driver conflicts."
        Write-Host "  [OK] No existing Wintun drivers detected." -ForegroundColor Green
    }
} catch {
    Log-Audit "Driver Check" "FAIL" "EXECUTION ERROR" "$($_.Exception.Message)" "High" "Could not query PnP drivers."
    Write-Host "  [ERROR] Driver check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# 2. CORE SYSTEM SERVICES (Includes Process Paths & Startup Types)

$Services = @(
    @{N="msiserver"; I="Critical"; E="Handles MSI database/rollback."; F="Disabled state prevents installation."}
    @{N="BFE"; I="High"; E="Manages firewall rules."; F="Installer cannot inject firewall exceptions."}
    @{N="Dnscache"; I="High"; E="Handles name resolution."; F="Handoff to encrypted DNS will fail."}
    @{N="WlanSvc"; I="Dependency"; E="WARP depends on this."; F="The background daemon will fail to start."}
)

Write-Host "`nChecking System Services..." -ForegroundColor Yellow
foreach ($S in $Services) {
    try {
        $svcObj = Get-Service -Name $S.N -ErrorAction Stop
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
    } catch {
        Log-Audit $S.N "FAIL" "EXECUTION ERROR" "$($_.Exception.Message)" $S.I "Service query failed."
        Write-Host "  [ERROR] Service $($S.N) query failed." -ForegroundColor Red
    }
}

# 3. ENVIRONMENT PATH AUDIT (System & User)

Write-Host "`nCapturing Environment PATH Variables..." -ForegroundColor Yellow
try {
    $SysPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $UsrPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $PathReport = @("--- SYSTEM PATH ---", ($SysPath -split ";"), "", "--- USER PATH ($Username) ---", ($UsrPath -split ";"))
    $PathReport | Out-File (Join-Path $DiagFolder "path_variables.txt")
    Log-Audit "Env: Path" "PASS" "Captured" "Logged to path_variables.txt" "Medium" "Identifies CLI tool accessibility."
    Write-Host "  [OK] Captured Path Variables." -ForegroundColor Green
} catch {
    Log-Audit "Env: Path" "FAIL" "EXECUTION ERROR" "$($_.Exception.Message)" "Medium" "Failed to read environment variables."
}

# 4. FILESYSTEM ACCESS AUDIT (Installation & Runtime paths)
$FSTargets = @(
    "C:\Program Files\Cloudflare", 
    "C:\ProgramData\Cloudflare", 
    "C:\Windows\Installer",
    "C:\ProgramData\Cloudflare\snapshots",
    "C:\ProgramData\Cloudflare\warp-diag-partials"
)
Write-Host "`nChecking Filesystem Access..." -ForegroundColor Yellow
foreach ($Path in $FSTargets) {
    try {
        if (!(Test-Path $Path)) { New-Item -Path $Path -ItemType Directory -Force | Out-Null }
        $testFile = Join-Path $Path "warp_audit.tmp"
        $null = New-Item -Path $testFile -ItemType File -Force -ErrorAction Stop
        Add-Content -Path $testFile -Value "Audit Write Test" -ErrorAction Stop
        Remove-Item $testFile -Force
        Log-Audit "Write: $Path" "PASS" "Granted" "Success" "Critical" "Binary/Log placement."
        Write-Host "  [OK] Access: $Path" -ForegroundColor Green
    } catch {
        Log-Audit "Write: $Path" "FAIL" "DENIED" "$($_.Exception.Message)" "Critical" "File placement will fail."
        Write-Host "  [Captured] Denied: $Path" -ForegroundColor Red
    }
}

# 5. NETWORK STACK & SOCKET GOVERNANCE

Write-Host "`nAuditing Network Stack & Socket Governance..." -ForegroundColor Yellow
try {
    Get-NetIPInterface | Select-Object InterfaceAlias, AddressFamily, NlMtu | Out-File (Join-Path $DiagFolder "mtu_audit.txt")
    & netsh int ipv4 show dynamicport tcp | Out-File (Join-Path $DiagFolder "ephemeral_ports.txt")
    Get-DnsClientNrptPolicy -ErrorAction SilentlyContinue | Out-File (Join-Path $DiagFolder "dns_nrpt_policy.txt")
    & netsh winhttp show proxy | Out-File (Join-Path $DiagFolder "proxy_settings.txt")

    # Audit Network Profile (Flagging Public)
    $NetProfile = Get-NetConnectionProfile
    foreach ($NP in $NetProfile) {
        $PF = if ($NP.NetworkCategory -eq 'Public') { "WARN" } else { "PASS" }
        Log-Audit "Net: Profile" $PF $NP.NetworkCategory "Alias: $($NP.InterfaceAlias)" "High" "Public profiles trigger stricter firewalling."
    }

    # Audit Hosts File (Flagging Redirects)
    $HostsContent = Get-Content "C:\Windows\System32\drivers\etc\hosts"
    $Redirects = $HostsContent | Where-Object { $_ -match "^\s*[^#]" }
    if ($Redirects) { Log-Audit "File: Hosts" "WARN" "Modified" "Non-default entries found" "Medium" "Check for traffic redirection." }
    $HostsContent | Out-File (Join-Path $DiagFolder "hosts_file_audit.txt")
} catch {
    Log-Audit "Network Audit" "FAIL" "EXECUTION ERROR" "$($_.Exception.Message)" "High" "Stack audit failed."
}

# 6. SPECIALIZED PERMISSIONS (Log Analysis Derived)
Write-Host "`nChecking Specialized Permissions..." -ForegroundColor Yellow

# Certificate Store Write Test
$CertStore = "HKLM:\SOFTWARE\Microsoft\SystemCertificates"
try {
    $testKey = Join-Path $CertStore "WARP_Audit"
    $null = New-Item -Path $testKey -Force -ErrorAction Stop
    Remove-Item $testKey -Force
    Log-Audit "Registry: CertStore" "PASS" "Granted" "Write Success" "High" "Required for Root CA."
} catch {
    Log-Audit "Registry: CertStore" "FAIL" "DENIED" "$($_.Exception.Message)" "High" "SSL inspection will fail."
}

# DLL & System Profile
if (Test-Path "C:\Windows\System32\dnsapi.dll") { Log-Audit "File: dnsapi.dll" "PASS" "Found" "Present" "Critical" "DNS Proxy support." }
$SysProfile = "C:\Windows\System32\config\systemprofile\AppData\Roaming\Microsoft\Credentials"
if (Test-Path $SysProfile) { Log-Audit "Path: SysProfile" "PASS" "Exists" "Found" "Medium" "Credential persistence." }

# ARM64 Cache
if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") {
    $XtaPath = "C:\Windows\xtacache"
    try {
        $testFile = Join-Path $XtaPath "warp_arm.tmp"
        $null = New-Item -Path $testFile -ItemType File -Force -ErrorAction Stop
        Remove-Item $testFile -Force
        Log-Audit "Path: xtacache" "PASS" "Granted" "ARM64 Cache OK" "High" "Required for translation."
    } catch {
        Log-Audit "Path: xtacache" "FAIL" "DENIED" "$($_.Exception.Message)" "High" "Performance failure."
    }
}

# 7. RUNNING DEEP-DIVE DIAGNOSTICS (System & User Scope)
Write-Host "`nRunning Deep-Dive Diagnostics (System & User Scope)..." -ForegroundColor Yellow

# A. Global Installed Applications (HKLM + HKCU)
try {
    $UninstallKeys = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*","HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*")
    Get-ItemProperty $UninstallKeys | Where-Object { $_.DisplayName -ne $null } | Select-Object DisplayName, DisplayVersion, Publisher | Sort-Object DisplayName | Out-File (Join-Path $DiagFolder "installed_applications.txt")
} catch { Log-Audit "Diag: Apps" "FAIL" "ERROR" "$($_.Exception.Message)" "Info" "App enumeration failed." }

# B. Global Startup Persistence (Registry + Folder + WMI)

try {
    Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User | Format-List | Out-File (Join-Path $DiagFolder "startup_apps.txt")
} catch { Log-Audit "Diag: Startup" "FAIL" "ERROR" "$($_.Exception.Message)" "Info" "Startup enumeration failed." }

# C. Scheduled Tasks (Triggers & Actions)

try {
    Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | Select-Object TaskName, TaskPath, @{N="Triggers";E={$_.Triggers.ToString()}}, @{N="Actions";E={$_.Actions.Execute}} | Format-List | Out-File (Join-Path $DiagFolder "scheduled_tasks.txt")
} catch { Log-Audit "Diag: Tasks" "FAIL" "ERROR" "$($_.Exception.Message)" "Info" "Task enumeration failed." }

# 8. FULL SECONDARY DIAGNOSTICS (All 23+ Commands with Detailed Error Reporting)
Write-Host "`nRunning Secondary Diagnostics..." -ForegroundColor Yellow
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
    $LowerLabel = $Diag.Label.ToLower()
    $OutPath = Join-Path $DiagFolder $LowerLabel
    Write-Host "  Processing: $LowerLabel..." -NoNewline
    try {
        $Error.Clear()
        Invoke-Expression $Diag.Cmd | Out-File -FilePath $OutPath -ErrorAction Stop
        $exitStatus = if ($LASTEXITCODE -eq $null) { "0" } else { $LASTEXITCODE.ToString() }
        
        if ($Error.Count -eq 0 -and ($exitStatus -eq "0" -or $exitStatus -eq "")) {
            Write-Host " [PASS]" -ForegroundColor Green
            Log-Audit "Diag: $LowerLabel" "PASS" "Success" "Captured" "Info" "Diagnostic successful."
        } else {
            Write-Host " [FAIL]" -ForegroundColor Red
            Log-Audit "Diag: $LowerLabel" "FAIL" "EXIT CODE: $exitStatus" "Execution Error" "Info" "Command returned non-zero or internal error."
        }
    } catch {
        Write-Host " [ERROR]" -ForegroundColor Red
        Log-Audit "Diag: $LowerLabel" "FAIL" "EXCEPTION" "$($_.Exception.Message)" "Info" "Script failed to execute command."
    }
    $global:LASTEXITCODE = $null
}

# 9. FINAL REPORT & ZIP
$ReportPath = Join-Path $DiagFolder "00_final_audit_report.txt"
$FileHeader = @"
--- Cloudflare WARP Unified Investigative Report ---
Host: $Hostname
Admin: $isAdmin
Time: $DisplayDate
User: $Username
Output: $DiagFolder
---------------------------------------------------------
"@
$FileHeader | Out-File -FilePath $ReportPath
$FinalReport | Format-Table -AutoSize | Out-File -FilePath $ReportPath -Append

Write-Host "`n--- FINAL AUDIT REPORT ---" -ForegroundColor Cyan
$FinalReport | Format-Table -AutoSize

Write-Host "`nCompressing results into: $ZipFile" -ForegroundColor Yellow
if (Test-Path $ZipFile) { Remove-Item $ZipFile -Force }
Compress-Archive -Path $DiagFolder -DestinationPath $ZipFile -Force
Write-Host "Process Complete. All data in ZIP archive." -ForegroundColor Cyan
