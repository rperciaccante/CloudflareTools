# Cloudflare WARP Pre-Installation Auditor

## Overview
This PowerShell script is a **non-interactive diagnostic tool** designed to verify if a Windows machine meets the specific environmental requirements for a successful Cloudflare WARP installation. 

The audit criteria are derived from a comprehensive file and registry access log of the Cloudflare WARP installer. It captures potential "Access Denied" events and system conflicts without interrupting the script execution, providing a gap analysis of what may cause an installation to fail.

---

## Key Features
* **Non-Remediating**: The script only reports; it does not change system settings or kill processes.
* **Robust Error Handling**: Uses `try/catch` blocks to capture and report permission denials that usually crash standard scripts.
* **Environment Validation**:
    * **Wintun Driver**: Checks for existing versions to prevent driver collisions.
    * **System Services**: Verifies `msiserver` (Windows Installer), `BFE` (Base Filtering Engine), and `WlanSvc` (WLAN AutoConfig).
    * **Filesystem & Registry**: Tests write access to critical paths in `Program Files`, `ProgramData`, and `HKLM`.
    * **Network Ports**: Audits Port 53 (DNS), 500/4500 (IPsec), and 2408 (WARP) for active listeners.

---

## Sample Output
When executed, the script provides real-time progress followed by a summarized report in the console:

```text
--- Cloudflare WARP Silent Audit Report ---

Hostname: WORKSTATION-01
Timestamp: Thursday, February 26, 2026 12:15:00 PM
Report run by: bob
-------------------------------------------

Checking Wintun Driver Versions...
  [OK] No existing Wintun drivers detected.

Checking System Services...
  [PASS] msiserver is Stopped (StartType: Manual)
  [PASS] BFE is Running (StartType: Automatic)
  [PASS] Dnscache is Running (StartType: Automatic)
  [FAIL/WARN] WlanSvc is Stopped (StartType: Disabled)

Checking Filesystem/Registry Access...
  [OK] Access: C:\Program Files\Cloudflare
  [OK] Access: C:\ProgramData\Cloudflare
  [Captured] Denied: C:\Windows\Installer

Checking Network Port Conflicts...
  [OK] Port 53 is free.
  [CONFLICT] Port 2408 used by AnotherVPNDaemon

--- FINAL AUDIT REPORT ---

Component      Pass/Fail Status  Details               Importance  Impact
---------      --------- ------  -------               ----------  ------
Driver: Wintun PASS      Not Found Clean state           Info        No conflicts.
msiserver      PASS      Stopped   StartType: Manual     Critical    Handles MSI DB.
BFE            PASS      Running   StartType: Automatic  High        Manages Firewall.
WlanSvc        FAIL      Stopped   StartType: Disabled   Dependency  Service won't start.
Write: C:\Prog PASS      Granted   Success               Critical    Binary placement.
Port:2408      FAIL      CONFLICT  Used by VPNApp        Critical    Tunnel will fail.
