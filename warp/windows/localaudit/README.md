# Cloudflare WARP Unified Pre-Install & Runtime Auditor

## Overview

This diagnostic tool performs a deep-level environment scan to ensure a Windows machine is ready for Cloudflare WARP. Unlike standard installers, this script uses "Two-Phase" logic based on actual Procmon installation and runtime logs:

1. **Installation Readiness**: Verifies the machine can register the MSI, install Wintun drivers, and inject Root Certificates.
2. **Runtime Health**: Verifies the background service can maintain logs, negotiate the WinSock catalog, and access system profile credentials.

---

## Key Diagnostic Features

* **Binary Translation Audit**: Specifically checks for `xtacache` write access on ARM64 devices to prevent performance degradation.
* **Protocol Catalog Audit**: Verifies read access to WinSock2 and TCP/IP Interface registry hives, ensuring the tunnel can assign IP addresses.
* **Certificate Store Integrity**: Checks for write permissions in `SystemCertificates` to ensure HTTPS inspection and Zero Trust Root CAs can be deployed.
* **Automated Bundling**: Generates a consolidated ZIP package containing the final report and 23 secondary network diagnostic logs.

---

## How to Use

1. **Prerequisites**: PowerShell 5.1+.
2. **Execution**: Run as Administrator for full registry and service auditing.
3. **Command**:
**.\warp_audit.ps1**
4. **Output**: A folder and a ZIP file named **warp_preinstall_audit_{HOSTNAME}_{TIMESTAMP}.zip** will be created in the script's directory.

---

## Technical Rationale (Based on Log Analysis)

**Wintun & Core Services**
Based on the `install_Logfile.CSV`, the installer explicitly probes for `msiserver` and `BFE`. If these are disabled, the installation fails immediately with a rollback.

**WinSock & Interface Registry**
Analysis of `run_Logfile.CSV` showed the service constantly polling `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`. If restricted, the adapter remains in a "Media Disconnected" state.

**ProgramData Snapshots**
The runtime service manages connectivity state in `C:\ProgramData\Cloudflare\snapshots`. Denied access here causes the app to stay stuck on "Connecting" even if the tunnel is technically up.

---

## Secondary Diagnostics Included

The script automatically captures the following data into the final ZIP:

* **Network Stack**: ipconfig, netstat, route tables, and DNS client status.
* **System Health**: Active processes, service states, and antivirus product detection.
* **Connectivity**: Tracert and packet monitor (pktmon) status.
* **Interfaces**: IPv4/IPv6 subinterface configuration and MTU settings.

---

## Disclaimer

This script is for diagnostic purposes. It identifies barriers found in the Cloudflare WARP installer and runtime logs. Environmental variables (GPO, EDR, AV) may create additional restrictions not covered by this audit.
