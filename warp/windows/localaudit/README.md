# README: Cloudflare WARP Unified Audit & Investigative Tool

## Overview

The **Cloudflare WARP Unified Audit & Investigative Tool** is an exhaustive, non-interactive diagnostic suite designed to identify environmental barriers preventing the successful installation, connection, and performance of the Cloudflare WARP agent.

Unlike standard diagnostic tools, this suite was engineered using a "Two-Phase" forensic approach. Every check is derived from an in-depth analysis of **Process Monitor (Procmon)** logs captured during both the initial installation phase and active runtime service execution. It captures high-fidelity data regarding filesystem permissions, registry integrity, network stack governance, and system-wide persistence.

---

## Complete Feature List

### 1. Installation Readiness Audit

Derived from `install_logfile.csv`, this phase identifies why the MSI installer might fail or roll back:

* **Windows Installer (msiserver) State**: Verifies the service is not disabled. It accounts for the fact that `msiserver` is often stopped by default and marks it as a PASS if it is in "Manual" or "Running" mode.
* **Certificate Store Integrity**: Performs a literal write-test to `HKLM:\SOFTWARE\Microsoft\SystemCertificates`. This ensures the installer can deploy the Cloudflare Root CA required for Zero Trust and HTTPS inspection.
* **Installer Cache Access**: Validates write permissions for `C:\Windows\Installer`, a common point of failure for MSI extraction.
* **DLL Dependency Verification**: Explicitly checks for the presence of `dnsapi.dll`, a core requirement for the agent's local DNS proxy.
* **ARM64 Translation Audit**: Identifies ARM64 architectures and validates access to `C:\Windows\xtacache`. This prevents failures in the x64-to-ARM binary translation layer.

### 2. Runtime Service Health & Permissions

Derived from `run_logfile.csv`, this phase identifies why the agent might be "Stuck on Connecting" or failing to stay stable:

* **Service Binary Path Integrity**: Queries the literal `PathName` from the registry for `BFE`, `Dnscache`, and `WlanSvc`. This detects if "debloating" scripts or malware have redirected or hijacked essential system services.
* **Persistence & Snapshots**: Validates "Modify" permissions for `C:\ProgramData\Cloudflare\snapshots` and `warp-diag-partials`. These folders are critical for the service to "remember" connection states after reboots.
* **WinSock & Interface Tuning**: Audits read access to the `WinSock2` Protocol Catalog and the `Tcpip\Interfaces` registry hives. If restricted, the agent cannot assign local IP addresses to the virtual adapter.
* **System Profile Access**: Checks for the existence and accessibility of the `SYSTEM` account’s credential store (`AppData\Roaming\Microsoft\Credentials`) to ensure persistent authentication.

### 3. Network Stack & Socket Governance

Audits the OS parameters that govern high-volume socket traffic and encrypted tunneling:

* **MTU (Maximum Transmission Unit)**: Captures the MTU for every active interface. This is critical for preventing packet fragmentation caused by VPN header overhead.
* **Ephemeral Port Range**: Reports the dynamic port range for both TCP and UDP. This identifies "Port Exhaustion" scenarios where the agent cannot open new control sockets.
* **NRPT (Name Resolution Policy Table)**: Dumps the NRPT to identify "Stale" DNS rules from previous VPNs (Cisco, AnyConnect, DirectAccess) that might be hijacking WARP's DNS queries.
* **Network Category Profile**: Specifically flags adapters set to the "Public" profile. Windows Firewall defaults to stricter blocking on Public profiles, which can intermittently drop WARP control traffic.
* **Hosts File Redirect Audit**: Scans the system `hosts` file and issues a **WARN** in the final report if non-commented redirects are found, which could interfere with tunnel resolution.

### 4. Deep-Dive Forensic Collection

Exhaustively maps the system state to identify third-party conflicts:

* **Global Application Inventory**: A unified scan of HKLM (64/32-bit) and HKCU registry hives. This identifies software installed at both the System and User level, uncovering "hidden" user-level VPNs or security tools.
* **Startup Persistence Audit**: Maps every boot-persistence item across the OS, including Registry `Run` keys, Startup Folders (User and Common), and WMI Startup Objects.
* **Task Scheduler Analysis**: Extracts all active tasks, including their literal **Triggers** and **Execution Commands**, to find background scripts that might be resetting network adapters.
* **System & User PATH Audit**: Captures both environment variables and splits them line-by-line. This helps debug failures where WARP CLI tools (`warp-cli`) are not being properly resolved.

---

## Detailed Outcomes & Reporting Logic

The tool generates a high-visibility summary table and logs specific execution results to ensure that even "internal" script failures are trackable.

### Summary Report Statuses

* **PASS**: The component meets all requirements for Cloudflare WARP.
* **FAIL**: A critical barrier was found (e.g., Access Denied to a mandatory registry hive).
* **WARN**: A potential conflict was found (e.g., an existing Wintun driver or a "Public" network profile) that may degrade performance.
* **EXECUTION ERROR**: This is a high-transparency status. If a diagnostic command (like `tracert` or `Get-WmiObject`) fails due to a system-level error or permissions, the **literal Exception Message** or **Non-Zero Exit Code** is displayed in the summary table.

### Technical Rationale Table

| Component | Audit Source | Rationale | Impact of Failure |
| --- | --- | --- | --- |
| **CertStore Write** | `install_logfile.csv` | Installer must inject Root CA. | "Privacy Error" or No Zero Trust connection. |
| **WinSock Catalog** | `run_logfile.csv` | Agent hooks into the network stack. | "Protocol Error" or "Media Disconnected." |
| **MTU Settings** | Network Stack | VPNs add encapsulation overhead. | Severe packet loss and speed degradation. |
| **NRPT Policy** | VPN Forensics | Directs DNS queries to specific tunnels. | DNS Leaks or "Domain Not Found" errors. |
| **BFE/Dnscache Path** | Forensic Audit | Ensures services are genuine system files. | Silently broken DNS proxy or Firewall. |

---

## How to Use

1. **Elevation**: This script **requires Administrator privileges** to perform write-tests on HKLM and audit the System Profile.
2. **Execution**:
`.\warp_audit.ps1`
3. **Filenames**: All output files use a strict **lowercase naming convention** to ensure they are compatible with Linux-based log analysis tools and cross-platform forensics.
4. **Artifact Generation**: The script automatically bundles the final report and 27 individual diagnostic files into a compressed ZIP file:
`warp_preinstall_audit_{hostname}_{timestamp}.zip`

---

## File Manifest (Inside the ZIP)

* `00_final_audit_report.txt`: The executive summary table and error log.
* `installed_applications.txt`: Full System and User software inventory.
* `startup_apps.txt`: All boot-persistence items.
* `scheduled_tasks.txt`: All active tasks with triggers and actions.
* `path_variables.txt`: Line-by-line split of System and User PATHs.
* `mtu_audit.txt`: MTU settings for all network adapters.
* `dns_nrpt_policy.txt`: Active Name Resolution Policy Table.
* `network_profiles.txt`: Connection categories (Public/Private).
* `23+ Secondary Diagnostics`: Detailed logs for `ipconfig`, `route`, `drivers`, `firewall`, `netstat`, and more.

---

## Disclaimer

This tool is for diagnostic purposes and identifies environmental barriers discovered in WARP installer and runtime logs. It does not remediate settings or modify the system permanently.
