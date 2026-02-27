# README: Cloudflare WARP Unified Audit & Investigative Tool

## Executive Overview

The **Cloudflare WARP Unified Audit & Investigative Tool** is a high-fidelity, cumulative diagnostic suite designed for exhaustive environmental analysis of Windows endpoints. This tool was engineered using a **Multi-Phase Forensic Approach**, where every check and validation is derived from an in-depth analysis of **Process Monitor (Procmon)** logs across the entire Cloudflare WARP stack: **Installation (`msiexec`)**, **Service Runtime (`warp-svc`)**, **Diagnostic Engine (`warp-diag`)**, and **Digital Experience Monitoring (`warp-dex`)**.

Operating under a strict **Cumulative Integrity Directive**, the script is additive-only. It provides a "Multi-Table" reporting outcome that separates core OS readiness from active network pathing and protocol-specific telemetry.

---

## Architectural Pillars & Functions

### 1. Phase 1: Installation Readiness (Forensic Pillar)

This section audits the machine's ability to host the WARP binary and drivers.

* **Wintun Driver Audit**: Queries the PnP signed driver database to find existing `Wintun` instances. It flags existing versions as **WARN** to prevent kernel-level adapter collisions with other VPN software.
* **Certificate Store Write-Access**: Executes a real-time registry write-test to `HKLM:\SOFTWARE\Microsoft\SystemCertificates`. This is required for the deployment of the Cloudflare Root CA used in SSL inspection.
* **DLL Dependency Verification**: Checks for the presence of `dnsapi.dll`, `dhcpcsvc.dll`, and `dhcpcsvc6.dll` in the System32 directory, which are critical for DHCP and DNS hooking.
* **ARM64 Translation Layer**: On ARM-based hardware, the script audits `C:\Windows\xtacache`. If the translation cache is restricted, the x86-to-ARM64 bridge fails, causing immediate service termination.

### 2. Phase 2: Runtime Service & Permission Integrity

This pillar monitors the environment where the active background daemon (`warp-svc.exe`) operates.

* **Forensic Service Path Mapping**: Unlike standard service checks, this function extracts the **literal binary PathName** for `BFE`, `Dnscache`, `msiserver`, and `WlanSvc`. This detects "ghosting" or redirections by malicious tools or "debloat" scripts.
* **Persistence Folder Audit**: Performs write/modify tests on `C:\ProgramData\Cloudflare\snapshots` and `warp-diag-partials`. Restricted access here prevents the service from remembering connection state after a reboot.
* **System Profile Credentials**: Validates the `SYSTEM` account’s access to its local credential store in `C:\Windows\System32\config\systemprofile`. This ensures Zero Trust authentication tokens can be safely stored.

### 3. Phase 3: Network Stack & Socket Governance

This pillar audits the OS-level networking parameters required for high-volume encrypted traffic.

* **MTU (Maximum Transmission Unit)**: Captures the MTU for every active interface to `mtu_audit.txt`. Incorrect MTU values cause packet fragmentation and severe performance degradation within VPN tunnels.
* **Ephemeral Port Range**: Reports the TCP/UDP dynamic port range. If ports are exhausted or restricted, the agent cannot open control sockets to the Cloudflare Edge.
* **NRPT Policy Dump**: Extracts the Name Resolution Policy Table to find stale rules from legacy VPNs (DirectAccess/AnyConnect) that hijack DNS queries.
* **Network Profile Audit**: Specifically flags interfaces marked as "Public," which trigger stricter Windows Firewall rules that can block WARP control traffic.

### 4. Phase 4: Active Connectivity & Protocol Probes

This section utilizes a set of internal helper functions to test active pathing to Cloudflare’s Ingress and API endpoints. Results are grouped by protocol to differentiate between WireGuard and MASQUE success.

* **`Test-UdpPort` & `Test-TcpPort**`: Custom socket-level probes that send specific payloads to verify bidirectional communication on critical ports (2408, 443, 500, 4500, 8443, etc.).
* **SSL/TLS Inspection Check**: Establishes a raw SSL stream to the Cloudflare API and audits the **X509 Certificate Issuer**. If the issuer does not match a known public CA (e.g., Google, DigiCert, Cloudflare), it flags a **WARN** for corporate SSL interception, which breaks WARP authentication.
* **WireGuard Probing**: Randomly selects IPs from the `162.159.193.x` range to test standard WireGuard tunneling.
* **MASQUE (HTTP/3) Probing**: Randomly selects IPs from the `162.159.197.x` range to test MASQUE/QUIC pathing, including TCP fallback.
* **Ingress Resolution**: Resolves `engage.cloudflareclient.com` and validates the path to the resolved IP.

### 5. Phase 5: Deep-Dive Forensics (System & User)

* **Global Application Inventory**: Scans HKLM (64/32-bit) and HKCU registry hives to provide a unified list of software.
* **Startup Persistence**: Maps all Registry `Run` keys, Startup Folders, and WMI boot items for both the System and the active User.
* **Environment PATH Split**: Captures and splits the **System vs. User PATH** variables line-by-line for visual auditing.
* **Scheduled Task Audit**: Lists active tasks with their literal **Triggers** and **Actions**.

### 6. Phase 6: Platform-Specific Component Audits

* **`warp-diag` Audit**: Based on `warp-diag_logfile.csv`. Audits write access to staging directories like `packet_captures` and `qlogs`, and read access to the `NameSpace_Catalog5` registry.
* **`warp-dex` Audit**: Based on `warp-dex_logfile.csv`. Audits the `CryptnetUrlCache` in the system profile and DNS Experience parameters. This ensures the Digital Experience Monitoring agent can collect performance telemetry.

### 7. Phase 7: Archive Verification & Safe Cleanup

The final stage of the script ensures the integrity of the data collected.

* **Archive Match Verification**: Re-opens the generated ZIP file using the `.NET ZipFile` library and compares the internal file manifest against the local folder's file list.
* **Safe Cleanup**: If and only if the ZIP contents perfectly match the source folder, the script performs a recursive, forced deletion of the local folder to maintain a clean working directory.

---

## Detailed Reporting Logic & Outputs

### Standardized Status Reporting

* **PASS**: Component is healthy and accessible.
* **FAIL**: A critical barrier exists. If caused by a script execution error, the **literal Exception Message** is captured in the "Details" column.
* **WARN**: Potential conflict detected (e.g., "Public" network profile or "Untrusted SSL Issuer").
* **EXIT CODE**: Native Windows tool results (e.g., `netsh`, `ipconfig`) capture the numeric exit code.

All files within the generated `warp_preinstall_audit_{hostname}_{timestamp}.zip` use a **strict lowercase naming convention**.

### Core Audit Reports

* **`00_final_audit_report.txt`**: The executive master report. Contains the **Core Readiness Table**, **Connectivity by Protocol Table**, and **Platform Audit (DIAG/DEX) Tables**. All command execution errors and exceptions are logged here.
* **`path_variables.txt`**: A forensic split of the `Machine` vs. `User` environment variables, listed line-by-line to identify conflicting CLI tool paths.
* **`mtu_audit.txt`**: Detailed list of MTU (Maximum Transmission Unit) settings for all physical and virtual interfaces (critical for fragmentation troubleshooting).
* **`ephemeral_ports.txt`**: Output of the TCP/UDP dynamic port range. Used to identify socket exhaustion barriers.
* **`dns_nrpt_policy.txt`**: The Name Resolution Policy Table. Identifies hidden DNS routing rules that may bypass WARP.
* **`network_profiles.txt`**: Identifies the Windows Network Category (Public/Private/Domain) for each adapter to determine firewall strictness.
* **`installed_applications.txt`**: A unified software inventory across HKLM (64/32), WOW6432Node, and HKCU hives.
* **`startup_apps.txt`**: Complete map of all boot-start applications (Registry, Startup Folders, and WMI).
* **`scheduled_tasks.txt`**: Comprehensive list of active system tasks including their literal **Triggers** and **Action Commands**.
* **`hosts_file_audit.txt`**: A copy of the system `hosts` file with an automated audit flag if non-default redirects are present.
* `proxy_settings.txt`: Current WinHTTP proxy configuration.

### Secondary Diagnostic Logs (Native OS Capture)

* **`ipconfig.txt`**: Full IP configuration and adapter details.
* **`routetable.txt`**: Active IPv4 and IPv6 routing table.
* **`route.txt`**: Result of a specific route look-up for Cloudflare’s DNS (`1.1.1.1`).
* **`drivers.txt`**: Full list of signed PnP drivers, versions, and manufacturers.
* **`services.txt`**: Current state and PIDs for all system services.
* **`bound-dns-ports.txt`**: Netstat output identifying which processes are listening on DNS (UDP/53).
* **`dns-client.txt`**: Detailed PowerShell output of the DNS Client settings.
* **`firewall-rules.txt`**: Dump of active Windows Filtering Platform (WFP) filters.
* **`interfaces-config.txt`**: Netsh output showing the IP configuration of all interfaces.
* **`v4interfaces.txt` / `v6interfaces.txt**`: Netsh output for specific IP version interface states.
* **`v4subinterfaces.txt` / `v6subinterfaces.txt**`: Detailed Netsh metrics for MTU and sub-interface health.
* **`pktmon.txt`**: Status of the Windows Packet Monitor (identifying if third-party captures are active).
* **`processes.txt`**: Full snapshot of running processes.
* **`systeminfo.txt`**: OS version, patch level, and hardware metadata.
* **`tracert.txt`**: Path trace to Cloudflare’s Anycast ingress point.
* **`antivirus-check.txt`**: WMI-based detection of active security products.
* **`cmdkey.txt`**: List of stored credentials (checks for generic credential isolation issues).
* **`sleep.txt`**: Power configuration settings to identify if network sleep is causing tunnel drops.
* **`user-session.txt`**: Result of `qwinsta` to identify concurrent sessions or RDP-related conflicts.
* **`com-avi-adapters.txt`**: Detailed WMI network adapter configuration.

---

## How to Run

1. **Elevation**: Must be run in an **Administrative PowerShell** terminal.
2. **Command**: `.\warp_audit.ps1`
3. **Completion**: Upon successful verification, the tool will provide a single ZIP file with the results of the assessment, as well as pertinent system information.
