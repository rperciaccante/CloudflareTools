# README: Cloudflare WARP Unified Audit & Investigative Tool

## Overview

The **Cloudflare WARP Unified Audit & Investigative Tool** is a cumulative, high-integrity diagnostic suite designed for exhaustive environmental analysis. This tool was engineered using a "Multi-Phase Forensic Approach," with every test derived from deep-packet and process-level analysis of **Process Monitor (Procmon)** logs across all functional modules of the Cloudflare WARP client: **Installation (`msiexec`)**, **Service Runtime (`warp-svc`)**, **Diagnostic Engine (`warp-diag`)**, and **Digital Experience Monitoring (`warp-dex`)**.

The script is strictly additive and operates under a **Cumulative Integrity Directive**, ensuring that no legacy tests are removed or simplified. It provides a "Three-Table" reporting outcome that visually differentiates between Core Readiness, Diagnostic Platform Health, and Experience Monitoring parameters.

---

## Detailed Audit Pillars

### 1. Phase 1: Installation Readiness & Log-Derived Audit

This pillar ensures the underlying OS environment permits the foundational setup of the agent:

* **Wintun Driver Integrity**: Audits the system for existing `Wintun` driver versions. Conflicting drivers from other VPN providers (OpenVPN, WireGuard) are flagged as **WARN** to prevent kernel-level adapter collisions.
* **Certificate Store Write-Access**: Performs a real-time write-test to `HKLM:\SOFTWARE\Microsoft\SystemCertificates`. This is critical for the injection of the Cloudflare Root CA, which is the backbone of Zero Trust HTTPS inspection.
* **DLL Dependency Mapping**: Validates the presence of `dnsapi.dll`, `dhcpcsvc.dll`, and `dhcpcsvc6.dll`. These files are frequently queried during setup and are required for the agent to hook into the Windows IP stack.
* **ARM64 Translation Layer**: Specifically for Snapdragon and ARM-based devices, the script audits the `C:\Windows\xtacache` directory. Without write access here, the x64-to-ARM64 translation fails, causing the service to crash on launch.

### 2. Phase 2: Runtime Service & Permission Audit

This pillar monitors the stability of the active background daemon:

* **Forensic Service Mapping**: Unlike standard checks, this script extracts the **literal binary PathName** for `BFE`, `Dnscache`, `msiserver`, and `WlanSvc`. This detects "ghost services" or redirections caused by "debloat" scripts that silently break WARP.
* **Telemetry & Snapshot Persistence**: Performs modify-access tests on `C:\ProgramData\Cloudflare\snapshots` and `warp-diag-partials`. These paths allow the service to persist connection states across reboots.
* **System Profile Integrity**: Audits the `SYSTEM` account’s access to its own credential store in `C:\Windows\System32\config\systemprofile`. Restricted access here prevents the agent from storing persistent Zero Trust authentication tokens.

### 3. Socket Governance & Network Stack

This pillar audits the low-level TCP/IP parameters required for high-volume socket traffic:

* **MTU (Maximum Transmission Unit)**: Logs the MTU of every active interface to `mtu_audit.txt`. This is used to diagnose packet fragmentation issues where the tunnel overhead exceeds the physical link capacity.
* **Ephemeral Port Exhaustion**: Audits the `netsh` dynamic port range. If the range is too small, the WARP agent will fail to open control sockets, resulting in "Socket Error" or "Media Disconnected" statuses.
* **NRPT Policy (Name Resolution Policy Table)**: Dumps the NRPT to identify stale rules from legacy VPNs (DirectAccess, AnyConnect) that may be hijacking DNS queries intended for the WARP local proxy.

### 4. Deep-Dive Forensics (System & User Scope)

A comprehensive inventory of the system state to identify third-party interference:

* **Global Application Inventory**: Scans HKLM (64/32-bit) and HKCU to provide a unified list of software. This identifies "user-only" VPN installations that standard system-wide audits miss.
* **Startup Persistence Audit**: Maps every boot-persistence item across Registry `Run` keys, Startup Folders, and WMI Startup Objects for both the System and the active User.
* **Environment PATH Audit**: Captures and splits the **System vs. User PATH** variables. Misconfigured paths prevent the `warp-cli` from communicating with the background daemon.
* **Scheduled Task Map**: Lists active tasks with their literal **Triggers** and **Execution Commands** to find background scripts that reset network adapters.

### 5. warp-diag: Diagnostic Platform Audit

This section ensures the agent's own troubleshooting tools can function:

* **Diagnostic Staging Access**: Verifies write access to `packet_captures` and `qlogs` staging directories. If these are blocked, support bundles will be empty.
* **WinSock Namespace Catalog**: Audits `NameSpace_Catalog5` to ensure the diagnostic engine can identify third-party Layered Service Providers (LSPs) that interfere with socket creation.
* **IPv6 Interface Tuning**: Queries the `Tcpip6\Parameters\Interfaces` registry hive to ensure the agent can monitor IPv6 tunnel health.

### 6. warp-dex: Digital Experience Audit

This section audits the monitoring metadata used for Zero Trust Experience scores:

* **Cryptnet URL Cache**: Audits `C:\Windows\System32\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache`. Access here is required for DEX to monitor certificate validation latencies and URL "Experience" metrics.
* **DNS Experience Parameters**: Probes the `Dnscache\Parameters` hive to ensure DEX can accurately report on local resolution behavior and NetBIOS interference.
* **Crypto OID Configuration**: Audits the Certificate Chain Engine metadata to identify if certificate performance monitoring is being restricted by local security policies.

---

## Robust Reporting Standards

To ensure the data is "Analysis-Ready" for support teams and automated log aggregators:

* **Standardized Lowercase**: All 28+ output files and the final ZIP use a **strict lowercase naming convention**.
* **Status & Exception Capture**: The Final Report includes an `Exit Code / Exception` column. If any diagnostic command fails, the literal error message (e.g., *Access Denied* or *WMI Class Not Found*) is preserved for remediation.
* **Consolidated Archive**: All artifacts, including the "Three-Table" summary report, are bundled into a single ZIP file named `warp_preinstall_audit_{hostname}_{timestamp}.zip`.

---

## Technical Manifesto (Outcome Table)

| Component | Forensic Origin | Audit Purpose | Failure Consequence |
| --- | --- | --- | --- |
| **CertStore Write** | `install_logfile` | Root CA injection for HTTPS. | SSL inspection fails; browsers show "Privacy Error." |
| **WinSock Catalog** | `run_logfile` | Network stack hooking. | "Protocol Error" or "No Internet" on tunnel. |
| **MTU Settings** | Stack Audit | Encapsulation overhead. | 90% speed loss due to fragmentation. |
| **Cryptnet Cache** | `warp-dex` log | Experience Monitoring. | DEX score remains 0; no telemetry for support. |
| **xtacache** | `install_logfile` | ARM64 x64 Translation. | Service crashes immediately on ARM devices. |

---

## How to Use

1. **Elevation**: Must be run as **Administrator** to access `systemprofile` and `HKLM` hives.
2. **Command**: `.\warp_audit.ps1`
3. **Result**: Review the three summary tables in the console, as well as the output files stored in the ZIP file in the directory where the script was run

---

## Disclaimer

This tool is for diagnostic purposes and identifies potential environmental barriers discovered in WARP installer and runtime logs. It does not remediate settings or modify the system in any way.
