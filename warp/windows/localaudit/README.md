I have updated the **README.md** to reflect the deep-dive forensic capabilities, the strict lowercase naming convention for cross-platform analysis, and the inclusion of "Two-Phase" auditing (Readiness vs. Runtime).

---

# Cloudflare WARP Unified Diagnostic & Forensic Tool

## Overview

This script is a 360-degree environment auditor designed specifically for Cloudflare WARP. It identifies common points of failure in the network stack, service permissions, and third-party software conflicts by analyzing telemetry patterns found in both installation and runtime logs.

It operates in two phases:

1. **Installation Readiness**: Ensures the OS is capable of registering the MSI, installing the Wintun driver, and injecting necessary Root Certificates.
2. **Runtime Health**: Verifies that the background service can maintain persistent logging, manage WinSock catalogs, and negotiate tunnel interfaces.

---

## Key Diagnostic Features

### 1. Global Software & Persistence Inventory

The tool now collects comprehensive data on the machine's software state:

* **installed_applications.txt**: Scans HKLM (64-bit/32-bit) and HKCU registry hives to list every application installed at both the System and User levels. This helps identify "hidden" VPNs or security suites.
* **startup_apps.txt**: Captures every boot-persistence item, including Registry Run keys, Startup Folders (User/Common), and WMI Startup Objects.
* **scheduled_tasks.txt**: Extracts active tasks, including their literal **Triggers** and **Execution Commands**, to identify scripts that might intermittently reset network adapters.

### 2. Forensic Service Mapping

The script extracts the literal **Binary Path** (PathName) for core dependencies like `BFE`, `Dnscache`, and `msiserver`. This ensures that essential Windows services haven't been redirected or disabled by "debloating" scripts or third-party hardening tools.

### 3. Cross-Platform Standardization

To support analysis on non-Windows log aggregators (like Linux-based ELK stacks or Splunk), the script enforces a **strict lowercase naming convention** for all generated files and the final ZIP archive.

### 4. Binary Translation Audit (ARM64)

Based on `install_Logfile.CSV` analysis, the script detects if the host is an ARM64 device and audits the `xtacache` write permissions required for WARP’s x64-to-ARM translation layer.

---

## How to Use

1. **Execution**: You **must** run this script as an **Administrator**. Without elevation, the script cannot audit System-level startup commands or sensitive network registry hives.
2. **Command**:
`.\warp_audit.ps1`
3. **Artifact**: The script creates a folder and a consolidated ZIP file:
`warp_preinstall_audit_{hostname}_{timestamp}.zip`

---

## Technical Rationale (Based on Log Analysis)

| Category | Finding | Impact of Failure |
| --- | --- | --- |
| **WinSock Registry** | Service polls `Protocol_Catalog9` during tunnel build. | "Protocol Error" or "Media Disconnected" on the WARP adapter. |
| **Cert Store** | `msiexec` requires write access to `SystemCertificates`. | HTTPS inspection fails; browser displays "Privacy Error" (Zero Trust). |
| **ProgramData** | Service writes to `snapshots` for connectivity state. | App stays stuck on "Connecting" after a reboot or network change. |
| **Port 53 Binding** | WARP acts as a local DNS proxy. | Conflict with "Internet Connection Sharing" (ICS) stops all DNS resolution. |

---

## Secondary Diagnostics Included

The final ZIP includes 26 individual diagnostic files, covering:

* **Networking**: Route tables, ipconfig, DNS client settings, and bound UDP ports.
* **System**: Active processes, antivirus status, and drivers.
* **Hardware**: Subinterface MTU settings and IPv4/IPv6 configuration.

---

## Disclaimer

This script is a diagnostic tool intended to find environmental barriers. While it addresses issues found in Cloudflare's own installation and runtime logs, it does not modify system settings.

Would you like me to add a **"Conflicts"** section to the README that lists known incompatible software (like certain EDR agents or legacy VPNs) that the script should specifically alert you about?
