# Cloudflare WARP Pre-Installation Readiness Assessment

## Overview

`localaudit.v2.ps1` is a comprehensive PowerShell diagnostic script that performs pre-installation readiness checks for Cloudflare WARP. It validates system requirements, services, permissions, network connectivity, and security configurations to identify potential issues before attempting WARP installation.

## Purpose

This script helps IT administrators and users:
- **Identify blockers** before WARP installation attempts
- **Diagnose connectivity issues** in restricted network environments
- **Validate system configurations** meet WARP requirements
- **Generate comprehensive reports** for troubleshooting
- **Reduce failed installations** by catching issues early

## Key Features

- ✅ **Single-file architecture** - Easy to distribute and execute
- ✅ **No external dependencies** - Uses native Windows PowerShell and .NET
- ✅ **Comprehensive testing** - 50+ individual test cases across 6 categories
- ✅ **Detailed reporting** - GO/NO-GO recommendation with remediation steps
- ✅ **Diagnostic collection** - 28+ diagnostic files for troubleshooting
- ✅ **Automatic cleanup** - Creates ZIP archive and removes temporary files

## Requirements

- **Operating System:** Windows 8 or later (Windows 10/11 recommended)
- **PowerShell:** Version 5.1 or later
- **Execution Policy:** Must allow script execution (`Set-ExecutionPolicy RemoteSigned`)
- **Permissions:** Administrator rights recommended (some tests require elevation)

## Usage

### Basic Execution

```powershell
# Run with administrator privileges
.\localaudit.v2.ps1
```

### Output

The script generates:
1. **Console output** - Real-time test results with color-coded status
2. **ZIP archive** - `warp_audit_<hostname>_<timestamp>.zip` containing:
   - `00_audit_report.txt` - Comprehensive assessment report
   - `all_test_results.csv` - Structured test data
   - `proxy_configuration.txt` - Detailed proxy settings
   - 28+ diagnostic files (network, DNS, firewall, etc.)

## Test Categories

### Category 1: System Requirements (9 tests)

Tests fundamental system prerequisites for WARP installation.

| Test | Why It Matters |
|------|----------------|
| **Operating System Version** | WARP requires Windows 8+ (6.2+). Older versions lack required APIs. |
| **Architecture** | WARP requires 64-bit Windows (AMD64 or ARM64). 32-bit is not supported. |
| **Disk Space** | Minimum 200 MB free on C: drive for installation files and logs. |
| **Existing WARP Installation** | Detects upgrade vs. fresh install scenario. |
| **Wintun Driver** | Checks for existing Wintun driver that may conflict. |
| **PowerShell Version** | WARP installer may require PowerShell 5.1+ for automation. |
| **.NET Framework** | WARP components may depend on .NET 4.6.2 or later. |
| **TLS 1.2/1.3 Support** | Critical for HTTPS connections to Cloudflare endpoints. Without TLS 1.2+, all API calls fail. |
| **IPv6 Configuration** | Informational - indicates if WARP can use IPv6 or IPv4-only. |

**Why These Tests:** System requirements failures cause immediate installation failures. These tests catch incompatible systems before wasting time on installation attempts.

---

### Category 2: Required Services (10 tests)

Validates critical Windows services that WARP depends on.

| Service | Why It's Required |
|---------|-------------------|
| **Windows Installer (msiserver)** | Required to install MSI packages. Must be set to Manual or Automatic. |
| **Base Filtering Engine (BFE)** | Required for Windows Filtering Platform. WARP uses this for firewall rules and packet filtering. |
| **DNS Client (Dnscache)** | Required for DNS resolution. WARP needs to resolve Cloudflare endpoints. |
| **Network Location Awareness (NlaSvc)** | Detects network changes and profiles. WARP needs this to adapt to network transitions. |
| **Network Store Interface Service (nsi)** | Core network stack service. Required for all network operations. |
| **Cryptographic Services (CryptSvc)** | Required for certificate validation and TLS connections. |
| **Windows Time (W32Time)** | Time synchronization is critical for TLS certificate validation. Clock skew breaks HTTPS. |
| **Remote Procedure Call (RpcSs)** | Core Windows service required by many WARP components. |
| **DHCP Client (Dhcp)** | Required for automatic network configuration. |
| **WLAN AutoConfig (WlanSvc)** | Optional - required on laptops for WiFi management. |

**Why These Tests:** Service failures cause WARP to malfunction or fail to start. These are the most common causes of "WARP won't connect" issues.

---

### Category 3: Permissions (6 tests)

Validates filesystem and registry write permissions.

| Test | Why It Matters |
|------|----------------|
| **Filesystem Write: C:\Program Files\Cloudflare** | WARP installs binaries here. Write access required. |
| **Filesystem Write: C:\ProgramData\Cloudflare** | WARP stores configuration and logs here. Write access required. |
| **Filesystem Write: C:\Windows\Installer** | MSI installer needs write access for temporary files. |
| **Registry Write: Certificate Store** | WARP may need to install root CA certificates. |
| **System DLL: dnsapi.dll** | Required for DNS operations. Missing indicates corrupted Windows. |
| **System DLL: dhcpcsvc.dll / dhcpcsvc6.dll** | Required for DHCP operations. Missing indicates corrupted Windows. |

**Why These Tests:** Permission failures cause silent installation failures or runtime errors. These tests identify permission issues before installation.

---

### Category 4: Proxy Configuration (6 tests)

Detects proxy configurations that may interfere with WARP.

| Test | Why It Matters |
|------|----------------|
| **System Proxy (WinHTTP)** | System-wide proxy affects all Windows services and applications. May route WARP traffic through proxy. |
| **Windows Internet Settings** | User-level proxy affects IE, Edge (system mode), and WinINet applications. |
| **Microsoft Edge Proxy** | Edge-specific proxy may bypass WARP tunnel. |
| **Google Chrome Proxy** | Chrome-specific proxy may bypass WARP tunnel. |
| **Firefox Proxy** | Firefox has independent proxy settings that bypass system proxy. |
| **VPN Client Detection** | Other VPN clients conflict with WARP. Only one VPN can be active at a time. |
| **Environment Variables** | HTTP_PROXY/HTTPS_PROXY variables affect CLI tools and applications. |

**Why These Tests:** Proxy configurations are the #1 cause of "WARP connects but traffic doesn't route" issues. Multiple proxy layers create complex routing problems.

---

### Category 5: Certificate & Security (6 tests)

Validates certificate infrastructure and security settings.

| Test | Why It Matters |
|------|----------------|
| **Certificate Store Health** | Verifies Windows certificate store is functional. Empty Root store breaks all TLS. |
| **Trusted Root CAs** | Checks for DigiCert/Baltimore CAs used by Cloudflare. Missing CAs cause TLS failures. |
| **Certificate Revocation Checking** | Informational - indicates if CRL/OCSP checking is enabled. |
| **Windows Defender** | Informational - antivirus may scan WARP traffic and cause latency. |
| **Windows Firewall** | Informational - firewall rules may need WARP exceptions. |
| **Time Synchronization** | Critical - clock skew >5 minutes breaks TLS certificate validation. |

**Why These Tests:** Certificate and time issues cause mysterious "connection failed" errors. These are difficult to diagnose without checking certificate infrastructure.

---

### Category 6: Network Connectivity (15+ tests)

Tests connectivity to Cloudflare endpoints per official firewall documentation.

#### 6.1: Client Orchestration API
- **zero-trust-client.cloudflareclient.com** - Registration and settings retrieval
- **notifications.cloudflareclient.com** - Push notifications
- **Why:** WARP cannot register or retrieve configuration without these endpoints.

#### 6.2: WireGuard Tunnel Ingress (162.159.193.0/24)
- **UDP ports:** 2408, 500, 1701, 4500
- **Why:** WireGuard protocol requires UDP connectivity. Blocked UDP = no tunnel.

#### 6.3: MASQUE Tunnel Ingress (162.159.197.0/24)
- **UDP ports:** 443, 500, 1701, 4500, 4443, 8443, 8095
- **TCP port:** 443
- **Why:** MASQUE is the fallback protocol when WireGuard is blocked. Uses QUIC over UDP.

#### 6.4: Connectivity Checks
- **162.159.197.3:443** - Connectivity check endpoint
- **engage.cloudflareclient.com:2408** - Tunnel establishment
- **Why:** WARP uses these to verify tunnel is working.

#### 6.5: Captive Portal Detection
- Tests 6 domains used for captive portal detection
- **Why:** WARP needs to detect captive portals to pause tunnel and allow authentication.

#### 6.6: Additional Endpoints
- **api.cloudflareclient.com** - Registration API
- **client.warp.cloudflare.com** - Updates and telemetry
- **Why:** Required for registration and optional for updates.

#### 6.7: Optional Features
- **time.cloudflare.com:123** - NTP time sync
- **a.nel.cloudflare.com** - Network Error Logging
- **Why:** Optional features that enhance WARP functionality.

**Test Methodology:**
- **TCP Tests:** Establish connection, verify 3-way handshake
- **UDP Tests:** Send test packet (delivery not confirmed - connectionless protocol)
- **HTTPS Tests:** TCP + TLS handshake, verify SSL certificate
- **DNS Tests:** Resolve hostname to IPv4 address

**Important Limitations:**
- ✗ Does NOT perform actual WARP/WireGuard/MASQUE protocol handshakes
- ✗ Does NOT validate server responses or protocol operations
- ✗ Does NOT confirm UDP packet delivery (connectionless protocol)
- ✓ ONLY tests network reachability and identifies firewall blocks

**Why These Tests:** Network connectivity failures are the most visible WARP issues. These tests identify firewall rules, proxy blocks, and routing issues that prevent WARP from connecting.

---

## Diagnostic Files Generated

The script collects 28+ diagnostic files for troubleshooting:

### Core Diagnostics
- `00_audit_report.txt` - Comprehensive assessment with GO/NO-GO recommendation
- `all_test_results.csv` - Structured test data for analysis
- `proxy_configuration.txt` - Complete proxy configuration details

### Network Diagnostics
- `network_interfaces.txt` - Network adapter configuration
- `route_table.txt` - Routing table
- `dns_config.txt` - DNS server configuration
- `firewall_profiles.txt` - Network profile settings
- `mtu_audit.txt` - MTU settings per interface
- `ephemeral_ports.txt` - Dynamic port range configuration
- `dns_nrpt_policy.txt` - DNS Name Resolution Policy Table
- `ipconfig_all.txt` - Complete IP configuration
- `netstat_ano.txt` - All network connections with PIDs
- `arp_table.txt` - ARP cache
- `dns_cache.txt` - DNS resolver cache
- `firewall_rules.txt` - All Windows Firewall rules
- `wlan_profiles.txt` - WiFi profiles
- `network_adapters.txt` - Detailed adapter information
- `tcp_connections.txt` - TCP connection table
- `udp_endpoints.txt` - UDP endpoint table
- `dns_client_cache.txt` - PowerShell DNS cache
- `network_statistics.txt` - Network protocol statistics
- `routing_table_detailed.txt` - Detailed routing table
- `interface_statistics.txt` - Interface statistics

### System Diagnostics
- `hosts_file.txt` - Hosts file contents
- `path_variables.txt` - System and user PATH variables
- `installed_apps.txt` - Installed applications
- `startup_apps.txt` - Startup applications
- `scheduled_tasks.txt` - Active scheduled tasks

**Why Collect These:** When WARP fails, these diagnostics provide the complete system context needed to identify root causes. They complement warp-diag output by capturing pre-installation state.

---

## Interpreting Results

### GO/NO-GO Decision Logic

The script provides a final recommendation:

- **GO** - System is ready for WARP installation
  - 0 critical failures
  - ≤2 high priority failures
  
- **CAUTION** - System has issues but may support WARP
  - ≤2 critical failures
  - Review failures and remediate if possible
  
- **NO-GO** - System does NOT meet requirements
  - >2 critical failures
  - Do not proceed until issues are resolved

### Test Results

Each test reports:
- **PASS** ✓ - Test passed, no action needed
- **FAIL** ✗ - Test failed, remediation required
- **WARN** ⚠ - Warning, may cause issues but not blocking
- **INFO** ℹ - Informational, no action needed

### Remediation

Failed tests include:
- **Impact** - What will happen if not fixed
- **Remediation** - Specific commands or steps to fix the issue

---

## Common Issues and Solutions

### Issue: TLS 1.2 Disabled
**Symptom:** All HTTPS endpoint tests fail  
**Cause:** TLS 1.2 disabled in registry or Group Policy  
**Fix:** Enable TLS 1.2 client protocols in registry or via Group Policy

### Issue: Proxy Detected
**Symptom:** WARN on proxy tests  
**Impact:** WARP traffic may route through proxy, causing conflicts  
**Fix:** Configure WARP split tunneling or disable proxy for Cloudflare IPs

### Issue: VPN Client Detected
**Symptom:** WARN on VPN detection  
**Impact:** Only one VPN can be active at a time  
**Fix:** Disable other VPN clients before using WARP

### Issue: Time Not Synchronized
**Symptom:** FAIL on time synchronization  
**Impact:** Clock skew breaks TLS certificate validation  
**Fix:** Enable Windows Time service and sync with time server

### Issue: Certificate Store Empty
**Symptom:** FAIL on certificate store health  
**Impact:** All TLS/SSL connections will fail  
**Fix:** Reinstall root certificates or repair Windows

### Issue: UDP Ports Blocked
**Symptom:** FAIL on WireGuard/MASQUE tests  
**Impact:** WARP cannot establish tunnel  
**Fix:** Allow UDP ports 2408, 500, 1701, 4500 to 162.159.193.0/24 and 162.159.197.0/24

---

## Version History

### Version 2.0 (Current)
- ✅ Complete rewrite with improved architecture
- ✅ Added 20+ new test cases
- ✅ New category: Certificate & Security
- ✅ Enhanced proxy detection (Edge, Chrome, Firefox, VPN)
- ✅ Added 7 critical services (NlaSvc, CryptSvc, W32Time, etc.)
- ✅ Added TLS 1.2/1.3 verification
- ✅ Added PowerShell and .NET Framework checks
- ✅ Fixed ZIP cleanup bug (verify before delete)
- ✅ Comprehensive diagnostics collection (28+ files)
- ✅ Detailed GO/NO-GO reporting with remediation

### Version 1.0
- Initial release with basic connectivity tests

---

## Technical Details

### Architecture
- **Language:** PowerShell 5.1+
- **Framework:** .NET Framework 4.6.2+
- **Dependencies:** None (uses native Windows APIs)
- **Execution Time:** 2-4 minutes depending on network conditions

### Network Testing Approach
- **TCP:** Uses .NET TcpClient with async connect and 3-second timeout
- **UDP:** Uses .NET UdpClient to send test packets (delivery not confirmed)
- **HTTPS:** TCP + SslStream for TLS handshake and certificate validation
- **DNS:** Uses .NET Dns.GetHostAddresses for resolution

### Data Collection
- **Non-invasive:** Read-only operations except for permission tests
- **Temporary files:** Creates test files in target directories, then removes them
- **No network modification:** Does not change firewall rules or network settings
- **Privacy:** No data sent externally, all results stored locally

---

## Troubleshooting the Script

### Script Won't Run
**Error:** "Execution policy does not allow..."  
**Fix:** `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser`

### Permission Errors
**Error:** "Access denied" on filesystem/registry tests  
**Fix:** Run PowerShell as Administrator (right-click → Run as administrator)

### Network Tests Timeout
**Cause:** Firewall blocking outbound connections  
**Expected:** This is what the script is designed to detect

### ZIP Creation Fails
**Cause:** Insufficient disk space or permissions  
**Result:** Script preserves output folder instead of deleting it

---

## Support and Documentation

### Official Cloudflare Documentation
- [WARP Firewall Requirements](https://developers.cloudflare.com/cloudflare-one/connections/connect-devices/warp/deployment/firewall/)
- [WARP Deployment Guide](https://developers.cloudflare.com/cloudflare-one/connections/connect-devices/warp/deployment/)

### Script Maintenance
- **Location:** `/Users/bob/projects/localaudit/`
- **Main Script:** `localaudit.v2.ps1`
- **Previous Version:** `localaudit.ps1` (archived in `.hold`)

---

## License and Disclaimer

This script is provided as-is for diagnostic purposes. It performs read-only operations except for temporary permission test files which are immediately removed.

**Disclaimer:** This script tests network reachability and system configuration. It does NOT replicate actual WARP client behavior or guarantee WARP will function correctly. Successful tests indicate the network path is available, but WARP may still encounter issues during actual operation.

---

## Contributing

When modifying this script:
1. Maintain single-file architecture for easy distribution
2. Add new tests to appropriate category
3. Include Impact and Remediation for all failures
4. Update this README with new tests and their purpose
5. Test on multiple Windows versions (10, 11, Server)
6. Verify no external dependencies are introduced

---

**Last Updated:** March 4, 2026  
**Script Version:** 2.0  
**Author:** IT Operations Team
