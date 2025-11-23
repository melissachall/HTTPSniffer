# Installation Guide - HTTP Sniffer MITM

## Prerequisites

### Operating System Requirements
- **Kali Linux 2023.x+** (Recommended)
- **Parrot OS 5.x+**
- **Ubuntu 20.04+** with security tools

### Hardware Requirements
- CPU: 2 cores minimum
- RAM: 2 GB minimum
- Network: Ethernet adapter (recommended)

---

## Step-by-Step Installation

### 1. Update System

```bash
sudo apt update && sudo apt upgrade -y
```

### 2. Install Python and Pip

```bash
# Install Python 3 and pip
sudo apt install -y python3 python3-pip

# Verify installation
python3 --version
pip3 --version
```

### 3. Install Python Dependencies

```bash
# Install Scapy
pip3 install scapy

# Install Colorama
pip3 install colorama

# Or install from requirements.txt
pip3 install -r requirements.txt
```

### 4. Install Network Tools

```bash
# Install dsniff (for arpspoof)
sudo apt install -y dsniff

# Install tcpdump (optional, for debugging)
sudo apt install -y tcpdump

# Install net-tools (optional, for ifconfig)
sudo apt install -y net-tools
```

### 5. Download the Tool

```bash
# Clone repository
git clone https://github.com/melissachall/HTTP-Sniffer-MITM.git
cd HTTP-Sniffer-MITM

# Make script executable
chmod +x http_sniffer.py
```

### 6. Enable IP Forwarding

**Temporary (until reboot):**
```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

**Permanent:**
```bash
# Edit sysctl.conf
sudo nano /etc/sysctl.conf

# Add or uncomment this line:
net.ipv4.ip_forward=1

# Apply changes
sudo sysctl -p

# Verify
cat /proc/sys/net/ipv4/ip_forward
# Should output: 1
```

### 7. Verify Installation

```bash
# Test Python imports
python3 -c "from scapy.all import *; print('✓ Scapy OK')"
python3 -c "from colorama import init; print('✓ Colorama OK')"
python3 -c "from scapy.layers.http import HTTPRequest; print('✓ HTTP Layer OK')"

# Check network tools
which arpspoof
which tcpdump

# Test script
sudo python3 http_sniffer.py --help
```

**Expected Output:**
```
usage: http_sniffer.py [-h] [-i IFACE] [--debug] [--show-raw] [--csv CSV]

HTTP Packet Sniffer (advanced). Suggested to run in MITM (arp spoof) context.
Supports CSV log, debug, filters.

optional arguments:
  -h, --help            show this help message and exit
  -i IFACE, --iface IFACE
                        Interface to use (default: scapy default)
  --debug               Active les logs DEBUG
  --show-raw            Affiche le contenu brut POST si présent
  --csv CSV             Enregistre les résultats dans un fichier CSV (ex:
                        --csv http_log.csv)
```

---

## Troubleshooting Installation

### Issue 1: "No module named 'scapy'"

```bash
ModuleNotFoundError: No module named 'scapy'
```

**Solution:**
```bash
# Try system package
sudo apt install python3-scapy

# Or pip with sudo
sudo pip3 install scapy

# Or use --user flag
pip3 install --user scapy
```

### Issue 2: "Permission Denied"

```bash
PermissionError: [Errno 1] Operation not permitted
```

**Solution:**
```bash
# Always run packet capture with sudo
sudo python3 http_sniffer.py
```

### Issue 3: "Cannot import HTTPRequest"

```bash
ImportError: cannot import name 'HTTPRequest'
```

**Solution:**
```bash
# Update Scapy to latest version
pip3 install --upgrade scapy

# Or install from GitHub
pip3 install git+https://github.com/secdev/scapy.git
```

### Issue 4: "arpspoof: command not found"

```bash
# Install dsniff
sudo apt install dsniff

# If unavailable, use ettercap
sudo apt install ettercap-text-only
```

### Issue 5: "Colorama colors not working"

```bash
# Reinstall colorama
pip3 uninstall colorama
pip3 install colorama

# Or use system package
sudo apt install python3-colorama
```

### Issue 6: IP Forwarding Not Persisting

```bash
# Check current value
cat /proc/sys/net/ipv4/ip_forward

# If 0, enable permanently
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

---

## Virtual Environment Setup (Optional but Recommended)

```bash
# Create virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate

# Install dependencies
pip install scapy colorama

# When done, deactivate
deactivate
```

---

## Network Configuration

### Find Your Network Interface

```bash
# Method 1: ip command
ip addr show

# Method 2: ifconfig
ifconfig

# Method 3: Scapy
python3 -c "from scapy.all import *; conf.iface"
```

**Common interface names:**
- `eth0` - Wired Ethernet
- `ens33` - VMware virtual adapter
- `wlan0` - Wireless adapter
- `enp0s3` - VirtualBox adapter

### Test Network Connectivity

```bash
# Ping gateway
ping -c 4 192.168.1.1

# Check routing table
ip route show

# Test DNS
nslookup google.com
```

---

## Post-Installation Configuration

### 1. Create Output Directory (Optional)

```bash
# Create directory for CSV logs
mkdir -p ~/http_captures

# Use it with the tool
sudo python3 http_sniffer.py --csv ~/http_captures/capture.csv
```

### 2. Test Packet Capture

```bash
# Capture your own traffic (test)
sudo python3 http_sniffer.py -i eth0

# In another terminal, generate HTTP traffic
curl http://neverssl.com

# Should see request in sniffer output
```

### 3. Configure Firewall (if needed)

```bash
# Allow port 80 traffic
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A OUTPUT -p tcp --sport 80 -j ACCEPT
```

---

## Verification Checklist

Run through this checklist before first use:

- [ ] Python 3.8+ installed (`python3 --version`)
- [ ] Scapy installed (`python3 -c "import scapy"`)
- [ ] Colorama installed (`python3 -c "import colorama"`)
- [ ] HTTPRequest importable (`python3 -c "from scapy.layers.http import HTTPRequest"`)
- [ ] arpspoof installed (`which arpspoof`)
- [ ] IP forwarding enabled (`cat /proc/sys/net/ipv4/ip_forward` = 1)
- [ ] Root/sudo access working (`sudo -v`)
- [ ] Network interface identified (`ip addr show`)
- [ ] Script executable (`ls -l http_sniffer.py` shows `x`)
- [ ] Help command works (`sudo python3 http_sniffer.py --help`)

---

## Quick Start Command Summary

```bash
# Complete installation in one go (Kali Linux)
sudo apt update
sudo apt install -y python3 python3-pip dsniff tcpdump
pip3 install scapy colorama
sudo sysctl -w net.ipv4.ip_forward=1
git clone https://github.com/melissachall/HTTP-Sniffer-MITM.git
cd HTTP-Sniffer-MITM
chmod +x http_sniffer.py
sudo python3 http_sniffer.py --help
```

---

## Next Steps

1. ✅ Review `README.md` for usage instructions
2. ✅ Set up virtual lab environment
3. ✅ Test ARP spoofing separately first
4. ✅ Run HTTP sniffer with `--debug` flag
5. ✅ Review legal/ethical guidelines

---

**Installation Date:** 2025-11-23  
**Last Updated:** 2025-11-23  
**Version:** 1.0
