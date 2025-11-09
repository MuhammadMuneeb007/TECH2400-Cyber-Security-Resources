# Week 01 - Cybersecurity Course Resources

## 🔴 Security & Privacy Resources

### Data Breach Checking
- [Have I Been Pwned](https://haveibeenpwned.com/) - Check if your email or phone has been compromised in a data breach

### Privacy & Compliance
- [EU General Data Protection Regulation (GDPR)](https://ovic.vic.gov.au/privacy/resources-for-organisations/eu-general-data-protection-regulation/) - OVIC resources for understanding GDPR compliance

## 🔴 Career Resources

- [ICT Security Specialist Occupation Profile](https://smartvisaguide.com/occupations/261315) - Visa and career information
- [Cyber Security Jobs on SEEK](https://www.seek.com.au/Cyber-security-jobs?jobId=88267991&type=standard) - Current job listings and requirements

## 🟢 Additional Career Resources

- [Australian Cyber Security Centre (ACSC) Careers](https://www.cyber.gov.au/acsc/view-all-content/jobs-acsc) - Government cybersecurity positions
- [CyberSeek Career Pathway](https://www.cyberseek.org/pathway.html) - Interactive cybersecurity career path tool
- [SANS Cyber Security Skills Roadmap](https://www.sans.org/cyber-security-skills-roadmap/) - Professional development guide

---

## 🟢 Virtual Lab Setup

### System Requirements
- **RAM:** Minimum 8GB (16GB recommended)
- **Storage:** 50GB free space
- **Processor:** 64-bit CPU with virtualization support (Intel VT-x or AMD-V)
- **Internet:** Stable connection for updates and downloads

### 🔴 Required Software Downloads

#### 1. VirtualBox
- **Download:** [VirtualBox Official Website](https://www.virtualbox.org/wiki/Downloads)
- Choose the appropriate version for your operating system
- Current stable version: 7.0.x

#### 2. Kali Linux VM
- **Download:** [Kali Linux Virtual Machines](https://www.kali.org/get-kali/#kali-virtual-machines)
- Select the VirtualBox (.vbox) image for easy setup
- Recommended: Download the 64-bit version
- File size: ~3-4GB

### 🟢 Installation Steps

#### VirtualBox Installation
1. Download the installer for your OS (Windows/macOS/Linux)
2. Run the installer with administrator privileges
3. Follow the installation wizard (use default settings)
4. Restart your computer if prompted

#### Kali Linux VM Import
1. Extract the downloaded Kali Linux .7z file
2. Open VirtualBox
3. Click **File** > **Import Appliance**
4. Browse to the extracted .vbox file
5. Review settings and click **Import**
6. Wait for the import process to complete

### 🔴 Bridge Connection Setup Instructions

To enable bridge networking in VirtualBox:

1. Open VirtualBox and select your Kali Linux VM
2. Click **Settings** > **Network**
3. Change **Attached to:** from "NAT" to "Bridged Adapter"
4. Select your physical network adapter from the **Name** dropdown
5. Click **OK** to save changes
6. Start your VM - it will now be directly accessible on your local network

### 🟢 Alternative Network Configurations

#### NAT Network (Recommended for Beginners)
- **Pros:** Isolated from host network, safer for testing
- **Cons:** Limited network visibility
- **Setup:** Settings > Network > Attached to: NAT

#### Host-Only Adapter
- **Pros:** VM can communicate with host only
- **Cons:** No internet access by default
- **Setup:** Settings > Network > Attached to: Host-only Adapter

#### Bridged Adapter
- **Pros:** Full network access, appears as separate device
- **Cons:** Exposes VM to local network
- **Setup:** (See instructions above)

### 🟢 Default Kali Linux Credentials
- **Username:** `kali`
- **Password:** `kali`

**⚠️ Change these immediately after first login!**

---

## 🔴 Network Scanning - Nmap

### Download
- [Nmap Official Download](https://nmap.org/download.html)

### 🔴 Documentation & Cheat Sheets
- [Nmap Mind Map](https://nmap.org/docs/nmap-mindmap.pdf) - Visual guide to Nmap features
- [Nmap Cheat Sheet v7](https://stationx-public-download.s3.us-west-2.amazonaws.com/nmap_cheet_sheet_v7.pdf) - Quick reference guide

### 🟢 What is Nmap?

Nmap (Network Mapper) is a free and open-source network discovery and security auditing tool. It's used to:
- Discover hosts on a network
- Identify open ports and services
- Detect operating systems and versions
- Find security vulnerabilities

### 🔴 Essential Nmap Commands

```bash
# Basic host discovery
nmap [target-ip]

# Scan specific ports
nmap -p 80,443 [target-ip]

# Scan port range
nmap -p 1-1000 [target-ip]

# Service version detection
nmap -sV [target-ip]

# Operating system detection
nmap -O [target-ip]

# Aggressive scan (OS detection, version detection, script scanning, and traceroute)
nmap -A [target-ip]

# Scan entire subnet
nmap 192.168.1.0/24

# Fast scan (top 100 ports)
nmap -F [target-ip]

# TCP SYN scan (stealth scan)
nmap -sS [target-ip]

# UDP scan
nmap -sU [target-ip]

# Save output to file
nmap -oN output.txt [target-ip]
```

### 🟢 Advanced Nmap Commands

```bash
# Scan with NSE scripts (Nmap Scripting Engine)
nmap --script vuln [target-ip]

# Detect service vulnerabilities
nmap --script vulners [target-ip]

# Comprehensive scan with timing control
nmap -T4 -A -v [target-ip]

# Scan multiple hosts
nmap 192.168.1.1 192.168.1.5 192.168.1.10

# Scan from a file
nmap -iL targets.txt

# Exclude hosts from scan
nmap 192.168.1.0/24 --exclude 192.168.1.1

# Detect firewall/IDS evasion
nmap -f [target-ip]

# Randomize scan order
nmap --randomize-hosts 192.168.1.0/24

# Verbose output with debugging
nmap -vv -d [target-ip]

# Output all formats
nmap -oA scan_results [target-ip]
```

### 🟢 Nmap Scan Types Explained

| Scan Type | Command | Description | Use Case |
|-----------|---------|-------------|----------|
| TCP Connect | `-sT` | Complete TCP handshake | Most reliable, easily detected |
| SYN Scan | `-sS` | Half-open scan | Stealthy, requires root |
| UDP Scan | `-sU` | Scans UDP ports | DNS, SNMP services |
| ACK Scan | `-sA` | Tests firewall rules | Firewall detection |
| NULL Scan | `-sN` | No TCP flags set | Firewall evasion |
| FIN Scan | `-sF` | FIN flag only | Firewall evasion |
| Xmas Scan | `-sX` | FIN, PSH, URG flags | Unusual, good for testing |

### 🟢 Nmap Best Practices

1. **Always get permission** before scanning any network
2. Start with less aggressive scans (`-sS` instead of `-A`)
3. Use timing templates: `-T0` (paranoid) to `-T5` (insane)
4. Save results in multiple formats: `-oA` for all formats
5. Use `--reason` flag to understand why ports appear as open/closed
6. Combine with Wireshark to see actual packets

---

## 🔴 Network Analysis - Wireshark

### Download
- [Wireshark Official Download](https://www.wireshark.org/download.html)

### 🔴 Documentation & Cheat Sheets
- [Wireshark Cheat Sheet (CTF Assets)](https://assets.ctfassets.net/kvf8rpi09wgk/a2PBJT7Qq9XL7Bbf81Ajh/e28b9c889edc13ddb1e81ed5ce678809/Wireshark_Cheat_Sheet__6_.pdf)
- [Wireshark Cheat Sheet (InfoSec Labs)](https://infoseclabs.io/wp-content/uploads/simple-file-list/Wireshark-Cheat-Sheet.pdf)

### 🟢 What is Wireshark?

Wireshark is the world's most popular network protocol analyzer. It allows you to:
- Capture live network traffic
- Analyze packets in detail
- Troubleshoot network issues
- Detect security threats
- Learn network protocols

### 🟢 Installation & Setup

#### Windows
1. Download the Windows installer
2. Run as administrator
3. Install Npcap (packet capture library) when prompted
4. Restart may be required

#### Linux (Debian/Ubuntu)
```bash
sudo apt update
sudo apt install wireshark
sudo usermod -aG wireshark $USER
# Log out and back in for group changes to take effect
```

#### macOS
1. Download the .dmg file
2. Drag to Applications folder
3. Install ChmodBPF for packet capture

### 🟢 Common Display Filters

```
# Filter by IP address
ip.addr == 192.168.1.1
ip.src == 192.168.1.1
ip.dst == 192.168.1.1

# Filter by protocol
http
dns
tcp
udp
icmp

# Filter by port
tcp.port == 80
tcp.port == 443
udp.port == 53

# HTTP specific filters
http.request
http.response
http.request.method == "POST"
http.request.uri contains "login"

# TCP flags
tcp.flags.syn == 1
tcp.flags.reset == 1

# Filter conversations
tcp.stream eq 1

# Find passwords (unencrypted)
http contains "password"
ftp contains "password"

# DNS queries
dns.qry.name contains "google"

# Filter by subnet
ip.addr == 192.168.1.0/24

# Exclude traffic
!(ip.addr == 192.168.1.1)

# Combination filters
http and ip.src == 192.168.1.1
tcp.port == 80 or tcp.port == 443
```

### 🟢 Capture Filters (Applied Before Capture)

```
# Capture only HTTP traffic
port 80

# Capture specific host
host 192.168.1.1

# Capture subnet
net 192.168.1.0/24

# Capture multiple ports
port 80 or port 443

# Capture except specific host
not host 192.168.1.1

# Capture TCP traffic only
tcp

# Capture UDP traffic only
udp
```

### 🟢 Wireshark Analysis Workflow

1. **Select Interface** - Choose network adapter to capture from
2. **Start Capture** - Click the shark fin icon
3. **Apply Filters** - Use display filters to narrow results
4. **Follow Streams** - Right-click packet > Follow > TCP/UDP Stream
5. **Export Objects** - File > Export Objects > HTTP/SMB
6. **Statistics** - Analyze traffic patterns in Statistics menu
7. **Save Capture** - File > Save As (.pcap format)

### 🟢 Wireshark Protocol Hierarchy

Understanding the protocol stack:
```
Physical Layer (Ethernet)
  └─ Network Layer (IP, ICMP, ARP)
      └─ Transport Layer (TCP, UDP)
          └─ Application Layer (HTTP, DNS, FTP, SSH)
```

### 🟢 Common Network Issues to Detect

| Issue | What to Look For | Filter |
|-------|------------------|--------|
| Packet Loss | Duplicate ACKs, retransmissions | `tcp.analysis.retransmission` |
| Slow Network | High latency in TCP handshake | `tcp.time_delta > 0.2` |
| ARP Spoofing | Multiple IPs claiming same MAC | `arp.duplicate-address-detected` |
| Port Scanning | Many SYN packets, no ACK | `tcp.flags.syn == 1 && tcp.flags.ack == 0` |
| DNS Issues | Failed DNS queries | `dns.flags.rcode != 0` |
| Unauthorized Access | Suspicious protocols/ports | `tcp.port > 1024` |

### 🟢 Additional Wireshark Resources

- [Wireshark Official User Guide](https://www.wireshark.org/docs/wsug_html_chunked/)
- [Sample Capture Files](https://wiki.wireshark.org/SampleCaptures) - Practice files
- [DisplayFilters Reference](https://www.wireshark.org/docs/dfref/) - Complete filter list

---

## 🔴 AI Tools for Command Assistance

### GROK AI
We will be using GROK AI as our "uncensored" assistant for generating and understanding security commands and techniques. Use responsibly and only in authorized environments.

## 🟢 Additional AI & Automation Tools

### ChatGPT (OpenAI)
- Use for explaining complex concepts
- Generate documentation
- Debug scripts and code

### GitHub Copilot
- AI pair programmer
- Code completion and suggestions
- Available as VS Code extension

### Metasploit Framework
Already included in Kali Linux - exploit development framework
```bash
# Launch Metasploit console
msfconsole

# Search for exploits
search [keyword]

# Use an exploit
use exploit/windows/smb/ms17_010_eternalblue
```

### Burp Suite Community Edition
Pre-installed on Kali - web application security testing
- Intercept HTTP/HTTPS traffic
- Scan for vulnerabilities
- Manual penetration testing

---

## 🟢 Week 01 Lab Exercises

### Exercise 1: Environment Setup ✅
- [ ] Install VirtualBox
- [ ] Import Kali Linux VM
- [ ] Configure network adapter
- [ ] Update Kali: `sudo apt update && sudo apt upgrade -y`
- [ ] Take a VM snapshot

### Exercise 2: Basic Nmap Scanning 🔍
- [ ] Scan your local router: `nmap 192.168.1.1`
- [ ] Perform a service scan: `nmap -sV 192.168.1.1`
- [ ] Scan your entire subnet: `nmap 192.168.1.0/24`
- [ ] Save results to a file
- [ ] Compare results from different scan types

### Exercise 3: Wireshark Packet Capture 📡
- [ ] Start a capture on your active network interface
- [ ] Visit a website (HTTP, not HTTPS)
- [ ] Filter for HTTP traffic
- [ ] Follow a TCP stream
- [ ] Export HTTP objects
- [ ] Identify your local IP, gateway, and DNS server

### Exercise 4: Security Research 🔐
- [ ] Check your email on Have I Been Pwned
- [ ] Review GDPR requirements for data handling
- [ ] Research 3 cybersecurity certifications (CEH, OSCP, Security+)
- [ ] Read about a recent data breach

---

## 🟢 Important Ethical Guidelines

### ⚠️ Legal Considerations

**YOU MAY ONLY:**
- Scan and test systems you own
- Use authorized penetration testing ranges (HackTheBox, TryHackMe)
- Practice in your isolated lab environment
- Test with explicit written permission

**NEVER:**
- Scan networks without authorization
- Access systems you don't own
- Use exploits on production systems
- Share vulnerabilities before responsible disclosure

**Unauthorized access is illegal under:**
- Computer Fraud and Abuse Act (USA)
- Computer Misuse Act (UK)
- Cybercrime Act (Australia)
- Similar laws in virtually every country

### 🎯 Recommended Practice Platforms

- [HackTheBox](https://www.hackthebox.com/) - Realistic penetration testing labs
- [TryHackMe](https://tryhackme.com/) - Guided cybersecurity learning
- [PentesterLab](https://pentesterlab.com/) - Web penetration testing
- [OverTheWire](https://overthewire.org/) - Wargames for security training
- [VulnHub](https://www.vulnhub.com/) - Vulnerable VMs for practice

---

## 🟢 Additional Resources

### Documentation
- [Kali Linux Documentation](https://www.kali.org/docs/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) - Web application security risks
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/) - Security configuration guides

### Communities
- [r/cybersecurity](https://reddit.com/r/cybersecurity) - Reddit community
- [r/netsec](https://reddit.com/r/netsec) - Network security discussions
- [Hack The Box Forums](https://forum.hackthebox.com/) - CTF community

### YouTube Channels
- NetworkChuck - Beginner-friendly tutorials
- John Hammond - CTF walkthroughs
- IppSec - HackTheBox solutions
- LiveOverflow - Advanced topics

### Certifications Path
1. **Entry Level:** CompTIA Security+
2. **Intermediate:** CEH (Certified Ethical Hacker)
3. **Advanced:** OSCP (Offensive Security Certified Professional)
4. **Expert:** OSCE³ (Offensive Security Certified Expert)

---

## 🟢 Troubleshooting Common Issues

### VirtualBox Issues

**VM won't start:**
- Enable virtualization in BIOS (Intel VT-x / AMD-V)
- Disable Hyper-V on Windows: `bcdedit /set hypervisorlaunchtype off`
- Check available RAM (need at least 2GB for VM)

**Slow VM performance:**
- Allocate more RAM (Settings > System)
- Enable PAE/NX (Settings > System > Processor)
- Use VDI disk format instead of VMDK

**Network not working:**
- Check adapter is enabled in VM settings
- Try different network modes (NAT, Bridged, Host-only)
- Restart networking: `sudo systemctl restart NetworkManager`

### Kali Linux Issues

**Can't update packages:**
```bash
# Fix repository issues
sudo apt update --fix-missing
sudo apt install -f
```

**Tools not working:**
```bash
# Reinstall tool (example: nmap)
sudo apt remove nmap
sudo apt install nmap
```

**Root access needed:**
```bash
# Switch to root
sudo su
# Or run single command as root
sudo [command]
```

---

## 📚 Week 01 Quiz

Test your knowledge:

1. What is the default username and password for Kali Linux?
2. Which Nmap scan type is considered "stealthy"?
3. What protocol does Wireshark use to capture packets?
4. What does GDPR stand for?
5. Name three types of network adapters in VirtualBox
6. What command shows Nmap's help page?
7. Which tool is used for web application penetration testing?
8. What is the purpose of Have I Been Pwned?
9. What file extension does Wireshark use for captures?
10. Why should you NEVER scan networks without permission?

---

**Last Updated:** Week 01 - 2025
**Course:** Cybersecurity Fundamentals
**Next Week:** Week 02 - Vulnerability Assessment & Exploitation Basics

---

### 🟢 Quick Reference Card

```
┌─────────────────────────────────────────┐
│     WEEK 01 QUICK COMMANDS              │
├─────────────────────────────────────────┤
│ Kali Update:                            │
│ $ sudo apt update && sudo apt upgrade   │
│                                         │
│ Basic Nmap:                             │
│ $ nmap -sV [target-ip]                  │
│                                         │
│ Start Wireshark:                        │
│ $ sudo wireshark                        │
│                                         │
│ Check IP:                               │
│ $ ip addr show                          │
│                                         │
│ Ping Google:                            │
│ $ ping -c 4 8.8.8.8                     │
└─────────────────────────────────────────┘
```

**Remember:** Practice makes perfect. Set up your lab and start exploring! 🚀
