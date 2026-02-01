# TECH2400 - Cyber Security
# Week 11: Intrusion Detection and Prevention Systems
## Complete Workshop Laboratory Manual

---

# TABLE OF CONTENTS

1. [Workshop Overview](#1-workshop-overview)
2. [Pre-Workshop Setup: Creating Your Snort.org Account](#2-pre-workshop-setup-creating-your-snortorg-account)
3. [Understanding IDS and IPS Concepts](#3-understanding-ids-and-ips-concepts)
4. [Introduction to Snort](#4-introduction-to-snort)
5. [Lab Environment Requirements](#5-lab-environment-requirements)
6. [Exercise 1: Installing Snort on pfSense](#6-exercise-1-installing-snort-on-pfsense)
7. [Exercise 2: Configuring Snort Global Settings](#7-exercise-2-configuring-snort-global-settings)
8. [Exercise 3: Adding and Configuring Snort Interface](#8-exercise-3-adding-and-configuring-snort-interface)
9. [Exercise 4: Downloading and Enabling Rule Sets](#9-exercise-4-downloading-and-enabling-rule-sets)
10. [Exercise 5: Creating Custom Snort Rules](#10-exercise-5-creating-custom-snort-rules)
11. [Exercise 6: Testing and Verifying Alerts](#11-exercise-6-testing-and-verifying-alerts)
12. [Exercise 7: Monitoring Malicious DNS Traffic](#12-exercise-7-monitoring-malicious-dns-traffic)
13. [Enterprise IDS/IPS Solutions](#13-enterprise-idsips-solutions)
14. [Troubleshooting Guide](#14-troubleshooting-guide)
15. [Workshop Summary](#15-workshop-summary)
16. [Additional Resources](#16-additional-resources)

---

# 1. WORKSHOP OVERVIEW

## 1.1 Workshop Description

This is a **hands-on laboratory workshop** where you will install, configure, and test an Intrusion Detection and Prevention System (IDS/IPS). You will work with **Snort**, the world's most widely deployed open-source IDS/IPS, running on **pfSense** firewall.

## 1.2 Learning Objectives

After completing this workshop, you will be able to:

| # | Objective |
|---|-----------|
| 1 | Explain the difference between IDS and IPS |
| 2 | Create a Snort.org account and obtain an Oinkmaster code |
| 3 | Install the Snort package on pfSense firewall |
| 4 | Configure Snort to monitor network interfaces |
| 5 | Download and enable threat detection rule sets |
| 6 | Write custom Snort rules to detect specific threats |
| 7 | Test rules and interpret Snort alerts |
| 8 | Understand enterprise IDS/IPS solutions |

## 1.3 Estimated Time

| Section | Time |
|---------|------|
| Pre-Workshop Setup (Snort Account) | 10 minutes |
| Concepts and Theory | 20 minutes |
| Snort Installation | 15 minutes |
| Configuration | 25 minutes |
| Custom Rules and Testing | 30 minutes |
| **Total** | **~100 minutes** |

---

# 2. PRE-WORKSHOP SETUP: CREATING YOUR SNORT.ORG ACCOUNT

> ⚠️ **IMPORTANT:** You MUST complete this section BEFORE the lab exercises. You need a Snort.org account to download official rules.

## 2.1 Why You Need a Snort.org Account

Snort uses **rules** to detect threats. The official rules from Cisco Talos require a free registered account. Without this account, you cannot download the latest threat signatures.

## 2.2 Step-by-Step Account Creation

### Step 2.2.1: Open the Snort Website

1. **Open your web browser** (Chrome, Firefox, Edge, or Safari)

2. **Type the following URL in the address bar:**
   ```
   https://www.snort.org
   ```

3. **Press Enter** to navigate to the website

4. **You should see the Snort homepage:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  🌐 https://www.snort.org                                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  [SNORT LOGO]     Home  Downloads  Rules  Documents  Community        │ │
│  │                                                   [Sign In] [Sign Up] │ │
│  │                                                              ▲        │ │
│  │                                                         Click here    │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│                    SNORT                                                     │
│          Network Intrusion Detection & Prevention System                     │
│                                                                              │
│          The World's Most Widely Deployed IDS/IPS Technology                │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Step 2.2.2: Navigate to Sign Up Page

1. **Look at the top-right corner** of the page

2. **Find and click the "Sign Up" button** (or link)

3. **Alternatively, go directly to:**
   ```
   https://www.snort.org/users/sign_up
   ```

### Step 2.2.3: Fill Out the Registration Form

You will see a registration form. Fill in each field exactly as described:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  🌐 https://www.snort.org/users/sign_up                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│                           Create Your Account                                │
│                           ───────────────────                               │
│                                                                              │
│  Email *                                                                     │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ your.email@student.kaplan.edu.au                                        ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│  ▲                                                                           │
│  └── Enter your student email address                                        │
│                                                                              │
│  Password *                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ ●●●●●●●●●●●●                                                            ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│  ▲                                                                           │
│  └── Create a strong password (minimum 8 characters)                         │
│      Include: uppercase, lowercase, numbers, symbols                         │
│                                                                              │
│  Password Confirmation *                                                     │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ ●●●●●●●●●●●●                                                            ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│  ▲                                                                           │
│  └── Re-type your password exactly                                           │
│                                                                              │
│  [✓] I agree to the Terms of Service                                        │
│  ▲                                                                           │
│  └── You MUST check this box                                                 │
│                                                                              │
│                        [ Sign Up ]                                           │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Field Requirements:**

| Field | Requirement | Example |
|-------|-------------|---------|
| **Email** | Valid email address | your.email@student.kaplan.edu.au |
| **Password** | Minimum 8 characters | MyStr0ng!Pass |
| **Password Confirmation** | Must match password exactly | MyStr0ng!Pass |
| **Terms of Service** | Must be checked | ✓ |

4. **Click the "Sign Up" button**

### Step 2.2.4: Verify Your Email

1. **Open your email inbox** (the email you registered with)

2. **Look for an email from Snort.org** with subject like:
   - "Confirmation instructions" or
   - "Please confirm your email"

3. **If you don't see it, check your Spam/Junk folder**

4. **Open the email and click the confirmation link**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  📧 Email from: noreply@snort.org                                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Subject: Confirmation instructions                                          │
│                                                                              │
│  Hello!                                                                      │
│                                                                              │
│  Please confirm your account by clicking the link below:                    │
│                                                                              │
│  [ Confirm my account ]  ◄── CLICK THIS LINK                                │
│                                                                              │
│  This link will expire in 24 hours.                                          │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

5. **After clicking, you'll see a confirmation message**

### Step 2.2.5: Log In to Your Account

1. **Navigate to the login page:**
   ```
   https://www.snort.org/users/sign_in
   ```

2. **Enter your credentials:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  🌐 https://www.snort.org/users/sign_in                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│                              Sign In                                         │
│                              ───────                                        │
│                                                                              │
│  Email                                                                       │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ your.email@student.kaplan.edu.au                                        ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                                                              │
│  Password                                                                    │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ ●●●●●●●●●●●●                                                            ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                                                              │
│  [ ] Remember me                                                             │
│                                                                              │
│                         [ Sign In ]                                          │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

3. **Click "Sign In"**

### Step 2.2.6: Obtain Your Oinkmaster Code (CRITICAL STEP)

The **Oinkmaster Code** (also called **Oinkcode**) is your unique key to download Snort rules. 

1. **After logging in, look at the top-right corner of the page**

2. **Click on your email address or username**

3. **A dropdown menu will appear. Click "Oinkcode"**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Snort.org - Logged in as: your.email@student.kaplan.edu.au                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  [SNORT]    Home  Downloads  Rules  Documents    your.email@student... ▼   │
│                                                   │                         │
│                                                   ├── Dashboard             │
│                                                   ├── Profile               │
│                                                   ├── Oinkcode  ◄── CLICK  │
│                                                   └── Sign Out              │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

4. **You can also navigate directly to:**
   ```
   https://www.snort.org/oinkcodes
   ```

5. **Your Oinkcode will be displayed:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  🌐 https://www.snort.org/oinkcodes                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│                           Your Oinkcode                                      │
│                           ─────────────                                     │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                                                                          ││
│  │   0a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t                             ││
│  │                                                                          ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                                                              │
│  ⚠️  IMPORTANT INSTRUCTIONS:                                                │
│                                                                              │
│  • This code is approximately 40 characters long                            │
│  • Copy the ENTIRE code (select all, then copy)                             │
│  • Do NOT copy any extra spaces before or after                             │
│  • Keep this code private - it's linked to your account                     │
│  • You will paste this into pfSense later                                   │
│                                                                              │
│  HOW TO COPY:                                                                │
│  1. Triple-click to select the entire code                                  │
│  2. Press Ctrl+C (Windows) or Cmd+C (Mac) to copy                          │
│  3. Save it in a text file or note for later use                           │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Step 2.2.7: Save Your Oinkcode

**CRITICAL:** Save your Oinkcode somewhere safe. You will need it in Exercise 2.

**Recommended:** Create a text file on your desktop:

1. Open Notepad (Windows) or TextEdit (Mac)
2. Paste your Oinkcode
3. Save as "my_snort_oinkcode.txt"

```
Example Oinkcode (yours will be different):
0a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t
```

> ✅ **Checkpoint:** You now have a Snort.org account and your Oinkmaster code ready for the lab exercises.

---

# 3. UNDERSTANDING IDS AND IPS CONCEPTS

## 3.1 What is an Intrusion Detection System (IDS)?

An **Intrusion Detection System (IDS)** is a security monitoring tool that:
- **Monitors** network traffic or system activities
- **Detects** suspicious or malicious activity
- **Alerts** administrators about potential threats
- **Does NOT block** traffic (passive monitoring only)

### IDS Analogy: Security Camera

Think of an IDS like a **security camera** in a building:
- It watches everything that happens
- It records suspicious activity
- It alerts security guards
- But it cannot physically stop an intruder

### IDS Network Position Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      IDS DEPLOYMENT - PASSIVE MODE                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│                                                                              │
│     ┌──────────┐                                           ┌──────────┐     │
│     │          │                                           │          │     │
│     │ INTERNET │                                           │ INTERNAL │     │
│     │          │                                           │ NETWORK  │     │
│     └────┬─────┘                                           └────▲─────┘     │
│          │                                                      │           │
│          │                                                      │           │
│          ▼                                                      │           │
│     ┌─────────────────────────────────────────────────────────────┐        │
│     │                                                              │        │
│     │                    NETWORK SWITCH/TAP                        │        │
│     │                                                              │        │
│     └─────────────────────────┬────────────────────────────────────┘        │
│                               │                                              │
│                               │ Mirror/Span Port                             │
│                               │ (Copy of all traffic)                        │
│                               ▼                                              │
│                        ┌─────────────┐                                       │
│                        │             │                                       │
│                        │     IDS     │──────► ALERT!                        │
│                        │   SENSOR    │        "Suspicious activity detected" │
│                        │             │                                       │
│                        └─────────────┘                                       │
│                                                                              │
│  KEY POINTS:                                                                 │
│  • IDS receives a COPY of traffic (not inline)                              │
│  • Original traffic flows normally to destination                           │
│  • IDS analyzes the copy and generates alerts                               │
│  • NO impact on network performance                                          │
│  • Traffic continues even if threat detected                                │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 3.2 What is an Intrusion Prevention System (IPS)?

An **Intrusion Prevention System (IPS)** is an active security tool that:
- **Monitors** network traffic (like IDS)
- **Detects** suspicious or malicious activity (like IDS)
- **BLOCKS** or **DROPS** malicious traffic automatically
- Provides **real-time protection**

### IPS Analogy: Security Guard

Think of an IPS like a **security guard** at a building entrance:
- Checks everyone who enters
- Watches for suspicious behavior
- Can physically stop and remove threats
- Has authority to deny entry

### IPS Network Position Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      IPS DEPLOYMENT - INLINE MODE                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│                                                                              │
│     ┌──────────┐                                           ┌──────────┐     │
│     │          │                                           │          │     │
│     │ INTERNET │                                           │ INTERNAL │     │
│     │          │                                           │ NETWORK  │     │
│     └────┬─────┘                                           └────▲─────┘     │
│          │                                                      │           │
│          │                                                      │           │
│          ▼                                                      │           │
│     ┌─────────────────────────────────────────────────────────────┐        │
│     │                                                              │        │
│     │                        IPS DEVICE                            │        │
│     │                    (INLINE POSITION)                         │        │
│     │                                                              │        │
│     │   ┌─────────────────────────────────────────────────────┐   │        │
│     │   │              TRAFFIC INSPECTION                      │   │        │
│     │   │                                                      │   │        │
│     │   │    Incoming     ┌──────────┐     Outgoing           │   │        │
│     │   │    Packet  ───► │ ANALYZE  │ ───► Decision          │   │        │
│     │   │                 └──────────┘                         │   │        │
│     │   │                      │                               │   │        │
│     │   │         ┌────────────┼────────────┐                 │   │        │
│     │   │         ▼            ▼            ▼                 │   │        │
│     │   │     ┌──────┐    ┌──────┐    ┌──────┐               │   │        │
│     │   │     │ PASS │    │ DROP │    │ALERT │               │   │        │
│     │   │     │      │    │      │    │      │               │   │        │
│     │   │     │Allow │    │Block │    │ Log  │               │   │        │
│     │   │     │packet│    │packet│    │event │               │   │        │
│     │   │     └──────┘    └──────┘    └──────┘               │   │        │
│     │   │                                                      │   │        │
│     │   └─────────────────────────────────────────────────────┘   │        │
│     │                                                              │        │
│     └─────────────────────────────────────────────────────────────┘        │
│                                                                              │
│  KEY POINTS:                                                                 │
│  • IPS sits INLINE - ALL traffic must pass through it                       │
│  • Can DROP malicious packets before reaching destination                   │
│  • Provides ACTIVE protection                                               │
│  • Small latency impact (must inspect every packet)                         │
│  • If IPS fails, may disrupt network (fail-open vs fail-close)             │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 3.3 IDS vs IPS Comparison Table

| Feature | IDS | IPS |
|---------|-----|-----|
| **Full Name** | Intrusion Detection System | Intrusion Prevention System |
| **Primary Function** | Monitor and Alert | Monitor, Alert, and Block |
| **Response Type** | Passive | Active |
| **Network Position** | Out-of-band (mirror port) | Inline (all traffic passes through) |
| **Can Block Traffic?** | ❌ No | ✅ Yes |
| **Latency Impact** | None | Minimal |
| **Risk of Blocking Legitimate Traffic** | None | Possible (if misconfigured) |
| **Best For** | Monitoring, Forensics, Learning | Active Protection |
| **Analogy** | Security Camera | Security Guard |

## 3.4 Popular IDS/IPS Solutions

### Open-Source IDS Solutions

| Name | Type | Description | Official Website |
|------|------|-------------|------------------|
| **Snort** | Network IDS/IPS | Most widely deployed, rule-based detection | https://www.snort.org |
| **Suricata** | Network IDS/IPS | High-performance, multi-threaded engine | https://suricata.io |
| **Zeek** | Network Monitor | Protocol analysis and security monitoring | https://zeek.org |
| **OSSEC** | Host-based IDS | Log analysis, file integrity, rootkit detection | https://www.ossec.net |
| **Security Onion** | Platform | Linux distro with multiple IDS tools | https://securityonionsolutions.com |

### Commercial/Enterprise IPS Solutions

| Name | Type | Description | Official Website |
|------|------|-------------|------------------|
| **Cisco Firepower** | NGFW + IPS | Enterprise next-generation firewall | https://www.cisco.com/c/en/us/products/security/firepower-ngfw/ |
| **Palo Alto Networks** | NGFW + IPS | Advanced threat prevention | https://www.paloaltonetworks.com |
| **Fortinet FortiGate** | NGFW + IPS | Unified threat management | https://www.fortinet.com |
| **pfSense** | Firewall + IPS | Open-source with Snort/Suricata | https://www.pfsense.org |

---

# 4. INTRODUCTION TO SNORT

## 4.1 What is Snort?

**Snort** is the world's most widely deployed open-source network intrusion detection and prevention system.

| Attribute | Details |
|-----------|---------|
| **Developer** | Originally Martin Roesch (1998), now Cisco Talos |
| **License** | GNU General Public License (GPL) - Free and Open Source |
| **Current Versions** | Snort 2.9.x (legacy), Snort 3.x (latest) |
| **Official Website** | https://www.snort.org |
| **Documentation** | https://www.snort.org/documents |
| **Rules** | https://www.snort.org/downloads#rules |

## 4.2 Snort Operating Modes

Snort can operate in three modes:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SNORT OPERATING MODES                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  MODE 1: PACKET SNIFFER                                             │    │
│  │  ─────────────────────────────────────────────────────────────────  │    │
│  │  • Captures and displays packets in real-time                       │    │
│  │  • Similar to tcpdump or Wireshark                                  │    │
│  │  • Command: snort -v                                                │    │
│  │  • Use case: Network debugging, traffic analysis                    │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  MODE 2: PACKET LOGGER                                              │    │
│  │  ─────────────────────────────────────────────────────────────────  │    │
│  │  • Captures packets and saves to disk                               │    │
│  │  • For later analysis and forensics                                 │    │
│  │  • Command: snort -l /var/log/snort                                │    │
│  │  • Use case: Traffic recording, incident investigation              │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  MODE 3: NETWORK IDS/IPS  ◄── THIS IS WHAT WE USE                  │    │
│  │  ─────────────────────────────────────────────────────────────────  │    │
│  │  • Analyzes traffic against rules                                   │    │
│  │  • Generates alerts for suspicious activity                         │    │
│  │  • Can block traffic (IPS mode)                                     │    │
│  │  • Command: snort -c /etc/snort/snort.conf                         │    │
│  │  • Use case: Security monitoring, threat detection                  │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 4.3 Snort Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          SNORT ARCHITECTURE                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│                         NETWORK TRAFFIC                                      │
│                              │                                               │
│                              │                                               │
│                              ▼                                               │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  LAYER 1: PACKET DECODER / DATA ACQUISITION (DAQ)                     │  │
│  │  ─────────────────────────────────────────────────────────────────── │  │
│  │  • Captures raw packets from network interface card                   │  │
│  │  • Uses libpcap library (or equivalent)                              │  │
│  │  • Decodes link layer (Ethernet), network layer (IP), transport      │  │
│  │    layer (TCP/UDP) headers                                            │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                              │                                               │
│                              ▼                                               │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  LAYER 2: PREPROCESSORS                                               │  │
│  │  ─────────────────────────────────────────────────────────────────── │  │
│  │  • Normalize traffic (handle fragmentation, encoding)                 │  │
│  │  • Decode application protocols (HTTP, DNS, FTP, SMTP, etc.)         │  │
│  │  • Detect protocol anomalies                                          │  │
│  │  • Examples: http_inspect, ftp_telnet, dns, stream5                  │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                              │                                               │
│                              ▼                                               │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  LAYER 3: DETECTION ENGINE                                            │  │
│  │  ─────────────────────────────────────────────────────────────────── │  │
│  │  • Core of Snort - performs pattern matching                         │  │
│  │  • Compares packets against loaded rules                              │  │
│  │  • Uses efficient algorithms (Boyer-Moore, Aho-Corasick)             │  │
│  │  • Triggers alerts when rules match                                   │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                              │                                               │
│                              ▼                                               │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  LAYER 4: OUTPUT MODULES                                              │  │
│  │  ─────────────────────────────────────────────────────────────────── │  │
│  │  • Generate alerts (console, file, syslog, database)                 │  │
│  │  • Log packets that triggered alerts                                  │  │
│  │  • Take action (block, drop, reset) in IPS mode                      │  │
│  │  • Send to SIEM or other analysis tools                              │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                              │                                               │
│                              ▼                                               │
│                         ┌─────────┐                                         │
│                         │ OUTPUT  │                                         │
│                         └─────────┘                                         │
│                              │                                               │
│              ┌───────────────┼───────────────┐                              │
│              ▼               ▼               ▼                              │
│         ┌────────┐     ┌──────────┐    ┌────────┐                          │
│         │ ALERT  │     │   LOG    │    │ BLOCK  │                          │
│         │ File/  │     │ Packet   │    │ Traffic│                          │
│         │ Console│     │ to disk  │    │ (IPS)  │                          │
│         └────────┘     └──────────┘    └────────┘                          │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 4.4 Snort Rule Sources

Snort uses **rules** to detect threats. There are several sources of rules:

| Rule Source | Cost | Description | Update Frequency |
|-------------|------|-------------|------------------|
| **Snort VRT (Registered)** | Free | Official rules for registered users | 30-day delay |
| **Snort VRT (Subscriber)** | Paid | Same rules with real-time updates | Immediate |
| **Emerging Threats Open** | Free | Community-maintained rules | Regular |
| **Emerging Threats Pro** | Paid | Commercial-grade community rules | Immediate |
| **Custom Rules** | Free | Rules you write yourself | As needed |

---

# 5. LAB ENVIRONMENT REQUIREMENTS

## 5.1 Required Components

Before starting the exercises, verify you have:

| Component | Requirement | Status |
|-----------|-------------|--------|
| **pfSense Firewall** | Version 2.6.0 or later, installed and running | ☐ Ready |
| **pfSense Access** | Admin username and password | ☐ Ready |
| **Network Access** | Computer connected to pfSense LAN | ☐ Ready |
| **Internet Access** | pfSense must have internet for downloads | ☐ Ready |
| **Snort.org Account** | Created with Oinkcode (Section 2) | ☐ Ready |
| **Web Browser** | Chrome, Firefox, Edge, or Safari | ☐ Ready |
| **Test Client** | Windows or Linux PC for testing rules | ☐ Ready |

## 5.2 Lab Network Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        LAB NETWORK TOPOLOGY                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│                           ┌─────────────┐                                   │
│                           │             │                                   │
│                           │  INTERNET   │                                   │
│                           │             │                                   │
│                           └──────┬──────┘                                   │
│                                  │                                          │
│                                  │ Public IP                                │
│                                  │                                          │
│                           ┌──────┴──────┐                                   │
│                           │             │                                   │
│                           │   MODEM/    │                                   │
│                           │   ROUTER    │                                   │
│                           │             │                                   │
│                           └──────┬──────┘                                   │
│                                  │                                          │
│                                  │                                          │
│   ┌──────────────────────────────┴───────────────────────────────────┐      │
│   │                                                                   │      │
│   │                      pfSENSE FIREWALL                            │      │
│   │                                                                   │      │
│   │  ┌─────────────────┐              ┌─────────────────┐           │      │
│   │  │   WAN (em0)     │              │   LAN (em1)     │           │      │
│   │  │                 │              │                 │           │      │
│   │  │  Gets IP from   │              │  192.168.1.1    │           │      │
│   │  │  upstream       │              │                 │           │      │
│   │  │                 │              │  DHCP Server:   │           │      │
│   │  │  ◄── SNORT     │              │  192.168.1.100- │           │      │
│   │  │      MONITORS   │              │  192.168.1.199  │           │      │
│   │  │      THIS       │              │                 │           │      │
│   │  └─────────────────┘              └────────┬────────┘           │      │
│   │                                            │                     │      │
│   └────────────────────────────────────────────┼─────────────────────┘      │
│                                                │                            │
│                                                │ LAN Network                │
│                                                │ 192.168.1.0/24             │
│                                                │                            │
│            ┌───────────────────────────────────┼────────────────────┐       │
│            │                                   │                    │       │
│            │                                   │                    │       │
│     ┌──────┴──────┐                   ┌────────┴────────┐   ┌──────┴─────┐ │
│     │             │                   │                 │   │            │ │
│     │  YOUR PC    │                   │   OTHER PCS     │   │  OTHER     │ │
│     │  (Browser)  │                   │                 │   │  DEVICES   │ │
│     │             │                   │                 │   │            │ │
│     │ 192.168.1.x │                   │  192.168.1.x    │   │ 192.168.1.x│ │
│     │             │                   │                 │   │            │ │
│     └─────────────┘                   └─────────────────┘   └────────────┘ │
│                                                                              │
│   ACCESSING pfSENSE:                                                        │
│   • Open browser and go to: https://192.168.1.1                            │
│   • Login: admin / [your_password]                                         │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 5.3 pfSense Default Credentials

| Setting | Default Value |
|---------|---------------|
| **LAN IP Address** | 192.168.1.1 |
| **Username** | admin |
| **Password** | pfsense (if not changed) |
| **Web Interface** | https://192.168.1.1 |

> ⚠️ **Note:** Your pfSense may have different settings. Use the values provided by your instructor.

---

# 6. EXERCISE 1: INSTALLING SNORT ON pfSENSE

## 6.1 Objective

Install the Snort package on pfSense firewall using the Package Manager.

## 6.2 Step-by-Step Instructions

### Step 6.2.1: Access pfSense Web Interface

1. **Open your web browser**

2. **In the address bar, type:**
   ```
   https://192.168.1.1
   ```
   (Replace with your pfSense IP if different)

3. **Press Enter**

4. **If you see a security warning:**
   
   **For Chrome:**
   - Click "Advanced"
   - Click "Proceed to 192.168.1.1 (unsafe)"
   
   **For Firefox:**
   - Click "Advanced"
   - Click "Accept the Risk and Continue"
   
   **For Edge:**
   - Click "Details"
   - Click "Go on to the webpage"

   > This warning appears because pfSense uses a self-signed SSL certificate. This is normal in a lab environment.

5. **Enter your login credentials:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          pfSense Login Page                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│                              ┌─────────────┐                                │
│                              │   pfSense   │                                │
│                              │    Logo     │                                │
│                              └─────────────┘                                │
│                                                                              │
│                          Sign in to continue                                 │
│                                                                              │
│  Username                                                                    │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ admin                                                                   ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                                                              │
│  Password                                                                    │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ ●●●●●●●●●                                                               ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                                                              │
│                            [ Sign In ]                                       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

6. **Click "Sign In"**

7. **You should now see the pfSense Dashboard**

### Step 6.2.2: Navigate to Package Manager

**Navigation Path:** `System` → `Package Manager`

1. **Look at the top menu bar**

2. **Hover your mouse over "System"** (a dropdown menu will appear)

3. **Click "Package Manager"**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  pfSense - Top Menu Navigation                                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                                                                         │ │
│  │  [pfSense Logo]                                                         │ │
│  │                                                                         │ │
│  │  ┌────────┬────────────┬──────────┬──────────┬─────┬────────┬────────┐│ │
│  │  │ System │ Interfaces │ Firewall │ Services │ VPN │ Status │ Diag...││ │
│  │  │   ▼    │            │          │          │     │        │        ││ │
│  │  └────┬───┴────────────┴──────────┴──────────┴─────┴────────┴────────┘│ │
│  │       │                                                                 │ │
│  │       │  ┌──────────────────────────────┐                              │ │
│  │       │  │ Advanced                     │                              │ │
│  │       │  │ Cert. Manager                │                              │ │
│  │       │  │ General Setup                │                              │ │
│  │       └─►│ Package Manager    ◄── CLICK │                              │ │
│  │          │ Routing                      │                              │ │
│  │          │ Setup Wizard                 │                              │ │
│  │          │ Update                       │                              │ │
│  │          │ User Manager                 │                              │ │
│  │          └──────────────────────────────┘                              │ │
│  │                                                                         │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Step 6.2.3: View Available Packages

1. **You are now on the Package Manager page**

2. **You will see two tabs at the top:**
   - "Installed Packages" - Shows already installed packages
   - "Available Packages" - Shows packages you can install

3. **Click the "Available Packages" tab**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  System / Package Manager                                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌───────────────────────┐ ┌────────────────────────┐                       │
│  │  Installed Packages   │ │  Available Packages ◄──│── Click this tab     │
│  └───────────────────────┘ └────────────────────────┘                       │
│                                                                              │
│  Search term                                                                 │
│  ┌─────────────────────────────────────────────────────┐                    │
│  │                                                      │ [Search] [Clear]  │
│  └─────────────────────────────────────────────────────┘                    │
│                                                                              │
│  Available Packages                                                          │
│  ──────────────────────────────────────────────────────────────────────────  │
│                                                                              │
│  Name            Version     Description                                     │
│  ──────────────────────────────────────────────────────────────────────────  │
│  acme            0.7.4       ACME protocol for Let's Encrypt certificates   │
│  arping          2.21        ARP ping utility                               │
│  ...             ...         ...                                             │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Step 6.2.4: Search for Snort Package

1. **Find the "Search term" text box**

2. **Type:** `snort`

3. **Click the "Search" button** (or press Enter)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Searching for Snort                                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Search term                                                                 │
│  ┌─────────────────────────────────────────────────────┐                    │
│  │ snort                                               │ [Search] [Clear]  │
│  └─────────────────────────────────────────────────────┘     ▲              │
│       ▲                                                      │              │
│       │                                                Click Search         │
│  Type "snort" here                                                          │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Step 6.2.5: Install Snort Package

1. **You will see the Snort package in the search results:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Search Results for "snort"                                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Available Packages (1 match)                                                │
│  ──────────────────────────────────────────────────────────────────────────  │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                                                                       │   │
│  │  Name:        snort                                                  │   │
│  │  Version:     4.1.6_17                                               │   │
│  │                                                                       │   │
│  │  Description: Snort is an open source network intrusion              │   │
│  │               prevention and detection system (IDS/IPS).             │   │
│  │               Combining the benefits of signature, protocol,         │   │
│  │               and anomaly-based inspection.                          │   │
│  │                                                                       │   │
│  │  Package Dependencies:                                                │   │
│  │  snort-2.9.20_8                                                      │   │
│  │                                                                       │   │
│  │                                              [ + Install ]  ◄── CLICK│   │
│  │                                                                       │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

2. **Click the green "+ Install" button**

3. **A confirmation dialog will appear:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Confirmation Required                                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│                      ┌─────────────────────────────┐                        │
│                      │                             │                        │
│                      │  Install package snort?     │                        │
│                      │                             │                        │
│                      │  [ Confirm ]    [ Cancel ]  │                        │
│                      │       ▲                     │                        │
│                      │  Click Confirm              │                        │
│                      │                             │                        │
│                      └─────────────────────────────┘                        │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

4. **Click "Confirm"**

### Step 6.2.6: Wait for Installation to Complete

1. **The installation process will begin**

2. **You will see progress messages on screen:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Package Installation Progress                                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  >>> Installing pfSense-pkg-snort...                                        │
│                                                                              │
│  Updating pfSense-core repository catalogue...                               │
│  pfSense-core repository is up to date.                                     │
│                                                                              │
│  Updating pfSense repository catalogue...                                    │
│  pfSense repository is up to date.                                          │
│                                                                              │
│  The following 2 package(s) will be affected (of 0 checked):                │
│                                                                              │
│  New packages to be INSTALLED:                                               │
│      pfSense-pkg-snort: 4.1.6_17 [pfSense]                                  │
│      snort: 2.9.20_8 [pfSense]                                              │
│                                                                              │
│  Number of packages to be installed: 2                                       │
│                                                                              │
│  (... more progress messages ...)                                           │
│                                                                              │
│  Installing snort-2.9.20_8...                                               │
│  [1/2] Installing snort-2.9.20_8...                                         │
│  [2/2] Extracting snort-2.9.20_8: .......... done                          │
│  [2/2] Installing pfSense-pkg-snort-4.1.6_17...                             │
│  Extracting pfSense-pkg-snort-4.1.6_17: .......... done                    │
│                                                                              │
│  ═══════════════════════════════════════════════════════════════════════    │
│  ║  pfSense-pkg-snort installation successfully completed              ║    │
│  ═══════════════════════════════════════════════════════════════════════    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

3. **WAIT until you see the success message:**
   ```
   pfSense-pkg-snort installation successfully completed
   ```

4. **This typically takes 2-5 minutes depending on internet speed**

> ⚠️ **DO NOT** navigate away or close the browser during installation!

### Step 6.2.7: Verify Installation

1. **After installation completes, navigate to:** `Services` → `Snort`

2. **If you see the Snort configuration page, installation was successful!**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Verifying Snort Installation                                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  If Snort installed successfully, you will now see "Snort" as an option    │
│  under the Services menu:                                                    │
│                                                                              │
│  Services ▼                                                                  │
│  ├── Captive Portal                                                          │
│  ├── DHCP Server                                                             │
│  ├── DNS Resolver                                                            │
│  ├── ...                                                                     │
│  ├── Snort         ◄── THIS SHOULD NOW APPEAR                               │
│  └── ...                                                                     │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

> ✅ **Checkpoint:** Snort package is now installed on pfSense!

---

# 7. EXERCISE 2: CONFIGURING SNORT GLOBAL SETTINGS

## 7.1 Objective

Configure Snort's global settings including adding your Oinkmaster code and enabling rule downloads.

## 7.2 Step-by-Step Instructions

### Step 7.2.1: Navigate to Snort

**Navigation Path:** `Services` → `Snort`

1. **In the top menu, hover over "Services"**

2. **Click "Snort" from the dropdown menu**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Navigating to Snort                                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  System  Interfaces  Firewall  [Services ▼]  VPN  Status  Diagnostics │ │
│  │                                     │                                  │ │
│  │                                     │  ┌────────────────────────────┐ │ │
│  │                                     └──│ Captive Portal             │ │ │
│  │                                        │ DHCP Server                │ │ │
│  │                                        │ DNS Forwarder              │ │ │
│  │                                        │ DNS Resolver               │ │ │
│  │                                        │ Dynamic DNS                │ │ │
│  │                                        │ IGMP Proxy                 │ │ │
│  │                                        │ Load Balancer              │ │ │
│  │                                        │ NTP                        │ │ │
│  │                                        │ PPPoE Server               │ │ │
│  │                                        │ SNMP                       │ │ │
│  │                                        │ Snort       ◄── CLICK      │ │ │
│  │                                        │ UPnP & NAT-PMP             │ │ │
│  │                                        │ Wake-on-LAN                │ │ │
│  │                                        └────────────────────────────┘ │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Step 7.2.2: View Snort Interface Page

1. **You will see the main Snort page with multiple tabs:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Services / Snort                                                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │ Snort      │ Global    │ Updates │ Alerts │ Blocked │ Pass   │ ...    │ │
│  │ Interfaces │ Settings  │         │        │         │ Lists  │        │ │
│  │     ▲      │           │         │        │         │        │        │ │
│  │  Default   │           │         │        │         │        │        │ │
│  │   tab      │           │         │        │         │        │        │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│  Interface Settings Overview                                                 │
│  ────────────────────────────────────────────────────────────────────────── │
│                                                                              │
│  Interface │ Snort Status │ Pattern Match │ Blocking │ Description │Actions │
│  ──────────┼──────────────┼───────────────┼──────────┼─────────────┼─────── │
│            │              │               │          │             │        │
│            │    (No Snort interfaces have been defined yet)        │        │
│            │              │               │          │             │        │
│                                                                              │
│                             [ + Add ]                                        │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Step 7.2.3: Go to Global Settings Tab

1. **Click the "Global Settings" tab**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Snort Tab Navigation                                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │ Snort      │ Global     │ Updates │ Alerts │ Blocked │ Pass   │ ...   │ │
│  │ Interfaces │ Settings   │         │        │         │ Lists  │       │ │
│  │            │     ▲      │         │        │         │        │       │ │
│  │            │   CLICK    │         │        │         │        │       │ │
│  │            │   THIS     │         │        │         │        │       │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Step 7.2.4: Configure Snort VRT Rules

1. **Scroll down to find the "Snort Subscriber Rules" section**

2. **Configure the following:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Services / Snort / Global Settings                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Snort Subscriber Rules                                                      │
│  ═══════════════════════════════════════════════════════════════════════    │
│                                                                              │
│  Enable Snort VRT                                                            │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ [✓] Click to enable download of Snort free Registered User or         ││
│  │     paid Subscriber rules                                              ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│       ▲                                                                      │
│       └── CHECK THIS BOX                                                     │
│                                                                              │
│  ℹ Sign Up for a free Registered User Rules Account at snort.org           │
│  ℹ Sign Up for paid Snort Subscriber Rule Set                              │
│                                                                              │
│  Snort Oinkmaster Code                                                       │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ 0a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t                               ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│       ▲                                                                      │
│       └── PASTE YOUR OINKCODE HERE (from Section 2)                         │
│                                                                              │
│  Obtain a snort.org Oinkmaster code and paste it here.                      │
│  (Paste the code only and not the URL!)                                      │
│                                                                              │
│  ⚠️  IMPORTANT:                                                              │
│  • Paste ONLY the code (approximately 40 characters)                        │
│  • Do NOT include any spaces before or after                                │
│  • Do NOT include the URL                                                   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Configuration Summary:**

| Setting | Action |
|---------|--------|
| **Enable Snort VRT** | ☑ Check this box |
| **Snort Oinkmaster Code** | Paste your code from Section 2 |

### Step 7.2.5: Enable Emerging Threats Rules

1. **Scroll down further to find "Emerging Threats (ET) Rules" section**

2. **Configure the following:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Emerging Threats (ET) Rules                                                 │
│  ═══════════════════════════════════════════════════════════════════════    │
│                                                                              │
│  Enable ET Open                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ [✓] Click to enable download of Emerging Threats Open rules           ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│       ▲                                                                      │
│       └── CHECK THIS BOX                                                     │
│                                                                              │
│  ETOpen is an open source set of Snort rules whose coverage is more         │
│  limited than ETPro.                                                         │
│                                                                              │
│  Enable ET Pro                                                               │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ [ ] Click to enable download of Emerging Threats Pro rules            ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│       ▲                                                                      │
│       └── LEAVE THIS UNCHECKED (requires paid subscription)                 │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Configuration Summary:**

| Setting | Action |
|---------|--------|
| **Enable ET Open** | ☑ Check this box |
| **Enable ET Pro** | ☐ Leave unchecked |

### Step 7.2.6: Review Rules Update Settings

1. **Scroll down to find "Rules Update Settings" section**

2. **Leave these at default values:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Rules Update Settings                                                       │
│  ═══════════════════════════════════════════════════════════════════════    │
│                                                                              │
│  Update Interval                                                             │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ [ 12 HOURS                                               ▼]            ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│  Select the update interval for rules. Default is 12 hours.                  │
│                                                                              │
│  Update Start Time                                                           │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ [ 00:05                                                  ▼]            ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│  Enter the start time for rules updates. Default is 00:05.                  │
│                                                                              │
│  (You can leave these at default values for the lab)                        │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Step 7.2.7: Save Global Settings

1. **Scroll to the BOTTOM of the page**

2. **Click the "Save" button**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│  (... more settings above ...)                                               │
│                                                                              │
│  General Settings                                                            │
│  ═══════════════════════════════════════════════════════════════════════    │
│                                                                              │
│  Remove Blocked Hosts Interval                                               │
│  [...settings...]                                                            │
│                                                                              │
│                                                                              │
│                              [ Save ]     ◄── CLICK THIS                    │
│                                                                              │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

3. **Wait for the page to reload and confirm settings are saved**

> ✅ **Checkpoint:** Global settings are configured with your Oinkcode and rule sources enabled!

---

# 8. EXERCISE 3: ADDING AND CONFIGURING SNORT INTERFACE

## 8.1 Objective

Add the WAN interface to Snort monitoring and start the Snort service.

## 8.2 Step-by-Step Instructions

### Step 8.2.1: Navigate to Snort Interfaces

**Navigation Path:** `Services` → `Snort` → `Snort Interfaces` tab

1. **Go to:** `Services` → `Snort`

2. **Click the "Snort Interfaces" tab** (this is usually the default tab)

### Step 8.2.2: Add a New Interface

1. **Click the green "+ Add" button**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Services / Snort / Snort Interfaces                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Interface Settings Overview                                                 │
│  ────────────────────────────────────────────────────────────────────────── │
│                                                                              │
│  Interface │ Snort Status │ Pattern Match │ Blocking │ Description │Actions │
│  ──────────┼──────────────┼───────────────┼──────────┼─────────────┼─────── │
│            │              │               │          │             │        │
│            │    (No Snort interfaces have been defined yet)        │        │
│            │              │               │          │             │        │
│                                                                              │
│                           [ + Add ]  ◄── CLICK THIS                         │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Step 8.2.3: Configure WAN Interface Settings

You will see a new page with many settings. Configure the following:

#### Section: General Settings

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Services / Snort / Interface Edit / General Settings                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  General Settings                                                            │
│  ═══════════════════════════════════════════════════════════════════════    │
│                                                                              │
│  Enable                                                                      │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ [✓] Enable interface         ◄── CHECK THIS BOX                        ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│  Checking this box enables Snort inspection on this interface.              │
│                                                                              │
│  Interface                                                                   │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ [ WAN (em0)                                              ▼]            ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│       ▲                                                                      │
│       └── SELECT "WAN" FROM THE DROPDOWN                                    │
│                                                                              │
│  Choose the interface where this Snort instance will inspect traffic.       │
│                                                                              │
│  Description                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ WAN                                                                     ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│       ▲                                                                      │
│       └── TYPE "WAN" AS THE DESCRIPTION                                     │
│                                                                              │
│  Enter a meaningful description here for your reference. Example:           │
│  WAN Traffic Monitor                                                         │
│                                                                              │
│  Snap Length                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ [ 1518                                                   ]             ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│       ▲                                                                      │
│       └── LEAVE AS DEFAULT (1518)                                           │
│                                                                              │
│  Enter the desired interface snap length value in bytes. The default of    │
│  1518 bytes is suitable for most applications.                              │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Configuration Summary:**

| Setting | Value | Action |
|---------|-------|--------|
| **Enable** | ✓ | Check the box |
| **Interface** | WAN (em0) | Select from dropdown |
| **Description** | WAN | Type this text |
| **Snap Length** | 1518 | Leave as default |

### Step 8.2.4: Review Alert Settings (Optional)

1. **Scroll down to find "Alert Settings" section**

2. **Leave at defaults for now:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Alert Settings                                                              │
│  ═══════════════════════════════════════════════════════════════════════    │
│                                                                              │
│  Send Alerts to System Log                                                   │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ [ ] Send Alerts to the firewall's system log                          ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                                                              │
│  Block Offenders                                                             │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ [ ] Block hosts generating alerts                                      ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                                                              │
│  (Leave these unchecked for now - we will just monitor alerts)              │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Step 8.2.5: Save Interface Settings

1. **Scroll to the BOTTOM of the page**

2. **Click "Save"**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│  (... more settings above ...)                                               │
│                                                                              │
│                              [ Save ]  [ Cancel ]                           │
│                                 ▲                                            │
│                            Click Save                                        │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Step 8.2.6: View the Added Interface

1. **You will be returned to the Snort Interfaces page**

2. **You should now see WAN listed:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Services / Snort / Snort Interfaces                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Interface Settings Overview                                                 │
│  ────────────────────────────────────────────────────────────────────────── │
│                                                                              │
│  Interface │ Snort   │ Pattern │ Blocking │ Description │ Actions          │
│            │ Status  │ Match   │          │             │                  │
│  ──────────┼─────────┼─────────┼──────────┼─────────────┼──────────────────│
│  WAN (em0) │  ⚪     │ AC-BNFA │ DISABLED │ WAN         │ [▶] [✎] [🗑]   │
│            │ Stopped │         │          │             │                  │
│                                                                              │
│  LEGEND:                                                                     │
│  ──────────────────────────────────────────────────────────────────────────  │
│  ⚪ = Stopped (grey icon)                                                   │
│  🟢 = Running (green icon)                                                  │
│  [▶] = Start/Play button                                                    │
│  [⏹] = Stop button (appears when running)                                   │
│  [✎] = Edit settings                                                        │
│  [🗑] = Delete interface                                                     │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Step 8.2.7: Start Snort on WAN

1. **Find the WAN row in the table**

2. **Click the Play/Start button [▶]** (it's blue/green)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Starting Snort                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Interface │ Snort   │ Pattern │ Blocking │ Description │ Actions          │
│            │ Status  │ Match   │          │             │                  │
│  ──────────┼─────────┼─────────┼──────────┼─────────────┼──────────────────│
│  WAN (em0) │  ⚪     │ AC-BNFA │ DISABLED │ WAN         │ [▶] [✎] [🗑]   │
│            │ Stopped │         │          │             │  ▲               │
│                                                             │               │
│                                                       Click this            │
│                                                       Start button          │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

3. **Wait 3-5 seconds for Snort to start**

4. **The status should change to Running:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Snort Running                                                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Interface │ Snort    │ Pattern │ Blocking │ Description │ Actions         │
│            │ Status   │ Match   │          │             │                 │
│  ──────────┼──────────┼─────────┼──────────┼─────────────┼─────────────────│
│  WAN (em0) │  🟢      │ AC-BNFA │ DISABLED │ WAN         │ [⏹] [✎] [🗑]  │
│            │ RUNNING  │         │          │             │                 │
│               ▲                                                             │
│               │                                                             │
│          Status is now                                                      │
│          "RUNNING" with                                                     │
│          green icon                                                         │
│                                                                              │
│  Note: The Start button [▶] changes to Stop button [⏹] when running        │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

> ⚠️ **If Snort doesn't start:** This is likely because rules haven't been downloaded yet. Continue to Exercise 4 to download rules, then come back and start Snort.

> ✅ **Checkpoint:** Snort interface is configured and running on WAN!

---

# 9. EXERCISE 4: DOWNLOADING AND ENABLING RULE SETS

## 9.1 Objective

Download the latest Snort and Emerging Threats rules, then enable specific rule categories.

## 9.2 Step-by-Step Instructions

### Step 9.2.1: Navigate to Updates Tab

**Navigation Path:** `Services` → `Snort` → `Updates` tab

1. **Go to:** `Services` → `Snort`

2. **Click the "Updates" tab**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Snort Tab Navigation                                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │ Snort      │ Global   │ Updates  │ Alerts │ Blocked │ Pass   │ ...    │ │
│  │ Interfaces │ Settings │    ▲     │        │         │ Lists  │        │ │
│  │            │          │  CLICK   │        │         │        │        │ │
│  │            │          │  THIS    │        │         │        │        │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Step 9.2.2: View Current Rule Status

1. **You will see the current status of rule sets:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Services / Snort / Updates                                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Installed Rule Set Signatures                                               │
│  ════════════════════════════════════════════════════════════════════════   │
│                                                                              │
│  Rule Set                              │ MD5 Hash      │ Last Updated      │
│  ──────────────────────────────────────┼───────────────┼───────────────────│
│  Snort VRT Rules                       │ (none)        │ Not Downloaded    │
│  Snort GPLv2 Community Rules           │ Not Enabled   │ Not Enabled       │
│  Emerging Threats Open Rules           │ (none)        │ Not Downloaded    │
│  Snort OpenAppID Detectors             │ Not Enabled   │ Not Enabled       │
│  Snort AppID Open Text Rules           │ Not Enabled   │ Not Enabled       │
│  Feodo Tracker Botnet C2 IP Rules      │ Not Enabled   │ Not Enabled       │
│                                                                              │
│  Last Update:  (never)                                                       │
│  Result:       (none)                                                        │
│                                                                              │
│                      [ UPDATE RULES ]    [ FORCE UPDATE ]                   │
│                             ▲                                                │
│                        Click this                                            │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Step 9.2.3: Download Rules

1. **Click the "UPDATE RULES" button**

2. **Wait for the download process to complete:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Rules Update Progress                                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ────────────────────────────────────────────────────────────────────────── │
│                                                                              │
│  Downloading Snort VRT rules file...                                        │
│  - Connecting to snort.org...                                               │
│  - Authenticating with Oinkcode...                                          │
│  - Downloading snortrules-snapshot-29200.tar.gz...                          │
│  - Download complete (15.2 MB)                                              │
│  - Extracting rules...                                                       │
│  - Installing rules to /usr/local/etc/snort/snort_xxxx/rules...            │
│  Snort VRT rules file downloaded and installed successfully!                │
│                                                                              │
│  Downloading Emerging Threats Open rules file...                            │
│  - Connecting to rules.emergingthreats.net...                               │
│  - Downloading emerging.rules.tar.gz...                                     │
│  - Download complete (8.7 MB)                                               │
│  - Extracting rules...                                                       │
│  - Installing rules to /usr/local/etc/snort/snort_xxxx/rules...            │
│  ET Open rules file downloaded and installed successfully!                  │
│                                                                              │
│  ════════════════════════════════════════════════════════════════════════   │
│  ║              Rules Update completed successfully!                    ║   │
│  ════════════════════════════════════════════════════════════════════════   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

3. **This process takes 2-5 minutes**

4. **DO NOT navigate away or close the browser!**

### Step 9.2.4: Verify Successful Download

1. **After completion, you should see:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Rules Successfully Downloaded                                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Rule Set                              │ MD5 Hash          │ Last Updated   │
│  ──────────────────────────────────────┼───────────────────┼────────────────│
│  Snort VRT Rules                       │ a7b8c9d0e1f2...   │ 2025-Mar-03    │
│  Snort GPLv2 Community Rules           │ Not Enabled       │ Not Enabled    │
│  Emerging Threats Open Rules           │ 1a2b3c4d5e6f...   │ 2025-Mar-03    │
│                                                                              │
│  Last Update:  2025-Mar-03 17:25:30                                         │
│  Result:       Success ✓                                                    │
│               ──────────                                                     │
│               ▲                                                              │
│               │                                                              │
│          This should say "Success"                                          │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Step 9.2.5: Enable Rule Categories for WAN Interface

Now we need to enable specific rule categories for the WAN interface.

1. **Go to:** `Services` → `Snort` → `Snort Interfaces` tab

2. **Click the pencil/edit icon [✎]** for the WAN interface

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Edit WAN Interface                                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Interface │ Snort   │ Pattern │ Blocking │ Description │ Actions          │
│            │ Status  │ Match   │          │             │                  │
│  ──────────┼─────────┼─────────┼──────────┼─────────────┼──────────────────│
│  WAN (em0) │  🟢     │ AC-BNFA │ DISABLED │ WAN         │ [⏹] [✎] [🗑]   │
│            │ RUNNING │         │          │             │      ▲           │
│                                                               │            │
│                                                          Click Edit        │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

3. **Click the "WAN Categories" tab**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  WAN Interface Tabs                                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │ WAN      │ WAN        │ WAN   │ WAN      │ WAN       │ WAN     │ ...  │ │
│  │ Settings │ Categories │ Rules │ Variables│ Preprocs  │ Barn... │      │ │
│  │          │     ▲      │       │          │           │         │      │ │
│  │          │   CLICK    │       │          │           │         │      │ │
│  │          │   THIS     │       │          │           │         │      │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Step 9.2.6: Select Rule Categories to Enable

1. **You will see a long list of available rule categories**

2. **Find and CHECK the following categories:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Services / Snort / WAN - Categories                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Select the rulesets (Categories) Snort will load at startup.               │
│                                                                              │
│  ═══════════════════════════════════════════════════════════════════════    │
│  Ruleset: ET Open Rules                                                      │
│  ═══════════════════════════════════════════════════════════════════════    │
│                                                                              │
│  Enable │ Category Name                     │ Purpose                       │
│  ───────┼───────────────────────────────────┼───────────────────────────────│
│   [ ]   │ emerging-activex.rules            │ ActiveX exploits              │
│   [ ]   │ emerging-attack_response.rules    │ Attack responses              │
│   [ ]   │ emerging-botcc.rules              │ Botnet C&C                    │
│   [ ]   │ emerging-chat.rules               │ Chat protocols                │
│   [ ]   │ emerging-current_events.rules     │ Current event threats         │
│   [✓]   │ emerging-dns.rules                │ DNS threats     ◄── ENABLE   │
│   [ ]   │ emerging-dos.rules                │ Denial of service             │
│   [✓]   │ emerging-exploit.rules            │ Exploit attempts ◄── ENABLE  │
│   [ ]   │ emerging-ftp.rules                │ FTP attacks                   │
│   [ ]   │ emerging-games.rules              │ Game traffic                  │
│   [ ]   │ emerging-icmp.rules               │ ICMP attacks                  │
│   [✓]   │ emerging-malware.rules            │ Malware traffic ◄── ENABLE   │
│   [ ]   │ emerging-misc.rules               │ Miscellaneous                 │
│   [ ]   │ emerging-netbios.rules            │ NetBIOS attacks               │
│   [ ]   │ emerging-p2p.rules                │ P2P traffic                   │
│   [ ]   │ emerging-policy.rules             │ Policy violations             │
│   [✓]   │ emerging-scan.rules               │ Network scans   ◄── ENABLE   │
│   [ ]   │ emerging-shellcode.rules          │ Shellcode                     │
│   [ ]   │ emerging-smtp.rules               │ SMTP attacks                  │
│   [✓]   │ emerging-trojan.rules             │ Trojan activity ◄── ENABLE   │
│   [ ]   │ emerging-user_agents.rules        │ User agents                   │
│   [✓]   │ emerging-web_client.rules         │ Web attacks    ◄── ENABLE    │
│   [ ]   │ emerging-web_server.rules         │ Server attacks                │
│   ...                                                                        │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Categories to Enable:**

| ✓ | Category | Description |
|---|----------|-------------|
| ☑ | emerging-dns.rules | Detect malicious DNS traffic |
| ☑ | emerging-exploit.rules | Detect exploitation attempts |
| ☑ | emerging-malware.rules | Detect known malware signatures |
| ☑ | emerging-scan.rules | Detect network scanning |
| ☑ | emerging-trojan.rules | Detect trojan communications |
| ☑ | emerging-web_client.rules | Detect web-based attacks |

3. **Scroll through the entire list and check the boxes for the categories above**

### Step 9.2.7: Save Category Settings

1. **Scroll to the bottom of the page**

2. **Click "Save"**

### Step 9.2.8: Restart Snort to Apply New Rules

**IMPORTANT:** After enabling new rule categories, you MUST restart Snort!

1. **Go to:** `Services` → `Snort` → `Snort Interfaces`

2. **Click the Stop button [⏹]** for WAN

3. **Wait 2-3 seconds**

4. **Click the Start button [▶]** for WAN

5. **Verify status shows "RUNNING"**

> ✅ **Checkpoint:** Rule sets downloaded and categories enabled!

---

# 10. EXERCISE 5: CREATING CUSTOM SNORT RULES

## 10.1 Objective

Write custom Snort rules to detect specific threats relevant to your environment.

## 10.2 Understanding Snort Rule Syntax

### Rule Structure

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       SNORT RULE STRUCTURE                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                          RULE HEADER                                │    │
│  │                                                                     │    │
│  │   ACTION   PROTOCOL   SRC_IP   SRC_PORT   DIRECTION   DST_IP DST_PORT  │
│  │                                                                     │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                   │                                          │
│                                   ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                          RULE OPTIONS                               │    │
│  │                                                                     │    │
│  │   (option1:value; option2:value; option3:value; ...)               │    │
│  │                                                                     │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  ══════════════════════════════════════════════════════════════════════════ │
│                                                                              │
│  EXAMPLE:                                                                    │
│                                                                              │
│  alert tcp any any -> any 80 (msg:"HTTP GET Request"; content:"GET"; sid:1;)│
│  ─────┬─── ─┬─ ─┬─  ┬  ─┬─ ─┬─ ──────────────────────────────────┬─────────│
│       │     │   │   │   │   │                                    │          │
│       │     │   │   │   │   │                     Rule Options ──┘          │
│       │     │   │   │   │   │                                               │
│       │     │   │   │   │   └── Destination Port: 80 (HTTP)                 │
│       │     │   │   │   │                                                   │
│       │     │   │   │   └── Destination IP: any                             │
│       │     │   │   │                                                       │
│       │     │   │   └── Direction: -> (source to destination)               │
│       │     │   │                                                           │
│       │     │   └── Source Port: any                                        │
│       │     │                                                               │
│       │     └── Source IP: any                                              │
│       │                                                                     │
│       └── Protocol: tcp                                                     │
│                                                                             │
│  └── Action: alert                                                          │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Rule Header Components

| Component | Description | Examples |
|-----------|-------------|----------|
| **Action** | What to do when rule matches | `alert`, `log`, `pass`, `drop`, `reject` |
| **Protocol** | Network protocol | `tcp`, `udp`, `icmp`, `ip` |
| **Source IP** | Where traffic originates | `any`, `192.168.1.0/24`, `$HOME_NET` |
| **Source Port** | Source port number | `any`, `80`, `1024:65535` |
| **Direction** | Traffic flow | `->` (one-way), `<>` (both ways) |
| **Dest IP** | Traffic destination | `any`, `10.0.0.1`, `$EXTERNAL_NET` |
| **Dest Port** | Destination port | `any`, `443`, `22` |

### Common Rule Options

| Option | Purpose | Example |
|--------|---------|---------|
| `msg` | Alert message | `msg:"Attack Detected";` |
| `content` | Match specific text/bytes | `content:"malware";` |
| `nocase` | Case-insensitive | `content:"GET"; nocase;` |
| `http_method` | Match HTTP method | `http_method;` |
| `http_header` | Match in HTTP headers | `http_header;` |
| `http_uri` | Match in URI | `http_uri;` |
| `flow` | Connection state | `flow:to_server,established;` |
| `sid` | Signature ID (UNIQUE!) | `sid:1000001;` |
| `rev` | Revision number | `rev:1;` |

## 10.3 Step-by-Step: Create Custom Rule to Detect Suspicious User-Agent

### Step 10.3.1: Navigate to Custom Rules

1. **Go to:** `Services` → `Snort` → `Snort Interfaces`

2. **Click the edit icon [✎]** for WAN

3. **Click the "WAN Rules" tab**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  WAN Interface Tabs                                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │ WAN      │ WAN        │ WAN    │ WAN      │ WAN       │ WAN     │ ... │ │
│  │ Settings │ Categories │ Rules  │ Variables│ Preprocs  │ Barn... │     │ │
│  │          │            │   ▲    │          │           │         │     │ │
│  │          │            │ CLICK  │          │           │         │     │ │
│  │          │            │ THIS   │          │           │         │     │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Step 10.3.2: Select Custom Rules Category

1. **Find the "Category Selection" dropdown**

2. **Select "custom.rules" from the dropdown**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Services / Snort / WAN - Rules                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Available Rule Categories                                                   │
│  ──────────────────────────────────────────────────────────────────────────  │
│                                                                              │
│  Category Selection                                                          │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ [ custom.rules                                           ▼]            ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│       ▲                                                                      │
│       └── SELECT "custom.rules" FROM DROPDOWN                               │
│                                                                              │
│  Select the rule category to view and manage.                               │
│                                                                              │
│  ──────────────────────────────────────────────────────────────────────────  │
│                                                                              │
│  Defined Custom Rules                                                        │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                                                                          ││
│  │                                                                          ││
│  │  (This text area is where you type your custom rules)                   ││
│  │                                                                          ││
│  │                                                                          ││
│  │                                                                          ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│       ▲                                                                      │
│       └── TYPE YOUR CUSTOM RULES HERE                                       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Step 10.3.3: Enter Custom Rule 1 - Suspicious User-Agent Detection

1. **In the "Defined Custom Rules" text area, type (or copy/paste) the following rule:**

```
alert tcp any any -> any 80 (msg:"SUSPICIOUS User-Agent EvilBot Detected"; content:"GET"; http_method; content:"User-Agent|3a| EvilBot/1.0"; http_header; classtype:trojan-activity; sid:1000001; rev:1;)
```

**Let's break down this rule:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  RULE BREAKDOWN: Suspicious User-Agent Detection                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  alert tcp any any -> any 80                                                │
│  │     │   │   │    │  │   │                                                │
│  │     │   │   │    │  │   └── Port 80 (HTTP web traffic)                   │
│  │     │   │   │    │  └── Destination: any IP address                      │
│  │     │   │   │    └── Direction: source → destination                     │
│  │     │   │   └── Source port: any                                         │
│  │     │   └── Source: any IP address                                       │
│  │     └── Protocol: TCP                                                    │
│  └── Action: Generate alert                                                  │
│                                                                              │
│  ══════════════════════════════════════════════════════════════════════════ │
│                                                                              │
│  (msg:"SUSPICIOUS User-Agent EvilBot Detected";                             │
│   │                                                                          │
│   └── Alert message displayed in Snort logs                                 │
│                                                                              │
│  content:"GET"; http_method;                                                │
│   │              │                                                           │
│   │              └── Look in the HTTP method field                          │
│   └── Match the text "GET"                                                  │
│                                                                              │
│  content:"User-Agent|3a| EvilBot/1.0"; http_header;                         │
│   │       │                             │                                    │
│   │       │                             └── Look in HTTP headers            │
│   │       └── |3a| is hex for ":" (colon character)                        │
│   └── Match "User-Agent: EvilBot/1.0"                                       │
│                                                                              │
│  classtype:trojan-activity;                                                 │
│   │                                                                          │
│   └── Classify as trojan-related activity                                   │
│                                                                              │
│  sid:1000001;                                                               │
│   │                                                                          │
│   └── Signature ID: 1000001 (MUST be unique)                                │
│       Custom rules should use SIDs >= 1000000                               │
│                                                                              │
│  rev:1;)                                                                    │
│   │                                                                          │
│   └── Revision 1 (increment when you modify the rule)                       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Step 10.3.4: Add Custom Rule 2 - SSH from Restricted Network

1. **On a NEW LINE below the first rule, add:**

```
alert tcp 192.168.1.0/24 any -> any 22 (msg:"SSH Connection Attempt from Restricted IP Range"; flow:to_server,established; classtype:policy-violation; sid:1000002; rev:1;)
```

### Step 10.3.5: Verify Your Custom Rules

Your custom rules text area should now look like this:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Defined Custom Rules                                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │alert tcp any any -> any 80 (msg:"SUSPICIOUS User-Agent EvilBot         ││
│  │Detected"; content:"GET"; http_method; content:"User-Agent|3a|          ││
│  │EvilBot/1.0"; http_header; classtype:trojan-activity; sid:1000001;      ││
│  │rev:1;)                                                                  ││
│  │alert tcp 192.168.1.0/24 any -> any 22 (msg:"SSH Connection Attempt     ││
│  │from Restricted IP Range"; flow:to_server,established;                   ││
│  │classtype:policy-violation; sid:1000002; rev:1;)                         ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                                                              │
│  ⚠️  IMPORTANT NOTES:                                                       │
│  • Each rule must be on its own line (or continuous without line breaks)   │
│  • SIDs must be unique - no two rules can have the same SID                │
│  • Custom rules should use SID >= 1000000                                  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Step 10.3.6: Save Custom Rules

1. **Click the "Save" button**

### Step 10.3.7: Restart Snort to Load New Rules

1. **Go to:** `Services` → `Snort` → `Snort Interfaces`

2. **Stop Snort** (click [⏹])

3. **Wait 3 seconds**

4. **Start Snort** (click [▶])

5. **Verify status is "RUNNING"**

> ✅ **Checkpoint:** Custom rules created and Snort restarted!

---

# 11. EXERCISE 6: TESTING AND VERIFYING ALERTS

## 11.1 Objective

Test your custom Snort rules and verify that alerts are generated correctly.

## 11.2 Testing Rule 1: Suspicious User-Agent

### Step 11.2.1: Open Command Prompt on Your Test PC

**On Windows:**
1. Press `Windows Key + R`
2. Type `cmd`
3. Press Enter

**On Mac/Linux:**
1. Open Terminal application

### Step 11.2.2: Run Test Command

**Using curl (if available):**

```bash
curl -A "EvilBot/1.0" http://example.com
```

**What this command does:**
- `curl` - Command-line tool for making HTTP requests
- `-A "EvilBot/1.0"` - Sets the User-Agent header to "EvilBot/1.0"
- `http://example.com` - A safe test website

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Command Prompt - Running Test                                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  C:\Users\Student> curl -A "EvilBot/1.0" http://example.com                 │
│                                                                              │
│  <!doctype html>                                                             │
│  <html>                                                                      │
│  <head>                                                                      │
│      <title>Example Domain</title>                                          │
│  ...                                                                         │
│                                                                              │
│  (You should see the HTML content of example.com)                           │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

**If curl is not installed, use PowerShell:**

```powershell
Invoke-WebRequest -Uri "http://example.com" -UserAgent "EvilBot/1.0"
```

### Step 11.2.3: Check Snort Alerts

1. **Go to:** `Services` → `Snort` → `Alerts` tab

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Snort Tab Navigation                                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │ Snort      │ Global   │ Updates │ Alerts  │ Blocked │ Pass   │ ...    │ │
│  │ Interfaces │ Settings │         │    ▲    │         │ Lists  │        │ │
│  │            │          │         │  CLICK  │         │        │        │ │
│  │            │          │         │  THIS   │         │        │        │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

2. **Select WAN interface from the dropdown (if not already selected)**

3. **Look for your alert:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Services / Snort / Alerts                                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Interface: [ WAN (em0)   ▼]          [ Download ]  [ Clear ]               │
│                                                                              │
│  Alert Log View                                                              │
│  ══════════════════════════════════════════════════════════════════════════ │
│                                                                              │
│  Date/Time          │ Pri │ Proto │ Source            │ Destination        │
│  ───────────────────┼─────┼───────┼───────────────────┼────────────────────│
│  2025-03-03         │  1  │ TCP   │ 192.168.1.100:    │ 93.184.216.34:     │
│  17:45:22           │     │       │ 54321             │ 80                 │
│                     │     │       │                   │                    │
│  Alert Message: SUSPICIOUS User-Agent EvilBot Detected                      │
│  Signature ID:  [1:1000001:1]  ◄── Your custom rule!                       │
│  Classification: trojan-activity                                             │
│                                                                              │
│  ────────────────────────────────────────────────────────────────────────── │
│                                                                              │
│  ✓ SUCCESS! Your custom rule detected the malicious User-Agent!            │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 11.3 Testing Rule 2: SSH from Restricted Network

### Step 11.3.1: Run SSH Test

From a PC in the 192.168.1.0/24 network, try connecting via SSH:

**Option A - Using SSH:**
```bash
ssh admin@192.168.1.1
```

**Option B - Using Telnet (tests port connectivity):**
```bash
telnet 192.168.1.1 22
```

**Option C - PowerShell (Windows):**
```powershell
Test-NetConnection -ComputerName 192.168.1.1 -Port 22
```

### Step 11.3.2: Check Snort Alerts

1. **Go to:** `Services` → `Snort` → `Alerts`

2. **Look for the SSH alert:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  SSH Alert                                                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Date/Time          │ Pri │ Proto │ Source            │ Destination        │
│  ───────────────────┼─────┼───────┼───────────────────┼────────────────────│
│  2025-03-03         │  1  │ TCP   │ 192.168.1.100:    │ 192.168.1.1:       │
│  17:50:15           │     │       │ 52431             │ 22                 │
│                     │     │       │                   │                    │
│  Alert Message: SSH Connection Attempt from Restricted IP Range             │
│  Signature ID:  [1:1000002:1]  ◄── Your second custom rule!                │
│  Classification: policy-violation                                            │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

> ✅ **Checkpoint:** Custom rules tested and alerts verified!

---

# 12. EXERCISE 7: MONITORING MALICIOUS DNS TRAFFIC

## 12.1 Objective

Use pre-built Emerging Threats rules to detect DNS queries to known malicious domains.

## 12.2 Understanding DNS-Based Threats

Malware often uses DNS to:
- Find Command & Control (C2) servers
- Tunnel data out of networks
- Resolve dynamically-generated domains (DGA)

## 12.3 Testing DNS Detection

### Step 12.3.1: Verify DNS Rules are Enabled

1. **Confirm `emerging-dns.rules` is enabled** (from Exercise 4)

2. **Confirm `emerging-malware.rules` is enabled**

### Step 12.3.2: Perform DNS Lookup

1. **Open Command Prompt**

2. **Run the following command:**

```bash
nslookup Vaccineprogram.co.kr
```

> ⚠️ **Note:** This domain is flagged in threat intelligence databases. You are only performing a DNS lookup (safe), not actually connecting to the site.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Command Prompt - DNS Lookup Test                                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  C:\Users\Student> nslookup Vaccineprogram.co.kr                            │
│                                                                              │
│  Server:  UnKnown                                                            │
│  Address:  192.168.1.1                                                       │
│                                                                              │
│  Non-authoritative answer:                                                   │
│  Name:    Vaccineprogram.co.kr                                              │
│  Address:  xxx.xxx.xxx.xxx                                                   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Step 12.3.3: Check for DNS Alerts

1. **Go to:** `Services` → `Snort` → `Alerts`

2. **Look for DNS-related alerts like:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  DNS Alert                                                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Date/Time          │ Pri │ Proto │ Source            │ Destination        │
│  ───────────────────┼─────┼───────┼───────────────────┼────────────────────│
│  2025-03-03         │  1  │ UDP   │ 192.168.1.100:    │ 8.8.8.8:           │
│  18:05:33           │     │       │ 54892             │ 53                 │
│                     │     │       │                   │                    │
│  Alert Message: ET CNC DNS Query to Known Malicious Domain                  │
│  Signature ID:  [1:2023456:3]                                               │
│  Classification: A Network Trojan was detected                              │
│                                                                              │
│  ────────────────────────────────────────────────────────────────────────── │
│                                                                              │
│  This alert indicates:                                                       │
│  • A device on your network (192.168.1.100) made a DNS query               │
│  • The queried domain is known to be associated with malware                │
│  • The device may be infected with malware trying to reach C2 server       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

> ✅ **Checkpoint:** DNS threat detection working!

---

# 13. ENTERPRISE IDS/IPS SOLUTIONS

## 13.1 Cisco Firepower

**Cisco Firepower** is an enterprise Next-Generation Firewall (NGFW) with advanced IPS capabilities.

**Official Website:** https://www.cisco.com/c/en/us/products/security/firepower-ngfw/

### Key Features

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      CISCO FIREPOWER FEATURES                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────┐    ┌─────────────────────┐                        │
│  │ Advanced Malware    │    │ Application         │                        │
│  │ Protection (AMP)    │    │ Visibility & Control│                        │
│  │                     │    │                     │                        │
│  │ • File sandboxing   │    │ • 4000+ applications│                        │
│  │ • Retrospection     │    │ • User-based policy │                        │
│  │ • Threat grid       │    │ • Risk-based access │                        │
│  └─────────────────────┘    └─────────────────────┘                        │
│                                                                              │
│  ┌─────────────────────┐    ┌─────────────────────┐                        │
│  │ Next-Gen IPS        │    │ URL Filtering       │                        │
│  │                     │    │                     │                        │
│  │ • Snort-powered     │    │ • 80+ categories    │                        │
│  │ • Talos intelligence│    │ • Reputation-based  │                        │
│  │ • Auto-tuning       │    │ • Custom lists      │                        │
│  └─────────────────────┘    └─────────────────────┘                        │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │           Firepower Management Center (FMC)                          │   │
│  │  • Centralized management for multiple devices                       │   │
│  │  • Unified policy deployment                                         │   │
│  │  • Advanced reporting and analytics                                  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 13.2 Comparison: Open Source vs Enterprise

| Feature | Snort + pfSense | Cisco Firepower |
|---------|-----------------|-----------------|
| **Cost** | Free | $$$$ (Commercial) |
| **Support** | Community | Cisco TAC 24/7 |
| **Management** | Per-device GUI | Centralized FMC |
| **Threat Intelligence** | ET Open, Snort VRT | Cisco Talos |
| **Scalability** | Single device | Enterprise-wide |
| **Best For** | SMB, Learning | Large enterprises |

---

# 14. TROUBLESHOOTING GUIDE

## 14.1 Common Issues and Solutions

### Issue: Snort Won't Start

| Possible Cause | Solution |
|----------------|----------|
| Rule syntax error | Check custom rules for typos |
| No rules enabled | Enable at least one rule category |
| Memory issue | Reduce enabled categories |

### Issue: No Alerts Generated

| Possible Cause | Solution |
|----------------|----------|
| Snort not running | Check status and start if needed |
| Rules not enabled | Verify categories are checked |
| Traffic not flowing | Verify network connectivity |

### Issue: Rules Won't Download

| Possible Cause | Solution |
|----------------|----------|
| Invalid Oinkcode | Verify code is correct, no spaces |
| No internet | Check pfSense WAN connectivity |
| Firewall blocking | Allow HTTPS to snort.org |

### Issue: Too Many Alerts (False Positives)

| Solution |
|----------|
| Disable overly-sensitive rule categories |
| Add trusted IPs to Pass Lists |
| Create suppress rules for known-good traffic |

---

# 15. WORKSHOP SUMMARY

## 15.1 What You Accomplished

| ✓ | Achievement |
|---|-------------|
| ☑ | Created Snort.org account and obtained Oinkcode |
| ☑ | Installed Snort on pfSense |
| ☑ | Configured global settings with rule sources |
| ☑ | Added WAN interface to Snort monitoring |
| ☑ | Downloaded and enabled rule sets |
| ☑ | Wrote custom Snort rules |
| ☑ | Tested rules and verified alerts |
| ☑ | Detected malicious DNS traffic |

## 15.2 Key Takeaways

1. **IDS monitors and alerts** (passive) while **IPS monitors and blocks** (active)
2. **Snort** is the most widely deployed open-source IDS/IPS
3. **Rules** define what Snort detects - keep them updated!
4. **Custom rules** allow detection of organization-specific threats
5. **Enterprise solutions** like Cisco Firepower offer additional features for large organizations

## 15.3 Snort Rule Quick Reference

```
ACTION PROTOCOL SRC_IP SRC_PORT -> DST_IP DST_PORT (OPTIONS)

Example:
alert tcp any any -> any 80 (msg:"Alert"; content:"pattern"; sid:1000001; rev:1;)
```

---

# 16. ADDITIONAL RESOURCES

## 16.1 Official Documentation

| Resource | URL |
|----------|-----|
| **Snort Website** | https://www.snort.org |
| **Snort User Manual** | https://www.snort.org/documents |
| **Snort Rules Download** | https://www.snort.org/downloads#rules |
| **pfSense Documentation** | https://docs.netgate.com |
| **Emerging Threats** | https://rules.emergingthreats.net |
| **Cisco Firepower** | https://www.cisco.com/c/en/us/products/security/firepower-ngfw/ |

## 16.2 Learning Resources

| Resource | URL |
|----------|-----|
| **Suricata (Alternative)** | https://suricata.io |
| **Zeek Network Monitor** | https://zeek.org |
| **Security Onion** | https://securityonionsolutions.com |
| **OSSEC HIDS** | https://www.ossec.net |

---

## NEXT WEEK PREVIEW

**Week 12: Introduction to Secure Software Development**

Topics:
- Software Development Lifecycle (SDLC)
- OWASP Top 10 Vulnerabilities
- Secure Coding Principles
- Security Testing Tools

---

*© TECH2400 Cyber Security - Kaplan Business School*

*This material is for educational purposes only.*
