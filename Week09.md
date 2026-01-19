# Week 09: Incident Response and SIEM Implementation with ELK Stack

## Table of Contents
1. [Introduction to Incident Response](#introduction-to-incident-response)
2. [Incident Response Lifecycle](#incident-response-lifecycle)
3. [Tools Overview](#tools-overview)
4. [Lab Activity: Complete ELK Stack Setup](#lab-activity-complete-elk-stack-setup)
5. [Troubleshooting Guide](#troubleshooting-guide)
6. [Additional Resources](#additional-resources)

---

## Introduction to Incident Response

**Incident Response (IR)** is a structured approach to managing and mitigating security incidents. It involves a coordinated effort to:
- Detect security incidents
- Analyze their scope and impact
- Contain the threat
- Eradicate the root cause
- Recover normal operations
- Learn from the incident

### Why is Incident Response Important?

- **Minimize Damage**: Quick response limits the impact of security breaches
- **Reduce Recovery Time**: Structured processes speed up restoration
- **Preserve Evidence**: Proper handling maintains forensic integrity
- **Meet Compliance**: Many regulations require documented IR procedures
- **Continuous Improvement**: Post-incident analysis strengthens defenses

---

## Incident Response Lifecycle

The IR lifecycle consists of six key phases:

### 1. **Preparation**
- Establish IR team and procedures
- Deploy monitoring and logging tools
- Configure alerting systems
- Conduct training and simulations

### 2. **Detection & Analysis**
- Monitor for security events
- Analyze alerts and anomalies
- Determine if an incident occurred
- Assess severity and scope

### 3. **Containment**
- **Short-term**: Isolate affected systems
- **Long-term**: Apply patches and security controls
- Prevent spread of the incident

### 4. **Eradication**
- Remove malware and threats
- Close vulnerabilities
- Eliminate attacker access

### 5. **Recovery**
- Restore systems to normal operation
- Validate system integrity
- Monitor for recurrence

### 6. **Lessons Learned**
- Document the incident
- Analyze response effectiveness
- Update procedures and controls

---

## Tools Overview

### IR Tools Mapped to Lab Components

| IR Phase | Process | Lab Tool | Purpose | Type |
|----------|---------|----------|---------|------|
| **Preparation** | Install OS | Linux Mint (Ubuntu 22.04) | Base operating system | Open Source |
| **Preparation** | Update system | apt package manager | System maintenance | Open Source |
| **Detection** | Generate logs | OpenSSH Server (sshd) | Authentication events | Open Source |
| **Detection** | View logs | /var/log/auth.log | Log file storage | Open Source |
| **Collection** | Ingest logs | Logstash | Data pipeline | Open Source |
| **Analysis** | Parse logs | Logstash grok filter | Log structuring | Open Source |
| **Storage** | Index data | Elasticsearch | Search and analytics | Open Source |
| **Analysis** | Search/Hunt | Kibana Discover | Interactive exploration | Open Source |
| **Visualization** | Create dashboards | Kibana Visualize | Visual analytics | Open Source |
| **Detection** | Alerting | Kibana Rules | Automated notifications | Open Source |
| **Containment** | Block IPs | ufw/iptables | Firewall controls | Open Source |

### Comprehensive IR Tool Ecosystem

#### Open-Source Alternatives

| Category | Tools |
|----------|-------|
| **SIEM/Log Management** | ELK Stack, OpenSearch, Wazuh, Graylog |
| **Network Monitoring** | Suricata, Zeek (Bro), Snort |
| **Threat Intelligence** | MISP, OpenCTI, Yeti |
| **Case Management** | TheHive, RTIR |
| **Automation (SOAR)** | Shuffle, StackStorm |
| **Forensics** | Velociraptor, Autopsy, Volatility |
| **Endpoint Protection** | Wazuh, OSSEC |

#### Commercial Alternatives

| Category | Tools |
|----------|-------|
| **SIEM** | Splunk Enterprise Security, Microsoft Sentinel, IBM QRadar |
| **EDR/XDR** | CrowdStrike Falcon, Microsoft Defender, SentinelOne |
| **Network Security** | Palo Alto Networks, Cisco Firepower, Fortinet |
| **SOAR** | Cortex XSOAR, Splunk SOAR, IBM Resilient |
| **Threat Intel** | Recorded Future, ThreatConnect, Anomali |
| **Incident Management** | ServiceNow SIRS, PagerDuty |

### Tool Documentation Links

- **Elasticsearch**: https://www.elastic.co/elasticsearch/
- **Logstash**: https://www.elastic.co/logstash/
- **Kibana**: https://www.elastic.co/kibana/
- **OpenSSH**: https://www.openssh.com/
- **Wazuh**: https://wazuh.com/
- **Suricata**: https://suricata.io/
- **TheHive**: https://github.com/TheHive-Project/TheHive

---

## Lab Activity: Complete ELK Stack Setup

### Lab Objectives

By the end of this lab, you will:
1. Install and configure Linux Mint VM
2. Deploy Elasticsearch, Logstash, and Kibana (ELK Stack)
3. Configure SSH logging for security events
4. Create Logstash pipeline to ingest SSH logs
5. Search and analyze logs in Kibana
6. Build visualizations for attack detection
7. Configure alerting for brute-force attacks

### Lab Architecture
```
┌─────────────────┐
│   SSH Failed    │
│  Login Attempts │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  /var/log/      │
│   auth.log      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Logstash      │
│  (Parse & Ship) │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Elasticsearch   │
│  (Store & Index)│
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│     Kibana      │
│ (Search/Visualize)│
└─────────────────┘
```

### Prerequisites

- **Host System**: Windows, macOS, or Linux
- **RAM**: 8GB minimum (16GB recommended)
- **Disk Space**: 30GB free
- **Software**: VirtualBox or VMware
- **Internet Connection**: Required for downloads

---

## PART 0: Host Machine Setup

### Block 0.1 - Install VirtualBox

**Type**: MANUAL

**Instructions**:
1. Navigate to: https://www.virtualbox.org/wiki/Downloads
2. Download VirtualBox for your operating system:
   - Windows hosts
   - macOS hosts
   - Linux distributions
3. Run the installer
4. Follow installation prompts
5. Restart if prompted

**Verification**:
- Open VirtualBox
- Verify version 7.0+ is installed

---

### Block 0.2 - Download Linux Mint OSBoxes VM

**Type**: MANUAL

**Instructions**:
1. Navigate to: https://www.osboxes.org/linux-mint/
2. On the OSBoxes page:
   - Select **VirtualBox** format (VDI)
   - Choose **Linux Mint 21.x (Cinnamon)**
   - Based on Ubuntu 22.04 LTS
3. Click the download link
4. Download the `.7z` file (~2-3 GB)
5. Save to a known location

**Note**: Download may take 15-30 minutes depending on connection speed.

---

### Block 0.3 - Extract the VM Archive

**Type**: MANUAL

**Instructions**:
1. Install 7-Zip if not present:
   - Download from: https://www.7-zip.org/
2. Locate the downloaded `.7z` file
3. Right-click → **7-Zip** → **Extract Here**
4. Extract to: `Documents/OSBoxes/LinuxMint/`
5. Verify extraction completed successfully

**Expected Result**:
- A `.vdi` file (VirtualBox Disk Image)
- Size: approximately 10-15 GB

---

### Block 0.4 - Import VM into VirtualBox

**Type**: MANUAL

**Instructions**:
1. Open VirtualBox
2. Click **New** button
3. Configure VM settings:
   - **Name**: `LinuxMint-ELK-Week09`
   - **Type**: Linux
   - **Version**: Ubuntu (64-bit)
4. Click **Next**
5. **Memory Size**: 
   - Minimum: 4096 MB (4 GB)
   - Recommended: 8192 MB (8 GB)
6. Click **Next**
7. **Hard Disk**: Select **Use an existing virtual hard disk file**
8. Click the folder icon
9. Navigate to extracted `.vdi` file
10. Select the file and click **Open**
11. Click **Create**

**Verification**:
- VM appears in VirtualBox Manager
- Shows "Powered Off" status

---

### Block 0.5 - Configure VM Settings

**Type**: MANUAL

**Instructions**:
1. Select your VM in VirtualBox Manager
2. Click **Settings**
3. **System** → **Processor**:
   - Set **Processor(s)**: 2 CPUs minimum
4. **Display** → **Screen**:
   - Video Memory: 128 MB
5. **Network** → **Adapter 1**:
   - **Attached to**: NAT (recommended for beginners)
   - Alternative: Bridged Adapter (for advanced users)
6. Click **OK**

**Network Options Explained**:
- **NAT**: VM can access internet, host cannot access VM (simpler)
- **Bridged**: VM gets own IP on network (allows SSH from host)

---

### Block 0.6 - Start and Login to VM

**Type**: MANUAL

**Instructions**:
1. Select your VM
2. Click **Start** (green arrow)
3. Wait for Linux Mint desktop to load (1-2 minutes)
4. Login with OSBoxes default credentials:
   - **Username**: `osboxes`
   - **Password**: `osboxes.org`
5. Press Enter

**Verification**:
- Linux Mint desktop appears
- You see taskbar, menu, and desktop icons

**Security Note**: Change password after login if required by lab policy.

---

### Block 0.7 - Verify Internet Connectivity

**Type**: VERIFY

**Instructions**:
1. Open Terminal:
   - Click **Menu** → **Terminal**
   - Or press `Ctrl+Alt+T`
2. Run network tests:
```bash
ping -c 2 1.1.1.1
ping -c 2 google.com
```

**Expected Output**:
```
PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=15.2 ms
64 bytes from 1.1.1.1: icmp_seq=2 ttl=57 time=14.8 ms

--- 1.1.1.1 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss
```

**Troubleshooting**:
- If IP ping works but DNS fails → DNS configuration issue
- If both fail → Network adapter not connected

**⚠️ CHECKPOINT**: Do not proceed until both pings succeed.

---

## PART 1: System Preparation

### Block 1.1 - Update Package Lists

**Type**: EXECUTE

**Instructions**:
Run the following command:
```bash
sudo apt update
```

**What this does**:
- Updates the local package database
- Checks for available updates
- Contacts Ubuntu/Mint repositories

**Expected Output**:
```
Hit:1 http://packages.linuxmint.com virginia InRelease
Get:2 http://archive.ubuntu.com/ubuntu jammy InRelease [270 kB]
...
Reading package lists... Done
```

---

### Block 1.2 - Upgrade Installed Packages

**Type**: EXECUTE

**Instructions**:
```bash
sudo apt upgrade -y
```

**What this does**:
- Upgrades all installed packages
- `-y` automatically confirms installation
- May take 5-15 minutes

**Expected Behavior**:
- Lists packages to upgrade
- Downloads and installs updates
- May require 100-500 MB download

---

### Block 1.3 - Install Essential Tools

**Type**: EXECUTE

**Instructions**:
```bash
sudo apt install -y curl gnupg apt-transport-https software-properties-common
```

**Purpose of Each Tool**:
- `curl`: Download files from command line
- `gnupg`: GPG key management for package verification
- `apt-transport-https`: Enable HTTPS repository access
- `software-properties-common`: Manage software repositories

---

## PART 2: Install Elasticsearch

### Block 2.1 - Add Elastic GPG Key

**Type**: EXECUTE

**Instructions**:
```bash
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | \
sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
```

**What this does**:
- Downloads Elastic's official GPG signing key
- Converts it to binary format
- Stores in system keyring directory

**Purpose**: Verifies authenticity of Elastic packages.

---

### Block 2.2 - Verify GPG Key Installation

**Type**: VERIFY

**Instructions**:
```bash
gpg --no-default-keyring \
--keyring /usr/share/keyrings/elasticsearch-keyring.gpg \
--list-keys
```

**Expected Output**:
```
pub   rsa4096 2013-09-16 [SC]
      4609...
uid           [ unknown] Elasticsearch (Elasticsearch Signing Key) <dev_ops@elasticsearch.org>
sub   rsa4096 2013-09-16 [E]
```

---

### Block 2.3 - Add Elastic APT Repository

**Type**: EXECUTE

**Instructions**:
```bash
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" | \
sudo tee /etc/apt/sources.list.d/elastic-7.x.list
```

**What this does**:
- Adds Elastic's 7.x repository to APT sources
- Configures GPG key for package verification

---

### Block 2.4 - Update Package Lists with Elastic Repo

**Type**: EXECUTE

**Instructions**:
```bash
sudo apt update
```

**Verification**:
- Look for "elastic-7.x.list" in output
- Should see Elastic packages available

---

### Block 2.5 - Install Elasticsearch

**Type**: EXECUTE

**Instructions**:
```bash
sudo apt install -y elasticsearch
```

**What happens**:
- Downloads Elasticsearch (~500 MB)
- Installs to `/usr/share/elasticsearch`
- Creates `elasticsearch` system user
- Takes 3-5 minutes

---

### Block 2.6 - Enable Elasticsearch Service

**Type**: EXECUTE

**Instructions**:
```bash
sudo systemctl enable elasticsearch
```

**Purpose**: Ensures Elasticsearch starts automatically on system boot.

---

### Block 2.7 - Configure Elasticsearch

**Type**: MANUAL

**Instructions**:
1. Open configuration file:
```bash
sudo nano /etc/elasticsearch/elasticsearch.yml
```

2. Find and modify these lines (uncomment by removing `#`):
```yaml
network.host: 0.0.0.0
http.port: 9200
discovery.type: single-node
```

3. Save and exit:
   - Press `Ctrl+O` to save
   - Press `Enter` to confirm
   - Press `Ctrl+X` to exit

**Configuration Explained**:
- `network.host: 0.0.0.0`: Listen on all network interfaces
- `http.port: 9200`: Default Elasticsearch port
- `discovery.type: single-node`: Configure for standalone operation

**⚠️ Security Warning**: `0.0.0.0` allows connections from any IP. For labs only. Production should use firewall rules.

---

### Block 2.8 - Start Elasticsearch

**Type**: EXECUTE

**Instructions**:
```bash
sudo systemctl start elasticsearch
```

**Note**: First start may take 30-60 seconds.

---

### Block 2.9 - Verify Elasticsearch is Running

**Type**: VERIFY

**Instructions**:
1. Check service status:
```bash
sudo systemctl status elasticsearch --no-pager
```

**Expected Output**:
```
● elasticsearch.service - Elasticsearch
     Loaded: loaded (/lib/systemd/system/elasticsearch.service; enabled)
     Active: active (running) since [timestamp]
```

2. Test HTTP API:
```bash
curl -s http://localhost:9200
```

**Expected Output** (JSON):
```json
{
  "name" : "osboxes",
  "cluster_name" : "elasticsearch",
  "cluster_uuid" : "...",
  "version" : {
    "number" : "7.17.x",
    "build_type" : "deb",
    ...
  },
  "tagline" : "You Know, for Search"
}
```

**⚠️ CHECKPOINT**: Must see "active (running)" and JSON response before proceeding.

---

## PART 3: Install Logstash

### Block 3.1 - Install Logstash

**Type**: EXECUTE

**Instructions**:
```bash
sudo apt install -y logstash
```

**What happens**:
- Installs Logstash (~200-300 MB)
- Includes bundled JDK (no separate Java needed)
- Creates `logstash` system user
- Takes 2-3 minutes

---

### Block 3.2 - Enable Logstash Service

**Type**: EXECUTE

**Instructions**:
```bash
sudo systemctl enable logstash
sudo systemctl start logstash
```

---

### Block 3.3 - Verify Logstash Service

**Type**: VERIFY

**Instructions**:
```bash
sudo systemctl status logstash --no-pager
```

**Expected Output**:
```
● logstash.service - logstash
     Loaded: loaded
     Active: active (running)
```

**Note**: Logstash won't process data until we configure a pipeline.

---

## PART 4: Install Kibana

### Block 4.1 - Install Kibana

**Type**: EXECUTE

**Instructions**:
```bash
sudo apt install -y kibana
```

**Download size**: ~300 MB

---

### Block 4.2 - Enable Kibana Service

**Type**: EXECUTE

**Instructions**:
```bash
sudo systemctl enable kibana
sudo systemctl start kibana
```

---

### Block 4.3 - Configure Kibana

**Type**: MANUAL

**Instructions**:
1. Open configuration:
```bash
sudo nano /etc/kibana/kibana.yml
```

2. Find and modify:
```yaml
server.host: "0.0.0.0"
server.port: 5601
```

3. Save and exit: `Ctrl+O`, `Enter`, `Ctrl+X`

---

### Block 4.4 - Restart Kibana

**Type**: EXECUTE

**Instructions**:
```bash
sudo systemctl restart kibana
```

**Note**: Kibana takes 60-90 seconds to fully start.

---

### Block 4.5 - Verify Kibana is Running

**Type**: VERIFY

**Instructions**:
```bash
sudo systemctl status kibana --no-pager
```

**Expected**: `active (running)`

---

### Block 4.6 - Access Kibana Web Interface

**Type**: MANUAL

**Instructions**:
1. **From VM browser**:
   - Open Firefox or Chromium
   - Navigate to: `http://localhost:5601`

2. **From host browser** (Bridged networking only):
   - Find VM IP: `ip a | grep inet`
   - Navigate to: `http://<VM-IP>:5601`

**Expected**: Kibana welcome screen appears.

**⚠️ CHECKPOINT**: Kibana must be accessible before proceeding.

---

## PART 5: Configure SSH Logging

### Block 5.1 - Install OpenSSH Server

**Type**: EXECUTE

**Instructions**:
```bash
sudo apt install -y openssh-server
```

---

### Block 5.2 - Enable SSH Service

**Type**: EXECUTE

**Instructions**:
```bash
sudo systemctl enable ssh
sudo systemctl start ssh
```

---

### Block 5.3 - Verify SSH is Running

**Type**: VERIFY

**Instructions**:
```bash
sudo systemctl status ssh --no-pager
```

**Expected**: `active (running)`

---

### Block 5.4 - Configure Verbose SSH Logging

**Type**: MANUAL

**Instructions**:
1. Open SSH configuration:
```bash
sudo nano /etc/ssh/sshd_config
```

2. Find line with `LogLevel` (or add if missing):
```
LogLevel VERBOSE
```

3. Save and exit: `Ctrl+O`, `Enter`, `Ctrl+X`

**Purpose**: Captures detailed authentication attempts including source IPs.

---

### Block 5.5 - Restart SSH Service

**Type**: EXECUTE

**Instructions**:
```bash
sudo systemctl restart ssh
```

---

### Block 5.6 - Generate Test Failed Login Attempts

**Type**: MANUAL

**Instructions**:
1. Run SSH command:
```bash
ssh invaliduser@localhost
```

2. When prompted for password, enter any random text
3. Press Enter (connection will be denied)
4. Repeat 5-10 times

**Expected Behavior**:
```
invaliduser@localhost's password: 
Permission denied, please try again.
```

---

### Block 5.7 - Verify Logs are Generated

**Type**: VERIFY

**Instructions**:
```bash
sudo tail -n 50 /var/log/auth.log
```

**Expected Output** (example):
```
2026-01-18T06:19:39.115775-05:00 osboxes sshd[9232]: Failed password for invalid user invaliduser from 127.0.0.1 port 53876 ssh2
```

**Look for**: 
- `Failed password`
- `invalid user`
- IP addresses
- Timestamps

**⚠️ CHECKPOINT**: Confirm failed login entries exist.

---

## PART 6: Create Logstash Pipeline

### Block 6.1 - Create Logstash Configuration File

**Type**: MANUAL

**Instructions**:
1. Create new configuration:
```bash
sudo nano /etc/logstash/conf.d/ssh_logs.conf
```

2. Paste the following complete configuration:
```ruby
input {
  file {
    path => "/var/log/auth.log"
    start_position => "beginning"
    sincedb_path => "/var/lib/logstash/sincedb-authlog"
    type => "ssh_auth"
  }
}

filter {
  if [type] == "ssh_auth" {
    grok {
      match => {
        "message" => [
          "%{TIMESTAMP_ISO8601:auth_ts} %{HOSTNAME:host} sshd\[%{POSINT:sshd_pid}\]: Failed password for (invalid user )?%{USERNAME:ssh_user} from %{IP:ssh_src_ip} port %{POSINT:ssh_src_port} ssh2",
          "%{TIMESTAMP_ISO8601:auth_ts} %{HOSTNAME:host} sshd\[%{POSINT:sshd_pid}\]: Accepted password for %{USERNAME:ssh_user} from %{IP:ssh_src_ip} port %{POSINT:ssh_src_port} ssh2"
        ]
      }
      tag_on_failure => ["_grok_ssh_failed"]
    }

    date {
      match => ["auth_ts", "ISO8601"]
      target => "@timestamp"
    }
  }
}

output {
  elasticsearch {
    hosts => ["http://localhost:9200"]
    index => "ssh_logs-%{+YYYY.MM.dd}"
  }
  stdout { codec => rubydebug }
}
```

3. Save and exit: `Ctrl+O`, `Enter`, `Ctrl+X`

**Configuration Explained**:

**Input Section**:
- Reads from `/var/log/auth.log`
- `start_position: beginning`: Process entire file
- `sincedb_path`: Tracks read position
- `type: ssh_auth`: Label for filtering

**Filter Section**:
- **grok**: Parses log lines using patterns
- Extracts: timestamp, hostname, PID, username, IP, port
- **date**: Converts timestamp to `@timestamp` field

**Output Section**:
- Sends to Elasticsearch on `localhost:9200`
- Creates daily indices: `ssh_logs-YYYY.MM.DD`
- Also outputs to stdout for debugging

---

### Block 6.2 - Create Sincedb Directory

**Type**: EXECUTE

**Instructions**:
```bash
sudo mkdir -p /var/lib/logstash
sudo chown -R logstash:logstash /var/lib/logstash
```

**Purpose**: Logstash tracks file read positions in sincedb files.

---

### Block 6.3 - Grant Logstash Access to Auth Logs (CRITICAL)

**Type**: EXECUTE

**Instructions**:
```bash
sudo usermod -aG adm logstash
```

**Why this is needed**:
- `/var/log/auth.log` is readable by group `adm`
- Logstash user must be in `adm` group to read the file
- Without this, Logstash silently fails to ingest logs

---

### Block 6.4 - Restart Logstash Service

**Type**: EXECUTE

**Instructions**:
```bash
sudo systemctl restart logstash
```

---

### Block 6.5 - Verify Logstash Service

**Type**: VERIFY

**Instructions**:
```bash
sudo systemctl status logstash --no-pager
```

**Expected**: `active (running)`

---

### Block 6.6 - Test Pipeline Configuration (Optional)

**Type**: VERIFY

**Instructions**:
```bash
sudo /usr/share/logstash/bin/logstash \
  --path.settings /etc/logstash \
  -f /etc/logstash/conf.d/ssh_logs.conf \
  --config.test_and_exit
```

**Expected Output** (end of output):
```
Configuration OK
[INFO] Using config.test_and_exit mode. Config Validation Result: OK. Exiting Logstash
```

---

### Block 6.7 - Generate Fresh Failed Login Attempts

**Type**: MANUAL

**Instructions**:
Create new log entries for Logstash to process:
```bash
ssh invaliduser@localhost
ssh invaliduser@localhost
ssh invaliduser@localhost
```

Enter wrong passwords each time.

**Wait 30 seconds** for Logstash to process.

---

### Block 6.8 - Verify Elasticsearch Index Created

**Type**: VERIFY

**Instructions**:
```bash
curl -s http://localhost:9200/_cat/indices?v | grep ssh_logs
```

**Expected Output**:
```
yellow open ssh_logs-2026.01.18 ABC123 1 1 423 0 132.3kb 132.3kb
```

**Status Meanings**:
- **green**: All primary and replica shards active
- **yellow**: Primary shards active, replicas not allocated (normal for single-node)
- **red**: Some primary shards not active (problem)

---

### Block 6.9 - Fix Yellow Index Status (Optional)

**Type**: EXECUTE

**Instructions**:
For single-node clusters, set replicas to 0:
```bash
curl -s -X PUT "http://localhost:9200/ssh_logs-*/_settings" \
  -H 'Content-Type: application/json' \
  -d '{"index":{"number_of_replicas":0}}'
```

**Verify**:
```bash
curl -s http://localhost:9200/_cat/indices?v | grep ssh_logs
```

**Expected**: Status changes to `green`.

---

## PART 7: Kibana - Search and Analysis

### Block 7.1 - Create Index Pattern

**Type**: MANUAL

**Instructions**:
1. Open Kibana: `http://localhost:5601`
2. Click menu icon (≡) → **Stack Management**
3. Under "Kibana" section → **Index Patterns**
4. Click **Create index pattern**
5. Index pattern name: `ssh_logs*`
6. Click **Next step**
7. Time field: Select `@timestamp`
8. Click **Create index pattern**

**Success**: "Index pattern created" message appears.

---

### Block 7.2 - Navigate to Discover

**Type**: MANUAL

**Instructions**:
1. Click menu icon (≡)
2. Under "Analytics" → Click **Discover**
3. Top-left dropdown: Ensure `ssh_logs*` is selected
4. Time picker (top-right): Set to **Last 24 hours**

**Expected**: Log documents appear in timeline and table.

---

### Block 7.3 - Search for Failed Login Attempts

**Type**: MANUAL

**Instructions**:
1. In Discover search bar, enter:
```
message : "Failed password"
```
2. Press **Enter** or click **Update**

**Expected Result**: Only failed login documents displayed.

---

### Block 7.4 - Inspect Document Fields

**Type**: MANUAL

**Instructions**:
1. Click `>` arrow next to any document to expand
2. Review extracted fields:
   - `@timestamp`: Event time
   - `ssh_src_ip`: Source IP address
   - `ssh_user`: Username attempted
   - `ssh_src_port`: Source port
   - `host`: Server hostname
   - `message`: Original log line

**Verification**: All fields should be populated correctly.

---

### Block 7.5 - Adjust Time Range if No Results

**Type**: MANUAL

**Instructions**:
If no documents appear:
1. Click time picker (top-right)
2. Select **Last 7 days** or **Last 30 days**
3. Or click **Absolute** and set custom range

---

## PART 8: Visualizations

### Block 8.1 - Create Bar Chart: Failed Attempts Over Time

**Type**: MANUAL

**Instructions**:

1. Menu (≡) → **Visualize Library**
2. Click **Create visualization**
3. Select **Aggregation based**
4. Choose **Vertical bar**
5. Data source: `ssh_logs*`

6. **Add Filter**:
   - Click **Add filter** (top)
   - Field: `message`
   - Query: `message : "Failed password"`
   - Click **Save**

7. **Configure X-Axis**:
   - Under **Buckets** → Click **Add**
   - Select **X-axis**
   - Aggregation: `Date Histogram`
   - Field: `@timestamp`
   - Minimum interval: `Auto`
   - Click **Update** button (▶ icon)

8. **Y-Axis** (automatic):
   - Aggregation: Count (default)

**Expected Result**: Bar chart showing failed attempts over time.

9. **Save Visualization**:
   - Click **Save** (top-right)
   - Title: `SSH Failed Attempts Over Time`
   - Optional: Add to new dashboard
   - Click **Save**

---

### Block 8.2 - Create Top Source IPs Visualization

**Type**: MANUAL

**Instructions**:

1. **Visualize Library** → **Create visualization**
2. **Aggregation based** → **Vertical bar**
3. Data source: `ssh_logs*`

4. **Add Filter**:
   - `message : "Failed password"`

5. **Configure X-Axis**:
   - Buckets → Add → X-axis
   - Aggregation: `Terms`
   - Field: `ssh_src_ip` or `ssh_src_ip.keyword`
   - Size: `10` (show top 10 IPs)
   - Click **Update**

**Expected Result**: Bar chart showing which IPs generated most failures.

6. **Save**:
   - Title: `Top SSH Attack Source IPs`
   - Click **Save**

---

## PART 9: Alerting

### Block 9.1 - Add Encryption Key to Kibana

**Type**: MANUAL

**Instructions**:
1. Open Kibana configuration:
```bash
sudo nano /etc/kibana/kibana.yml
```

2. Add anywhere in file:
```yaml
xpack.encryptedSavedObjects.encryptionKey: "shortkey123"
```

3. Save and exit: `Ctrl+O`, `Enter`, `Ctrl+X`

**Security Note**: 
- "shortkey123" is for lab purposes only
- Production requires 32+ character random string

---

### Block 9.2 - Restart Kibana

**Type**: EXECUTE

**Instructions**:
```bash
sudo systemctl restart kibana
```

**Wait**: 60-90 seconds for Kibana to restart.

---

### Block 9.3 - Verify Kibana Restarted

**Type**: VERIFY

**Instructions**:
```bash
sudo systemctl status kibana --no-pager
```

**Expected**: `active (running)`

**Refresh browser** at `http://localhost:5601`

---

### Block 9.4 - Create Brute Force Detection Rule

**Type**: MANUAL

**Instructions**:

1. Kibana → **Stack Management** → **Rules and Connectors**
2. Click **Create rule**

3. **Configure Rule**:
   
   **Basic Information**:
   - Name: `SSH Brute Force Detection`
   - Check every: `1 minute`
   - Notify: `Only on status change`

   **Rule Type**:
   - Select: `Index threshold`

   **Define Rule**:
   - Index: `ssh_logs*`
   - Time field: `@timestamp`
   - WHEN: `count()`
   - OVER: `all documents`
   - IS ABOVE: `50`
   - FOR THE LAST: `5 minutes`

4. Click **Save**

**What this does**: 
- Checks every minute
- Triggers alert if >50 SSH events in 5 minutes
- Indicates potential brute-force attack

---

### Block 9.5 - Test Alert (Optional)

**Type**: MANUAL

**Instructions**:
Generate many failed attempts quickly:
```bash
for i in {1..60}; do 
  ssh invaliduser@localhost
done
```

Press `Ctrl+C` after several attempts.

**Check alert status**:
- Stack Management → Rules and Connectors
- View rule status

---

## PART 10: Additional Analysis

### Block 10.1 - Create Dashboard

**Type**: MANUAL

**Instructions**:
1. Menu (≡) → **Dashboard**
2. Click **Create new dashboard**
3. Click **Add from library**
4. Select your saved visualizations:
   - SSH Failed Attempts Over Time
   - Top SSH Attack Source IPs
5. Click **Add**
6. Arrange panels on dashboard
7. Click **Save**
8. Title: `SSH Security Monitoring`

---

### Block 10.2 - Analyze Attack Patterns

**Type**: MANUAL

**Instructions**:
In Discover, create searches to identify:

**1. Failed Root Login Attempts**:
```
ssh_user: root AND message: "Failed password"
```

**2. Multiple Failures from Same IP**:
- Use Top Source IPs visualization
- Look for IPs with high counts

**3. Unusual Login Times**:
- Use time-based filters
- Check for attempts outside business hours

---

## Troubleshooting Guide

### Problem 1: "Unable to locate package" Errors

**Symptoms**:
```
E: Unable to locate package elasticsearch
E: Unable to locate package openjdk-17-jdk
```

**Cause**: Missing or incomplete APT repositories.

**Solution**:
```bash
# Check current repos
grep -R "^deb " /etc/apt/sources.list /etc/apt/sources.list.d/

# If Ubuntu repos missing, restore them
sudo tee /etc/apt/sources.list >/dev/null <<'EOF'
deb http://archive.ubuntu.com/ubuntu jammy main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu jammy-updates main restricted universe multiverse
deb http://security.ubuntu.com/ubuntu jammy-security main restricted universe multiverse
EOF

sudo apt update
```

---

### Problem 2: Logstash Not Creating Index

**Symptoms**:
- Logstash running but no `ssh_logs-*` index in Elasticsearch

**Common Causes**:
1. **File permissions** (most common)
2. **Elasticsearch not reachable**
3. **No new log events generated**

**Solution**:
```bash
# Check Logstash can read auth.log
ls -la /var/log/auth.log
id logstash

# Add logstash to adm group if not already
sudo usermod -aG adm logstash
sudo systemctl restart logstash

# Generate new test events
ssh invaliduser@localhost  # Repeat 5 times

# Wait 30 seconds, then check
curl -s http://localhost:9200/_cat/indices?v | grep ssh_logs
```

---

### Problem 3: Kibana Shows No Data

**Symptoms**:
- "No results found" in Discover

**Solutions**:

**A. Check Time Range**:
- Expand to Last 7 days or Last 30 days

**B. Verify Index Exists**:
```bash
curl -s http://localhost:9200/_cat/indices?v | grep ssh_logs
```

**C. Check Document Count**:
```bash
curl -s http://localhost:9200/ssh_logs-*/_count
```

If count is 0, go back to Problem 2.

---

### Problem 4: Service Won't Start

**Symptoms**:
```
● elasticsearch.service - Elasticsearch
     Active: failed (Result: exit-code)
```

**Solution**:
```bash
# View detailed logs
sudo journalctl -u elasticsearch -n 100 --no-pager

# Common issues:
# - Port already in use
# - Insufficient memory
# - Configuration syntax error

# Check config syntax
sudo /usr/share/elasticsearch/bin/elasticsearch --version

# Check port availability
sudo netstat -tulpn | grep 9200
```

---

### Problem 5: Grok Pattern Not Matching

**Symptoms**:
- Documents have `_grok_ssh_failed` tag
- Fields not extracted (ssh_src_ip, ssh_user missing)

**Solution**:
1. Check log format in `/var/log/auth.log`
2. Verify timestamp format matches pattern
3. Test pattern at: https://grokdebugger.com/

**Example log formats**:
- ISO8601: `2026-01-18T06:19:39.115775-05:00`
- Syslog: `Jan 18 06:19:39`

Adjust grok pattern accordingly.

---

### Problem 6: Yellow Index Status

**Symptoms**:
```
yellow open ssh_logs-2026.01.18 ...
```

**Cause**: Replicas cannot be allocated on single-node cluster.

**Solution**:
```bash
curl -s -X PUT "http://localhost:9200/ssh_logs-*/_settings" \
  -H 'Content-Type: application/json' \
  -d '{"index":{"number_of_replicas":0}}'
```

---

### Problem 7: Cannot Access Kibana from Host

**Symptoms**:
- Kibana works on VM (`localhost:5601`)
- Doesn't work from host browser

**Solution**:

**A. Check Kibana Config**:
```bash
sudo grep server.host /etc/kibana/kibana.yml
# Should show: server.host: "0.0.0.0"
```

**B. Check VM IP**:
```bash
ip a | grep inet
```

**C. Verify Network Mode**:
- VirtualBox → VM Settings → Network
- Should be Bridged Adapter (not NAT)

**D. Test from VM first**:
```bash
curl -s http://localhost:5601/api/status
```

---

## Summary and Next Steps

### What You Accomplished

✅ **Installed complete ELK Stack**:
- Elasticsearch (search engine)
- Logstash (data pipeline)
- Kibana (visualization)

✅ **Configured security logging**:
- SSH verbose logging
- Failed login capture

✅ **Created data pipeline**:
- Log ingestion from `/var/log/auth.log`
- Grok parsing for field extraction
- Elasticsearch indexing

✅ **Built analytics**:
- Interactive search in Discover
- Time-series visualizations
- Top attacker IP analysis
- Brute-force detection alerts

---

### Key Concepts Learned

1. **SIEM Architecture**: Collection → Parsing → Storage → Analysis
2. **Log Management**: Centralized logging for security monitoring
3. **Data Pipeline**: Structured approach to log processing
4. **Security Analytics**: Detecting attack patterns
5. **Incident Detection**: Automated alerting for threats

---

### Real-World Applications

This lab simulates:
- **Enterprise SIEM**: How organizations monitor thousands of systems
- **Threat Hunting**: Searching for indicators of compromise
- **Incident Response**: Detecting and investigating security events
- **Compliance**: Logging requirements for regulations (PCI DSS, HIPAA, SOC 2)

---

### Enhancements and Extensions

#### 1. Add More Log Sources

**Firewall Logs**:
```ruby
input {
  file {
    path => "/var/log/ufw.log"
    type => "firewall"
  }
}
```

**Web Server Logs**:
```ruby
input {
  file {
    path => "/var/log/apache2/access.log"
    type => "apache_access"
  }
}
```

---

#### 2. Enable GeoIP Enrichment

Add to Logstash filter:
```ruby
geoip {
  source => "ssh_src_ip"
  target => "geoip"
}
```

**Benefit**: Map attacker locations on world map in Kibana.

---

#### 3. Implement Automated Response

**Install fail2ban**:
```bash
sudo apt install -y fail2ban
```

**Configure to ban IPs after failed attempts**:
```bash
sudo nano /etc/fail2ban/jail.local
```
```ini
[sshd]
enabled = true
maxretry = 5
bantime = 3600
```

---

#### 4. Add Additional Visualizations

**Heatmap**: Login attempts by hour of day
**Pie Chart**: Success vs failed logins
**Data Table**: Top targeted usernames
**Metric**: Total login attempts today

---

#### 5. Configure Email Alerts

In Kibana rule configuration:
1. Add Connector → Email
2. Configure SMTP settings
3. Attach to brute-force rule

---

### Production Considerations

#### Security Hardening

1. **Enable Elasticsearch Security**:
```yaml
xpack.security.enabled: true
xpack.security.transport.ssl.enabled: true
```

2. **Configure TLS/SSL**:
- Generate certificates
- Enable HTTPS for Kibana
- Encrypt Elasticsearch transport

3. **Implement Authentication**:
- User accounts with passwords
- Role-based access control (RBAC)
- Integration with LDAP/Active Directory

4. **Network Security**:
- Firewall rules (only allow necessary ports)
- VPN access for remote monitoring
- Network segmentation

---

#### Scalability

**Multi-node Elasticsearch Cluster**:
```yaml
cluster.name: production-elk
node.name: node-1
discovery.seed_hosts: ["node-1", "node-2", "node-3"]
cluster.initial_master_nodes: ["node-1", "node-2", "node-3"]
```

**Logstash Pipeline Scaling**:
- Multiple Logstash instances
- Kafka for buffering
- Redis for queuing

**Kibana Load Balancing**:
- Multiple Kibana instances
- Nginx/HAProxy frontend

---

### Additional Resources

#### Official Documentation

- **Elastic Stack**: https://www.elastic.co/guide/index.html
- **Elasticsearch Reference**: https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html
- **Logstash Reference**: https://www.elastic.co/guide/en/logstash/current/index.html
- **Kibana Guide**: https://www.elastic.co/guide/en/kibana/current/index.html

#### Community Resources

- **Elastic Forums**: https://discuss.elastic.co/
- **GitHub**: https://github.com/elastic
- **Blog**: https://www.elastic.co/blog

#### Related Tools

- **Beats**: Lightweight data shippers
  - Filebeat: Log files
  - Metricbeat: System metrics
  - Packetbeat: Network traffic
  - Winlogbeat: Windows event logs

- **Wazuh**: Open-source XDR/SIEM
  - Host-based intrusion detection
  - File integrity monitoring
  - Integrates with ELK

---

### Practice Exercises

#### Exercise 1: Custom Dashboard
Create a comprehensive security dashboard with:
- Total events today (Metric)
- Failed logins timeline (Line chart)
- Top IPs (Bar chart)
- Geographic map (if GeoIP enabled)
- Recent events table (Data table)

#### Exercise 2: Advanced Searches
Practice KQL queries:
```
# Multiple conditions
ssh_user: (root OR admin) AND message: "Failed"

# IP range
ssh_src_ip: 192.168.1.0/24

# Time-based
@timestamp >= "now-1h"

# Wildcards
ssh_user: admin*
```

#### Exercise 3: Alert Tuning
Modify brute-force rule:
- Different thresholds (10, 25, 100 attempts)
- Shorter time windows (1 min, 2 min)
- Specific usernames (root, admin)

#### Exercise 4: Log Sources
Add another log source:
- Apache/Nginx access logs
- Sudo command logs (`/var/log/auth.log`)
- System logs (`/var/log/syslog`)

---

### Assessment Questions

1. **Conceptual**:
   - What is the purpose of each ELK component?
   - Why is centralized logging important for security?
   - How does the IR lifecycle apply to this lab?

2. **Technical**:
   - What does the grok filter do?
   - Why must Logstash be in the `adm` group?
   - What does "yellow" index status indicate?

3. **Analytical**:
   - How would you identify a distributed brute-force attack?
   - What patterns indicate credential stuffing vs. brute-force?
   - How could you correlate failed logins with successful ones?

4. **Practical**:
   - How would you investigate a specific IP address?
   - What query finds all successful root logins?
   - How do you export search results?

---

### Lab Completion Checklist

- [ ] Linux Mint VM installed and running
- [ ] Internet connectivity verified
- [ ] Elasticsearch installed and accessible
- [ ] Logstash installed and configured
- [ ] Kibana installed and accessible via browser
- [ ] SSH server configured with verbose logging
- [ ] Logstash pipeline created and tested
- [ ] Failed login events visible in Elasticsearch
- [ ] Index pattern created in Kibana
- [ ] Discover shows SSH log documents
- [ ] Failed password search filter works
- [ ] Bar chart visualization created
- [ ] Top IPs visualization created
- [ ] Dashboard created with visualizations
- [ ] Brute-force alert rule configured
- [ ] Alert tested successfully

---

### Conclusion

This lab provided hands-on experience with:
- **Setting up a SIEM**: From OS installation to full ELK deployment
- **Log management**: Collection, parsing, and indexing
- **Security analytics**: Searching and visualizing threats
- **Incident detection**: Automated alerting for attacks

These skills are directly applicable to:
- **Security Operations Center (SOC)** roles
- **Incident Response** positions
- **Security Engineering** careers
- **DevSecOps** practices

The ELK Stack is used by organizations worldwide for:
- Security information and event management (SIEM)
- Application performance monitoring (APM)
- Log analytics and troubleshooting
- Business intelligence and metrics

Continue practicing with real-world scenarios and explore advanced features to deepen your expertise in security monitoring and incident response.

---

**End of Week 09 Tutorial**
