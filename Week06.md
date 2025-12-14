# pfSense Complete Lab Guide
## Network Segmentation & OpenVPN Remote Access

---

## 📑 Table of Contents

1. [Lab 1: Network Segmentation - LOCAL and GUEST Networks](#lab-1-network-segmentation)
   - Prerequisites
   - Network Architecture
   - Step-by-Step Configuration
   - Testing and Verification
   - Troubleshooting

2. [Lab 2: OpenVPN Remote Access for Contractors](#lab-2-openvpn-remote-access)
   - Prerequisites
   - VPN Architecture
   - Step-by-Step Configuration
   - Client Setup
   - Testing and Verification
   - Troubleshooting

3. [Appendices](#appendices)
   - Quick Reference Tables
   - Common Commands
   - Additional Resources

---

# Lab 1: Network Segmentation

## Creating Isolated LOCAL and GUEST Networks

---

## 🎯 Lab 1 Objectives

By the end of this lab, you will:
- Configure pfSense with separate LOCAL (Employee) and GUEST networks
- Implement network isolation using firewall rules
- Enable internet access for both networks
- Test connectivity and isolation between networks

---

## 📋 Lab 1 Prerequisites

- VirtualBox installed
- pfSense VM already set up with:
  - WAN interface (NAT for internet)
  - LAN interface (for internal networks)
- At least one test VM (Kali Linux or similar)
- Basic understanding of IP addressing and subnetting

---

## 🏗️ Lab 1 Network Architecture

```
Internet
   |
  WAN (NAT - 10.0.2.15/24)
   |
pfSense VM
   |
   ├── LOCAL Network (192.168.10.0/24)
   |   └── Employee devices
   |   └── Full access to internal resources
   |   └── Internet access
   |
   └── GUEST Network (192.168.20.0/24)
       └── Guest devices
       └── Internet access ONLY
       └── Blocked from LOCAL network
```

---

## 📝 Lab 1: Step-by-Step Configuration

### Step 1: Create Internal Networks in VirtualBox

#### 1.1 Configure pfSense VM Network Adapters

**⚠️ IMPORTANT:** Shut down pfSense VM completely before making these changes.

1. In VirtualBox Manager, select your pfSense VM
2. Click **Settings** → **Network**
3. Configure each adapter as follows:

**Adapter 1 (WAN) - Internet Connection:**

| Setting | Value |
|---------|-------|
| Enable Network Adapter | ☑️ Checked |
| Attached to | NAT |
| Adapter Type | Intel PRO/1000 MT Desktop (82540EM) |
| Promiscuous Mode | Deny |
| Cable Connected | ☑️ Checked |

**Adapter 2 (LOCAL) - Employee Network:**

| Setting | Value |
|---------|-------|
| Enable Network Adapter | ☑️ Checked |
| Attached to | Internal Network |
| Name | `Local` |
| Adapter Type | Intel PRO/1000 MT Desktop (82540EM) |
| Promiscuous Mode | **Allow All** ⚠️ |
| Cable Connected | ☑️ Checked |

**Adapter 3 (GUEST) - Guest Network:**

| Setting | Value |
|---------|-------|
| Enable Network Adapter | ☑️ Checked |
| Attached to | Internal Network |
| Name | `GUESTS_NET` |
| Adapter Type | Intel PRO/1000 MT Desktop (82540EM) |
| Promiscuous Mode | **Allow All** ⚠️ |
| Cable Connected | ☑️ Checked |

> **⚠️ CRITICAL SETTING:** 
> - Promiscuous Mode MUST be "Allow All" on Adapters 2 & 3
> - This is required for DHCP broadcasts and proper routing in VirtualBox
> - Without this, DHCP will fail and VMs won't get IP addresses

4. Click **OK** to save settings
5. Start pfSense VM

#### 1.2 Wait for pfSense to Boot

Wait approximately 1-2 minutes for pfSense to fully start and detect all network interfaces.

---

### Step 2: Access pfSense Web Interface

#### 2.1 Determine Access Method

**Option A: From Host Machine (if you have a VM on default LAN)**
- Navigate to: `http://192.168.1.1`

**Option B: From pfSense Console**
- You can configure interfaces from the console menu if needed

#### 2.2 Login to pfSense

| Field | Value |
|-------|-------|
| Username | `admin` |
| Password | `pfsense` |

> **⚠️ SECURITY WARNING:** Change the default password immediately after logging in:
> - Go to **System → User Manager → Users → admin → Edit**
> - Set a strong password
> - Save changes

---

### Step 3: Assign Interfaces in pfSense

#### 3.1 Navigate to Interface Assignments

1. Click **Interfaces** in top menu
2. Select **Assignments**

#### 3.2 View Current Interface Assignments

You should see:
- **WAN** → em0 (or similar)
- **LAN** → em1 (or similar)
- Available interfaces: em2, em3, etc.

#### 3.3 Add New Interfaces

1. For the first available interface (will become LOCAL):
   - Click **+ Add**
   - You'll see "OPT1" added

2. For the second available interface (will become GUEST):
   - Click **+ Add** again
   - You'll see "OPT2" added

3. Click **Save**

You should now have:
- WAN (em0)
- LAN (em1)
- OPT1 (em2) - will be LOCAL
- OPT2 (em3) - will be GUEST

---

### Step 4: Configure LOCAL Interface

#### 4.1 Navigate to LOCAL Interface Settings

1. Click **Interfaces** menu
2. Select **OPT1**

#### 4.2 Configure General Settings

| Field | Value | Notes |
|-------|-------|-------|
| **Enable** | ☑️ Enable interface | Must be checked |
| **Description** | `LOCAL` | This name will appear in menus |
| **IPv4 Configuration Type** | Static IPv4 | Select from dropdown |
| **IPv6 Configuration Type** | None | Unless IPv6 is required |

#### 4.3 MAC Address and MTU Settings

| Field | Value | Notes |
|-------|-------|-------|
| **MAC Address** | (Leave blank) | Auto-detected |
| **MTU** | (Leave blank) | Default 1500 bytes |
| **MSS** | (Leave blank) | Default |
| **Speed and Duplex** | Autoselect | Do not force speed |

#### 4.4 Static IPv4 Configuration

| Field | Value |
|-------|-------|
| **IPv4 Address** | `192.168.10.1` |
| **Subnet Mask** | `/24` (255.255.255.0) |
| **IPv4 Upstream Gateway** | None |

> **⚠️ IMPORTANT:** 
> - Do NOT select a gateway
> - Gateway selection makes pfSense treat this as a WAN interface
> - This is a LAN interface, so gateway must be "None"

#### 4.5 Reserved Networks Settings

| Field | Value | Notes |
|-------|-------|-------|
| **Block private networks** | ❌ Unchecked | Required for internal network |
| **Block bogon networks** | ❌ Unchecked | Only use on WAN |

> **Note:** These options should ONLY be enabled on WAN interfaces. Enabling them on internal interfaces will block legitimate traffic.

#### 4.6 Save Configuration

1. Scroll to bottom
2. Click **Save**
3. Click **Apply Changes** when prompted

---

### Step 5: Configure GUEST Interface

#### 5.1 Navigate to GUEST Interface Settings

1. Click **Interfaces** menu
2. Select **OPT2**

#### 5.2 Configure General Settings

| Field | Value | Notes |
|-------|-------|-------|
| **Enable** | ☑️ Enable interface | Must be checked |
| **Description** | `GUEST` | This name will appear in menus |
| **IPv4 Configuration Type** | Static IPv4 | Select from dropdown |
| **IPv6 Configuration Type** | None | Unless IPv6 is required |

#### 5.3 MAC Address and MTU Settings

| Field | Value | Notes |
|-------|-------|-------|
| **MAC Address** | (Leave blank) | Auto-detected |
| **MTU** | (Leave blank) | Default 1500 bytes |
| **MSS** | (Leave blank) | Default |
| **Speed and Duplex** | Autoselect | Do not force speed |

#### 5.4 Static IPv4 Configuration

| Field | Value |
|-------|-------|
| **IPv4 Address** | `192.168.20.1` |
| **Subnet Mask** | `/24` (255.255.255.0) |
| **IPv4 Upstream Gateway** | None |

#### 5.5 Reserved Networks Settings

| Field | Value | Notes |
|-------|-------|-------|
| **Block private networks** | ❌ Unchecked | Required for internal network |
| **Block bogon networks** | ❌ Unchecked | Only use on WAN |

#### 5.6 Save Configuration

1. Scroll to bottom
2. Click **Save**
3. Click **Apply Changes** when prompted

---

### Step 6: Configure DHCP Server for LOCAL Network

#### 6.1 Navigate to DHCP Server

1. Click **Services** in top menu
2. Select **DHCP Server**
3. Click on **LOCAL** tab

#### 6.2 Configure DHCP Backend

| Field | Value | Notes |
|-------|-------|-------|
| **DHCP Backend** | ISC DHCP | Default, will be migrated to Kea in future |

#### 6.3 Enable DHCP

| Field | Value | Notes |
|-------|-------|-------|
| **Enable** | ☑️ Enable DHCP server on LOCAL interface | Must be checked |
| **BOOTP** | ☑️ Ignore BOOTP queries | Recommended |
| **Deny Unknown Clients** | Allow all clients | Default setting |
| **Ignore Denied Clients** | ❌ Unchecked | Not needed |
| **Ignore Client Identifiers** | ❌ Unchecked | Not needed |

#### 6.4 Primary Address Pool Configuration

| Field | Value | Notes |
|-------|-------|-------|
| **Subnet** | `192.168.10.0/24` | Auto-detected from interface |
| **Subnet Range** | `192.168.10.1 - 192.168.10.254` | Available range |
| **Address Pool Range - From** | `192.168.10.100` | Start of DHCP range |
| **Address Pool Range - To** | `192.168.10.200` | End of DHCP range |

> **Note:** This gives 101 addresses for DHCP clients (100-200 inclusive), while reserving 1-99 for static assignments.

#### 6.5 Server Options

| Field | Value | Notes |
|-------|-------|-------|
| **WINS Servers** | (Leave blank) | Not commonly needed |
| **DNS Servers** | (Leave blank) | pfSense will act as DNS forwarder |

#### 6.6 Other DHCP Options

| Field | Value | Notes |
|-------|-------|-------|
| **Gateway** | (Leave blank) | Uses interface IP (192.168.10.1) |
| **Domain Name** | (Leave blank) | Optional |
| **Domain Search List** | (Leave blank) | Optional |
| **Default Lease Time** | `7200` | 2 hours (7200 seconds) |
| **Maximum Lease Time** | `86400` | 24 hours (86400 seconds) |
| **Failover peer IP** | (Leave blank) | Not using HA |

#### 6.7 Additional Options (Leave Defaults)

| Field | Value |
|-------|-------|
| **Static ARP** | ❌ Unchecked |
| **Time format change** | ❌ Unchecked |
| **Statistics graphs** | ❌ Unchecked |
| **Ping check** | ❌ Leave enabled (default) |

#### 6.8 Save DHCP Configuration

1. Scroll to bottom
2. Click **Save**

---

### Step 7: Configure DHCP Server for GUEST Network

#### 7.1 Navigate to GUEST DHCP Tab

1. Ensure you're still in **Services → DHCP Server**
2. Click on **GUEST** tab

#### 7.2 Configure DHCP Backend

| Field | Value | Notes |
|-------|-------|-------|
| **DHCP Backend** | ISC DHCP | Same as LOCAL |

#### 7.3 Enable DHCP

| Field | Value | Notes |
|-------|-------|-------|
| **Enable** | ☑️ Enable DHCP server on GUEST interface | Must be checked |
| **BOOTP** | ☑️ Ignore BOOTP queries | Recommended |
| **Deny Unknown Clients** | Allow all clients | Default for guest network |
| **Ignore Denied Clients** | ❌ Unchecked | Not needed |
| **Ignore Client Identifiers** | ❌ Unchecked | Not needed |

#### 7.4 Primary Address Pool Configuration

| Field | Value | Notes |
|-------|-------|-------|
| **Subnet** | `192.168.20.0/24` | Auto-detected from interface |
| **Subnet Range** | `192.168.20.1 - 192.168.20.254` | Available range |
| **Address Pool Range - From** | `192.168.20.100` | Start of DHCP range |
| **Address Pool Range - To** | `192.168.20.200` | End of DHCP range |

#### 7.5 Server Options

| Field | Value | Notes |
|-------|-------|-------|
| **WINS Servers** | (Leave blank) | Not needed |
| **DNS Servers** | Optional: `8.8.8.8`, `1.1.1.1` | Public DNS for guests (optional) |

> **Note:** You can specify public DNS servers for guests, or leave blank to use pfSense's DNS forwarder.

#### 7.6 Other DHCP Options

| Field | Value | Notes |
|-------|-------|-------|
| **Gateway** | (Leave blank) | Uses interface IP (192.168.20.1) |
| **Domain Name** | (Leave blank) | Not needed for guests |
| **Domain Search List** | (Leave blank) | Not needed for guests |
| **Default Lease Time** | `3600` | 1 hour (shorter for guests) |
| **Maximum Lease Time** | `86400` | 24 hours |
| **Failover peer IP** | (Leave blank) | Not using HA |

#### 7.7 Additional Options (Leave Defaults)

| Field | Value |
|-------|-------|
| **Static ARP** | ❌ Unchecked |
| **Time format change** | ❌ Unchecked |
| **Statistics graphs** | ❌ Unchecked |
| **Ping check** | ❌ Leave enabled (default) |

#### 7.8 Save DHCP Configuration

1. Scroll to bottom
2. Click **Save**

---

### Step 8: Configure Firewall Rules for LOCAL Network

#### 8.1 Navigate to Firewall Rules

1. Click **Firewall** in top menu
2. Select **Rules**
3. Click on **LOCAL** tab

#### 8.2 Create Allow All Rule for LOCAL

1. Click **↑ Add** (add button at top - creates rule at top of list)

#### 8.3 Configure Rule Fields

**Action and Basic Settings:**

| Field | Value | Notes |
|-------|-------|-------|
| **Action** | Pass | Allow traffic |
| **Disabled** | ❌ Unchecked | Rule is active |
| **Interface** | LOCAL | Auto-selected |
| **Address Family** | IPv4 | For IPv4 traffic |
| **Protocol** | Any | All protocols (TCP, UDP, ICMP, etc.) |

**Source Configuration:**

| Field | Value | Notes |
|-------|-------|-------|
| **Source** | LOCAL net | Select from dropdown |
| **Invert match** | ❌ Unchecked | Do not invert |
| **Source Port Range** | Any | Any source port |

**Destination Configuration:**

| Field | Value | Notes |
|-------|-------|-------|
| **Destination** | Any | Any destination |
| **Invert match** | ❌ Unchecked | Do not invert |
| **Destination Port Range - From** | Any | Any port |
| **Destination Port Range - To** | Any | Any port |

**Extra Options:**

| Field | Value | Notes |
|-------|-------|-------|
| **Log** | ❌ Unchecked | Optional - check if troubleshooting |
| **Description** | `Allow LOCAL network full access` | Descriptive text |

#### 8.4 Save Rule

1. Scroll to bottom
2. Click **Save**
3. Click **Apply Changes** when prompted

> **What this rule does:** Allows all devices on LOCAL network (192.168.10.0/24) to access any destination on any protocol. This gives employees full network access.

---

### Step 9: Configure Firewall Rules for GUEST Network

#### 9.1 Navigate to GUEST Firewall Tab

1. Ensure you're still in **Firewall → Rules**
2. Click on **GUEST** tab

> **⚠️ CRITICAL: Rule Order Matters!**
> - pfSense evaluates rules from top to bottom
> - First matching rule wins
> - Block rule MUST be above Allow rule for proper isolation

#### 9.2 Create Block Rule (MUST BE FIRST)

##### Rule 1: Block GUEST → LOCAL

1. Click **↑ Add** (add at top)

**Action and Basic Settings:**

| Field | Value | Notes |
|-------|-------|-------|
| **Action** | Block | Block traffic |
| **Disabled** | ❌ Unchecked | Rule is active |
| **Interface** | GUEST | Auto-selected |
| **Address Family** | IPv4 | For IPv4 traffic |
| **Protocol** | Any | All protocols |

**Source Configuration:**

| Field | Value | Notes |
|-------|-------|-------|
| **Source** | GUEST net | Select from dropdown |
| **Invert match** | ❌ Unchecked | Do not invert |
| **Source Port Range** | Any | Any source port |

**Destination Configuration:**

| Field | Value | Notes |
|-------|-------|-------|
| **Destination** | LOCAL net | Select from dropdown |
| **Invert match** | ❌ Unchecked | Do not invert |
| **Destination Port Range - From** | Any | Any port |
| **Destination Port Range - To** | Any | Any port |

**Extra Options:**

| Field | Value | Notes |
|-------|-------|-------|
| **Log** | ☑️ Checked | Recommended - logs blocked attempts |
| **Description** | `Block GUEST access to LOCAL network` | Descriptive text |

2. Click **Save** (DO NOT apply changes yet)

#### 9.3 Create Allow Rule (MUST BE SECOND)

##### Rule 2: Allow GUEST → Internet

1. Click **↑ Add** (this will be placed below the block rule)

**Action and Basic Settings:**

| Field | Value | Notes |
|-------|-------|-------|
| **Action** | Pass | Allow traffic |
| **Disabled** | ❌ Unchecked | Rule is active |
| **Interface** | GUEST | Auto-selected |
| **Address Family** | IPv4 | For IPv4 traffic |
| **Protocol** | Any | All protocols |

**Source Configuration:**

| Field | Value | Notes |
|-------|-------|-------|
| **Source** | GUEST net | Select from dropdown |
| **Invert match** | ❌ Unchecked | Do not invert |
| **Source Port Range** | Any | Any source port |

**Destination Configuration:**

| Field | Value | Notes |
|-------|-------|-------|
| **Destination** | Any | Any destination |
| **Invert match** | ❌ Unchecked | Do not invert |
| **Destination Port Range - From** | Any | Any port |
| **Destination Port Range - To** | Any | Any port |

**Extra Options:**

| Field | Value | Notes |
|-------|-------|-------|
| **Log** | ❌ Unchecked | Optional |
| **Description** | `Allow GUEST internet access only` | Descriptive text |

2. Click **Save**
3. Click **Apply Changes**

#### 9.4 Verify Rule Order

After applying changes, your GUEST rules should appear in this order:

| # | Action | Source | Destination | Description |
|---|--------|--------|-------------|-------------|
| 1 | Block | GUEST net | LOCAL net | Block GUEST access to LOCAL network |
| 2 | Pass | GUEST net | Any | Allow GUEST internet access only |

> **How this works:**
> 1. Traffic from GUEST to LOCAL is blocked (rule 1)
> 2. All other traffic from GUEST is allowed (rule 2)
> 3. Result: GUEST can access internet but NOT LOCAL network

---

### Step 10: Configure NAT for Internet Access

#### 10.1 Navigate to NAT Configuration

1. Click **Firewall** in top menu
2. Select **NAT**
3. Click on **Outbound** tab

#### 10.2 Set Outbound NAT Mode

| Field | Value | Notes |
|-------|-------|-------|
| **Mode** | ☑️ Automatic outbound NAT rule generation | Recommended for most setups |

**What the modes mean:**

- **Automatic:** pfSense automatically creates NAT rules for all internal networks
- **Hybrid:** Automatic + manual rules (advanced)
- **Manual:** You create all rules manually (expert)
- **Disable:** No outbound NAT (breaks internet access)

#### 10.3 Save Configuration

1. Ensure "Automatic" is selected
2. Click **Save**
3. Click **Apply Changes**

#### 10.4 Verify Automatic Rules

After saving, you should see automatic rules listed:

| Interface | Source | NAT Address | Description |
|-----------|--------|-------------|-------------|
| WAN | 192.168.10.0/24 | WAN address | Auto created rule |
| WAN | 192.168.20.0/24 | WAN address | Auto created rule |

> **What this does:** Translates private IP addresses (192.168.10.x and 192.168.20.x) to the public WAN IP address when accessing the internet.

---

### Step 11: Configure Test VMs

#### 11.1 Configure VM for LOCAL Network

**Shut down your test VM completely**, then:

1. In VirtualBox Manager, select the test VM
2. Click **Settings**
3. Click **Network**
4. Select **Adapter 1**

**Adapter 1 Configuration:**

| Setting | Value | Notes |
|---------|-------|-------|
| **Enable Network Adapter** | ☑️ Checked | Must be enabled |
| **Attached to** | Internal Network | Select from dropdown |
| **Name** | `Local` | MUST match pfSense adapter name exactly |
| **Adapter Type** | Intel PRO/1000 MT Desktop | Default |
| **Promiscuous Mode** | Allow All | Required for proper operation |
| **Cable Connected** | ☑️ Checked | Must be checked |

5. Click **OK**

#### 11.2 Configure Additional VM for GUEST Network (Optional)

If you have a second VM to test GUEST network:

**Repeat above steps but use:**

| Setting | Value |
|---------|-------|
| **Name** | `GUESTS_NET` |

---

### Step 12: Test LOCAL Network

#### 12.1 Start LOCAL Network VM

1. Start your test VM
2. Wait for operating system to boot
3. Open terminal

#### 12.2 Check IP Address Assignment

**On Linux:**
```bash
ip addr show
# or
ifconfig
```

**On Windows:**
```cmd
ipconfig
```

**Expected Output:**
```
eth0: inet 192.168.10.xxx  netmask 255.255.255.0
      gateway 192.168.10.1
```

#### 12.3 If No IP Address is Assigned

**Try requesting DHCP manually:**

```bash
# Linux - try these in order:
sudo dhclient eth0
# or
sudo dhcpcd eth0
# or
sudo systemctl restart NetworkManager
nmcli connection up "Wired connection 1"
```

```cmd
# Windows:
ipconfig /release
ipconfig /renew
```

#### 12.4 Connectivity Tests for LOCAL Network

**Test 1: Ping LOCAL Gateway**
```bash
ping -c 4 192.168.10.1
```
Expected: ✅ Success (replies received)

**Test 2: Ping Internet (IP)**
```bash
ping -c 4 8.8.8.8
```
Expected: ✅ Success (proves routing and NAT work)

**Test 3: Ping Internet (DNS)**
```bash
ping -c 4 google.com
```
Expected: ✅ Success (proves DNS resolution works)

**Test 4: Ping GUEST Gateway (optional)**
```bash
ping -c 4 192.168.20.1
```
Expected: ✅ Success (LOCAL can access GUEST gateway by default)

---

### Step 13: Test GUEST Network

#### 13.1 Start GUEST Network VM

1. Start your second test VM (configured for GUESTS_NET)
2. Wait for OS to boot
3. Open terminal

#### 13.2 Check IP Address Assignment

```bash
ip addr show
```

**Expected Output:**
```
eth0: inet 192.168.20.xxx  netmask 255.255.255.0
      gateway 192.168.20.1
```

#### 13.3 Connectivity Tests for GUEST Network

**Test 1: Ping GUEST Gateway**
```bash
ping -c 4 192.168.20.1
```
Expected: ✅ Success

**Test 2: Ping Internet (IP)**
```bash
ping -c 4 8.8.8.8
```
Expected: ✅ Success (internet works)

**Test 3: Ping Internet (DNS)**
```bash
ping -c 4 google.com
```
Expected: ✅ Success (DNS works)

**Test 4: Ping LOCAL Gateway (SHOULD FAIL)**
```bash
ping -c 4 192.168.10.1
```
Expected: ❌ 100% packet loss (isolation working!)

**Test 5: Try to Access LOCAL Network Device**
```bash
ping -c 4 192.168.10.100
```
Expected: ❌ 100% packet loss (blocked by firewall)

---

### Step 14: Verification and Documentation

#### 14.1 Complete Test Matrix

| Test | LOCAL VM | GUEST VM | Expected Result | Status |
|------|----------|----------|-----------------|--------|
| Get DHCP IP | 192.168.10.x | 192.168.20.x | Both receive IPs | |
| Ping own gateway | 192.168.10.1 | 192.168.20.1 | Both succeed | |
| Ping internet IP | 8.8.8.8 | 8.8.8.8 | Both succeed | |
| DNS resolution | google.com | google.com | Both succeed | |
| LOCAL → GUEST gateway | ✅ | N/A | Optional (can succeed) | |
| GUEST → LOCAL gateway | N/A | ❌ | MUST FAIL | |
| GUEST → LOCAL device | N/A | ❌ | MUST FAIL | |

#### 14.2 View DHCP Leases

In pfSense:
1. Go to **Status → DHCP Leases**
2. Verify your VMs appear with correct IPs

#### 14.3 View Firewall Logs

To see blocked attempts from GUEST:
1. Go to **Status → System Logs → Firewall**
2. Look for entries with GUEST interface
3. You should see blocked packets if GUEST tried to access LOCAL

---

## 🐛 Lab 1 Troubleshooting

### Issue 1: VM Not Getting IP Address

**Symptoms:**
- `ifconfig` shows no IP on eth0
- OR shows 169.254.x.x (APIPA address)

**Solutions:**

1. **Check VirtualBox Internal Network Names:**
   - Adapter name must EXACTLY match (case-sensitive)
   - LOCAL VM: `Local`
   - GUEST VM: `GUESTS_NET`

2. **Verify Promiscuous Mode:**
   - On pfSense VM adapters 2 & 3: Must be "Allow All"
   - On test VMs: Should be "Allow All"

3. **Check DHCP is Enabled:**
   - pfSense → Services → DHCP Server
   - Verify checkbox is checked for LOCAL and GUEST

4. **Manual DHCP Request:**
   ```bash
   sudo ip addr flush dev eth0
   sudo dhclient eth0
   ```

5. **Check pfSense Interface Status:**
   - pfSense → Status → Interfaces
   - Verify LOCAL and GUEST show "up"

---

### Issue 2: No Internet Access

**Symptoms:**
- Can ping gateway (192.168.10.1 or 192.168.20.1)
- Cannot ping 8.8.8.8
- Cannot ping google.com

**Solutions:**

1. **Verify NAT Configuration:**
   - Firewall → NAT → Outbound
   - Mode should be "Automatic"
   - Verify automatic rules exist for both subnets

2. **Check WAN Interface:**
   - Status → Interfaces → WAN
   - Verify it has an IP address
   - Test: ping 8.8.8.8 from pfSense console

3. **Verify Firewall Rules:**
   - Firewall → Rules → LOCAL/GUEST
   - Ensure "Pass" rules allow traffic to "Any" destination

4. **Check DNS:**
   - If ping 8.8.8.8 works but google.com fails
   - Problem is DNS, not connectivity
   - Set explicit DNS in DHCP server configuration

---

### Issue 3: GUEST Can Access LOCAL Network

**Symptoms:**
- Ping from GUEST (192.168.20.x) to LOCAL (192.168.10.1) succeeds
- Isolation is not working

**Solutions:**

1. **Verify Firewall Rule Order:**
   - Firewall → Rules → GUEST
   - Block rule MUST be above Allow rule
   - Drag rules to reorder if needed

2. **Check Rule Configuration:**
   - Verify Source: GUEST net
   - Verify Destination: LOCAL net
   - Verify Action: Block

3. **Ensure Rule is Enabled:**
   - Checkbox next to rule should NOT be checked (unchecked = enabled)
   - If disabled, edit rule and uncheck "Disabled"

4. **Apply Changes:**
   - After editing rules, click "Apply Changes"
   - Test again after applying

---

### Issue 4: DHCP Timeout on eth1 or eth2

**Symptoms:**
- NetworkManager shows "getting IP configuration"
- Eventually times out
- Only affects secondary adapters

**Solutions:**

**Option A: Use Static IP (Temporary for Testing)**
```bash
sudo ip addr add 192.168.20.100/24 dev eth0
sudo ip route add default via 192.168.20.1
```

**Option B: Force DHCP Request**
```bash
sudo dhclient eth0
```

**Option C: Use NetworkManager CLI**
```bash
nmcli connection show
nmcli connection up "Wired connection 1"
```

---

### Step 8: Install OpenVPN Client on Test VM

Before you can test the VPN, you need to install the OpenVPN client software on your test machine.

#### 8.1 Download OpenVPN Package

**On Kali Linux (or Debian/Ubuntu-based system):**

If your VM has internet access:
```bash
# Download OpenVPN package directly
wget http://http.kali.org/kali/pool/main/o/openvpn/openvpn_2.7.0~rc3-1_amd64.deb

# Or for older version
wget http://http.kali.org/kali/pool/main/o/openvpn/openvpn_2.7.0~rc2-2_amd64.deb
```

**If VM cannot access internet:**
1. Download on host machine: http://http.kali.org/kali/pool/main/o/openvpn/
2. Transfer to VM via:
   - **Shared folder** (VirtualBox: Devices → Shared Folders)
   - **USB drive** mapped to VM
   - **SCP:** `scp openvpn_2.7.0~rc2-2_amd64.deb user@vm-ip:/home/user/`

#### 8.2 Install OpenVPN

```bash
# Install the downloaded package
sudo dpkg -i openvpn_2.7.0~rc2-2_amd64.deb

# If dependency errors occur, run:
sudo apt --fix-broken install
```

#### 8.3 Verify Installation

```bash
openvpn --version
```

**Expected Output:**
```
OpenVPN 2.7_rc2 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] [DCO]
library versions: OpenSSL 3.5.2 5 Aug 2025, LZO 2.10
```

✅ OpenVPN is now installed and ready to use.

---

### Step 9: Download VPN Configuration from pfSense

#### 9.1 Export Configuration File

In pfSense:
1. Go to **VPN → OpenVPN → Client Export**
2. Scroll down to the user you want to test (e.g., `contractor1`)
3. Under "Most Clients", click on the configuration type:
   - **Inline Configurations** - Bundled config (recommended)
   - **Archive** - ZIP file with certificates

**Download the file** - it will be named something like:
- `pfSense-UDP4-1194-contractor1-inline.ovpn` (inline config)
- `pfSense-UDP4-1194-config.zip` (archive)

#### 9.2 Transfer Configuration to Test VM

**Option A: Via Browser on VM**
- If test VM has GUI and internet access
- Download directly to VM

**Option B: Via Shared Folder**
1. VirtualBox: **Devices → Shared Folders → Shared Folder Settings**
2. Add shared folder pointing to host directory with `.ovpn` file
3. Access in VM: `/media/sf_<folder_name>/` (Linux) or `\\vboxsvr\<folder_name>` (Windows)

**Option C: Via SCP**
```bash
# From host or another machine
scp pfSense-UDP4-1194-config.zip user@vm-ip:/home/user/Desktop/
```

---

### Step 10: Prepare and Test VPN Connection

#### 10.1 Extract Configuration (if using ZIP)

```bash
# Navigate to where you saved the file
cd ~/Desktop

# Extract the ZIP file
unzip pfSense-UDP4-1194-config.zip -d ~/Desktop/pfSenseVPN/
```

**Extracted files:**
```
pfSenseVPN/
├── pfSense-UDP4-1194/
│   ├── pfSense-UDP4-1194.ovpn          # Main configuration
│   ├── pfSense-UDP4-1194-ca.crt        # Certificate Authority cert
│   ├── pfSense-UDP4-1194-tls.key       # TLS authentication key
│   └── (possibly user cert/key)
```

#### 10.2 Automated Connection Script

Create a bash script to automatically connect:

```bash
#!/bin/bash

# Set variables
ZIP_FILE=~/Desktop/pfSense-UDP4-1194-config.zip
DEST_DIR=~/Desktop/pfSenseVPN

# 1. Unzip the pfSense VPN package
mkdir -p "$DEST_DIR"
unzip -o "$ZIP_FILE" -d "$DEST_DIR"

# Find the extracted folder
EXTRACTED_FOLDER=$(find "$DEST_DIR" -maxdepth 1 -type d -name "pfSense-UDP4-1194*")

# 2. Fix the .ovpn file paths (if needed)
OVPN_FILE=$(find "$EXTRACTED_FOLDER" -name "*.ovpn")
sed -i "s|ca .*|ca $EXTRACTED_FOLDER/pfSense-UDP4-1194-ca.crt|g" "$OVPN_FILE"
sed -i "s|tls-auth .*|tls-auth $EXTRACTED_FOLDER/pfSense-UDP4-1194-tls.key 1|g" "$OVPN_FILE"

# 3. Run OpenVPN
echo "Starting OpenVPN..."
sudo openvpn --config "$OVPN_FILE"
```

**Save and run:**
```bash
# Save as connect_vpn.sh
nano ~/Desktop/connect_vpn.sh

# Paste the script above, then save (Ctrl+O, Enter, Ctrl+X)

# Make executable
chmod +x ~/Desktop/connect_vpn.sh

# Run
~/Desktop/connect_vpn.sh
```

#### 10.3 Manual Connection (Alternative)

```bash
# Navigate to extracted folder
cd ~/Desktop/pfSenseVPN/pfSense-UDP4-1194/

# Connect to VPN
sudo openvpn --config pfSense-UDP4-1194.ovpn
```

#### 10.4 Enter Credentials

When prompted:
```
Enter Auth Username: contractor1
Enter Auth Password: ••••••••
```

**What happens next:**
```
2025-12-14 05:39:22 OpenVPN 2.7_rc2 x86_64-pc-linux-gnu
2025-12-14 05:39:22 TCP/UDP: Preserving recently used remote address: [AF_INET]10.0.2.15:1194
2025-12-14 05:39:22 UDPv4 link remote: [AF_INET]10.0.2.15:1194
2025-12-14 05:39:22 [OpenVPN Server] Peer Connection Initiated with [AF_INET]10.0.2.15:1194
2025-12-14 05:39:24 TUN/TAP device tun0 opened
2025-12-14 05:39:24 net_addr_v4_add: 10.0.10.2/24 dev tun0
2025-12-14 05:39:24 Initialization Sequence Completed
```

**✅ "Initialization Sequence Completed" = VPN is connected!**

---

### Step 11: Test VPN Connection

Now that you've exported the client configuration, it's time to test the VPN connection.

#### 8.1 Install OpenVPN Client Software

**For Windows:**
1. Download OpenVPN GUI from: https://openvpn.net/community-downloads/
2. Download "Windows Installer (64-bit)"
3. Run installer with administrator privileges
4. Complete installation wizard

**For macOS:**
1. Download Tunnelblick from: https://tunnelblick.net/
2. Open DMG file and drag to Applications
3. Launch Tunnelblick
4. Grant necessary permissions

**For Linux (Debian/Ubuntu/Kali):**
```bash
sudo apt update
sudo apt install openvpn
```

**For Mobile:**
- **iOS**: Install "OpenVPN Connect" from App Store
- **Android**: Install "OpenVPN Connect" from Google Play Store

#### 8.2 Import Configuration File

**Windows (OpenVPN GUI):**
1. Locate the downloaded `.ovpn` file (e.g., `contractor1-inline.ovpn`)
2. Right-click the OpenVPN GUI icon in system tray
3. Select **Import → Import file...**
4. Browse to and select the `.ovpn` file
5. File is imported and appears in the connection list

**Alternative:** Copy `.ovpn` file to: `C:\Program Files\OpenVPN\config\`

**macOS (Tunnelblick):**
1. Double-click the `.ovpn` file
2. Tunnelblick will ask to install configuration
3. Click **Install Configuration**
4. Enter administrator password when prompted

**Linux:**
```bash
# Copy config file to OpenVPN directory
sudo cp contractor1-inline.ovpn /etc/openvpn/client/

# Or run directly
sudo openvpn contractor1-inline.ovpn
```

#### 8.3 Connect to VPN

**Windows (OpenVPN GUI):**
1. Right-click OpenVPN GUI icon in system tray
2. Select your configuration (e.g., "contractor1")
3. Click **Connect**
4. Enter credentials when prompted:
   - Username: `contractor1`
   - Password: (the password you set)
5. Wait for connection (10-30 seconds)
6. Icon turns green when connected

**macOS (Tunnelblick):**
1. Click Tunnelblick icon in menu bar
2. Select **Connect contractor1**
3. Enter username and password
4. Status shows "Connected"

**Linux:**
```bash
# Connect using OpenVPN
sudo openvpn --config /etc/openvpn/client/contractor1-inline.ovpn

# Or if you installed as systemd service
sudo systemctl start openvpn-client@contractor1
```

#### 8.4 Verify VPN Connection

**Test 1: Check Connection Status**

**Windows/macOS:** Look for "Connected" status in client

**Linux:**
```bash
# Check if tun interface exists
ip addr show tun0

# Should show something like:
# tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP>
#     inet 10.0.10.6/24 scope global tun0
```

**Expected Result:**
- Client shows "Connected" status
- No error messages
- Connection established within 30 seconds

---

**Test 2: Check VPN IP Address**

**Windows:**
```cmd
ipconfig /all
```
Look for adapter named "OpenVPN TAP-Windows" or "Local Area Connection"

**macOS/Linux:**
```bash
ifconfig tun0
# or
ip addr show tun0
```

**Expected Output:**
```
tun0: inet 10.0.10.6 netmask 255.255.255.0
```

**What this means:**
- Your device has been assigned VPN IP: `10.0.10.6` (or similar)
- This is from the tunnel network `10.0.10.0/24`
- VPN tunnel is established

---

**Test 3: Ping pfSense VPN Server**

```bash
ping 10.0.10.1
```

**Expected Result:**
```
Reply from 10.0.10.1: bytes=32 time=20ms TTL=64
Reply from 10.0.10.1: bytes=32 time=18ms TTL=64
Reply from 10.0.10.1: bytes=32 time=19ms TTL=64

Ping statistics for 10.0.10.1:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss)
```

**What this means:**
- ✅ VPN tunnel is working
- ✅ pfSense VPN server is reachable
- ✅ Encrypted traffic is flowing

---

**Test 4: Ping LOCAL Network Gateway**

```bash
ping 192.168.10.1
```

**Expected Result:**
```
Reply from 192.168.10.1: bytes=32 time=22ms TTL=64
Reply from 192.168.10.1: bytes=32 time=20ms TTL=64
```

**What this means:**
- ✅ Routing is working
- ✅ Traffic to LOCAL network goes through VPN tunnel
- ✅ Firewall rules allow VPN → LOCAL traffic

---

**Test 5: Access Internal Resource**

If you have a device on LOCAL network (e.g., from Lab 1):

```bash
# Ping internal device
ping 192.168.10.100

# Access pfSense web interface
# Open browser to: http://192.168.10.1
# or: http://192.168.1.1
```

**Expected Result:**
- ✅ Can ping internal devices on 192.168.10.0/24
- ✅ Can access pfSense web interface through VPN
- ✅ Can access other internal resources (file servers, databases, etc.)

---

**Test 6: Verify GUEST Network is Blocked**

```bash
ping 192.168.20.1
```

**Expected Result:**
```
Request timeout for icmp_seq 1
Request timeout for icmp_seq 2
```

**What this means:**
- ✅ VPN users CANNOT access GUEST network
- ✅ Firewall rules are working correctly
- ✅ Proper network segmentation is enforced

---

**Test 7: Verify Internet Access (Split Tunnel)**

```bash
ping 8.8.8.8
ping google.com
```

**Expected Result:**
```
Reply from 8.8.8.8: bytes=32 time=10ms
```

**Check which route is used:**

**Windows:**
```cmd
tracert 8.8.8.8
```

**Linux/macOS:**
```bash
traceroute 8.8.8.8
```

**Expected Result (Split Tunnel - Redirect Gateway OFF):**
```
1    <your local gateway>    1ms
2    <your ISP>              10ms
3    8.8.8.8                 15ms
```

**What this means:**
- ✅ Internet traffic goes directly (not through VPN)
- ✅ Split-tunnel is working correctly
- ✅ Only internal traffic (192.168.10.0/24) uses VPN

**Alternative Result (Full Tunnel - Redirect Gateway ON):**
```
1    10.0.10.1              20ms    (pfSense VPN server)
2    10.0.2.2               25ms    (pfSense WAN gateway)
3    <ISP gateway>          30ms
4    8.8.8.8                35ms
```

**What this means:**
- ✅ ALL traffic goes through VPN
- ✅ Full-tunnel is working
- ✅ Contractor internet appears from company IP

---

**Test 8: DNS Resolution Test**

```bash
# Test internal DNS resolution (if you have internal hostnames)
nslookup pfsense.local

# Test external DNS resolution
nslookup google.com
```

**Expected Result:**
- Internal names resolve through pfSense DNS (192.168.1.1)
- External names resolve successfully
- No DNS errors

---

#### 8.5 Check pfSense VPN Status

While VPN is connected, check pfSense:

**View Connected Clients:**
1. In pfSense, go to **Status → OpenVPN**
2. You should see connected client(s)

**Expected Information:**

| Field | Value | What It Means |
|-------|-------|---------------|
| **Common Name** | contractor1 | User that is connected |
| **Real Address** | 203.0.113.50:xxxxx | Client's public IP and source port |
| **Virtual Address** | 10.0.10.6 | VPN IP assigned to client |
| **Bytes Sent** | 15.2 KB | Data sent from server to client |
| **Bytes Received** | 8.5 KB | Data received from client |
| **Connected Since** | 2024-12-14 10:30:25 | Connection timestamp |

---

#### 8.6 View VPN Logs

**Check Connection Logs:**
1. Go to **Status → System Logs → OpenVPN**
2. Look for connection events

**Successful Connection Log:**
```
Dec 14 10:30:25 openvpn[12345]: contractor1/203.0.113.50:54321 MULTI_sva: pool returned IPv4=10.0.10.6
Dec 14 10:30:25 openvpn[12345]: contractor1/203.0.113.50:54321 PUSH: Received control message: 'PUSH_REQUEST'
Dec 14 10:30:25 openvpn[12345]: contractor1/203.0.113.50:54321 SENT CONTROL [contractor1]: 'PUSH_REPLY,route 192.168.10.0 255.255.255.0'
Dec 14 10:30:26 openvpn[12345]: contractor1/203.0.113.50:54321 Data Channel: using negotiated cipher 'AES-256-GCM'
```

**What to look for:**
- ✅ "pool returned IPv4" - Client got VPN IP
- ✅ "PUSH_REPLY" - Server sent routes to client
- ✅ "Data Channel" - Encrypted tunnel established
- ❌ Look for "AUTH_FAILED" or "TLS_ERROR" if problems

---

#### 8.7 Test VPN from Different Locations

**Test Scenario 1: From Different Network**
- Connect from home network
- Connect from coffee shop WiFi
- Connect from mobile data

**Should work from anywhere with internet access**

**Test Scenario 2: Multiple Users**
- Have contractor1 connected
- Connect contractor2 from different location
- Both should work simultaneously

---

#### 8.8 Test Disconnection and Reconnection

1. Disconnect VPN
2. Wait 10 seconds
3. Reconnect
4. Should reconnect successfully with same or different VPN IP

---

### Step 9: Verify Security and Access Control

#### 9.1 Test Authentication Requirements

**Test 1: Wrong Password**
1. Try to connect with incorrect password
2. **Expected:** Connection fails with "AUTH_FAILED"
3. **What this proves:** Password authentication is working

**Test 2: No Certificate**
1. Edit `.ovpn` file and remove certificate section
2. Try to connect
3. **Expected:** Connection fails immediately
4. **What this proves:** Certificate authentication is required

---

#### 9.2 Test Access Control

**Create Test Matrix:**

| Source | Destination | Protocol | Expected Result | Actual Result |
|--------|-------------|----------|-----------------|---------------|
| VPN Client (10.0.10.6) | LOCAL (192.168.10.1) | ICMP ping | ✅ Allow | |
| VPN Client (10.0.10.6) | LOCAL device (192.168.10.100) | Any | ✅ Allow | |
| VPN Client (10.0.10.6) | GUEST (192.168.20.1) | ICMP ping | ❌ Block | |
| VPN Client (10.0.10.6) | GUEST device (192.168.20.100) | Any | ❌ Block | |
| VPN Client (10.0.10.6) | Internet (8.8.8.8) | ICMP ping | ✅ Allow | |
| VPN Client (10.0.10.6) | pfSense WAN | Any | ❌ Block (should not be allowed) | |

---

#### 9.3 Monitor VPN Traffic

**View Real-Time Traffic:**
1. pfSense → **Diagnostics → Packet Capture**
2. Interface: **OpenVPN**
3. Click **Start**
4. Generate traffic from VPN client (ping, browse, etc.)
5. Click **Stop**
6. Review captured packets

**What you should see:**
- Encrypted traffic on WAN interface (gibberish)
- Decrypted traffic on OpenVPN interface (readable IPs and protocols)

---

### Step 10: Performance Testing (Optional)

#### 10.1 Test VPN Speed

**Using iperf3:**

**On pfSense (or LOCAL network device):**
```bash
# Install iperf3 if needed
pkg install iperf3

# Run server
iperf3 -s
```

**On VPN Client:**
```bash
# Install iperf3
sudo apt install iperf3  # Linux
brew install iperf3      # macOS

# Test download speed (server → client)
iperf3 -c 192.168.10.1

# Test upload speed (client → server)
iperf3 -c 192.168.10.1 -R
```

**Expected Results:**
- 10-100 Mbps depending on:
  - Client's internet speed
  - pfSense hardware
  - Network latency

---

#### 10.2 Test Latency

```bash
# Continuous ping to measure latency
ping 192.168.10.1 -t

# Or with statistics
ping -c 100 192.168.10.1
```

**Typical Latency:**
- Same city: 10-30ms
- Same country: 30-80ms
- International: 100-300ms

---

## 📊 Lab 2 Testing Summary

### Complete Test Checklist

| Test | Expected Result | Status |
|------|-----------------|--------|
| **Installation & Configuration** |
| OpenVPN package installed | ✅ Package appears in installed list | [ ] |
| CA created | ✅ Appears in Cert Manager → CAs | [ ] |
| Server certificate created | ✅ Appears in Cert Manager → Certificates | [ ] |
| OpenVPN server configured | ✅ Appears in VPN → OpenVPN → Servers | [ ] |
| Users created | ✅ Appear in System → User Manager | [ ] |
| WAN firewall rule created | ✅ Appears in Firewall → Rules → WAN | [ ] |
| OpenVPN firewall rule created | ✅ Appears in Firewall → Rules → OpenVPN | [ ] |
| **Client Connection** |
| Client software installed | ✅ OpenVPN client runs | [ ] |
| Config file imported | ✅ Appears in client connection list | [ ] |
| VPN connects successfully | ✅ "Connected" status | [ ] |
| VPN IP assigned | ✅ Client has 10.0.10.x IP | [ ] |
| **Connectivity Tests** |
| Ping VPN gateway (10.0.10.1) | ✅ Success | [ ] |
| Ping LOCAL gateway (192.168.10.1) | ✅ Success | [ ] |
| Ping LOCAL device | ✅ Success | [ ] |
| Access pfSense web GUI through VPN | ✅ Success | [ ] |
| **Security Tests** |
| Ping GUEST network | ❌ Blocked (should fail) | [ ] |
| Wrong password fails | ❌ AUTH_FAILED | [ ] |
| No certificate fails | ❌ Connection rejected | [ ] |
| **Internet Access** |
| Ping internet (8.8.8.8) | ✅ Success | [ ] |
| DNS resolution works | ✅ Success | [ ] |
| Internet traffic routing correct | ✅ Direct or via VPN (based on Redirect Gateway) | [ ] |
| **pfSense Monitoring** |
| Connected client appears in Status | ✅ Shows in Status → OpenVPN | [ ] |
| Connection logs show success | ✅ No errors in OpenVPN logs | [ ] |

---

## 📖 Understanding What You Built: High-Level Explanation

Now that you've completed the lab, let's understand **what you actually built** and **why each component is necessary**. This section explains the big picture of your VPN infrastructure.

---

### 🏗️ The Components You Created

You built a complete VPN environment using pfSense as the central hub. Here's what each piece does:

#### **1. pfSense (Firewall & Router)**
- Acts as your **firewall and router**
- Manages traffic between:
  - Internal network (LAN)
  - Internet (WAN)
  - VPN clients
- Runs services like **OpenVPN Server**

#### **2. OpenVPN Server (on pfSense)**
- The **VPN service** that remote devices connect to
- Allows clients to **securely tunnel** into your network over the internet
- Acts as a **gatekeeper** that checks credentials and certificates before granting access
- **Assigns VPN IP addresses** to connected clients

#### **3. Certificate Authority (CA)**
- Acts like a **trusted authority** (like a passport office)
- **Issues certificates** to users and servers
- Certificates are like **digital passports** proving identity
- Allows you to **revoke access** if a certificate is compromised

#### **4. Client Certificates + Username/Password**
- **Certificates** ensure strong authentication (can't just guess your way in)
- **Username/password** is an extra layer (two-factor authentication)
- Each user/device gets their **own certificate** → revocable if compromised
- **Two-factor authentication:**
  - **Something you have:** Certificate file
  - **Something you know:** Username and password

#### **5. Client Machine**
- The computer or VM trying to connect
- Uses **`.ovpn` file** which contains:
  - VPN server address
  - Certificates (CA, client, TLS key)
  - Configuration (IP range, encryption, etc.)

---

### 🔐 Why Certificates Are Needed

**Q: Why not just use username and password?**

Certificates provide several critical security benefits:

1. **Verify identities** cryptographically
   - Prevent anyone from pretending to be a legitimate client
   - Much harder to forge than passwords

2. **Ensure encryption is trusted**
   - No one in between can intercept your data
   - Protects against man-in-the-middle attacks

3. **TLS key adds extra layer**
   - Only devices with the matching key can even **start the handshake**
   - Prevents unauthorized connection attempts
   - Acts as "pre-authentication"

4. **Revocable access**
   - If a device is lost/stolen, revoke its certificate
   - User can't connect even if they know the password

**Think of it like airport security:**
- **Password** = showing your boarding pass
- **Certificate** = showing your passport
- **TLS Key** = having the right airport ticket to even enter security

---

### 🌐 Why OpenVPN Server

**Q: Why do we need a VPN server?**

The OpenVPN Server:

1. **Acts as a central secure hub**
   - All VPN client traffic is routed through this server
   - Single point to manage and monitor remote access

2. **Handles encryption**
   - AES-256-GCM encryption for all traffic
   - Protects data traveling over the internet

3. **Handles authentication**
   - Verifies certificates
   - Checks username/password
   - Assigns IP addresses to clients

4. **Enforces access rules**
   - Controls who can access which parts of the network
   - Firewall rules determine what VPN users can reach

5. **Provides secure remote access**
   - Employees/contractors can work from anywhere
   - Access internal resources securely

---

### 🔢 Why VPN IP Range Is Different

**Q: Why does VPN use 10.0.10.0/24 instead of my LAN 192.168.1.0/24?**

Your networks:
- **LAN (local network):** 192.168.1.0/24 or 192.168.10.0/24
- **VPN assigns addresses:** 10.0.10.0/24

**Reasons for separate range:**

1. **Avoid IP conflicts**
   - If VPN used same range as your home/office network
   - Two devices could have same IP = network chaos

2. **Virtual network within physical network**
   - You're **logically connected** but in a **separate subnet**
   - Still routed through pfSense
   - Can access LAN if firewall rules allow

3. **Easier management**
   - Easy to identify VPN clients (10.0.10.x)
   - Easy to create firewall rules for VPN users
   - Easy to monitor VPN traffic separately

**Think of it like:**
- Your house is on **Main Street (LAN)**
- VPN clients visit via **Virtual Avenue (VPN subnet)**
- pfSense is the **gateway** connecting both streets

---

### 🔄 What Happens When You Connect to VPN

**Step-by-step connection process:**

#### **Step 1: Client Initiates Connection**
```
Client opens OpenVPN using .ovpn file
↓
Connects to pfSense OpenVPN server over UDP port 1194
```

#### **Step 2: Server Checks Authentication (3 layers)**
```
pfSense checks:
1. TLS key → Is it valid? (Pre-authentication)
2. Client certificate → Signed by our CA? (Device authentication)
3. Username/password → Correct credentials? (User authentication)
```

**If ANY check fails → Connection rejected**

#### **Step 3: VPN Tunnel Created**
```
If all checks pass:
- VPN tunnel is established (encrypted connection)
- tun0 interface created on your machine
- Client assigned a VPN IP (e.g., 10.0.10.6)
```

#### **Step 4: Routing Configured**
```
Routing table updated:
- Traffic to 10.0.10.0/24 → goes through VPN tunnel
- Traffic to 192.168.10.0/24 → goes through VPN tunnel (if pushed)
- Internet traffic → through VPN (if redirect-gateway enabled)
```

#### **Step 5: Data Flows**
```
Your traffic:
[Your Computer]
    ↓ (encrypted)
[Internet]
    ↓ (encrypted)
[pfSense OpenVPN Server]
    ↓ (decrypted)
[Internal Network / Internet]
```

**All data is encrypted end-to-end** until it reaches the VPN server.

---

### 🌍 Can I Connect Even If I'm Not on the LAN?

**Q: Can I connect to the network using VPN even if I'm not part of that network?**

**✅ YES! That's the entire point of VPN:**

**Scenario 1: You're at home**
```
[Your Home Network: 192.168.0.x]
    ↓ (VPN tunnel over internet)
[pfSense VPN Server]
    ↓
[Office LAN: 192.168.1.x]
```

**Scenario 2: You're at a coffee shop**
```
[Coffee Shop WiFi: 10.50.1.x]
    ↓ (VPN tunnel over internet)
[pfSense VPN Server]
    ↓
[Office LAN: 192.168.1.x]
```

**Scenario 3: You're traveling internationally**
```
[Hotel WiFi in Another Country]
    ↓ (encrypted VPN tunnel)
[pfSense VPN Server]
    ↓
[Your Office Network]
```

**What you get:**
- ✅ **Virtual presence** inside the private network
- ✅ **Secure connection** even on untrusted WiFi
- ✅ **Access to internal resources** (if firewall allows)
- ✅ **Encrypted traffic** that can't be intercepted

**Access to local devices depends on configuration:**
- If `push "route 192.168.10.0 255.255.255.0"` is set → you can reach LAN
- Otherwise, your VPN is **isolated** to its own subnet
- Firewall rules on pfSense determine **exactly** what you can access

---

### 📊 High-Level Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    THE BIG PICTURE                              │
└─────────────────────────────────────────────────────────────────┘

[Remote Laptop]                    [Office Desktop]
 Anywhere in World                  On Office LAN
 IP: Varies                         IP: 192.168.10.50
     │                                     │
     │ Encrypted VPN Tunnel               │
     │ Over Internet                       │
     │                                     │
     ▼                                     ▼
┌────────────────────────────────────────────────┐
│           pfSense Firewall/Router              │
│                                                │
│  WAN: 10.0.2.15 (Internet)                    │
│  LAN: 192.168.10.1 (Office Network)           │
│  VPN: 10.0.10.1 (VPN Gateway)                 │
│                                                │
│  ┌──────────────────────────────────────┐    │
│  │      OpenVPN Server                  │    │
│  │  - Assigns VPN IPs                   │    │
│  │  - Checks Certificates               │    │
│  │  - Verifies Username/Password        │    │
│  │  - Encrypts/Decrypts Traffic         │    │
│  │  - Enforces Firewall Rules           │    │
│  └──────────────────────────────────────┘    │
└────────────────────────────────────────────────┘
         │                   │
         │                   │
         ▼                   ▼
[Internal Network]      [Internet]
192.168.10.0/24         (via NAT)
- File Servers
- Databases
- Internal Apps
```

**Traffic Flow:**
1. **Contractor types** `https://fileserver.local` on their laptop
2. **VPN client** encrypts the request
3. **Traffic travels** over internet (encrypted)
4. **pfSense receives** and decrypts (inside VPN tunnel)
5. **pfSense checks** firewall rules
6. **If allowed**, forwards to internal file server (192.168.10.20)
7. **Response** travels back through encrypted tunnel
8. **Contractor sees** the internal website

**Without VPN:**
- ❌ Can't reach `fileserver.local` (not on internet)
- ❌ Can't access 192.168.10.x (private addresses)
- ❌ No secure way to work remotely

**With VPN:**
- ✅ Secure access from anywhere
- ✅ Acts as if physically in the office
- ✅ All traffic encrypted
- ✅ Centrally managed access

---

### 🔐 Security Layers Explained

**Your VPN has multiple security layers:**

```
┌─────────────────────────────────────────┐
│   Layer 1: Network-Level Encryption     │  
│   (All traffic through VPN is encrypted)│
└─────────────────────────────────────────┘
                  ↓
┌─────────────────────────────────────────┐
│   Layer 2: TLS Pre-Authentication       │
│   (TLS key prevents unauthorized        │
│    connection attempts)                 │
└─────────────────────────────────────────┘
                  ↓
┌─────────────────────────────────────────┐
│   Layer 3: Certificate Authentication   │
│   (Client cert signed by CA)            │
└─────────────────────────────────────────┘
                  ↓
┌─────────────────────────────────────────┐
│   Layer 4: Username/Password Auth       │
│   (User must know correct credentials)  │
└─────────────────────────────────────────┘
                  ↓
┌─────────────────────────────────────────┐
│   Layer 5: Firewall Rules               │
│   (pfSense controls what VPN users      │
│    can access)                          │
└─────────────────────────────────────────┘
```

**All 5 layers must be satisfied** for a successful connection.

---

### 💡 Key Takeaways

1. **Certificates** = Your passport to enter the network safely
2. **OpenVPN Server** = Security gate and traffic controller
3. **VPN IP range** = Virtual space for clients (avoids IP conflicts)
4. **Two-factor auth** = Certificate (what you have) + Password (what you know)
5. **Encrypted tunnel** = All traffic is protected end-to-end
6. **Firewall rules** = Control exactly what VPN users can access
7. **Remote access** = Work securely from anywhere in the world

**Complete Flow:**
```
pfSense installed → OpenVPN configured → CA created → 
Certificates issued → Configs distributed → Clients connect → 
Get virtual IP → Traffic through encrypted tunnel → 
Access to LAN (if allowed) or internet
```

---

## 🐛 Lab 2 Troubleshooting

### Issue 1: Cannot Connect to VPN

**Symptoms:**
- Client shows "Connection timeout"
- Client shows "TLS handshake failed"
- Connection attempt takes long time then fails

**Solutions:**

1. **Check WAN Firewall Rule:**
   - Firewall → Rules → WAN
   - Verify rule exists to allow UDP 1194
   - Action must be "Pass"
   - Destination must be "WAN address"

2. **Verify OpenVPN Server is Running:**
   - Status → Services
   - Look for "openvpn" service
   - Should show "Running"
   - If stopped, start it

3. **Check Port Forwarding (if behind NAT):**
   - If pfSense WAN is behind another router
   - Forward UDP 1194 to pfSense WAN IP
   - Or use port triggering

4. **Test from Outside Network:**
   - VPN won't work from INSIDE the same network
   - Test from mobile data or different location

5. **Check Client Config Hostname:**
   - Open `.ovpn` file in text editor
   - Look for line: `remote X.X.X.X 1194`
   - Verify IP address is correct WAN IP
   - If dynamic IP, use DDNS hostname

---

### Issue 2: AUTH_FAILED Error

**Symptoms:**
- Connection attempts but fails with "AUTH_FAILED"
- Logs show authentication failure

**Solutions:**

1. **Verify Username/Password:**
   - Check username is correct (case-sensitive)
   - Verify password is correct
   - Try resetting password in User Manager

2. **Check User is Enabled:**
   - System → User Manager
   - Verify user is not disabled
   - Check "Disabled" checkbox is unchecked

3. **Verify Certificate:**
   - System → User Manager → Edit user
   - Verify user has certificate
   - Check certificate is not expired

4. **Check Authentication Backend:**
   - VPN → OpenVPN → Servers → Edit
   - Verify "Backend for authentication" is "Local Database"

---

### Issue 3: Connected but Cannot Access Internal Resources

**Symptoms:**
- VPN shows "Connected"
- Can ping 10.0.10.1 (VPN gateway)
- Cannot ping 192.168.10.1 (LOCAL gateway)
- Cannot access internal resources

**Solutions:**

1. **Check OpenVPN Firewall Rules:**
   - Firewall → Rules → OpenVPN
   - Must have rule allowing OpenVPN → LOCAL net
   - Action: Pass
   - Source: Any (or OpenVPN net)
   - Destination: LOCAL net

2. **Verify Routes Pushed to Client:**
   - VPN → OpenVPN → Servers → Edit
   - Check "IPv4 Local Network(s)" = 192.168.10.0/24
   - This tells client to route LOCAL traffic through VPN

3. **Check Client Routing Table:**
   
   **Windows:**
   ```cmd
   route print
   ```
   
   **Linux/macOS:**
   ```bash
   netstat -rn
   ```
   
   Should show route to 192.168.10.0/24 via tun0 interface

4. **Test from pfSense:**
   - Diagnostics → Ping
   - Source: OpenVPN interface
   - Host: 192.168.10.1
   - If this fails, problem is pfSense routing

---

### Issue 4: Can Access LOCAL but Not Internet

**Symptoms:**
- VPN connected
- Can access 192.168.10.0/24
- Cannot ping 8.8.8.8
- Internet doesn't work

**Solutions:**

**If Redirect Gateway is OFF (split tunnel):**
1. **Check Local Internet Connection:**
   - Disconnect VPN
   - Test internet access
   - Problem may be local connection, not VPN

2. **Check DNS:**
   - Try ping by IP: `ping 8.8.8.8`
   - If works, but `ping google.com` fails = DNS issue
   - Set DNS manually: DNS Server 1 = 8.8.8.8 in OpenVPN server config

**If Redirect Gateway is ON (full tunnel):**
1. **Check NAT:**
   - Firewall → NAT → Outbound
   - Verify automatic rule exists for 10.0.10.0/24 → WAN

2. **Check OpenVPN Firewall Rules:**
   - Firewall → Rules → OpenVPN
   - Need rule: OpenVPN → Any (not just LOCAL)

---

### Issue 5: DNS Not Working

**Symptoms:**
- Can ping by IP (8.8.8.8 works)
- Cannot ping by name (google.com fails)
- "Name or service not known" errors

**Solutions:**

1. **Check DNS Servers Configured:**
   - VPN → OpenVPN → Servers → Edit
   - Verify DNS Server 1 and 2 are configured
   - Example: 192.168.1.1, 8.8.8.8

2. **Check Client DNS Settings:**
   
   **Windows:**
   ```cmd
   ipconfig /all
   ```
   Look for DNS servers on VPN adapter
   
   **Linux:**
   ```bash
   cat /etc/resolv.conf
   ```

3. **Force DNS Through VPN:**
   - Edit client config
   - Add these lines:
   ```
   dhcp-option DNS 192.168.1.1
   dhcp-option DNS 8.8.8.8
   ```

4. **Test DNS Directly:**
   ```bash
   nslookup google.com 192.168.1.1
   ```

---

### Issue 6: VPN Disconnects Frequently

**Symptoms:**
- VPN connects successfully
- Disconnects after few minutes
- Must reconnect frequently

**Solutions:**

1. **Check Firewall State Table:**
   - System → Advanced → Firewall & NAT
   - Increase "Firewall Maximum States" if needed

2. **Add Keepalive to Client Config:**
   - VPN → OpenVPN → Servers → Edit
   - Advanced Configuration, add:
   ```
   keepalive 10 60
   ```

3. **Check Client Internet Stability:**
   - Ping test without VPN
   - If unstable connection, VPN will drop

4. **Increase Verbosity for Debugging:**
   - VPN → OpenVPN → Servers → Edit
   - Verbosity level: 5 (temporary for debugging)
   - Check logs for disconnect reason

---

### Issue 7: Certificate Errors

**Symptoms:**
- "Certificate verification failed"
- "TLS Error: certificate verify failed"

**Solutions:**

1. **Check Server Certificate:**
   - System → Cert. Manager → Certificates
   - Verify OpenVPN_Server_Cert exists
   - Check not expired

2. **Check CA:**
   - System → Cert. Manager → CAs
   - Verify OpenVPN_CA exists
   - Check not expired

3. **Regenerate Client Config:**
   - VPN → OpenVPN → Client Export
   - Export fresh config for user
   - Replace old config on client

4. **Verify Certificate Type:**
   - Server cert MUST be "Server Certificate" type
   - User cert MUST be "User Certificate" type

---

### Issue 8: Can Connect but Very Slow

**Symptoms:**
- VPN connects
- Ping times very high (>100ms when should be <50ms)
- File transfers very slow

**Solutions:**

1. **Check Compression:**
   - VPN → OpenVPN → Servers → Edit
   - Compression: Should be "Disable Compression"
   - Compression can actually slow things down

2. **Check MTU:**
   - May need to adjust MTU
   - Add to client config:
   ```
   tun-mtu 1400
   fragment 1300
   ```

3. **Check Protocol:**
   - UDP should be faster than TCP
   - Verify using UDP on port 1194

4. **Check pfSense Resources:**
   - Status → System → Activity
   - If CPU/memory high, pfSense may be overloaded

5. **Test Without VPN:**
   - Test speed between two LOCAL devices
   - Establishes baseline
   - VPN will be slower due to encryption overhead

---

## 📊 Lab 2 Summary

### VPN Configuration Reference

| Component | Value | Purpose |
|-----------|-------|---------|
| **OpenVPN Server Port** | UDP 1194 | Entry point for VPN connections |
| **VPN Tunnel Network** | 10.0.10.0/24 | Virtual network for VPN clients |
| **Accessible Network** | 192.168.10.0/24 | LOCAL network contractors can reach |
| **Certificate Authority** | OpenVPN_CA | Issues all certificates |
| **Server Certificate** | OpenVPN_Server_Cert | Authenticates pfSense to clients |
| **User Certificates** | One per contractor | Authenticates devices |
| **Authentication Mode** | Certificate + User/Password | Two-factor authentication |
| **Encryption** | AES-256-GCM | Strong encryption algorithm |
| **Redirect Gateway** | OFF (split tunnel) | Only internal traffic through VPN |

### Traffic Flow

```
Contractor Device                VPN Tunnel              pfSense              Internal Network
================                ==============          =========            ==================

To 192.168.10.0/24    ─────────> Encrypted ────────────> Decrypted ──────────> LOCAL Network
(Internal resources)               Tunnel                  (10.0.10.1)          (192.168.10.x)
                                                                                  ✅ ACCESS

To 8.8.8.8            ─────────────────────────────────────────────────────────> Internet
(Internet)                       Direct Route                                    ✅ ACCESS
                              (Split Tunnel Mode)

To 192.168.20.0/24    ─────────> Encrypted ────────────> Firewall ──────X────> GUEST Network
(Guest network)                   Tunnel                   BLOCKS              ❌ BLOCKED
```

### Key Takeaways

1. ✅ **Two-Factor Authentication**: Certificate AND password required
2. ✅ **Encrypted Tunnel**: All VPN traffic is AES-256-GCM encrypted
3. ✅ **Split Tunnel**: Only internal traffic uses VPN (efficient)
4. ✅ **Selective Access**: VPN users access LOCAL but not GUEST
5. ✅ **Scalable**: Easy to add/remove contractors via User Manager
6. ✅ **Auditable**: All connections logged in Status → OpenVPN

---

## 📊 Lab 1 Summary

### Network Configuration Reference

| Parameter | LOCAL Network | GUEST Network |
|-----------|---------------|---------------|
| **pfSense Interface** | LOCAL (OPT1, em2) | GUEST (OPT2, em3) |
| **Gateway IP** | 192.168.10.1/24 | 192.168.20.1/24 |
| **DHCP Range** | 192.168.10.100-200 | 192.168.20.100-200 |
| **VirtualBox Network** | Internal: `Local` | Internal: `GUESTS_NET` |
| **Promiscuous Mode** | Allow All | Allow All |
| **Internet Access** | ✅ Yes | ✅ Yes |
| **Access to LOCAL** | ✅ Yes (own network) | ❌ No (blocked) |
| **Access to GUEST** | ✅ Optional | ✅ Yes (own network) |
| **Typical Use Case** | Employees, internal systems | Guest WiFi, contractors |

### Key Takeaways

1. ✅ Promiscuous Mode "Allow All" is required on pfSense internal adapters
2. ✅ Firewall rules are evaluated top-to-bottom (order matters)
3. ✅ Block rules must come before allow rules for proper isolation
4. ✅ Automatic NAT handles multiple internal networks correctly
5. ✅ Network names in VirtualBox must match exactly (case-sensitive)

---

# Lab 2: OpenVPN Remote Access

## Configuring Secure VPN for Remote Contractors

---

## 🎯 Lab 2 Objectives

By the end of this lab, you will:
- Install OpenVPN package on pfSense
- Configure OpenVPN server for remote access
- Create Certificate Authority (CA) and certificates
- Set up user accounts for contractors
- Configure firewall rules for VPN access
- Export and install OpenVPN client configuration
- Test remote access connectivity
- Verify security and isolation

---

## 📋 Lab 2 Prerequisites

- Completed Lab 1 (or have working pfSense with internet)
- pfSense with WAN interface accessible from internet (or can simulate)
- Client device for testing VPN connection
- Basic understanding of VPNs and PKI (Public Key Infrastructure)
- OpenVPN client software available for testing device

---

## 📖 Lab 2 Overview: What We're Building

### The Problem
Your organization needs to provide secure remote access to contractors who need to:
- Access internal resources (files, databases, applications)
- Connect from anywhere in the world
- Have encrypted communications
- Use individual credentials (not shared accounts)
- Be unable to access guest networks or other sensitive areas

### The Solution: OpenVPN Remote Access VPN

**OpenVPN** is an open-source VPN solution that provides:
- **Encrypted tunnel** through the internet
- **Strong authentication** using certificates + username/password
- **Selective access** to specific internal networks
- **Cross-platform support** (Windows, Mac, Linux, mobile)

### How It Works

1. **Contractor connects** from their device using OpenVPN client
2. **Authentication** happens in two layers:
   - Certificate (proves device is authorized)
   - Username/Password (proves user is authorized)
3. **Encrypted tunnel** is established through the internet
4. **Traffic routing**: Contractor can access internal network as if physically present
5. **Firewall rules** control what VPN users can and cannot access

---

## 🏗️ Lab 2 Network Architecture

```
┌─────────────────────┐                    ┌──────────────────┐                  ┌─────────────────────┐
│ Contractor's Laptop │                    │   pfSense VPN    │                  │  Internal Networks  │
│   (Remote)          │                    │     Server       │                  │                     │
│                     │                    │                  │                  │                     │
│ Public IP:          │                    │ WAN: 10.0.2.15   │                  │ LAN: 192.168.1.1    │
│ 203.0.113.50        │────Internet────────▶ Port: 1194/UDP   ├─────────────────▶│ LOCAL: 192.168.10.1 │
│                     │   (Encrypted)      │                  │                  │ GUEST: 192.168.20.1 │
│ OpenVPN Client      │                    │ OpenVPN Server   │                  │                     │
│                     │                    │                  │                  │ Contractors can     │
│ Gets VPN IP:        │                    │ VPN Network:     │                  │ access LOCAL only   │
│ 10.0.10.6           │◀───Tunnel─────────│ 10.0.10.0/24     │                  │                     │
└─────────────────────┘                    └──────────────────┘                  └─────────────────────┘
```

---

## 🌐 Lab 2 Network Addressing Scheme

| Network Component | IP Address/Range | Purpose | Notes |
|-------------------|------------------|---------|-------|
| **WAN Interface** | 10.0.2.15/24 (NAT) | pfSense internet connection | VirtualBox NAT |
| **LAN Interface** | 192.168.1.1/24 | Original pfSense LAN | Management access |
| **LOCAL Network** | 192.168.10.0/24 | Employee network | From Lab 1 |
| **GUEST Network** | 192.168.20.0/24 | Guest network | From Lab 1 |
| **VPN Tunnel Network** | 10.0.10.0/24 | VPN client IPs | Contractor devices get IPs here |
| **OpenVPN Server Port** | UDP 1194 | VPN entry point | Can be changed if needed |

### VPN Client IP Assignment

| Client | VPN IP | Access Level |
|--------|--------|--------------|
| pfSense (server-side) | 10.0.10.1 | Server endpoint |
| contractor1 | 10.0.10.6 | First available client IP |
| contractor2 | 10.0.10.10 | Second client IP |
| contractor3 | 10.0.10.14 | Third client IP |

> **Note:** OpenVPN uses every 4th IP in the tunnel network (topology subnet mode)

---

## 🔐 Lab 2 Security Architecture

### Authentication Layers

```
┌─────────────────────────────────────────────────────────┐
│                  VPN Authentication                     │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Layer 1: Certificate Authentication (PKI)             │
│  ├─ Certificate Authority (CA) validates certificates  │
│  ├─ Server Certificate (proves pfSense is legitimate)  │
│  └─ User Certificate (proves device is authorized)     │
│                                                         │
│  +  (AND - both required)                              │
│                                                         │
│  Layer 2: Username/Password Authentication             │
│  ├─ Username: contractor1                              │
│  └─ Password: *************                            │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

This **two-factor approach** provides:
- **Something you have**: Certificate on device
- **Something you know**: Username and password

---

## 🔧 Lab 2 Components We'll Create

| Component | Quantity | Purpose |
|-----------|----------|---------|
| Certificate Authority (CA) | 1 | Issues and validates all certificates |
| Server Certificate | 1 | Authenticates pfSense VPN server |
| User Certificates | 3+ | One per contractor (authenticates devices) |
| User Accounts | 3+ | One per contractor (username/password) |
| Firewall Rules | 2 | WAN (allow VPN in), OpenVPN (allow access out) |
| Client Config Files | 3+ | One .ovpn file per contractor |

---

## 📝 Lab 2: Step-by-Step Configuration

### Step 1: Install OpenVPN Package

#### 1.1 Navigate to Package Manager

1. Login to pfSense web interface
2. Click **System** in top menu
3. Select **Package Manager**
4. Click on **Available Packages** tab

#### 1.2 Search for OpenVPN

1. In the search box, type: `openvpn`
2. Press Enter or click Search

#### 1.3 Install OpenVPN Client Export Package

Look for: **openvpn-client-export**

| Package Name | Description |
|--------------|-------------|
| openvpn-client-export | OpenVPN Client Export Utility |

1. Click **+ Install** button
2. On confirmation page, click **Confirm**
3. Wait for installation to complete (may take 1-2 minutes)
4. You'll see "Success" when done

> **Note:** The core OpenVPN functionality is built into pfSense. This package adds the client export tool which makes distributing configurations much easier.

---

### Step 2: Create Certificate Authority (CA)

Before creating the VPN server, you need a Certificate Authority to issue certificates.

#### 2.1 Navigate to Certificate Manager

1. Click **System** menu
2. Select **Cert. Manager**
3. Click on **CAs** tab

#### 2.2 Create New CA

1. Click **+ Add** button

#### 2.3 Configure CA Settings

**Descriptive Information:**

| Field | Value | Notes |
|-------|-------|-------|
| **Descriptive name** | `OpenVPN_CA` | Name for reference |
| **Method** | Create an internal Certificate Authority | Select from dropdown |

**Certificate Authority Details:**

| Field | Value | Notes |
|-------|-------|-------|
| **Key Type** | RSA | Recommended |
| **Key Length** | `2048` bits | Minimum 2048, can use 4096 for higher security |
| **Digest Algorithm** | SHA256 | Secure hash algorithm |
| **Lifetime (days)** | `3650` | 10 years (can adjust as needed) |

**Distinguished Name Fields:**

| Field | Value | Example |
|-------|-------|---------|
| **Country Code** | Two-letter code | `US`, `AU`, `GB`, etc. |
| **State or Province** | Full name | `Queensland` |
| **City** | City name | `Brisbane` |
| **Organization** | Company/Org name | `My Company` |
| **Organizational Unit** | Department | `IT Department` |
| **Common Name** | CA identifier | `OpenVPN CA` |

#### 2.4 Save CA

1. Scroll to bottom
2. Click **Save**

You should see your new CA listed in the CAs tab.

---

### Step 3: Create Server Certificate

#### 3.1 Navigate to Certificates

1. Still in **System → Cert. Manager**
2. Click on **Certificates** tab

#### 3.2 Create New Certificate

1. Click **+ Add/Sign** button

#### 3.3 Configure Server Certificate

**Method and CA:**

| Field | Value | Notes |
|-------|-------|-------|
| **Method** | Create an internal Certificate | Select from dropdown |
| **Descriptive name** | `OpenVPN_Server_Cert` | Name for reference |
| **Certificate authority** | OpenVPN_CA | Select the CA you just created |

**Certificate Attributes:**

| Field | Value | Notes |
|-------|-------|-------|
| **Key Type** | RSA | Must match CA |
| **Key Length** | `2048` bits | Match CA or higher |
| **Digest Algorithm** | SHA256 | Match CA |
| **Lifetime (days)** | `3650` | 10 years |
| **Common Name** | `OpenVPN Server` | Identifies this certificate |

**Certificate Type:**

| Field | Value | Notes |
|-------|-------|-------|
| **Certificate Type** | Server Certificate | CRITICAL: Must be server type |

**Alternative Names (Optional but Recommended):**

| Field | Value | Notes |
|-------|-------|-------|
| **Alternative Names - Type** | FQDN or Hostname | If you have a domain name |
| **Alternative Names - Value** | `vpn.yourdomain.com` | Your VPN server's hostname |

#### 3.4 Save Certificate

1. Scroll to bottom
2. Click **Save**

---

### Step 4: Configure OpenVPN Server

#### 4.1 Navigate to OpenVPN Server

1. Click **VPN** in top menu
2. Select **OpenVPN**
3. Click on **Servers** tab

#### 4.2 Create New OpenVPN Server

1. Click **+ Add** button

#### 4.3 General Information

| Field | Value | Notes | What This Does |
|-------|-------|-------|----------------|
| **Disabled** | ❌ Unchecked | Server is active | Checking this would disable the VPN server |
| **Server Mode** | Remote Access (SSL/TLS + User Auth) | Requires both cert and user/pass | Enforces two-factor authentication: certificate AND password |
| **Backend for authentication** | Local Database | Use pfSense user accounts | Uses users created in pfSense; alternatives: RADIUS, LDAP for enterprise |
| **Device Mode** | tun | Layer 3 tunnel (routed) | Creates routed tunnel; "tap" would be bridged (Layer 2) - tun is standard |
| **Interface** | WAN | VPN accepts connections from internet | Must be WAN so external users can connect |
| **Protocol** | UDP on IPv4 only | Recommended for performance | UDP is faster than TCP; TCP-over-TCP causes issues |
| **Local Port** | `1194` | Default OpenVPN port | Standard port; change if you want to "hide" VPN or avoid blocks |

> **Why UDP?** UDP is faster and better for VPN traffic. TCP-over-TCP (TCP VPN carrying TCP applications) can cause severe performance degradation due to double retransmission.

#### 4.4 Cryptographic Settings

| Field | Value | Notes | What This Does |
|-------|-------|-------|----------------|
| **TLS Configuration** | ☑️ Use a TLS Key | Recommended | Adds extra layer of authentication; prevents unauthorized connections |
| **Automatically generate a TLS Key** | ☑️ Checked | Auto-generate | pfSense creates shared secret for TLS authentication |
| **Peer Certificate Authority** | OpenVPN_CA | Select your CA | This CA will validate all client certificates |
| **Server Certificate** | OpenVPN_Server_Cert | Select server cert | Identifies this VPN server to clients |
| **DH Parameter Length** | `2048 bit` | Default is sufficient | Diffie-Hellman for key exchange; 2048 is secure and fast |
| **Encryption Algorithm** | AES-256-GCM | Strong encryption | GCM mode provides encryption + authentication; very secure |
| **Auth Digest Algorithm** | SHA256 | Secure hash | Used for HMAC authentication; SHA256 is current standard |

> **What is TLS Authentication?**
> - Adds HMAC signature to all packets
> - Prevents DoS attacks and unauthorized connection attempts
> - Client must have the TLS key to even initiate connection
> - Acts as a "pre-authentication" layer

> **Encryption Explained:**
> - **AES-256**: Advanced Encryption Standard with 256-bit key (very strong)
> - **GCM**: Galois/Counter Mode - provides both encryption and authentication
> - This ensures data is both private and tamper-proof

#### 4.5 Tunnel Settings

**IPv4 Tunnel Network:**

| Field | Value | Notes | What This Does |
|-------|-------|-------|----------------|
| **IPv4 Tunnel Network** | `10.0.10.0/24` | VPN clients get IPs from this range | This is the "virtual network" created inside the VPN tunnel |

> **Important:** This must be a network that doesn't overlap with:
> - WAN: 10.0.2.0/24
> - LAN: 192.168.1.0/24
> - LOCAL: 192.168.10.0/24
> - GUEST: 192.168.20.0/24
> 
> We use 10.0.10.0/24 because it's private and doesn't conflict with existing networks.

**IPv4 Local Network(s):**

| Field | Value | Notes | What This Does |
|-------|-------|-------|----------------|
| **IPv4 Local Network(s)** | `192.168.10.0/24` | LOCAL network contractors can access | Routes to these networks are pushed to VPN clients |

> **What this means:**
> - When contractors connect, their VPN client learns: "To reach 192.168.10.0/24, use the VPN tunnel"
> - Traffic to 192.168.10.x goes through encrypted tunnel
> - Traffic to other destinations (like 192.168.20.0/24 or internet) does NOT go through tunnel (unless Redirect Gateway is enabled)
> 
> **To allow access to multiple networks:**
> - Enter: `192.168.10.0/24,192.168.1.0/24`
> - Separate with commas, no spaces

**IPv4 Remote Network(s):**

| Field | Value | Notes | What This Does |
|-------|-------|-------|----------------|
| **IPv4 Remote Network(s)** | (Leave blank) | Not needed for Remote Access VPN | Used for site-to-site VPNs where remote site has its own network |

**Concurrent Connections:**

| Field | Value | Notes | What This Does |
|-------|-------|-------|----------------|
| **Concurrent connections** | (Leave blank) | No limit | Limits how many contractors can connect simultaneously; blank = unlimited |

**Compression:**

| Field | Value | Notes | What This Does |
|-------|-------|-------|----------------|
| **Compression** | Disable Compression | Recommended | Compression can expose encrypted data to attacks (VORACLE); disable unless needed |

**Type-of-Service:**

| Field | Value | Notes | What This Does |
|-------|-------|-------|----------------|
| **Type-of-Service** | ❌ Unchecked | Leave default | Copies TOS bits from inner packet to outer; rarely needed |

#### 4.6 Client Settings

| Field | Value | Notes |
|-------|-------|-------|
| **Dynamic IP** | ☑️ Allow connected clients to retain their connections | Recommended |
| **Topology** | Subnet | Use subnet topology |
| **DNS Default Domain** | (Optional) | Your domain if needed |
| **DNS Server 1** | `192.168.1.1` | pfSense LAN interface (for internal DNS) |
| **DNS Server 2** | `8.8.8.8` | Google DNS (backup) |
| **DNS Server 3** | (Leave blank) | Optional |
| **DNS Server 4** | (Leave blank) | Optional |
| **NTP Server 1** | (Leave blank) | Optional |
| **NTP Server 2** | (Leave blank) | Optional |
| **NetBIOS Options** | Disable | Unless you need NetBIOS |

#### 4.7 Advanced Client Settings

**Redirect Gateway:**

| Field | Value | Notes |
|-------|-------|-------|
| **Redirect Gateway** | ❌ Unchecked | Only tunnel traffic to local network, not all internet |

> **What this means:**
> - Unchecked: Only traffic to 192.168.10.0/24 goes through VPN
> - Checked: ALL contractor internet traffic goes through VPN
> - For remote workers accessing internal resources only, leave unchecked

**Other Settings:**

| Field | Value | Notes |
|-------|-------|-------|
| **Force DNS cache update** | ❌ Unchecked | Default |
| **UDP Fast I/O** | ☑️ Checked | Improves performance (if using UDP) |

#### 4.8 Advanced Configuration

| Field | Value | Notes |
|-------|-------|-------|
| **Custom options** | (Leave blank) | Unless you have specific requirements |
| **Verbosity level** | `3` | Default logging level |

#### 4.9 Save OpenVPN Server Configuration

1. Scroll to bottom
2. Click **Save**
3. The OpenVPN service will automatically start

---

### Step 5: Create VPN User Accounts

#### 5.1 Navigate to User Manager

1. Click **System** in top menu
2. Select **User Manager**
3. Click on **Users** tab

#### 5.2 Create First Contractor User

1. Click **+ Add** button

#### 5.3 Configure User Account

**User Account Information:**

| Field | Value | Example |
|-------|-------|---------|
| **Disabled** | ❌ Unchecked | Account is active |
| **Username** | `contractor1` | Username for VPN login |
| **Password** | Strong password | Must be complex |
| **Confirm Password** | (same) | Re-enter password |
| **Full name** | Contractor's full name | `John Smith` |
| **Expiration date** | (Optional) | Set if temporary access |
| **Group membership** | (Leave default) | No special groups needed |

**Certificate Settings:**

This is CRITICAL - creates user certificate for VPN authentication.

| Field | Value | Notes |
|-------|-------|-------|
| **Certificate** | ☑️ Click to create a user certificate | Must check this |

After checking, additional fields appear:

| Field | Value | Notes |
|-------|-------|-------|
| **Descriptive name** | `contractor1-cert` | Certificate identifier |
| **Certificate authority** | OpenVPN_CA | Select your CA |
| **Key length** | `2048` bits | Standard |
| **Lifetime** | `3650` days | Match CA or shorter |
| **Certificate Type** | User Certificate | CRITICAL: Must be User type |

#### 5.4 Save User

1. Scroll to bottom
2. Click **Save**

#### 5.5 Create Additional Users

Repeat steps 5.2-5.4 for each contractor:
- contractor2
- contractor3
- etc.

Each user needs:
- Unique username
- Strong password
- Individual certificate

---

### Step 6: Configure Firewall Rules for VPN

#### 6.1 Allow VPN Connections Through WAN

Navigate to: **Firewall → Rules → WAN**

##### 6.1.1 Create Rule to Allow OpenVPN

1. Click **↑ Add** (add at top)

**Rule Configuration:**

| Field | Value | Notes |
|-------|-------|-------|
| **Action** | Pass | Allow traffic |
| **Disabled** | ❌ Unchecked | Rule is active |
| **Interface** | WAN | Traffic from internet |
| **Address Family** | IPv4 | For IPv4 traffic |
| **Protocol** | UDP | Must match OpenVPN server protocol |

**Source:**

| Field | Value | Notes |
|-------|-------|-------|
| **Source** | Any | Contractors can connect from anywhere |
| **Source Port Range** | Any | Client uses random source ports |

**Destination:**

| Field | Value | Notes |
|-------|-------|-------|
| **Destination** | WAN address | pfSense WAN interface |
| **Destination Port Range - From** | OpenVPN (1194) | Select from dropdown |
| **Destination Port Range - To** | OpenVPN (1194) | Same as From |

**Extra Options:**

| Field | Value | Notes |
|-------|-------|-------|
| **Log** | ☑️ Checked | Optional - useful for monitoring |
| **Description** | `Allow OpenVPN connections` | Descriptive text |

2. Click **Save**
3. Click **Apply Changes**

---

#### 6.2 Configure OpenVPN Interface Rules

Navigate to: **Firewall → Rules → OpenVPN**

> **Note:** This tab appears after you create an OpenVPN server.

##### 6.2.1 Create Rule to Allow VPN Client Access

1. Click **↑ Add**

**Rule Configuration:**

| Field | Value | Notes |
|-------|-------|-------|
| **Action** | Pass | Allow traffic |
| **Disabled** | ❌ Unchecked | Rule is active |
| **Interface** | OpenVPN | Traffic from VPN clients |
| **Address Family** | IPv4 | For IPv4 traffic |
| **Protocol** | Any | Allow all protocols |

**Source:**

| Field | Value | Notes |
|-------|-------|-------|
| **Source** | Any | Any VPN client |
| **Source Port Range** | Any | Any source port |

**Destination:**

| Field | Value | Notes |
|-------|-------|-------|
| **Destination** | LOCAL net | Select 192.168.10.0/24 |
| **Destination Port Range** | Any | Any port/service |

**Extra Options:**

| Field | Value | Notes |
|-------|-------|-------|
| **Log** | ❌ Unchecked | Optional |
| **Description** | `Allow VPN access to LOCAL network` | Descriptive text |

2. Click **Save**
3. Click **Apply Changes**

---

### Step 7: Export Client Configuration

#### 7.1 Navigate to Client Export

1. Click **VPN** menu
2. Select **OpenVPN**
3. Click on **Client Export** tab

#### 7.2 Configure Export Settings

**OpenVPN Server:**

| Field | Value | Notes |
|-------|-------|-------|
| **Remote Access Server** | Select your OpenVPN server | The one you created |

**Host Name Resolution:**

| Field | Value | Notes |
|-------|-------|-------|
| **Host Name Resolution** | Interface IP Address | Or use "Other" if you have a domain |
| **Host Name** | (Auto-filled) | WAN IP or domain name |

> **Important:** If your WAN IP is dynamic or behind NAT, you may need to use a DDNS hostname here.

**Verify Server CN:**

| Field | Value | Notes |
|-------|-------|-------|
| **Verify Server CN** | Automatic - Use verify-x509-name (OpenVPN 2.3+) | Recommended |

**Use Random Local Port:**

| Field | Value | Notes |
|-------|-------|-------|
| **Use Random Local Port** | ☑️ Checked | Recommended |

**Additional Configuration Options:**

| Field | Value | Notes |
|-------|-------|-------|
| **Certificate Export Options** | Standard Configuration | Default |
| **Use Microsoft Certificate Storage** | ❌ Unchecked | Unless Windows-specific need |
| **Use a Password** | ☑️ Checked | Recommended for security |

#### 7.3 Export Configuration for Contractor

Scroll down to the **OpenVPN Clients** section. You'll see each user you created:

| User | Configuration Options |
|------|----------------------|
| contractor1 | [Multiple download options] |
| contractor2 | [Multiple download options] |

**For each contractor, you can download:**

| Option | Description | When to Use |
|--------|-------------|-------------|
| **Most Clients** | Standard `.ovpn` file with inline certificates | Easiest - all-in-one file for most OpenVPN clients |
| **Archive** | ZIP file with separate cert files | If client doesn't support inline configs |
| **Windows Installer** | `.exe` installer for Windows | Windows users with OpenVPN GUI |
| **Viscosity** | Config for Viscosity VPN client | macOS/Windows Viscosity users |

**For this lab, download: "Most Clients" (inline configuration)**

1. Click the download button next to the contractor user
2. Save the file (e.g., `pfSense-UDP4-1194-contractor1-inline.ovpn`)
3. Securely send to contractor via:
   - Encrypted email
   - Secure file sharing (OneDrive, Dropbox with password)
   - Hand delivery on USB drive
   - Company secure portal

> **⚠️ SECURITY IMPORTANT:**
> - This file contains the user's certificate and keys
> - Treat it like a password - send securely
> - Never send via unencrypted email
> - Instruct user to store securely and not share

#### 7.4 Repeat for All Contractors

Export configuration for each user:
- contractor1
- contractor2
- contractor3
- etc.

Each user gets their **own unique configuration** with their **own certificate**.

---

### Step 8: Install OpenVPN Client on Test VM

Before you can test the VPN, you need to install the OpenVPN client software on your test machine.

#### 8.1 Download OpenVPN Package

**On Kali Linux (or Debian/Ubuntu-based system):**

If your VM has internet access:
```bash
# Download OpenVPN package directly
wget http://http.kali.org/kali/pool/main/o/openvpn/openvpn_2.7.0~rc3-1_amd64.deb

# Or for older version
wget http://http.kali.org/kali/pool/main/o/openvpn/openvpn_2.7.0~rc2-2_amd64.deb
```

**If VM cannot access internet:**
1. Download on host machine from: http://http.kali.org/kali/pool/main/o/openvpn/
2. Transfer to VM via:
   - **Shared folder** (VirtualBox: Devices → Shared Folders)
   - **USB drive** mapped to VM
   - **SCP:** `scp openvpn_2.7.0~rc2-2_amd64.deb user@vm-ip:/home/user/`

**On Windows:**
1. Download OpenVPN GUI from: https://openvpn.net/community-downloads/
2. Run installer with administrator privileges
3. Complete installation wizard

**On macOS:**
1. Download Tunnelblick from: https://tunnelblick.net/
2. Open DMG file and drag to Applications
3. Launch Tunnelblick and grant permissions

#### 8.2 Install OpenVPN (Linux)

```bash
# Navigate to download location
cd ~/Downloads

# Install the downloaded package
sudo dpkg -i openvpn_2.7.0~rc2-2_amd64.deb

# If dependency errors occur, run:
sudo apt --fix-broken install
```

#### 8.3 Verify Installation

```bash
openvpn --version
```

**Expected Output:**
```
OpenVPN 2.7_rc2 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] [DCO]
library versions: OpenSSL 3.5.2 5 Aug 2025, LZO 2.10
DCO version: N/A
Originally developed by James Yonan
Copyright (C) 2002-2025 OpenVPN Inc
```

✅ OpenVPN is now installed and ready to use.

---

### Step 9: Download VPN Configuration from pfSense

#### 9.1 Export Configuration File

In pfSense:
1. Go to **VPN → OpenVPN → Client Export**
2. Scroll down to the user you want to test (e.g., `contractor1`)
3. Under "Most Clients", click on **Inline Configurations**

**Download the file** - it will be named something like:
- `pfSense-UDP4-1194-contractor1-inline.ovpn` (inline config)
- Or download the **Archive** (ZIP file) which includes all certificates separately

#### 9.2 Transfer Configuration to Test VM

**Option A: Via Browser on VM**
- If test VM has GUI and internet access
- Download directly to VM from pfSense

**Option B: Via Shared Folder (VirtualBox)**
1. VirtualBox: **Devices → Shared Folders → Shared Folder Settings**
2. Click **+** to add folder
3. **Folder Path:** Select host directory containing `.ovpn` file
4. **Folder Name:** `vpn_configs`
5. **Auto-mount:** ☑️ Check
6. Click **OK**
7. Access in VM: 
   - Linux: `/media/sf_vpn_configs/`
   - Windows: `\\vboxsvr\vpn_configs`

**Option C: Via SCP (if VMs have networking)**
```bash
# From host or another machine
scp pfSense-UDP4-1194-config.zip user@vm-ip:/home/user/Desktop/
```

**Option D: Via USB Drive**
1. Map USB drive to VM (Devices → USB → select drive)
2. Copy file from USB to VM desktop

---

### Step 10: Prepare and Test VPN Connection

#### 10.1 Extract Configuration (if using ZIP)

```bash
# Navigate to where you saved the file
cd ~/Desktop

# List files to confirm
ls -la

# Extract the ZIP file
unzip pfSense-UDP4-1194-config.zip -d ~/Desktop/pfSenseVPN/
```

**Extracted files:**
```
pfSenseVPN/
└── pfSense-UDP4-1194/
    ├── pfSense-UDP4-1194.ovpn          # Main configuration
    ├── pfSense-UDP4-1194-ca.crt        # Certificate Authority cert
    └── pfSense-UDP4-1194-tls.key       # TLS authentication key
```

#### 10.2 Automated Connection Script

Create a bash script to automatically connect:

**Create the script:**
```bash
nano ~/Desktop/connect_vpn.sh
```

**Paste this content:**
```bash
#!/bin/bash

# Set variables
ZIP_FILE=~/Desktop/pfSense-UDP4-1194-config.zip
DEST_DIR=~/Desktop/pfSenseVPN

# 1. Unzip the pfSense VPN package
mkdir -p "$DEST_DIR"
unzip -o "$ZIP_FILE" -d "$DEST_DIR"

# Find the extracted folder
EXTRACTED_FOLDER=$(find "$DEST_DIR" -maxdepth 1 -type d -name "pfSense-UDP4-1194*")

# 2. Fix the .ovpn file paths (if needed)
OVPN_FILE=$(find "$EXTRACTED_FOLDER" -name "*.ovpn")
sed -i "s|ca .*|ca $EXTRACTED_FOLDER/pfSense-UDP4-1194-ca.crt|g" "$OVPN_FILE"
sed -i "s|tls-auth .*|tls-auth $EXTRACTED_FOLDER/pfSense-UDP4-1194-tls.key 1|g" "$OVPN_FILE"

# 3. Run OpenVPN
echo "Starting OpenVPN..."
sudo openvpn --config "$OVPN_FILE"
```

**Save and run:**
```bash
# Save (Ctrl+O, Enter, Ctrl+X)

# Make executable
chmod +x ~/Desktop/connect_vpn.sh

# Run
~/Desktop/connect_vpn.sh
```

#### 10.3 Manual Connection (Alternative)

If you prefer manual connection:

```bash
# Navigate to extracted folder
cd ~/Desktop/pfSenseVPN/pfSense-UDP4-1194/

# Connect to VPN
sudo openvpn --config pfSense-UDP4-1194.ovpn
```

#### 10.4 Enter Credentials

When prompted:
```
Enter Auth Username: contractor1
Enter Auth Password: ••••••••
```

**What happens next (successful connection):**
```
2025-12-14 05:38:55 DEPRECATED: --persist-key option ignored. Keys are now always persisted across restarts.
2025-12-14 05:38:55 OpenVPN 2.7_rc2 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL]
2025-12-14 05:38:55 library versions: OpenSSL 3.5.2 5 Aug 2025, LZO 2.10
2025-12-14 05:38:55 DCO version: N/A
2025-12-14 05:39:22 TCP/UDP: Preserving recently used remote address: [AF_INET]10.0.2.15:1194
2025-12-14 05:39:22 UDPv4 link local: (not bound)
2025-12-14 05:39:22 UDPv4 link remote: [AF_INET]10.0.2.15:1194
2025-12-14 05:39:22 WARNING: this configuration may cache passwords in memory -- use the auth-nocache option to prevent this
2025-12-14 05:39:22 [OpenVPN Server] Peer Connection Initiated with [AF_INET]10.0.2.15:1194
2025-12-14 05:39:24 TUN/TAP device tun0 opened
2025-12-14 05:39:24 tun/tap device [tun0] opened
2025-12-14 05:39:24 net_iface_mtu_set: mtu 1500 for tun0
2025-12-14 05:39:24 net_iface_up: set tun0 up
2025-12-14 05:39:24 net_addr_v4_add: 10.0.10.2/24 dev tun0
2025-12-14 05:39:24 /usr/libexec/openvpn/dns-updown
setting DNS using resolv.conf file
2025-12-14 05:39:24 dns up command exited with status 0
2025-12-14 05:39:24 Initialization Sequence Completed
```

**✅ "Initialization Sequence Completed" = VPN is connected!**

**Key lines to look for:**
- `TUN/TAP device tun0 opened` - Virtual network interface created
- `net_addr_v4_add: 10.0.10.2/24 dev tun0` - VPN IP assigned
- `Initialization Sequence Completed` - Connection successful

---

### Step 11: Test VPN Connection
