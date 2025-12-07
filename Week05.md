# pfSense Firewall Setup - Complete Beginner's Guide
## (Explained Like You're Learning for the First Time!)

---

## 🎯 What We're Going to Build

Imagine you're building a security guard station for your digital neighborhood:
- **pfSense** = The security guard who checks everyone coming in and out
- **Kali Linux** = A computer inside your protected neighborhood
- **VirtualBox** = The playground where we build this safely

By the end, you'll have a working firewall that can block bad websites and protect your network!

---

## 📋 Before You Start - What You Need

### Your Computer Needs:
- Windows, Mac, or Linux computer
- At least 8GB of RAM (more is better!)
- At least 60GB of free hard drive space
- Internet connection to download files

### Time Needed:
- 2-3 hours for first-time setup
- Don't rush! Take breaks if needed

---

## Part 1: Downloading Everything (30 minutes)

### Step 1.1: Get VirtualBox (The Playground)

**What is VirtualBox?**
Think of it as a "computer simulator" that lets you run fake computers inside your real computer. It's completely safe!

**Do This Now:**
1. Open your web browser
2. Go to: `https://www.virtualbox.org/wiki/Downloads`
3. Click the big blue button for your computer type:
   - Windows? Click "Windows hosts"
   - Mac? Click "macOS hosts"
   - Linux? Click "Linux distributions"
4. Wait for the file to download (it's about 100MB)
5. Double-click the downloaded file
6. Click "Next" → "Next" → "Yes" → "Install"
7. If Windows asks "Do you trust this?", click "Yes"
8. Click "Finish" when done

**✅ How to know it worked:**
- You should see a new program called "Oracle VM VirtualBox" on your computer

---

### Step 1.2: Download pfSense (The Security Guard)

**Do This Now:**
1. Go to: `https://www.pfsense.org/download/`
2. You'll see a form with dropdowns. Choose these:
   - **Architecture**: AMD64 (64-bit) ← This works for most computers
   - **Installer**: DVD Image (ISO) Installer
   - **Mirror**: Choose one close to your country
3. Click the big "Download" button
4. Wait for the download (it's about 800MB - time for a snack!)
5. Save it somewhere you'll remember (like your Downloads folder)

**✅ The file should be named something like:**
`pfSense-CE-2.8.1-RELEASE-amd64.iso`

---

### Step 1.3: Download Kali Linux (The Computer to Protect)

**Do This Now:**
1. Go to: `https://www.kali.org/get-kali/#kali-virtual-machines`
2. Scroll down to "Virtual Machines"
3. Click the "VirtualBox" tab
4. Click the "64-bit" download button
5. This is a BIG file (3-4GB) - might take 30-60 minutes!
6. Save it to your Downloads folder

**✅ The file should be named something like:**
`kali-linux-2024.4-virtualbox-amd64.7z`

**Extra Step: Extract Kali**
1. Right-click the downloaded file
2. Choose "Extract All" (Windows) or use an app like "The Unarchiver" (Mac)
3. Wait for extraction to finish
4. You should now have a file ending in `.ova`

---

## Part 2: Building the pfSense Security Guard (45 minutes)

### Step 2.1: Create a New Virtual Machine

**Do This Now:**
1. Open VirtualBox (that program we installed)
2. Click the blue "New" button at the top
3. A window pops up - fill it in:

   **Name and Operating System screen:**
   - Name: Type `pfSense`
   - Folder: Leave it as default
   - Type: Choose "BSD" from the dropdown
   - Version: Choose "FreeBSD (64-bit)"
   
4. Click "Next"

**Memory (RAM) screen:**
5. Move the slider to **2048 MB** (that's 2GB)
6. Click "Next"

**Hard Disk screen:**
7. Choose "Create a virtual hard disk now"
8. Click "Create"

**Hard Disk Type screen:**
9. Choose "VDI (VirtualBox Disk Image)"
10. Click "Next"

**Storage screen:**
11. Choose "Dynamically allocated"
12. Click "Next"

**Size screen:**
12. Set size to **20 GB**
13. Click "Create"

**✅ You should now see "pfSense" in your VM list on the left!**

---

### Step 2.2: Configure pfSense VM (IMPORTANT!)

**Do This Now:**
1. Click on "pfSense" in the list (to highlight it)
2. Click the orange "Settings" button at the top
3. Now we'll change several things...

**System Settings:**
4. Click "System" on the left
5. Click the "Processor" tab at the top
6. Change "Processor(s)" to **2**
7. Keep this window open - don't click OK yet!

**Network Settings (SUPER IMPORTANT!):**
8. Click "Network" on the left
9. Click the "Adapter 1" tab:
   - Check "Enable Network Adapter" ✓
   - "Attached to": Choose **NAT**
   - This is pfSense's "internet connection"
   
10. Click the "Adapter 2" tab:
    - Check "Enable Network Adapter" ✓
    - "Attached to": Choose **Internal Network**
    - "Name": Type `LAN` (exactly like that!)
    - This is pfSense's "protected network"

**Storage Settings:**
11. Click "Storage" on the left
12. You'll see a tree-like list. Click where it says "Empty" under "Controller: IDE"
13. On the right side, click the little CD icon (💿)
14. Click "Choose a disk file..."
15. Find and select the pfSense ISO file you downloaded
16. Click "Open"

17. **NOW** click "OK" at the bottom to save everything!

**✅ Double-check:**
- Adapter 1 = NAT
- Adapter 2 = Internal Network named "LAN"
- ISO file is loaded in the CD drive

---

### Step 2.3: Install pfSense (The Exciting Part!)

**Do This Now:**
1. Double-click "pfSense" in your VM list
2. A new window opens - you'll see lots of text scrolling (this is normal!)
3. Wait about 30 seconds...

**Installation Menu:**
4. You'll see a menu with options. Type `I` (for Install)
5. Press Enter

**Keymap Selection:**
6. Press Enter (to accept default "US" keyboard)

**Partition (Automatic):**
7. Press Enter (to accept "Auto (UFS)")

**Installation Progress:**
8. Wait 2-3 minutes while it copies files
9. You'll see a progress bar

**Final Reboot:**
10. When it says "Complete", select "Reboot"
11. Press Enter
12. The VM will restart - wait about 1 minute

**First Boot Menu:**
13. You'll see "Welcome to pfSense" and lots of text
14. Eventually you'll see a menu with options 0-15
15. Just wait here! Don't press anything yet.

**✅ You should see:**
- WAN (em0) → v4: Some IP like 10.0.2.15
- LAN (em1) → v4: 192.168.1.1

---

### Step 2.4: Basic pfSense Configuration

**Understanding what you see:**
- **WAN** = pfSense's internet connection (from VirtualBox)
- **LAN** = pfSense's protected network (where we'll put Kali)
- The numbers (192.168.1.1) are like street addresses for computers

**Do This Now:**

**Option 2 - Set Interface IP:**
1. Type `2` and press Enter
2. "Available interfaces:" → Type `2` (for LAN)
3. Press Enter

**Configure LAN:**
4. "Configure IPv4 via DHCP?" → Type `n` (no)
5. "Enter new LAN IPv4 address:" → Type `192.168.1.1`
6. Press Enter
7. "Enter subnet bit count:" → Type `24`
8. Press Enter
9. "For a WAN, press enter:" → Just press Enter (no upstream gateway)
10. "Configure IPv6?" → Type `n` (we're keeping it simple)

**Enable DHCP Server:**
11. "Enable DHCP server on LAN?" → Type `y` (yes)
12. "Start address of range:" → Type `192.168.1.100`
13. Press Enter
14. "End address of range:" → Type `192.168.1.200`
15. Press Enter
16. "Revert to HTTP?" → Type `n` (keep HTTPS)

**✅ You should see:**
- LAN configuration updated
- DHCP server enabled
- Back at the main menu

---

## Part 3: Adding Kali Linux (30 minutes)

### Step 3.1: Import Kali Linux VM

**Do This Now:**
1. Go back to the main VirtualBox window (not the pfSense console)
2. Click "File" → "Import Appliance..."
3. Click the folder icon on the right
4. Find the Kali `.ova` file you extracted earlier
5. Click "Open"
6. Click "Next"
7. You'll see settings - leave them all as default
8. Click "Import"
9. Wait 3-5 minutes (time for another snack!)

**✅ You should now see "Kali Linux" in your VM list**

---

### Step 3.2: Configure Kali Network (CRITICAL!)

**Do This Now:**
1. Click on "Kali Linux" in the list (to highlight it)
2. Click the orange "Settings" button
3. Click "Network" on the left
4. Click the "Adapter 1" tab:
   - Check "Enable Network Adapter" ✓
   - "Attached to": Choose **Internal Network**
   - "Name": Type `LAN` (MUST match pfSense!)
5. Click "OK"

**✅ Double-check:**
- Kali is on "Internal Network" named "LAN"
- This puts Kali "behind" the pfSense firewall

---

### Step 3.3: Start Both VMs

**Do This Now:**
1. Double-click "pfSense" to start it (if not already running)
2. Wait for it to show the menu (with options 0-15)
3. Double-click "Kali Linux" to start it
4. Wait for Kali to boot (about 1 minute)
5. You should see a login screen

**Login to Kali:**
6. Username: `kali`
7. Password: `kali`
8. Press Enter

**✅ You should be at the Kali desktop now!**

---

## Part 4: Testing the Firewall Connection (15 minutes)

### Step 4.1: Check Kali's IP Address

**Do This Now:**
1. In Kali, click the terminal icon at the top (it looks like >_)
2. Type this command and press Enter:
```bash
ip addr show eth0
```

3. Look for a line that says "inet" followed by numbers
4. You should see something like: `192.168.1.100`

**What if it doesn't show an IP?**
- Type: `sudo dhclient eth0`
- Enter password: `kali`
- Wait 5 seconds, then try `ip addr show eth0` again

**✅ Good sign:** You have an IP starting with 192.168.1.xxx

---

### Step 4.2: Test Connection to pfSense

**Do This Now:**
1. In the Kali terminal, type:
```bash
ping -c 4 192.168.1.1
```

2. You might see "Destination unreachable" - that's OK!
3. The important thing is pfSense received the ping

**Now test internet:**
4. Type:
```bash
ping -c 4 8.8.8.8
```

5. You should see replies! Like:
```
64 bytes from 8.8.8.8: icmp_seq=1 ttl=115 time=15.2 ms
```

**✅ If you see replies, your firewall is working!**

---

### Step 4.3: Access pfSense Web Interface

**This is where it gets cool!**

**Do This Now:**
1. In Kali, open Firefox browser (click the Firefox icon)
2. In the address bar, type: `http://192.168.1.1`
3. Press Enter
4. You'll see a security warning - click "Advanced" → "Accept Risk"

**Login Page:**
5. Username: `admin`
6. Password: `pfsense`
7. Click "Sign In"

**Setup Wizard:**
8. Click "Next" through the wizard:
   - Next → Next
   - Hostname: `pfSense` (leave it)
   - Domain: `localdomain` (leave it)
   - Next
   - Primary DNS: `8.8.8.8`
   - Next
   - Timezone: Choose your timezone
   - Next
   - WAN: Leave as DHCP
   - Next
   - LAN: Should show 192.168.1.1
   - Next
   - **Change admin password to something you'll remember!**
   - Next → Reload → Finish

**✅ You should now see the pfSense Dashboard!**

---

## Part 5: Understanding Firewall Rules (10 minutes)

### What Are Firewall Rules?

**Simple explanation:**
Firewall rules are like a bouncer's checklist at a club:
- "Is this person on the VIP list?" → ALLOW
- "Is this person banned?" → BLOCK
- "Are they wearing the right clothes?" → CHECK CRITERIA

**In pfSense:**
- Rules are checked from TOP to BOTTOM
- FIRST matching rule wins (like first come, first served)
- If no rule matches, the DEFAULT action happens

**Important Rule Parts:**
1. **Action**: Block, Reject, or Allow (Pass)
2. **Interface**: Which network connection (LAN, WAN)
3. **Protocol**: TCP, UDP, ICMP, or Any
4. **Source**: Where is the traffic coming FROM?
5. **Destination**: Where is the traffic going TO?
6. **Port**: Which service (80=HTTP, 443=HTTPS, 22=SSH)

### Block vs Reject - What's the Difference?

**Block:**
- Silently drops the packet (pretends you don't exist)
- Attacker doesn't know if firewall is there
- More secure but slower timeout

**Reject:**
- Sends back "connection refused" message
- Faster for legitimate users
- Reveals firewall presence

**Tip:** Use Block for external threats, Reject for internal testing!

---

## Part 6: Creating Firewall Rules - Multiple Examples (45 minutes)

### Rule #1: Block HTTP Traffic (Force HTTPS)

**Why do this?**
- HTTP sends passwords in plain text (dangerous!)
- HTTPS encrypts everything
- This forces secure connections

**Do This Now:**
1. In pfSense, click "Firewall" → "Rules"
2. Click the "LAN" tab
3. Click the ↑ with green + (Add rule to top)

**Fill in the form:**
4. **Action**: Choose "Block"
5. **Disabled**: Leave UNCHECKED
6. **Interface**: "LAN"
7. **Address Family**: "IPv4"
8. **Protocol**: "TCP"

**Source section:**
9. **Source**: 
   - Click dropdown → Choose "LAN net"
   - This means "anyone on our network"

**Destination section:**
10. **Destination**: Leave as "any"
11. **Destination Port Range**:
    - From: Type `HTTP` or choose from dropdown, or type `80`
    - To: Should auto-fill to same value

**Extra options at bottom:**
12. **Description**: "Block HTTP - Force HTTPS only"
13. Click "Save"
14. Click "Apply Changes" button at top

**Order matters!**
15. Your new rule should be at the TOP
16. The "Default allow LAN to any" rule should be BELOW it

**✅ Rule created! Now test it...**

---

### Testing Rule #1

**Test 1: HTTPS still works**
1. In Kali Firefox, try: `https://www.google.com`
2. Should load fine! ✓

**Test 2: HTTP is blocked**
3. Try: `http://neverssl.com`
4. Should NOT load (timeout or error)! ✓

**Test 3: Command line test**
5. In Kali terminal:
```bash
curl -I http://example.com
```
6. Should fail/timeout ✓

7. Now try:
```bash
curl -I https://example.com
```
8. Should work and show "200 OK"! ✓

**View the block in action:**
9. In pfSense, go to: Status → System Logs → Firewall
10. You'll see red lines showing blocked HTTP attempts!

**✅ HTTP is now blocked on your network!**

---

### Rule #2: Block Social Media (Facebook, Instagram, Twitter)

**Why do this?**
- Reduce distractions during work/study
- Save bandwidth
- Parental controls
- Corporate policy enforcement

**Do This Now:**
1. Firewall → Rules → LAN
2. Click ↑ with green + (Add to top)

**Fill in the form:**
3. **Action**: "Block"
4. **Interface**: "LAN"
5. **Address Family**: "IPv4"
6. **Protocol**: "TCP/UDP"

**Source:**
7. **Source**: "LAN net"

**Destination:**
8. **Destination**: Click "Single host or alias"
9. In the box that appears, we'll create an alias...

**Wait! We need to create an alias first!**

---

### Creating an Alias (List of Websites)

**What's an alias?**
Think of it like a contact group in your phone:
- Instead of texting 10 people individually
- You create a group "Family" and text once
- Aliases group IP addresses or domains together!

**Do This Now:**
1. Open a new browser tab (keep the rule tab open!)
2. Go to: Firewall → Aliases
3. Click "Add" (green + button)

**Fill in the alias:**
4. **Name**: `Social_Media` (no spaces!)
5. **Description**: "Block Facebook, Instagram, Twitter"
6. **Type**: "Host(s)"

**Add the entries:**
7. Click "Add Host" button
8. In the first box, type: `facebook.com`
9. Description: "Facebook"
10. Click "Add Host" again
11. Type: `instagram.com` - Description: "Instagram"
12. Click "Add Host" again
13. Type: `twitter.com` - Description: "Twitter"
14. Click "Add Host" again
15. Type: `www.facebook.com` - Description: "Facebook WWW"
16. Click "Add Host" again
17. Type: `www.instagram.com` - Description: "Instagram WWW"

18. Click "Save"
19. Click "Apply Changes"

**✅ Alias created! Now back to the rule...**

---

### Completing Rule #2

**Do This Now:**
1. Go back to your rule tab (or Firewall → Rules → LAN → Edit the partial rule)
2. **Destination**: Choose "Single host or alias"
3. In the dropdown that appears, choose: `Social_Media`
4. **Destination Port**: Leave as "any"

**Bottom section:**
5. **Description**: "Block Social Media Sites"
6. Click "Save"
7. Click "Apply Changes"

**✅ Now test it!**

---

### Testing Rule #2

**Test in browser:**
1. In Kali, try to visit: `http://facebook.com`
2. Should timeout or fail! ✓
3. Try: `https://facebook.com`
4. Should also fail! ✓

**Note about DNS:**
- Some sites might still appear briefly
- This is DNS caching
- Solution: Use pfBlockerNG for better domain blocking (we'll do this later!)

**Test with ping:**
```bash
ping facebook.com
```
- Might still work! (We blocked web traffic, not ICMP pings)

**✅ Social media is blocked!**

---

### Rule #3: Block Specific Computer from Internet

**Why do this?**
- Quarantine infected device
- Restrict guest devices
- Parental controls for specific computer
- Troubleshooting network issues

**Scenario:** Block Kali VM from accessing internet (for testing)

**Do This Now:**
1. First, find Kali's IP address
2. In Kali terminal:
```bash
ip addr show eth0 | grep inet
```
3. Write down the IP (something like 192.168.1.100)

**Create the rule:**
4. Firewall → Rules → LAN → Add ↑
5. **Action**: "Block"
6. **Interface**: "LAN"
7. **Protocol**: "Any"

**Source (THIS IS KEY!):**
8. **Source**: Choose "Single host or alias"
9. In the box, type Kali's IP: `192.168.1.100`

**Destination:**
10. **Destination**: "any"
11. **Destination Port**: "any"

12. **Description**: "Block Kali VM from Internet"
13. Click "Save"
14. Click "Apply Changes"

**✅ Rule created!**

---

### Testing Rule #3

**Test from Kali:**
1. Try to ping Google:
```bash
ping 8.8.8.8
```
2. Should FAIL! ✓

3. Try to browse any website
4. Should FAIL! ✓

**But you can still access pfSense:**
```bash
ping 192.168.1.1
```
5. Should WORK! (Local network access remains) ✓

**To undo this (restore internet):**
6. Go to Firewall → Rules → LAN
7. Find the "Block Kali VM" rule
8. Click the ✓ checkbox on the left (disables rule)
9. Click "Apply Changes"

**✅ Kali is blocked from internet!**

---

### Rule #4: Allow Only Specific Ports (Whitelist Approach)

**Why do this?**
- Maximum security
- Only allow what you need
- Block everything else
- Good for servers or kiosks

**Scenario:** Only allow web browsing (HTTP/HTTPS) and DNS

**⚠️ WARNING:** This will block everything except web browsing!

**Do This Now:**

**First, let's allow DNS (required for websites to work):**
1. Firewall → Rules → LAN → Add ↑
2. **Action**: "Pass" (Pass = Allow)
3. **Interface**: "LAN"
4. **Protocol**: "UDP"
5. **Source**: "LAN net"
6. **Destination**: "any"
7. **Destination Port**: "DNS (53)"
8. **Description**: "Allow DNS queries"
9. Save → Apply Changes

**Allow HTTPS:**
10. Add another rule ↑
11. **Action**: "Pass"
12. **Protocol**: "TCP"
13. **Source**: "LAN net"
14. **Destination**: "any"
15. **Destination Port**: "HTTPS (443)"
16. **Description**: "Allow HTTPS browsing"
17. Save → Apply Changes

**Allow HTTP (optional):**
18. Add another rule ↑
19. **Action**: "Pass"
20. **Protocol**: "TCP"
21. **Source**: "LAN net"
22. **Destination**: "any"
23. **Destination Port**: "HTTP (80)"
24. **Description**: "Allow HTTP browsing"
25. Save → Apply Changes

**Block everything else:**
26. Find the "Default allow LAN to any" rule
27. Click the pencil icon to edit it
28. Change **Action** from "Pass" to "Block"
29. Change **Description** to "Block all other traffic"
30. Save → Apply Changes

**✅ Only web browsing is now allowed!**

---

### Testing Rule #4

**What should work:**
- ✓ Web browsing (HTTP/HTTPS)
- ✓ DNS lookups

**What should fail:**
- ✗ SSH (port 22)
- ✗ FTP (port 21)
- ✗ Ping (ICMP)
- ✗ Gaming
- ✗ Streaming apps

**Test it:**
```bash
# This should work
curl https://google.com

# This should fail
ping 8.8.8.8

# This should fail
ssh user@example.com
```

**To undo (restore full access):**
- Edit the "Block all other traffic" rule
- Change Action back to "Pass"
- Apply Changes

**✅ Whitelist rules are working!**

---

### Rule #5: Time-Based Rules (Block After Hours)

**Why do this?**
- Enforce bedtime for kids
- Block gaming during work hours
- Reduce after-hours company usage
- Schedule internet downtime

**⚠️ Note:** pfSense doesn't have built-in time schedules, but we can work around it!

**Method 1: Create Schedule (Advanced Package)**
1. System → Package Manager → Available Packages
2. Search for "Schedule" or use cron jobs
3. Install scheduling package if available

**Method 2: Manual Enable/Disable**
1. Create the rule as normal
2. Click the ✓ checkbox to disable when not needed
3. Click Apply Changes

**Method 3: Using pfBlockerNG (Recommended)**
- pfBlockerNG has scheduling built-in
- We'll cover this in the pfBlockerNG section!

---

### Rule #6: Block Torrenting / P2P Traffic

**Why do this?**
- Save bandwidth
- Prevent copyright issues
- Comply with company policy
- Block malware distribution

**Common P2P Ports:**
- BitTorrent: 6881-6889, 6969
- uTorrent: 6881-6999
- Others: Various high ports

**Do This Now:**
1. Firewall → Rules → LAN → Add ↑
2. **Action**: "Block"
3. **Interface**: "LAN"
4. **Protocol**: "TCP/UDP"
5. **Source**: "LAN net"
6. **Destination**: "any"

**Destination Port (This is the tricky part):**
7. **Destination Port Range**: 
   - From: "Other" → Type `6881`
   - To: "Other" → Type `6999`

8. **Description**: "Block BitTorrent ports"
9. Save → Apply Changes

**Add more rules for other P2P protocols:**
10. Repeat for ports: 4662 (eMule), 1214 (Kazaa), etc.

**✅ Torrenting ports are blocked!**

---

### Rule #7: Geo-Blocking (Block Countries)

**Why do this?**
- Block traffic from high-risk countries
- Comply with GDPR/data laws
- Reduce attack surface
- Block regions you don't do business with

**Requirements:**
- pfBlockerNG installed (we'll do this next!)
- Or use MaxMind GeoIP database

**Quick version (using pfBlockerNG):**
1. We'll cover this in detail in Part 7!
2. pfBlockerNG → IP → GeoIP
3. Select countries to block
4. Save and update

**✅ Coming up in pfBlockerNG section!**

---

### Understanding Rule Order (CRITICAL!)

**THE GOLDEN RULE:**
**First match wins! Rules are processed TOP to BOTTOM.**

**Example Problem:**
```
Rule 1 (Bottom): Allow all traffic from LAN
Rule 2 (Top): Block Facebook

Result: Facebook is still blocked ✓ (Rule 2 checked first)
```

**Another Example:**
```
Rule 1 (Top): Allow all traffic from LAN
Rule 2 (Bottom): Block Facebook

Result: Facebook is ALLOWED! ✗ (Rule 1 matched first)
```

**How to reorder rules:**
1. Click the + icon next to a rule
2. Drag and drop to reorder
3. Apply Changes

**Best Practice Order (Top to Bottom):**
1. Block specific threats (malware IPs)
2. Block services (torrents, social media)
3. Block protocols (HTTP)
4. Allow specific needed traffic (DNS, HTTPS)
5. Default allow/block rule (at bottom)

**✅ Order matters more than you think!**

---

## Part 7: Viewing and Managing Rules (10 minutes)

### Reading the Rules Table

**Do This Now:**
1. Go to: Firewall → Rules → LAN
2. You'll see a table with columns:

**Column meanings:**
- **↑/↓ arrows**: Drag to reorder
- **✓ checkbox**: Enable/disable rule (green=enabled, gray=disabled)
- **Protocol**: TCP, UDP, ICMP, etc.
- **Source**: Where traffic comes FROM
- **Port**: Source port (usually "any")
- **Destination**: Where traffic goes TO
- **Port**: Destination port (the service)
- **Gateway**: Which internet connection to use
- **Queue**: Traffic shaping/priority
- **Schedule**: Time-based rules
- **Description**: Your notes
- **Actions**: Edit (✏️), Copy, Delete (🗑️)

---

### Rule Statistics

**See how many packets hit each rule:**
1. Status → System Logs → Firewall
2. You'll see real-time blocked/allowed traffic
3. Click "Normal View" at the top

**Viewing per-rule stats:**
1. Diagnostics → pfTop
2. Shows live traffic and which rules it matches
3. Press 'q' to quit

**✅ Now you can see what your rules are doing!**

---

### Temporarily Disable a Rule

**Do This Now:**
1. Firewall → Rules → LAN
2. Click the green ✓ checkbox next to any rule
3. It turns gray (disabled)
4. Click "Apply Changes"
5. Rule is now inactive but saved!

**To re-enable:**
- Click the gray ✓ again
- Turns green
- Apply Changes

**✅ Great for testing without deleting rules!**

---

### Copying a Rule (Make Variations)

**Do This Now:**
1. Find a rule you want to copy
2. Click the + icon with two pages (copy)
3. Modify the copied rule
4. Save → Apply Changes

**Use case:**
- Block Facebook AND Instagram
- Copy the "Block Facebook" rule
- Change destination to Instagram
- Now you have two similar rules quickly!

**✅ Saves time creating similar rules!**

---

### Deleting Rules

**Do This Now:**
1. Click the 🗑️ (trash) icon next to a rule
2. Confirm deletion
3. Click "Apply Changes"

**⚠️ WARNING:** Can't undo! Rule is gone!

**Tip:** Disable first, test, THEN delete if sure!

**✅ Remove rules you don't need!**

---

## Part 8: Common Rule Mistakes (Learn from Others!)

### Mistake #1: Wrong Rule Order

**Problem:**
```
Rule 1: Allow all LAN traffic
Rule 2: Block Facebook
```
Result: Facebook still works! (Rule 1 matched first)

**Fix:**
- Move "Block Facebook" ABOVE "Allow all"
- Apply Changes

---

### Mistake #2: Blocking pfSense Access

**Problem:**
Created a "block all" rule and now can't access pfSense web interface!

**Fix:**
1. Go to pfSense console (the VM window)
2. Type: `8` (for shell)
3. Type: `pfctl -d` (disables firewall temporarily)
4. Access web interface: http://192.168.1.1
5. Fix/delete the bad rule
6. The firewall auto-enables on reboot

**Prevention:**
- Never block traffic TO 192.168.1.1
- Always test before applying!

---

### Mistake #3: Forgot Protocol

**Problem:**
Rule blocks TCP but site uses UDP or vice versa

**Fix:**
- Change Protocol to "TCP/UDP" or "Any"
- Be specific only when you know the protocol

---

### Mistake #4: Wrong Source/Destination

**Problem:**
Confused source and destination

**Remember:**
- **Source** = WHERE IS IT COMING FROM?
- **Destination** = WHERE IS IT GOING TO?

**Example:**
Blocking Facebook:
- Source: LAN net (your computer)
- Destination: Facebook's IP (where you're trying to go)

---

### Mistake #5: Not Applying Changes

**Problem:**
Made rules but didn't click "Apply Changes"

**Fix:**
- ALWAYS click "Apply Changes" button!
- Look for the orange banner at top
- Rules don't activate until applied!

**✅ Learn from these common mistakes!**

---

## Part 9: Deep Dive - Understanding pfBlockerNG (20 minutes READ THIS FIRST!)

### What is pfBlockerNG? (Detailed Explanation)

**Simple explanation:**
It's like a phonebook of bad addresses that automatically updates itself!

**Technical explanation:**
pfBlockerNG is an add-on package for pfSense that extends its blocking capabilities beyond simple firewall rules. Think of it as pfSense's super-powered blocking assistant.

---

### pfSense vs pfBlockerNG - What's the Difference?

**pfSense (The Foundation):**
- Basic firewall that controls traffic
- Can block specific IPs or domains manually
- You create each rule by hand
- Great for blocking 1-10 things

**Example with pfSense only:**
- Want to block Facebook? Create a rule.
- Want to block Instagram? Create another rule.
- Want to block 1,000 ad servers? Create 1,000 rules! 😱

**pfBlockerNG (The Automation Layer):**
- Blocks THOUSANDS of sites automatically
- Uses "feeds" (pre-made lists) that update daily
- Blocks by category (ads, malware, tracking, etc.)
- No need to know every bad site

**Example with pfBlockerNG:**
- Want to block all ads? Enable "Ads" feed → 50,000+ ad servers blocked instantly!
- Want to block all malware sites? Enable "Malware" feed → protected!
- New threats discovered? Feeds auto-update → automatic protection!

---

### Why Do We Need pfBlockerNG?

**Scenario 1: Manual Blocking (pfSense only)**
```
You: "Block Facebook"
pfSense: ✓ Blocked facebook.com
Facebook: "Ha! We also use fbcdn.net, facebook.net, fb.com..."
You: "Block those too..."
Facebook: "We have 47 more domains and they change weekly!"
You: 😭
```

**Scenario 2: Automated Blocking (pfBlockerNG)**
```
You: "Block all social media"
pfBlockerNG: ✓ Subscribed to social media feed
Feed: 2,847 domains blocked automatically
Feed: Auto-updates weekly
You: 😎 Done!
```

---

### How pfBlockerNG Works with Encryption (SSL/TLS)

**Your Important Question:**
> "If websites use HTTPS encryption, how can pfBlockerNG read and block content? Doesn't it need to decrypt everything?"

**The Answer: It doesn't decrypt! Here's how:**

#### Method 1: DNS-Level Blocking (No Decryption Needed!)

**What happens when you visit a website:**

**Step 1: DNS Lookup (PLAINTEXT - Not encrypted!)**
```
Your Computer: "Hey DNS, what's the IP for badsite.com?"
DNS: "It's 192.168.5.50"
Your Computer: "Thanks!" → Connects to 192.168.5.50
```

**Step 2: HTTPS Connection (ENCRYPTED)**
```
Your Computer ←→ [Encrypted tunnel] ←→ badsite.com
Content is secure, pfSense cannot see inside
```

**How pfBlockerNG Blocks:**
```
Your Computer: "Hey DNS, what's the IP for badsite.com?"
pfBlockerNG: "BLOCKED! That domain is on my malware list!"
pfBlockerNG: "Here's 0.0.0.0 instead (fake IP)"
Your Computer: "Can't connect to 0.0.0.0" → Connection fails ✓
```

**Key Point:** pfBlockerNG intercepts the DNS request BEFORE encryption happens!

#### Method 2: IP-Level Blocking

**How it works:**
- pfBlockerNG has lists of bad IP addresses
- Blocks traffic to/from those IPs
- No decryption needed - just checks the destination IP

**Example:**
```
Firewall: "Where are you going?"
Traffic: "To 123.45.67.89"
Firewall: "That's a malware server IP! BLOCKED!"
```

#### When Would Decryption Be Needed? (pfBlockerNG doesn't do this!)

**SSL/TLS Inspection (Man-in-the-Middle):**
This is a completely different technique that pfBlockerNG does NOT use:

```
Your Computer ←→ pfSense (decrypts) ←→ pfSense (reads content) ←→ pfSense (re-encrypts) ←→ Website
```

**Requirements for SSL inspection:**
- Install pfSense's certificate on every device
- Significant performance impact
- Complex configuration
- Privacy concerns (pfSense can see everything!)

**Why pfBlockerNG doesn't need this:**
- DNS and IP blocking work without decryption
- Much faster and simpler
- No privacy invasion
- Blocks 99% of threats without decrypting

---

### Understanding Feeds - The Secret Sauce

**What is a Feed?**

Think of a feed like a newspaper subscription:
- You subscribe once
- New issues arrive automatically
- You don't write the content yourself

**In pfBlockerNG:**
- A feed is a URL pointing to a list of bad domains/IPs
- Lists are maintained by security researchers
- Updated daily/weekly automatically
- You just subscribe and forget!

**Feed Example:**
```
Feed URL: https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt

Contents (simplified):
192.168.1.100    # Malware server
45.67.89.123     # Botnet controller
111.222.333.444  # Phishing site
... (thousands more)
```

---

### Types of Feeds in pfBlockerNG

#### 1. IP Feeds
**What they block:** IP addresses or IP ranges

**Use cases:**
- Block entire countries (Geo-IP blocking)
- Block malware server IPs
- Block botnet command servers

**Example feeds:**
- Emerging Threats Block IPs
- Spamhaus DROP list
- FireHOL malicious IPs

#### 2. DNSBL Feeds (DNS Blacklist)
**What they block:** Domain names

**Use cases:**
- Block ad servers (doubleclick.net)
- Block tracking domains (google-analytics.com)
- Block malware domains
- Block adult content

**Example feeds:**
- EasyList (ads)
- EasyPrivacy (trackers)
- NoVirusThanks (malware)
- Malware Domain List

#### 3. GeoIP Feeds
**What they block:** Entire countries or regions

**Use cases:**
- Block countries you don't do business with
- Block high-risk regions
- Comply with data regulations

**Example:**
- Block all traffic from North Korea, Iran, etc.

---

### Popular Feeds Explained (Why So Many?)

**You asked: "Why are there so many feeds? It's confusing!"**

**Answer:** Each feed targets different threats. Think of them as specialists:

| Feed Name | What It Blocks | Why You Need It |
|-----------|----------------|-----------------|
| **EasyList** | Ad servers | Blocks visual ads on websites |
| **EasyPrivacy** | Tracking scripts | Stops companies tracking you (Google Analytics, Facebook Pixel) |
| **NoVirusThanks** | Malware domains | Blocks sites hosting viruses |
| **Malware Domain List** | Malware/phishing | Active malware campaigns |
| **Project Honeypot** | Spam IPs | Email spam sources, comment spam |
| **Spamhaus DROP** | Malicious networks | Known criminal networks |
| **Steven Black's Hosts** | Unified list | Combines multiple sources |
| **MVPS Hosts** | Ads + malware | Classic blocking list |

**Strategy:** Start with 2-3 feeds, add more as needed!

---

### DNSBL Categories - Organized Lists

**What are categories?**
Pre-grouped feeds organized by purpose:

**Common Categories:**
- **Ads** → Block advertisements
- **Trackers** → Block tracking scripts
- **Malware** → Block malicious sites
- **Phishing** → Block fake login pages
- **Adult** → Block adult content
- **Gambling** → Block gambling sites
- **Social** → Block social media

**Why categories?**
- Easy to enable/disable by purpose
- Multiple feeds under one category
- Better organization

---

### EasyList Explained (Your Specific Question)

**What is EasyList?**
- Most popular ad-blocking list in the world
- Created by Adblock Plus community in 2006
- Maintained by volunteers globally
- Updated constantly (daily)

**Who uses it?**
- AdBlock Plus browser extension
- uBlock Origin browser extension
- pfBlockerNG (for network-wide blocking)
- Pi-hole
- Millions of users worldwide

**What's in EasyList?**

**Example entries:**
```
doubleclick.net                    # Google's ad server
/pre-pixel/                        # Tracking pixel script
/pre-bit-pro.js                    # Ad injection script
googlesyndication.com              # Ad network
facebook.com/tr/                   # Facebook tracking pixel
```

**Why the weird entries like `/pre-pixel/` and `/pre-bit-pro.js`?**

These are URL patterns (paths) that match ad scripts:
- `/pre-pixel/` = Any website using this path for tracking pixels
- `/pre-bit-pro.js` = A specific JavaScript file that shows ads

**In browser extensions:** These patterns are super useful
**In pfBlockerNG:** Domain-based blocking works better

---

### Why You Can Still Access Some URLs After Adding EasyList

**You asked: "I added EasyList but can still access some URLs. Why?"**

**Reason 1: DNSBL Only Blocks Domains, Not URL Paths**

**What pfBlockerNG DNSBL blocks:**
```
✓ badsite.com              (entire domain)
✓ ads.example.com          (subdomain)
```

**What pfBlockerNG DNSBL CANNOT block:**
```
✗ example.com/ads/         (specific path on allowed domain)
✗ example.com/pre-pixel/   (path on allowed domain)
```

**Why?**
- DNS only resolves domain names to IPs
- DNS doesn't know about URL paths
- To block paths, you need HTTP inspection (different tool)

**Reason 2: Browser or Device DNS Cache**

Even after blocking, your device might remember the old DNS answer:

**Solution:**
```bash
# Windows
ipconfig /flushdns

# Linux/Mac
sudo systemd-resolve --flush-caches
# OR
sudo killall -HUP mDNSResponder

# In browser
Clear browser cache (Ctrl+Shift+Delete)
```

**Reason 3: DNS Over HTTPS (DoH) Bypass**

Some browsers use DoH, which bypasses pfSense's DNS:

**What happens:**
```
Normal:    Browser → pfSense DNS → Blocked ✓
With DoH:  Browser → Cloudflare DNS (encrypted) → Not blocked ✗
```

**Solution:**
- Disable DoH in browser settings
- Or block DoH providers in pfSense

**Reason 4: Didn't Force Update/Reload**

After adding a feed, you MUST reload:

**Do This:**
1. pfBlockerNG → Update tab
2. Click "Force Reload" for DNSBL
3. Wait 2-5 minutes

**Reason 5: Wrong Feed Format**

EasyList has two formats:
- **Browser format** (.txt with patterns) - Won't work well in DNSBL
- **Domain-only format** - Works perfectly in DNSBL

**Better feed for pfBlockerNG:**
```
Instead of: https://easylist.to/easylist/easylist.txt
Use: https://easylist.to/easylist/easylist_noelemhide.txt (domain-focused)
```

---

### Testing EasyPrivacy Feed (Your Request)

**What is EasyPrivacy?**
- Companion to EasyList
- Focuses on tracking/privacy instead of ads
- Blocks: Google Analytics, Facebook Pixel, tracking cookies, etc.

**How to Add EasyPrivacy to pfBlockerNG:**

**Method 1: Use DNSBL Category (Easiest)**
1. Firewall → pfBlockerNG → DNSBL
2. Click "DNSBL Category" tab
3. Find "EasyPrivacy" in the list
4. Check the box to enable it
5. Save
6. Update → Force Reload DNSBL

**Method 2: Add as Custom Feed**
1. Firewall → pfBlockerNG → DNSBL
2. Click "DNSBL Groups" tab
3. Click "+ Add"
4. Fill in:
   - **Name:** `EasyPrivacy`
   - **State:** `ON`
   - **Action:** `Unbound`
   - **Format:** `Auto`
   - **URL:** `https://easylist.to/easylist/easyprivacy.txt`
   - **Header:** `EasyPrivacy`
5. Save
6. Update → Force Reload

**Testing After Adding:**

**Test 1: Check if tracking is blocked**
```bash
# In Kali terminal
nslookup google-analytics.com
# Should return: 0.0.0.0 or 10.10.10.1 (blocked)

nslookup facebook.com
# Should still work (not a tracker domain)
```

**Test 2: Browser test**
1. Open browser developer tools (F12)
2. Go to "Network" tab
3. Visit any news website
4. Look for blocked requests in red
5. Should see fewer tracking scripts loading

**Test 3: Check pfBlockerNG Reports**
1. Firewall → pfBlockerNG → Reports
2. Click "DNSBL" tab
3. You'll see blocked tracking domains!

---

### Common Feeds Comparison

| Feed | Type | What It Blocks | Size | Update Frequency |
|------|------|----------------|------|------------------|
| EasyList | DNSBL | Ads | ~50k domains | Daily |
| EasyPrivacy | DNSBL | Trackers | ~15k domains | Daily |
| Steven Black | DNSBL | Ads + Malware | ~80k domains | Weekly |
| NoVirusThanks | IP | Malware IPs | ~5k IPs | Daily |
| Emerging Threats | IP | Malicious IPs | ~10k IPs | Daily |
| Spamhaus DROP | IP | Spam networks | ~1k ranges | Daily |
| GeoIP MaxMind | GeoIP | Countries | All countries | Weekly |

---

### Feed Update Process (Behind the Scenes)

**What happens when you add a feed:**

**Step 1: Initial Download**
```
pfBlockerNG → Downloads feed URL
pfBlockerNG → Parses the file (extracts domains/IPs)
pfBlockerNG → Creates firewall rules
pfBlockerNG → Loads into memory
```

**Step 2: Regular Updates (Automatic)**
```
Every [set frequency]:
  1. Download updated feed
  2. Compare with old version
  3. Add new entries
  4. Remove obsolete entries
  5. Reload firewall rules
  6. Clear DNS cache
```

**Step 3: Blocking in Action**
```
User requests: badsite.com
  ↓
pfSense DNS checks: Is it in DNSBL?
  ↓
Found in EasyList feed!
  ↓
Return: 0.0.0.0 (blocked)
  ↓
User sees: "Can't connect"
```

---

### Understanding the pfBlockerNG Interface

**When you see this screen:**
```
DNSBL Source Definitions:
- Format
- State
- Source
- Header/Label
```

**What each field means:**

**Format:**
- How the feed is structured
- Options: Auto, Domain, Host, etc.
- Usually leave as "Auto"

**State:**
- ON = Feed is active
- OFF = Feed is disabled

**Source:**
- The URL where the list is downloaded from
- Example: `https://easylist.to/easylist/easylist.txt`

**Header/Label:**
- Your description/name for this feed
- Example: "EasyList - Ad Blocking"

---

### Settings Explained (From Your Screenshot)

**Action:**
- **Disabled:** Feed is downloaded but not blocking
- **Unbound:** Uses pfSense DNS to block (recommended!)
- **Deny Both:** Blocks incoming AND outgoing

**Update Frequency:**
- Never = Manual only
- Daily = Updates every day
- Weekly = Updates once per week
- Best: Match the feed's update schedule

**Logging / Blocking Mode:**
- **Enabled:** Logs every blocked request (detailed)
- **Disabled:** Blocks silently (better performance)
- For learning: Enable logging!

**TOP1M Whitelist:**
- Prevents blocking of top 1 million popular sites
- Reduces false positives (accidental blocks)
- Recommended: Enable!

---

## Part 10: Installing pfBlockerNG - The Super Blocker (30 minutes)

### Step 10.1: Install the Package

**Do This Now:**
1. In pfSense web interface, click "System"
2. Click "Package Manager"
3. Click "Available Packages" tab
4. In the search box, type: `pfblockerng`
5. Find "pfBlockerNG-devel" (NOT just "pfBlockerNG")
6. Click "+ Install" on the right
7. Click "Confirm"
8. Wait 2-3 minutes (it's downloading and installing)

**✅ When done, you'll see green checkmark!**

---

### Step 10.2: Initial Configuration

**Do This Now:**
1. Click "Firewall" → "pfBlockerNG"
2. Click "IP" tab

**IP Configuration:**
3. **Enable**: Check the box ✓
4. **Enable Reputation**: Check the box ✓
5. Scroll down → Click "Save"

**DNSBL (Domain Blocking):**
6. Click "DNSBL" tab
7. **Enable DNSBL**: Check the box ✓
8. **DNSBL Mode**: Choose "Unbound mode"
9. Scroll down → Click "Save"

---

### Step 10.3: Add Blocking Lists (The Fun Part!)

**Do This Now:**

**Add IP Blocklist:**
1. Click "IP" tab
2. Click "Add" (green + button)
3. **List name**: Type `Malicious_IPs`
4. **List Action**: Choose "Deny Both"
5. **Update Frequency**: "Daily"
6. In the "IPv4 URL" box, paste:
```
https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt
```
7. Click "Save"

**Add Ad-Blocking (DNSBL):**
8. Click "DNSBL" → "DNSBL Feeds" tab
9. Scroll down to "Ads/Trackers" section
10. Check these boxes:
    - ✓ Ads_Basic
    - ✓ Ads_Extended
11. Scroll to bottom → Click "Save"

**Apply Everything:**
12. Click "Update" tab
13. Click "Run" next to "Force Update"
14. Wait 2-5 minutes (downloading blocklists)
15. You'll see green "Success!" messages

**✅ pfBlockerNG is now active!**

---

### Step 10.4: Test Ad Blocking

**Do This Now:**

**Test 1: Check if it's working**
1. In Kali terminal, type:
```bash
nslookup doubleclick.net
```
2. Should return `0.0.0.0` or `10.10.10.1` (blocked!) ✓

**Test 2: Browse an ad-heavy website**
3. In Firefox, go to any news website
4. You should see FEWER ads! ✓

**Test 3: View blocked list**
5. In pfSense, go to: Firewall → pfBlockerNG → "Reports" tab
6. You'll see blocked domains/IPs!

**✅ You're now blocking ads and bad websites!**

---

---

## 📊 Visual Guide - How Everything Works Together

### Diagram 1: pfSense Network Position

```
                    INTERNET (Dangerous!)
                           |
                           |
                    [Cable/DSL Modem]
                           |
                           | WAN Interface (em0)
                           |
                  +--------+---------+
                  |                  |
                  |     pfSense      |  ← Your Security Guard
                  |    Firewall      |
                  |                  |
                  +--------+---------+
                           | LAN Interface (em1)
                           | 192.168.1.1
                           |
              +------------+------------+
              |            |            |
          [Kali VM]   [Windows VM]  [Other VMs]
       192.168.1.100  192.168.1.101 192.168.1.102
          (Protected)  (Protected)   (Protected)
```

**Key Points:**
- pfSense sits BETWEEN internet and your devices
- ALL traffic must go through pfSense
- pfSense inspects and controls everything

---

### Diagram 2: How pfBlockerNG DNSBL Works (DNS Blocking)

**Normal Connection (Without pfBlockerNG):**
```
Step 1: DNS Lookup
┌──────────────┐                    ┌──────────────┐
│  Your Kali   │ "What's the IP     │   Internet   │
│     VM       │ for badsite.com?"  │     DNS      │
│              │ ─────────────────> │              │
│              │                     │              │
│              │ <───────────────── │              │
│              │   "192.168.5.50"   │              │
└──────────────┘                    └──────────────┘

Step 2: Connect to Website
┌──────────────┐                    ┌──────────────┐
│  Your Kali   │                    │  badsite.com │
│     VM       │ ══════════════════>│ 192.168.5.50 │
│              │  HTTPS connection   │              │
│              │    (encrypted)      │  Malware!    │
└──────────────┘                    └──────────────┘
        ✗ You got infected!
```

**Protected Connection (With pfBlockerNG):**
```
Step 1: DNS Lookup - INTERCEPTED!
┌──────────────┐     ┌─────────────────┐
│  Your Kali   │     │    pfSense      │
│     VM       │─────│  + pfBlockerNG  │
│              │  ①  │                 │
│              │     │ Checks: Is      │
│ "What's the  │     │ badsite.com on  │
│  IP for      │     │ blocklist?      │
│ badsite.com?"│     │                 │
│              │     │ ✓ YES! BLOCK!   │
│              │<────│                 │
│              │  ②  │ Returns:        │
│              │     │ 0.0.0.0         │
└──────────────┘     └─────────────────┘

Step 2: Try to Connect - FAILS!
┌──────────────┐
│  Your Kali   │
│     VM       │ ─────X────> 0.0.0.0 (nowhere!)
│              │
│  "Can't      │
│   connect!"  │
└──────────────┘
        ✓ Protected!
```

---

### Diagram 3: Types of Blocking in pfBlockerNG

```
┌─────────────────────────────────────────────┐
│          pfBlockerNG Blocking Types         │
└─────────────────────────────────────────────┘
                    |
        ┌───────────┴───────────┐
        |                       |
   ┌────▼────┐            ┌────▼────┐
   │   IP    │            │  DNSBL  │
   │ Blocking│            │ Blocking│
   └────┬────┘            └────┬────┘
        |                      |
   Blocks by:             Blocks by:
   - IP address          - Domain name
   - IP range            - URL patterns
   - Countries           - Categories
        |                      |
   ┌────▼─────────────┐   ┌───▼──────────────┐
   │ Examples:        │   │ Examples:        │
   │                  │   │                  │
   │ • 45.67.89.10    │   │ • ads.com        │
   │ • 123.0.0.0/8    │   │ • tracker.net    │
   │ • All of China   │   │ • malware.org    │
   │ • Malware server │   │ • facebook.com   │
   └──────────────────┘   └──────────────────┘
```

---

### Diagram 4: Feed Update Process

```
Day 1: Install Feed
───────────────────────────────────────────
pfBlockerNG downloads list
    ↓
10,000 malicious domains added
    ↓
Firewall rules created
    ↓
DNS blocking active
    ↓
✓ Protected!


Day 2-6: Normal Operation
───────────────────────────────────────────
Blocks 50-100 threats per day
Logs all blocked attempts
Everything runs automatically


Day 7: Auto-Update
───────────────────────────────────────────
pfBlockerNG checks for updates
    ↓
Feed has 500 new entries
    ↓
Downloads new list
    ↓
Adds new domains to block
    ↓
Removes old/dead entries
    ↓
Reloads firewall
    ↓
✓ Still protected with latest threats!
```

---

### Diagram 5: Firewall Rule Processing Order

```
Traffic arrives at pfSense
          |
          ↓
┌─────────────────────┐
│ Rule 1: Block HTTP  │ ← Checked FIRST
└─────────┬───────────┘
          | No match
          ↓
┌─────────────────────┐
│ Rule 2: Block       │ ← Checked SECOND
│   Facebook          │
└─────────┬───────────┘
          | MATCH! ✓
          ↓
   ┌──────────┐
   │  BLOCK   │ ← Action executed
   │  TRAFFIC │
   └──────────┘
          ↓
   Rules 3-10 never checked!
   (First match wins!)
```

**Important:** Rules below a match are IGNORED!

---

### Diagram 6: What Happens During HTTPS (Encrypted) Connection

```
WHAT PFSENSE CAN SEE:
═══════════════════════════════════════════════
┌──────────────────────────────────────────┐
│ Domain Name (badsite.com) ← DNS lookup  │ ✓ Can block
│ Destination IP (192.168.5.50)           │ ✓ Can block
│ Port (443 for HTTPS)                     │ ✓ Can see
│ Amount of data transferred               │ ✓ Can see
└──────────────────────────────────────────┘


WHAT PFSENSE CANNOT SEE:
═══════════════════════════════════════════════
┌──────────────────────────────────────────┐
│ [🔒 Encrypted Data 🔒]                   │ ✗ Cannot see
│ • URL path (/login/account)             │ ✗ Cannot see
│ • Form data (passwords, etc.)           │ ✗ Cannot see
│ • Page content                          │ ✗ Cannot see
│ • Cookies                               │ ✗ Cannot see
└──────────────────────────────────────────┘
```

**This is GOOD for privacy!**
pfBlockerNG blocks based on domain/IP, not content.

---

### Diagram 7: DNS Cache Problem (Why Sites Still Load)

```
Timeline: Adding Facebook to Blocklist
═══════════════════════════════════════════════

10:00 AM - Before Blocking
─────────────────────────────────────────
Your computer: "What's facebook.com IP?"
DNS: "It's 31.13.71.36"
Your computer: Saves this for 24 hours
Your computer: Connects to Facebook ✓

10:05 AM - You Add Block Rule
─────────────────────────────────────────
pfBlockerNG: "Facebook is now blocked!"

10:06 AM - You Try Facebook Again
─────────────────────────────────────────
Your computer: "I already know the IP!"
Your computer: Uses cached: 31.13.71.36
Your computer: Connects to Facebook ✓
        ↑
    Problem! DNS cache bypassed blocker!

10:07 AM - You Flush DNS Cache
─────────────────────────────────────────
You run: ipconfig /flushdns
Cache cleared!

10:08 AM - Try Again
─────────────────────────────────────────
Your computer: "What's facebook.com IP?"
pfBlockerNG: "BLOCKED! Returns 0.0.0.0"
Your computer: Can't connect ✓
        ↑
    Fixed!
```

---

### Diagram 8: Complete Traffic Flow with All Features

```
 User requests website: www.example.com
            |
            ↓
    ┌───────────────┐
    │   pfSense     │
    │   Firewall    │
    └───────┬───────┘
            |
   ┌────────▼────────┐
   │ Step 1: Check   │
   │ Firewall Rules  │
   └────────┬────────┘
            |
     ┌──────▼──────┐
     │ Blocked by  │  YES → BLOCK ✗
     │ custom rule?│
     └──────┬──────┘
            | NO
            ↓
   ┌────────────────┐
   │ Step 2: Check  │
   │ pfBlockerNG IP │
   └────────┬───────┘
            |
     ┌──────▼──────┐
     │ IP on       │  YES → BLOCK ✗
     │ blocklist?  │
     └──────┬──────┘
            | NO
            ↓
   ┌────────────────┐
   │ Step 3: DNS    │
   │ Lookup         │
   └────────┬───────┘
            |
     ┌──────▼──────┐
     │ Domain on   │  YES → BLOCK ✗
     │ DNSBL list? │
     └──────┬──────┘
            | NO
            ↓
   ┌────────────────┐
   │ Step 4: NAT &  │
   │ Route to       │
   │ Internet       │
   └────────┬───────┘
            |
            ↓
      [INTERNET]
            |
            ↓
      ✓ ALLOWED
      Connection succeeds!
```

---

## Part 11: Understanding What You Built

### The Big Picture

```
INTERNET (Dangerous)
     ↓
[pfSense Firewall] ← You control this!
     ↓
Protected Network (Safe)
     ↓
[Kali Linux] ← Your safe computer
```

### What pfSense Does:
1. ✅ Checks every website you visit
2. ✅ Blocks bad IPs and domains
3. ✅ Blocks ads and trackers
4. ✅ Logs everything for review
5. ✅ Protects ALL devices behind it

### What You Can Do Now:
- Add more VMs behind the firewall (same Internal Network "LAN")
- Create custom block rules
- Add more blocklists
- Monitor traffic
- Learn network security!

---

## 🐛 Troubleshooting Common Problems

### Problem: Kali has no internet

**Solution:**
1. Check Kali's network adapter is "Internal Network" named "LAN"
2. In Kali terminal:
```bash
sudo dhclient eth0
ip addr show eth0
```
3. Restart both VMs

---

### Problem: Can't access pfSense web interface

**Solution:**
1. Check pfSense LAN IP: Should be 192.168.1.1
2. In Kali, try: `ping 192.168.1.1`
3. If fails, check Adapter 2 on pfSense is "Internal Network"
4. Restart both VMs

---

### Problem: Everything is blocked!

**Solution:**
1. Go to Firewall → Rules → LAN
2. Make sure there's an "Allow LAN to any" rule at the BOTTOM
3. Your block rules should be ABOVE it
4. Click "Apply Changes"

---

### Problem: pfBlockerNG not blocking anything

**Solution:**
1. Firewall → pfBlockerNG → "Update" tab
2. Click "Force Reload" for all categories
3. Wait 5 minutes
4. Check Services → DNS Resolver is running
5. In Kali, flush DNS: `sudo systemd-resolve --flush-caches`

---

---

## ❓ Frequently Asked Questions (FAQ)

### Q1: Why do I need pfBlockerNG if pfSense can already block websites?

**Short Answer:** Scale and automation!

**Detailed Answer:**
- **pfSense alone:** You manually create each blocking rule. Want to block 10,000 ad servers? Create 10,000 rules! 😱
- **pfBlockerNG:** Subscribe to a feed → 10,000 sites blocked automatically, updates daily → Easy! 😎

**Example:**
```
Manual pfSense blocking:
  Rule 1: Block facebook.com
  Rule 2: Block fb.com
  Rule 3: Block fbcdn.net
  Rule 4: Block facebook.net
  ... 47 more Facebook domains
  Tomorrow: Facebook adds 10 new domains
  You: 😭 More work!

With pfBlockerNG:
  Subscribe to "Social Media" feed
  All 50+ Facebook domains blocked automatically
  Tomorrow: Feed updates with new domains
  You: 😎 Still protected, zero work!
```

---

### Q2: How does pfBlockerNG block HTTPS sites without decrypting them?

**Short Answer:** It blocks the DNS lookup, not the encrypted content!

**Detailed Answer:**

**Step 1: What happens when you visit https://badsite.com**
```
1. Computer asks: "What's the IP for badsite.com?" ← DNS (PLAINTEXT!)
2. pfBlockerNG intercepts: "That domain is blocked!"
3. pfBlockerNG returns: 0.0.0.0 (fake IP)
4. Computer tries: Connect to 0.0.0.0 → Fails!
```

**Step 2: If it reached the site (without blocking):**
```
5. Computer → [HTTPS encrypted tunnel] → badsite.com
   ↑
   This step never happens because DNS was blocked!
```

**Key Point:**
- DNS lookups happen BEFORE encryption
- pfBlockerNG blocks during DNS phase
- No decryption needed!

---

### Q3: Can pfSense decrypt and inspect HTTPS traffic?

**Short Answer:** Yes, but pfBlockerNG doesn't do this by default.

**Detailed Answer:**

**Two methods:**

**Method 1: DNS/IP Blocking (pfBlockerNG default)**
- No decryption
- Blocks based on domain/IP
- Fast, simple, privacy-friendly
- ✓ Blocks 99% of threats

**Method 2: SSL/TLS Inspection (Advanced, not covered here)**
- Full decryption required
- pfSense acts as man-in-the-middle
- Must install pfSense certificate on every device
- Slow, complex, privacy concerns
- Can see everything (passwords, content, etc.)

**For learning and most use cases: Stick with Method 1!**

---

### Q4: What is a "feed" in pfBlockerNG?

**Short Answer:** A subscription to a list of bad sites that updates automatically.

**Detailed Answer:**

Think of it like a magazine subscription:
- You subscribe once
- New issues arrive automatically
- You don't write the articles yourself

**In pfBlockerNG:**
- Feed = URL pointing to a list file
- List contains domains/IPs to block
- Updated daily/weekly by security researchers
- You just subscribe and forget!

**Example feed:**
```
URL: https://example.com/malware-list.txt

Contents:
badsite1.com
badsite2.com
malware.org
phishing.net
... (thousands more)

pfBlockerNG downloads this daily and blocks everything in it!
```

---

### Q5: Why are there so many different feeds? It's confusing!

**Short Answer:** Each feed targets different threats - like having specialists!

**Detailed Answer:**

**Think of it like a hospital:**
- Cardiologist → Heart problems
- Neurologist → Brain problems
- Pediatrician → Children's health
- All needed for complete care!

**Same with feeds:**
- EasyList → Blocks ads
- EasyPrivacy → Blocks trackers
- NoVirusThanks → Blocks malware
- Spamhaus → Blocks spam
- All needed for complete protection!

**Start simple:**
1. Begin with 2-3 feeds (Ads + Malware)
2. Add more as needed
3. Don't enable everything at once!

---

### Q6: What's the difference between EasyList and EasyPrivacy?

**Short Answer:**
- **EasyList** = Blocks ads (visual annoyances)
- **EasyPrivacy** = Blocks trackers (invisible spying)

**Detailed Answer:**

**EasyList blocks:**
```
✓ Banner ads
✓ Pop-up ads
✓ Video ads
✓ Ad networks
Example: doubleclick.net, googlesyndication.com
```

**EasyPrivacy blocks:**
```
✓ Google Analytics (tracks which pages you visit)
✓ Facebook Pixel (tracks what you do)
✓ Tracking cookies
✓ Cross-site trackers
Example: google-analytics.com, facebook.com/tr/
```

**Use both for maximum protection!**

---

### Q7: I added a feed but can still access blocked sites. Why?

**8 Common Reasons:**

**Reason 1: Didn't Force Reload** ← Most common!
```
Solution:
  1. Go to: pfBlockerNG → Update
  2. Click "Force Reload" - DNSBL
  3. Wait 2-5 minutes
  4. Try again
```

**Reason 2: DNS Cache**
```
Solution:
  Windows: ipconfig /flushdns
  Linux: sudo systemd-resolve --flush-caches
  Browser: Clear cache (Ctrl+Shift+Del)
```

**Reason 3: Device Not Using pfSense DNS**
```
Check:
  ip addr show eth0
  Should show DNS: 192.168.1.1 (pfSense)
  
Fix:
  Edit /etc/resolv.conf
  Set nameserver 192.168.1.1
```

**Reason 4: Browser Using DNS over HTTPS (DoH)**
```
Firefox/Chrome bypasses pfSense DNS!

Fix:
  Firefox: Settings → Network → Disable DoH
  Chrome: Settings → Privacy → Disable "Secure DNS"
```

**Reason 5: Site Uses IP Instead of Domain**
```
Problem: Site accessed by IP (http://192.168.1.1)
DNSBL only blocks domain names!

Fix: Use IP blocklists instead
```

**Reason 6: Wrong Feed Format**
```
EasyList has patterns like "/ads/" that don't work in DNSBL

Fix: Use domain-only versions of feeds
```

**Reason 7: Site Not on the Feed**
```
Feeds don't contain EVERY bad site

Fix: Add custom domains manually
```

**Reason 8: Rule Order Problem**
```
Allow rule is above block rule

Fix: Reorder rules (block rules on top!)
```

---

### Q8: What does `/pre-pixel/` or `/pre-bit-pro.js` mean in EasyList?

**Short Answer:** These are patterns matching ad/tracking scripts on websites.

**Detailed Answer:**

**In browser extensions:**
```
Pattern: /pre-pixel/

Matches:
✓ example.com/pre-pixel/track.js
✓ site.com/ads/pre-pixel/
✓ any-site.com/pre-pixel/code

Browser blocks these scripts from loading
```

**In pfBlockerNG (DNSBL):**
```
These patterns DON'T work well!
DNSBL blocks full domains, not URL paths

Better to use domain-focused feeds
```

**Why they exist:**
- Created for browser extensions
- Target specific ad scripts
- Very effective in browsers
- Less useful in pfBlockerNG

---

### Q9: What's the difference between Block and Reject?

**Short Answer:**
- **Block** = Silent drop (stealth mode)
- **Reject** = Send back "connection refused"

**Detailed Explanation:**

**Block (Recommended for external threats):**
```
Attacker: Tries to connect
pfSense: [Silently drops packet]
Attacker: [Waits... waits... timeout]
Attacker: "Is there even a firewall here?"

Pros: Stealth, security
Cons: Slower timeouts
```

**Reject (Good for internal testing):**
```
Your computer: Tries to connect
pfSense: "Connection refused!"
Your computer: "OK, failed immediately"

Pros: Fast response, good for testing
Cons: Reveals firewall existence
```

**Best practice:**
- External rules → Block
- Internal rules → Reject
- Testing → Reject

---

### Q10: Can I block specific countries?

**Short Answer:** Yes! It's called Geo-IP blocking.

**Detailed Answer:**

**How to enable:**
1. pfBlockerNG → IP → GeoIP
2. Select countries to block
3. Example: Block China, Russia, North Korea
4. Save → Update

**Use cases:**
- Block countries you don't do business with
- Reduce attack surface (most attacks from certain regions)
- Comply with data regulations
- Block high-risk regions

**Warning:**
- VPNs can bypass this (attacker uses VPN to appear from different country)
- May block legitimate users
- Keep logs to verify effectiveness

---

### Q11: How do I know if pfBlockerNG is actually working?

**5 Ways to Verify:**

**Method 1: Test Known Bad Domain**
```bash
nslookup doubleclick.net
# Should return: 0.0.0.0 or 10.10.10.1 (blocked)
```

**Method 2: Check pfBlockerNG Reports**
```
pfSense → pfBlockerNG → Reports → DNSBL
You'll see blocked domains in real-time!
```

**Method 3: Check Firewall Logs**
```
Status → System Logs → Firewall
Look for "pfBlockerNG" entries
```

**Method 4: Count Blocked Requests**
```
pfBlockerNG → Reports → Dashboard
Shows total blocks, top blocked domains, etc.
```

**Method 5: Browse Ad-Heavy Site**
```
Visit any news website
Should see FEWER ads!
Open browser DevTools (F12) → Network tab
See blocked requests in red
```

---

### Q12: Will pfBlockerNG slow down my internet?

**Short Answer:** Minimal impact - usually not noticeable!

**Detailed Answer:**

**Performance impact:**
```
DNS lookup: +1-5ms (barely noticeable)
Large blocklists: +5-10ms
Overall: 99% of users won't notice

CPU usage: Very low (1-5%)
Memory: ~100-500MB
```

**Tips for best performance:**
- Don't enable EVERY feed (start with 3-5)
- Disable logging if not needed
- Use SSD if possible
- Allocate 2GB+ RAM to pfSense VM

**Comparison:**
```
Without pfBlockerNG: 50ms to load page
With pfBlockerNG:    52ms to load page
BUT: Blocked 20 ads → Actually FASTER overall!
```

---

### Q13: What happens if I block too much and break legitimate sites?

**Short Answer:** Temporarily disable the rule or add to whitelist.

**Detailed Answer:**

**Quick fix (Disable rule):**
```
1. Firewall → Rules → LAN
2. Click ✓ checkbox (turns gray = disabled)
3. Apply Changes
4. Test if site works now
```

**Permanent fix (Whitelist):**
```
1. pfBlockerNG → DNSBL → Whitelist
2. Add domain that was incorrectly blocked
3. Example: cdn.example.com
4. Save → Force Reload
```

**Enable TOP1M Whitelist:**
```
Prevents blocking top 1 million popular sites
Reduces false positives significantly

Enable in: DNSBL settings → TOP1M Whitelist
```

**Testing mode:**
```
Set Action to "Disabled" instead of "Unbound"
Feed downloads but doesn't block
Check what WOULD be blocked
Then enable when confident
```

---

### Q14: How often should feeds update?

**Short Answer:** Daily for most feeds, weekly for others.

**Detailed Answer:**

**Update frequency by feed type:**

**Daily (Fast-changing):**
- Malware domains (new threats daily)
- Phishing sites (short-lived)
- Botnet IPs
- Spam sources

**Weekly (Slow-changing):**
- Ad networks (rarely change)
- Tracking domains
- GeoIP data
- General blocklists

**Recommendation:**
```
Match feed's own update schedule:
- If feed updates daily → Set to daily
- If feed updates weekly → Set to weekly

Don't update more often than the feed updates!
(Wastes bandwidth, no benefit)
```

---

### Q15: Can I create my own custom blocklist?

**Short Answer:** Yes! Add custom domains/IPs easily.

**Detailed Answer:**

**Method 1: Add Single Entries**
```
1. pfBlockerNG → DNSBL → DNSBL Groups
2. Click on any group
3. Scroll to "Custom Domain List"
4. Add one domain per line:
   badsite.com
   another-bad.com
   tracking.net
5. Save → Force Reload
```

**Method 2: Create Custom Feed File**
```
1. Create a text file with domains:
   badsite1.com
   badsite2.com
   malware.org

2. Host it somewhere (GitHub, personal server)

3. pfBlockerNG → Add Feed
   URL: https://your-site.com/blocklist.txt
   
4. pfBlockerNG downloads it automatically!
```

**Method 3: Use Firewall Aliases**
```
1. Firewall → Aliases → Add
2. Type: Host(s)
3. Add domains/IPs
4. Use in firewall rules
```

---

### Q16: What's the difference between DNSBL and IP blocking?

**Comparison Table:**

| Feature | DNSBL | IP Blocking |
|---------|-------|-------------|
| Blocks by | Domain name | IP address |
| Works with | DNS queries | All traffic |
| Example | facebook.com | 31.13.71.36 |
| Pros | Blocks domain even if IP changes | Works even without DNS |
| Cons | Requires DNS lookup | IP addresses can change |
| Best for | Websites, ads | Countries, specific servers |

**Use both for best protection!**

---

### Q17: My router already has parental controls. Why use pfSense?

**Short Answer:** pfSense is WAY more powerful and customizable!

**Comparison:**

**Home Router:**
```
✗ Limited rules (maybe 10-20)
✗ No automatic updates
✗ Basic categories only
✗ Can't customize much
✗ No detailed logs
✗ Can't block by country
✗ No custom feeds
```

**pfSense + pfBlockerNG:**
```
✓ Unlimited rules
✓ Auto-updates daily
✓ Any category imaginable
✓ Full customization
✓ Detailed logs and reports
✓ Geo-IP blocking
✓ Custom feeds
✓ VPN, IDS/IPS, and more!
```

**Plus:** pfSense is a learning tool for cybersecurity!

---

### Q18: Can I use pfSense at home on real hardware?

**Short Answer:** Absolutely! Many people do.

**Hardware options:**

**Option 1: Old Computer**
```
Requirements:
- 2+ network ports (or add NIC card)
- 4GB+ RAM
- Any CPU from last 10 years
- Small SSD (20GB+)

Cost: Free (using old PC)
```

**Option 2: Purpose-Built**
```
Netgate Appliances:
- $199-$2,000+
- Pre-configured
- Official support
- Great performance
```

**Option 3: DIY Mini PC**
```
Intel NUC / Protectli:
- $200-$500
- Low power
- Small form factor
- Add NIC if needed
```

**For learning:** Stick with VirtualBox (free, safe)!
**For production:** Consider dedicated hardware.

---

### Q19: Is pfSense legal? Am I allowed to block ads/trackers?

**Short Answer:** Yes, completely legal on YOUR network!

**Legal explanation:**

**You CAN:**
- Block any site on your own network
- Protect your own devices
- Block ads, trackers, malware
- Filter content for your family
- Use pfSense for education

**You CANNOT:**
- Interfere with ISP equipment
- Hack other people's networks
- Provide commercial ad-blocking services (complex legal area)

**Ethics:**
- Some say blocking ads hurts content creators
- Others say tracking is invasion of privacy
- You decide what's right for YOUR network!

**Recommendation:** Use for learning and personal protection!

---

### Q20: Where can I learn more?

**Official Resources:**
- pfSense Docs: https://docs.netgate.com/pfsense/
- pfBlockerNG Guide: https://docs.netgate.com/pfsense/en/latest/packages/pfblocker.html
- Netgate Forum: https://forum.netgate.com/

**Video Tutorials:**
- Search: "Lawrence Systems pfSense" on YouTube
- Search: "Crosstalk Solutions pfBlockerNG"
- Search: "Tom Lawrence pfSense tutorial"

**Communities:**
- r/pfSense on Reddit
- r/homelab on Reddit
- r/selfhosted on Reddit

**Practice:**
- Break things in your VM!
- Try different rules
- Test various feeds
- Join forums and ask questions

**This guide is just the beginning!** 🚀

---

## 🐛 Troubleshooting Common Problems

### Problem: Kali has no internet

**Solution Checklist:**
```
□ Check Kali network adapter = "Internal Network" named "LAN"
□ Check pfSense Adapter 2 = "Internal Network" named "LAN"
□ In Kali terminal, run:
  sudo dhclient eth0
  ip addr show eth0
□ Should show IP: 192.168.1.xxx
□ Try: ping 192.168.1.1 (should work)
□ Try: ping 8.8.8.8 (should work if NAT correct)
□ Check pfSense: Firewall → Rules → LAN → Should have "Allow LAN to any" rule
□ Restart both VMs if needed
```

---

### Problem: Can't access pfSense web interface

**Solution Checklist:**
```
□ From Kali, verify pfSense IP: ping 192.168.1.1
□ Try both: http://192.168.1.1 and https://192.168.1.1
□ Accept security warnings in browser
□ Check pfSense console - is it showing the menu?
□ Verify pfSense LAN adapter is enabled
□ Try Firefox instead of Chrome
□ Clear browser cache
□ If locked out: pfSense console → Type 8 → pfctl -d (disables firewall)
```

---

### Problem: Everything is blocked!

**Solution Checklist:**
```
□ Check rule order: Firewall → Rules → LAN
□ Block rules should be ABOVE "Allow LAN to any" rule
□ Temporarily disable problematic rules (click ✓ checkbox)
□ Check if you accidentally blocked 0.0.0.0/0 (all traffic)
□ Look for: "Allow LAN net to any" rule at bottom (should be enabled)
□ Apply Changes after any modifications
```

---

### Problem: pfBlockerNG not blocking anything

**Solution Checklist:**
```
□ Did you Force Reload? pfBlockerNG → Update → Force Reload DNSBL
□ Wait 5 minutes after reload
□ Check feed downloaded: pfBlockerNG → Logs
□ Verify DNS: In Kali, check /etc/resolv.conf shows nameserver 192.168.1.1
□ Clear DNS cache:
  sudo systemd-resolve --flush-caches
  sudo killall -HUP mDNSResponder (Mac)
  ipconfig /flushdns (Windows)
□ Disable browser DoH: Firefox Settings → Network → Disable DNS over HTTPS
□ Test with: nslookup doubleclick.net (should return 0.0.0.0)
□ Check pfBlockerNG → Reports → See if anything is being blocked
```

---

### Problem: Specific site incorrectly blocked (false positive)

**Solution Checklist:**
```
□ pfBlockerNG → DNSBL → Whitelist
□ Add the domain that's incorrectly blocked
□ Save → Force Reload
□ Or enable TOP1M Whitelist (prevents blocking top sites)
□ Check which feed blocked it: pfBlockerNG → Reports
□ Consider disabling that specific feed if too aggressive
□ Temporarily disable rule to test: Click ✓ checkbox
```

---

### Problem: Can still access blocked sites

**Solution Checklist:**
```
□ Did you Apply Changes? (Orange button at top)
□ Did you Force Reload pfBlockerNG?
□ Clear DNS cache (see above)
□ Check browser isn't using DoH
□ Verify device is using pfSense as DNS (not 8.8.8.8)
□ Check rule order (block rules on top!)
□ Try incognito/private browsing mode
□ Check if site uses IP address instead of domain
□ Wait 5-10 minutes after making changes
```

---

### Problem: pfSense VM won't boot / kernel panic

**Solution Checklist:**
```
□ Check VirtualBox settings: System → Enable EFI may need to be toggled
□ Verify adequate RAM (2GB minimum)
□ Check ISO file is attached correctly
□ Try: Settings → System → Disable "Enable PAE/NX"
□ Reinstall from ISO if corrupted
□ Create new VM from scratch
```

---

### Problem: Slow internet after installing pfBlockerNG

**Solution Checklist:**
```
□ Don't enable too many feeds (start with 3-5)
□ Disable logging: DNSBL → Logging Mode → Disabled
□ Increase pfSense VM RAM to 4GB
□ Check CPU usage: Status → Dashboard
□ Disable duplicate feeds (don't need 10 ad blockers!)
□ Clear old logs: Status → System Logs → Clear
```

---

### Problem: VMs can't communicate with each other

**Solution Checklist:**
```
□ Both VMs on same "Internal Network" name? Must match exactly!
□ Both VMs should show: "LAN" (case-sensitive)
□ Check IPs in same subnet: 192.168.1.xxx
□ Check firewall doesn't block inter-VLAN traffic
□ Try: ping from one VM to the other
```

---

### Problem: Lost admin password

**Solution Checklist:**
```
□ Go to pfSense console (VM window)
□ Option 3: Reset webConfigurator password
□ Enter new password twice
□ Try logging in again
```

---

### Problem: Feed won't download / errors

**Solution Checklist:**
```
□ Check internet connection from pfSense
□ Try: Diagnostics → Ping → 8.8.8.8
□ Verify feed URL is correct (no typos)
□ Check feed site isn't down (try URL in browser)
□ Some feeds require registration/API key
□ Check: Status → System Logs → look for errors
□ Try different feed from same category
```

---

### Problem: High CPU usage

**Solution Checklist:**
```
□ Check: Status → Dashboard → CPU graph
□ Disable unnecessary packages
□ Reduce feed count
□ Disable logging
□ Increase VM CPU cores to 2+
□ Check for runaway processes: Diagnostics → Command Prompt → top
```

---

### Emergency Reset (Nuclear Option)

**If nothing works:**
```
1. pfSense console → Option 4: Reset to factory defaults
2. Confirm: y
3. Wait for reboot
4. Reconfigure from scratch (use this guide!)
5. Or: Delete VM and create new one
```

**Tip:** Take VirtualBox snapshots after each major step!
- Machine → Take Snapshot
- Name it: "Working firewall rules" or "After pfBlockerNG install"
- If you break something, restore the snapshot!

---

## 🎓 Next Steps - Keep Learning!

### Easy:
- [ ] Add more firewall rules (block social media, gaming, etc.)
- [ ] Explore pfSense dashboard and graphs
- [ ] Add custom domains to pfBlockerNG

### Medium:
- [ ] Set up a VPN server on pfSense
- [ ] Install Snort or Suricata (intrusion detection)
- [ ] Create traffic shaping rules (prioritize video calls)

### Advanced:
- [ ] Add a Windows VM behind the firewall
- [ ] Set up high availability with 2 pfSense VMs
- [ ] Integrate with a SIEM tool

---

## 📚 Helpful Resources

**Official Documentation:**
- pfSense Docs: https://docs.netgate.com/pfsense/
- pfBlockerNG Guide: https://docs.netgate.com/pfsense/en/latest/packages/pfblocker.html

**Video Tutorials:**
- Search YouTube for "Lawrence Systems pfSense"
- Search for "Crosstalk Solutions pfBlockerNG"

**Communities:**
- r/pfSense on Reddit
- Netgate Forum: https://forum.netgate.com/

---

## ✨ Congratulations!

You just built a real firewall from scratch! 🎉

You learned:
- ✅ How firewalls work
- ✅ Network architecture
- ✅ Creating security rules
- ✅ Blocking threats
- ✅ Virtual networking

This is the same technology used by:
- Small businesses
- Home networks
- Cybersecurity labs
- IT professionals

**You're now a junior network security engineer!** 🔒

---

## 📝 Quick Reference Card

### Important IPs:
- pfSense web interface: `http://192.168.1.1`
- Default login: admin / pfsense (CHANGE THIS!)
- Kali IP range: 192.168.1.100-200

### Important Commands (Kali):
```bash
# Check IP
ip addr show eth0

# Renew DHCP
sudo dhclient eth0

# Test connection
ping 192.168.1.1
ping 8.8.8.8

# Test website
curl -I http://example.com
```

### Where Things Are (pfSense):
- Rules: Firewall → Rules → LAN
- pfBlockerNG: Firewall → pfBlockerNG
- Logs: Status → System Logs → Firewall
- Packages: System → Package Manager

---

**Remember:** 
- Save your work often
- Take snapshots of VMs (Machine → Take Snapshot)
- Don't be afraid to break things and rebuild
- Learning by doing is the best way!

Good luck with your cybersecurity journey! 🚀
