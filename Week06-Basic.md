# Setting Up OpenVPN on pfSense for Contractors

### Step 1: Install OpenVPN Package (If Not Already Installed)

- On pfSense, go to **System > Package Manager > Available Packages**.
- Search for OpenVPN and click **Install** if it’s not already installed.

### Step 2: Set Up the OpenVPN Server

- Go to **VPN > OpenVPN**.
- Under the **Servers** tab, click **+Add** to create a new OpenVPN server.
- **Server Mode**: Select **Remote Access (User Auth)** to allow contractors to authenticate with individual usernames and passwords.
- **Backend for Authentication**: Choose **Local User Access** (or configure an external authentication server like RADIUS or LDAP if needed).
- **Protocol**: Select **UDP** (recommended for performance) and choose the appropriate port (default is 1194).
- **Device Mode**: Choose **tun** for routed IP (Layer 3) traffic.
- **Interface**: Select **WAN** as OpenVPN will be exposed to the internet.
- **Local Port**: Default is 1194, but change this if needed.
- **IPv4 Tunnel Network**: Choose a private subnet for the VPN clients (e.g., 10.0.10.0/24).
- **IPv4 Local Network(s)**: Enter your internal network, e.g., 192.168.1.0/24, which the contractors will access.
- **Redirect Gateway**: Enable this to route all internet traffic through the VPN, or disable it if only internal access is needed.
- **DNS Default Domain and DNS Servers**: Optionally, specify DNS servers for the VPN clients. Use 192.168.1.1 (your pfSense LAN IP) for internal DNS resolution.
- **Compression**: Choose **Disabled** unless required for specific use cases.
- **Encryption Options**: You can leave these as default for most situations, or configure your own encryption settings based on your security policies.
- Save your settings.

### Step 3: Create a Certificate Authority (CA) and Server Certificate

- Go to **System > Cert. Manager > CAs** and click **+Add**.
  - **Descriptive Name**: Provide a name (e.g., "OpenVPN_CA").
  - **Method**: Choose **Create an internal Certificate Authority**.
  - **Key Length**: Choose 2048 bits or higher for security.
  - **Digest Algorithm**: SHA256 is recommended.
  - **Lifetime**: Set a reasonable expiration date for the CA (e.g., 3650 days).
  - Save the CA.
- Go to **System > Cert. Manager > Certificates** and click **+Add/Sign** to create a new certificate for the OpenVPN server.
  - **Descriptive Name**: Give a name (e.g., "OpenVPN_Server_Cert").
  - **Certificate Authority**: Select the CA you just created.
  - **Key Length**: Select 2048 bits or higher.
  - **Digest Algorithm**: Choose SHA256.
  - **Lifetime**: Set the expiration date (e.g., 3650 days).
  - **Certificate Type**: Choose **Server Certificate**.
  - Save the certificate.

### Step 4: Create VPN User Accounts for Contractors

- Go to **System > User Manager**.
- Click **+Add** to create a new user for each contractor.
  - **Username**: Create a username (e.g., contractor1).
  - **Password**: Set a strong password for the user.
  - **Certificate**: Create a new certificate for each user by checking the **Create an internal Certificate** option. Choose **User Certificate** as the certificate type.
  - Save the user.
- Repeat for other contractors as needed.

### Step 5: Configure Firewall Rules to Allow VPN Access

- Go to **Firewall > Rules > WAN**.
- Add a rule to allow traffic on the VPN port (default is UDP 1194):
  - **Action**: Pass
  - **Interface**: WAN
  - **Protocol**: UDP
  - **Source**: any
  - **Destination**: WAN address
  - **Destination port range**: 1194 (OpenVPN)
  - Save the rule.
- Go to **Firewall > Rules > OpenVPN**.
  - This is where you can configure rules specific to the VPN traffic.
  - Add a rule to allow access from VPN clients (e.g., allow access to internal resources like 192.168.1.0/24).
  - **Action**: Pass
  - **Interface**: OpenVPN
  - **Source**: any
  - **Destination**: LAN network (e.g., 192.168.1.0/24)
  - Save the rule.

### Step 6: Export OpenVPN Configuration for Contractors

- Go to **VPN > OpenVPN > Client Export**.
- Select the OpenVPN Server you just created.
- Choose the contractor user and select **Export**.
- Download the .ovpn configuration file for the user.
  - Send this .ovpn file to the contractor via a secure method (e.g., encrypted email).

### Step 7: Install OpenVPN Client on Contractor Devices

- **Download and Install OpenVPN**: Contractors will need to install the OpenVPN client on their devices (available for Windows, macOS, Linux, and mobile devices).
- **Import Configuration**: They should import the .ovpn file you provided into the OpenVPN client.

# Setting Up Separate Wi-Fi Networks for Employees and Guests Using VLANs on pfSense

### Step 1: Log in to pfSense

- Open a web browser and navigate to the IP address of your pfSense device (default is usually 192.168.1.1).
- Enter your login credentials (default user is admin and the password is the one you set during installation).

### Step 2: Create VLANs for Employee and Guest Networks

- Go to **Interfaces > Assignments**.
- Under the “VLANs” tab, click on **+Add**.
- Create two VLANs:
  - VLAN 10 for Employees (e.g., internal network)
  - VLAN 20 for Guests (e.g., isolated internet access)
- Assign the VLANs to the appropriate interfaces (if not done automatically). If you have a physical interface for Wi-Fi, assign VLANs to that interface.

### Step 3: Configure Wi-Fi Networks (Wireless Interfaces)

- Go to **Interfaces > Wireless**.
- Add a new wireless interface for each network:
  - Wi-Fi for Employees: Assign it to VLAN 10
  - Wi-Fi for Guests: Assign it to VLAN 20
- Ensure the wireless interface is properly configured (SSID, security settings, etc.) for both networks.

### Step 4: Configure IP Addresses and Subnets for the VLANs

- Go to **Interfaces > Assignments > VLAN 10 (Employees)** and **VLAN 20 (Guests)**.
- Assign IP addresses to both VLANs:
  - VLAN 10 (Employees): Use an internal subnet like 192.168.10.1/24
  - VLAN 20 (Guests): Use a separate subnet like 192.168.20.1/24
- Enable DHCP for both VLANs:
  - Go to **Services → DHCP Server** and enable DHCP for both VLANs.
  - Configure the DHCP ranges (e.g., 192.168.10.100-192.168.10.200 for Employees and 192.168.20.100-192.168.20.200 for Guests).

### Step 5: Create Firewall Rules to Separate Employee and Guest Traffic

- Go to **Firewall > Rules**.
- For VLAN 10 (Employees):
  - Add a rule to allow internal traffic, including access to company resources (such as internal servers or intranet).
  - Add rules to allow communication to the internet.
  - Example:
    - **Action**: Pass
    - **Interface**: LAN (VLAN 10)
    - **Source**: VLAN 10 network (192.168.10.0/24)
    - **Destination**: any
    - **Protocol**: any
- For VLAN 20 (Guests):
  - Add a rule to block access to the internal network (e.g., prevent access to the Employee VLAN 10).
  - Add a rule to allow access to the internet only.
  - Example:
    - **Action**: Pass
    - **Interface**: LAN (VLAN 20)
    - **Source**: VLAN 20 network (192.168.20.0/24)
    - **Destination**: any
    - **Protocol**: any
- Block access between VLANs:
  - On VLAN 20 (Guest) rules, ensure you add a rule to block access to VLAN 10 (Employee network). This is essential to prevent guests from accessing internal company resources.
  - Example:
    - **Action**: Block
    - **Interface**: LAN (VLAN 20)
    - **Source**: VLAN 20 network (192.168.20.0/24)
    - **Destination**: VLAN 10 network (192.168.10.0/24)
    - **Protocol**: any

### Step 6: Set up NAT (Network Address Translation)

- Go to **Firewall > NAT**.
- Make sure Automatic NAT is enabled for both VLANs. This ensures that all traffic from the guest and employee networks will be properly routed to the internet.
