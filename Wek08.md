# Week 08: Cybersecurity Laws, Standards, and Ethical Hacking Tools

## Learning Objectives

By the end of this week, you will be able to:

- Understand key Australian and international cybersecurity laws and standards
- Identify the purpose and application of various ethical hacking tools
- Apply the ACS Code of Professional Conduct to cybersecurity scenarios
- Analyse real-world case studies involving data breaches and cyber incidents
- Evaluate the legal and ethical implications of penetration testing

---

## 1. Australian Cybersecurity Legal Framework

Australia has developed a comprehensive legal framework to address cybersecurity threats, protect personal information, and ensure the resilience of critical infrastructure.

### 1.1 Privacy Act 1988 (Australia)

The **Privacy Act 1988** is Australia's primary privacy legislation, governing how personal information is collected, used, stored, and disclosed through the **Australian Privacy Principles (APPs)**.

| Aspect | Details |
|--------|---------|
| **Year Introduced** | 1988 |
| **Target Audience** | Australian government agencies and private organisations with annual turnover > $3 million |
| **Key Protection** | Requires organisations to collect only necessary data, secure it against unauthorised access, and respect individuals' rights to access and correct their data |
| **Purpose** | Protect individual privacy and ensure responsible handling of personal information |

#### The 13 Australian Privacy Principles (APPs)

1. **APP 1** – Open and transparent management of personal information
2. **APP 2** – Anonymity and pseudonymity
3. **APP 3** – Collection of solicited personal information
4. **APP 4** – Dealing with unsolicited personal information
5. **APP 5** – Notification of the collection of personal information
6. **APP 6** – Use or disclosure of personal information
7. **APP 7** – Direct marketing
8. **APP 8** – Cross-border disclosure of personal information
9. **APP 9** – Adoption, use or disclosure of government related identifiers
10. **APP 10** – Quality of personal information
11. **APP 11** – Security of personal information
12. **APP 12** – Access to personal information
13. **APP 13** – Correction of personal information

> **Example:** A healthcare provider must ensure patient records are encrypted, access is limited to authorised staff, and patients can request copies of their medical data under APP 12.

---

### 1.2 Notifiable Data Breaches (NDB) Scheme

The **Notifiable Data Breaches Scheme** became mandatory in February 2018, requiring organisations to report serious data breaches.

| Aspect | Details |
|--------|---------|
| **Year Introduced** | 2018 |
| **Target Audience** | Organisations covered by the Privacy Act |
| **Key Protection** | Forces organisations to notify affected individuals and the OAIC promptly, enabling people to take protective action |
| **Purpose** | Increase transparency and reduce harm caused by data breaches |

#### When Notification is Required

A data breach is notifiable when:
1. There is unauthorised access to, or disclosure of, personal information
2. The breach is likely to result in serious harm to any individual
3. The organisation has not been able to prevent the likely risk of serious harm through remedial action

#### Notification Requirements

- Notify the **Office of the Australian Information Commissioner (OAIC)** as soon as practicable
- Notify affected individuals directly (where possible)
- Include: description of the breach, types of information involved, and recommended steps

> **Example:** If a university database containing student names, addresses, and financial information is breached, the university must notify both the OAIC and affected students within 30 days.

---

### 1.3 Cyber Security Act 2024 (Australia)

Australia's **first standalone cybersecurity legislation**, introducing comprehensive obligations for cyber resilience.

| Aspect | Details |
|--------|---------|
| **Year Introduced** | 2024 |
| **Target Audience** | Medium and large businesses, smart-device suppliers, critical sectors |
| **Key Protection** | Improves national cyber defence through reporting requirements, device security standards, and coordinated government response |
| **Purpose** | Strengthen Australia's cyber resilience and improve response to cyber incidents |

#### Key Provisions

- **Ransomware payment reporting** – Organisations must report ransomware payments to the government
- **Smart device security standards** – Manufacturers must meet minimum security requirements
- **Cyber incident review board** – Enables post-incident analysis of major cyber events
- **Limited use provisions** – Protects information shared with the Australian Signals Directorate (ASD)

---

### 1.4 Security of Critical Infrastructure Act 2018 (SOCI)

Protects essential infrastructure from cyber and national security threats.

| Aspect | Details |
|--------|---------|
| **Year Introduced** | 2018 (expanded 2021-2022) |
| **Target Audience** | Owners and operators of critical infrastructure |
| **Key Protection** | Requires risk assessments, mitigation strategies, and incident reporting; allows government intervention during serious threats |
| **Purpose** | Ensure continuity, safety, and resilience of essential services |

#### Critical Infrastructure Sectors (11 Sectors)

1. Communications
2. Data storage and processing
3. Defence industry
4. Energy
5. Financial services and markets
6. Food and grocery
7. Health care and medical
8. Higher education and research
9. Space technology
10. Transport
11. Water and sewerage

---

### 1.5 Criminal Code Act 1995 (Cybercrime Provisions)

| Aspect | Details |
|--------|---------|
| **Year Introduced** | 1995 (cyber provisions added progressively) |
| **Target Audience** | Individuals and organisations in Australia |
| **Key Protection** | Deters cybercrime through criminal penalties and empowers law enforcement |
| **Purpose** | Punish and deter cybercrime; protect national security |

#### Key Offences Under Part 10.7

| Offence | Maximum Penalty |
|---------|-----------------|
| Unauthorised access to computer data | 2 years imprisonment |
| Unauthorised modification of data | 10 years imprisonment |
| Unauthorised impairment of electronic communication | 10 years imprisonment |
| Possession of data with intent to commit a computer offence | 3 years imprisonment |

---

### 1.6 Telecommunications (Interception and Access) Act 1979

| Aspect | Details |
|--------|---------|
| **Year Introduced** | 1979 |
| **Target Audience** | Law enforcement agencies, telecom and ISPs |
| **Key Protection** | Protects privacy by requiring warrants while allowing lawful access for investigations |
| **Purpose** | Balance individual privacy with lawful surveillance needs |

---

## 2. International Standards and Regulations

### 2.1 GDPR (General Data Protection Regulation – EU)

| Aspect | Details |
|--------|---------|
| **Year Introduced** | 2018 |
| **Target Audience** | Any organisation worldwide processing EU residents' data |
| **Key Protection** | Strong individual rights (access, correction, deletion), privacy-by-design, heavy fines |
| **Purpose** | Give individuals control over personal data and enforce high standards |

#### Key GDPR Rights

- **Right to access** – Know what data is held about you
- **Right to rectification** – Correct inaccurate data
- **Right to erasure** ("Right to be forgotten") – Request deletion of data
- **Right to data portability** – Transfer data between services
- **Right to object** – Object to certain types of processing

#### GDPR Penalties

- Up to **€20 million** or **4% of annual global turnover** (whichever is higher)

> **Example:** An Australian e-commerce company selling to EU customers must comply with GDPR, including obtaining explicit consent for data collection and allowing EU customers to request data deletion.

---

### 2.2 PCI-DSS (Payment Card Industry Data Security Standard)

| Aspect | Details |
|--------|---------|
| **Year Introduced** | 2004 |
| **Target Audience** | Businesses that store, process, or transmit cardholder data |
| **Key Protection** | Requires encryption, secure networks, and restricted access to card data |
| **Purpose** | Protect payment card data and ensure secure financial transactions |

#### The 12 PCI-DSS Requirements

1. Install and maintain a firewall configuration
2. Do not use vendor-supplied defaults for passwords
3. Protect stored cardholder data
4. Encrypt transmission of cardholder data
5. Use and regularly update anti-virus software
6. Develop and maintain secure systems and applications
7. Restrict access to cardholder data by business need-to-know
8. Assign a unique ID to each person with computer access
9. Restrict physical access to cardholder data
10. Track and monitor all access to network resources
11. Regularly test security systems and processes
12. Maintain an information security policy

---

## 3. Australian Computer Society (ACS) Code of Professional Conduct

The **ACS Code of Professional Conduct** provides ethical guidelines for ICT professionals in Australia. Cybersecurity professionals must adhere to these principles when conducting security assessments and handling sensitive information.

### 3.1 Core Values

| Value | Description | Cybersecurity Application |
|-------|-------------|---------------------------|
| **The Primacy of the Public Interest** | Place public interest above personal, business, or sectional interests | Report vulnerabilities responsibly; don't exploit discovered weaknesses |
| **The Enhancement of Quality of Life** | Promote the quality of life of those affected by your work | Protect user data and privacy; design secure systems |
| **Honesty** | Be honest in your representation of skills, knowledge, services, and products | Accurately report penetration testing findings; don't exaggerate risks |
| **Competence** | Work competently and diligently for stakeholders | Stay current with security threats and tools; pursue continuous learning |
| **Professional Development** | Enhance your own professional development and that of colleagues | Mentor junior security analysts; participate in security communities |
| **Professionalism** | Enhance the integrity of the profession | Follow responsible disclosure practices; adhere to legal boundaries |

### 3.2 ACS Code Applied to Penetration Testing

When conducting ethical hacking or penetration testing, ACS members must:

1. **Obtain proper authorisation** – Written permission from system owners before testing
2. **Define scope clearly** – Document systems, timeframes, and testing boundaries
3. **Protect sensitive data** – Securely handle any data accessed during testing
4. **Report findings responsibly** – Provide clear, actionable reports to stakeholders
5. **Maintain confidentiality** – Never disclose client vulnerabilities publicly without consent
6. **Act within legal boundaries** – Ensure all activities comply with Australian law

> **Reference:** Australian Computer Society. (2014). *ACS Code of Professional Conduct*. Retrieved from https://www.acs.org.au/content/dam/acs/rules-and-regulations/Code-of-Professional-Conduct_v2.1.pdf

---

## 4. Ethical Hacking Tools

Ethical hacking (penetration testing) uses the same techniques as malicious hackers but with authorisation, to identify and remediate vulnerabilities before they can be exploited.

### 4.1 Network Discovery & Scanning

These foundational tools are used for asset discovery, attack surface mapping, and incident response.

| Tool | Purpose | Link |
|------|---------|------|
| **Nmap** | Network scanning, host discovery, port and service identification | https://nmap.org |
| **Masscan** | Extremely fast large-scale port scanning | https://github.com/robertdavidgraham/masscan |
| **Netcat (nc)** | Network debugging, port listening, data transfer | https://nc110.sourceforge.io |
| **Arp-scan** | Discover devices on local networks | https://github.com/royhills/arp-scan |

#### Example: Basic Nmap Scan

```bash
# Scan a target for open ports
nmap -sV -sC 192.168.1.1

# Scan an entire subnet
nmap -sn 192.168.1.0/24

# Detect operating system
nmap -O 192.168.1.1
```

---

### 4.2 Web Application Security

Most breaches originate from web applications, making these tools critical for security assessments.

| Tool | Purpose | Link |
|------|---------|------|
| **Burp Suite Community** | Intercepting and analysing web traffic | https://portswigger.net/burp |
| **OWASP ZAP** | Automated and manual web vulnerability testing | https://www.zaproxy.org |
| **Nikto** | Web server vulnerability scanning | https://cirt.net/Nikto2 |
| **SQLmap** | Automated SQL injection detection/exploitation | https://sqlmap.org |
| **Gobuster** | Directory and DNS brute forcing | https://github.com/OJ/gobuster |

#### OWASP Top 10 (2021)

Understanding common web vulnerabilities is essential:

1. **A01:2021** – Broken Access Control
2. **A02:2021** – Cryptographic Failures
3. **A03:2021** – Injection
4. **A04:2021** – Insecure Design
5. **A05:2021** – Security Misconfiguration
6. **A06:2021** – Vulnerable and Outdated Components
7. **A07:2021** – Identification and Authentication Failures
8. **A08:2021** – Software and Data Integrity Failures
9. **A09:2021** – Security Logging and Monitoring Failures
10. **A10:2021** – Server-Side Request Forgery (SSRF)

> **Reference:** OWASP Foundation. (2021). *OWASP Top Ten*. Retrieved from https://owasp.org/Top10/

---

### 4.3 Password & Authentication Testing

Weak passwords and credential reuse remain the primary attack vector in many breaches.

| Tool | Purpose | Link |
|------|---------|------|
| **John the Ripper** | Password cracking and strength auditing | https://www.openwall.com/john |
| **Hashcat** | GPU-accelerated password cracking | https://hashcat.net/hashcat |
| **Hydra** | Online login brute-force testing | https://github.com/vanhauser-thc/thc-hydra |
| **CrackMapExec** | Active Directory credential testing | https://github.com/byt3bl33d3r/CrackMapExec |

#### Example: Testing Password Strength with John the Ripper

```bash
# Crack password hashes from a file
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# Show cracked passwords
john --show hashes.txt
```

---

### 4.4 Network Traffic Analysis & Monitoring

Critical for incident response, malware analysis, and breach detection.

| Tool | Purpose | Link |
|------|---------|------|
| **Wireshark** | Deep packet inspection | https://www.wireshark.org |
| **tcpdump** | Command-line packet capture | https://www.tcpdump.org |
| **Zeek (Bro)** | Network security monitoring and analytics | https://zeek.org |
| **Suricata** | Intrusion detection and prevention (IDS/IPS) | https://suricata.io |

---

### 4.5 Vulnerability Assessment & Management

Used for continuous security posture assessment.

| Tool | Purpose | Link |
|------|---------|------|
| **OpenVAS / Greenbone CE** | Vulnerability scanning and reporting | https://www.greenbone.net |
| **Nuclei** | Fast template-based vulnerability scanning | https://github.com/projectdiscovery/nuclei |
| **Trivy** | Container and cloud vulnerability scanning | https://github.com/aquasecurity/trivy |
| **Lynis** | Linux system hardening audits | https://github.com/CISOfy/lynis |

---

### 4.6 Exploitation & Testing Frameworks

Used to prove real risk, not just theoretical vulnerabilities.

| Tool | Purpose | Link |
|------|---------|------|
| **Metasploit Framework** | Exploitation and payload testing | https://github.com/rapid7/metasploit-framework |
| **Searchsploit** | Exploit database search | https://www.exploit-db.com |
| **BeEF** | Browser exploitation framework | https://github.com/beefproject/beef |

#### Example: Metasploit Basic Usage

```bash
# Start Metasploit console
msfconsole

# Search for exploits
search type:exploit name:apache

# Use an exploit module
use exploit/multi/http/apache_mod_cgi_bash_env_exec

# Set target options
set RHOSTS 192.168.1.100
set TARGETURI /cgi-bin/vulnerable.cgi

# Run the exploit
exploit
```

---

### 4.7 Security Operating Systems & Toolkits

Standardised platforms for security operations and testing.

| Tool | Purpose | Link |
|------|---------|------|
| **Kali Linux** | Industry-standard penetration testing OS | https://www.kali.org |
| **Parrot OS** | Security & privacy-focused Linux OS | https://www.parrotsec.org |
| **Security Onion** | SOC monitoring and incident response | https://securityonion.net |

---

### 4.8 SIEM, Logs & Threat Analysis (SOC Roles)

Essential for SOC analysts, compliance, and monitoring.

| Tool | Purpose | Link |
|------|---------|------|
| **ELK Stack (Elastic)** | Log analysis and SIEM | https://www.elastic.co/elastic-stack |
| **Wazuh** | Host-based intrusion detection | https://wazuh.com |
| **TheHive** | Incident response case management | https://thehive-project.org |
| **MISP** | Threat intelligence sharing | https://www.misp-project.org |

---

## 5. Case Studies

### Case Study 1: Optus Data Breach (2022)

#### Overview

In September 2022, Optus, Australia's second-largest telecommunications company, suffered a significant data breach affecting approximately **9.8 million customers**.

#### What Happened

- An attacker exploited an unauthenticated API endpoint
- Personal data including names, dates of birth, phone numbers, email addresses, and identity document numbers (driver's licences, passport numbers, Medicare numbers) were exposed
- The attacker initially demanded a US$1 million ransom

#### Legal and Regulatory Response

- **OAIC investigation** under the Privacy Act 1988
- Potential fines under the Notifiable Data Breaches scheme
- Class action lawsuits initiated by affected customers
- Government introduced legislation to increase penalties for serious privacy breaches

#### Lessons Learned

1. **API Security** – APIs must have proper authentication and authorisation
2. **Data Minimisation** – Only collect and retain necessary data
3. **Incident Response** – Have a clear breach response plan
4. **Regular Security Testing** – Conduct penetration testing on all public-facing systems

> **Reference:** Office of the Australian Information Commissioner. (2022). *OAIC opens investigation into Optus data breach*. Retrieved from https://www.oaic.gov.au/newsroom/oaic-opens-investigation-into-optus-data-breach

---

### Case Study 2: Medibank Data Breach (2022)

#### Overview

In October 2022, Medibank, one of Australia's largest health insurers, experienced a cyberattack resulting in the theft of **9.7 million customer records**, including sensitive health claims data.

#### What Happened

- Attackers used stolen credentials to access Medibank's network
- Data exfiltrated included names, addresses, dates of birth, Medicare numbers, and health claims information
- The ransomware group "BlogXX" (linked to REvil) claimed responsibility
- Medibank refused to pay the ransom; attackers published data on the dark web

#### Impact

- Sensitive health information (mental health, HIV status, pregnancy) exposed
- Estimated costs exceeding **$35 million** in remediation
- Class action lawsuit filed
- Share price dropped significantly

#### Regulatory Response

- OAIC investigation into Privacy Act compliance
- Australian Federal Police investigation
- Government sanctions against the responsible threat actor
- Accelerated passage of the Cyber Security Act 2024

> **Reference:** Australian Cyber Security Centre. (2022). *Cyber security incident affecting Medibank Private*. Retrieved from https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/cyber-security-incident-affecting-medibank-private

---

### Case Study 3: Latitude Financial Data Breach (2023)

#### Overview

In March 2023, Latitude Financial disclosed a data breach affecting **14 million records**, including customer and applicant data dating back to 2005.

#### What Happened

- Attackers obtained employee login credentials through a phishing attack
- Accessed customer data including driver's licence numbers, passport numbers, and financial statements
- One of Australia's largest data breaches by volume

#### Key Issues Identified

1. **Data Retention** – Retained data longer than necessary (some records from 2005)
2. **Credential Security** – Employee credentials compromised via social engineering
3. **Third-Party Risk** – Breach originated through a third-party vendor

#### Lessons Learned

- Implement strong multi-factor authentication (MFA)
- Review data retention policies regularly
- Conduct security assessments on third-party vendors
- Train employees on phishing awareness

> **Reference:** Latitude Financial Services. (2023). *Cyber incident update*. Retrieved from https://www.latitudefinancial.com.au/cyber-incident/

---

### Case Study 4: British Airways GDPR Fine (2020)

#### Overview

The UK Information Commissioner's Office (ICO) fined British Airways **£20 million** for a 2018 data breach under GDPR.

#### What Happened

- Attackers compromised BA's website through a supply chain attack
- Malicious code redirected customers to a fraudulent site
- Approximately **400,000 customers** had personal and payment card details stolen

#### GDPR Violations

- Failure to implement appropriate security measures
- Lack of multi-factor authentication
- Inadequate logging and monitoring

#### Key Takeaways

- GDPR applies to Australian companies processing EU data
- Security must include third-party/supply chain considerations
- Logging and monitoring are essential for breach detection

> **Reference:** Information Commissioner's Office. (2020). *ICO fines British Airways £20m for data breach affecting more than 400,000 customers*. Retrieved from https://ico.org.uk/about-the-ico/media-centre/news-and-blogs/2020/10/ico-fines-british-airways-20m-for-data-breach-affecting-more-than-400-000-customers/

---

## 6. Penetration Testing Methodology

### 6.1 The Five Phases

```
┌─────────────────┐
│ 1. Reconnaissance │ → Gather information about the target
└────────┬────────┘
         ↓
┌─────────────────┐
│ 2. Scanning      │ → Identify live hosts, open ports, services
└────────┬────────┘
         ↓
┌─────────────────┐
│ 3. Gaining Access│ → Exploit vulnerabilities to enter systems
└────────┬────────┘
         ↓
┌─────────────────┐
│ 4. Maintaining   │ → Establish persistence, escalate privileges
│    Access        │
└────────┬────────┘
         ↓
┌─────────────────┐
│ 5. Covering Tracks│ → Document findings, clean up test artifacts
│    & Reporting   │
└─────────────────┘
```

### 6.2 Legal Requirements for Penetration Testing in Australia

Before conducting any penetration test:

1. **Written Authorisation** – Obtain signed permission from the system owner
2. **Scope Definition** – Clearly define target systems, IP ranges, and exclusions
3. **Rules of Engagement** – Document testing hours, notification procedures, and escalation contacts
4. **Legal Review** – Ensure compliance with Criminal Code Act 1995
5. **Insurance** – Maintain professional indemnity insurance
6. **Confidentiality Agreement** – Sign NDAs to protect client information

---

## 7. Summary

### Key Takeaways

1. **Australian Legal Framework**
   - Privacy Act 1988 and APPs govern data handling
   - NDB Scheme requires breach notification
   - Cyber Security Act 2024 introduces new obligations
   - Criminal Code Act criminalises unauthorised access

2. **International Standards**
   - GDPR has global reach for EU data
   - PCI-DSS applies to all card payment processing

3. **ACS Professional Conduct**
   - Public interest comes first
   - Honesty and competence are essential
   - Professional development is ongoing

4. **Ethical Hacking**
   - Always obtain authorisation
   - Use appropriate tools for each phase
   - Report findings responsibly
   - Stay within legal boundaries

---

## 8. Review Questions

1. What are the key differences between the Privacy Act 1988 and the Cyber Security Act 2024?

2. Under what circumstances must an organisation notify the OAIC of a data breach?

3. How does GDPR affect Australian businesses?

4. Explain how the ACS Code of Professional Conduct applies to penetration testing.

5. Using the Optus case study, identify three security controls that could have prevented or minimised the breach.

6. What is the difference between Nmap and Masscan? When would you use each?

7. List five ethical considerations when conducting password auditing.

---

## 9. Practical Exercises

### Exercise 1: Nmap Network Discovery

Using a virtual lab environment (e.g., TryHackMe, HackTheBox):
```bash
# Perform a comprehensive scan
nmap -sV -sC -O -p- [target-IP]
```
Document your findings including open ports, services, and potential vulnerabilities.

### Exercise 2: Web Application Testing

Using OWASP WebGoat or DVWA:
1. Set up the vulnerable application
2. Use Burp Suite to intercept traffic
3. Identify and document three vulnerabilities
4. Propose remediation strategies

### Exercise 3: Case Study Analysis

Choose one of the case studies above and prepare a report addressing:
- Root cause analysis
- Applicable laws and regulations breached
- Recommended security controls
- Estimated business impact

---

## 10. References

### Legislation

- *Criminal Code Act 1995* (Cth)
- *Cyber Security Act 2024* (Cth)
- *Privacy Act 1988* (Cth)
- *Security of Critical Infrastructure Act 2018* (Cth)
- *Telecommunications (Interception and Access) Act 1979* (Cth)
- General Data Protection Regulation (EU) 2016/679

### Standards and Guidelines

- Australian Computer Society. (2014). *ACS Code of Professional Conduct*. https://www.acs.org.au/content/dam/acs/rules-and-regulations/Code-of-Professional-Conduct_v2.1.pdf

- Australian Cyber Security Centre. (2023). *Essential Eight Maturity Model*. https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight

- OWASP Foundation. (2021). *OWASP Top Ten*. https://owasp.org/Top10/

- PCI Security Standards Council. (2022). *PCI DSS v4.0*. https://www.pcisecuritystandards.org/

### Case Study References

- Information Commissioner's Office. (2020). *ICO fines British Airways £20m for data breach affecting more than 400,000 customers*. https://ico.org.uk/about-the-ico/media-centre/news-and-blogs/2020/10/ico-fines-british-airways-20m-for-data-breach-affecting-more-than-400-000-customers/

- Latitude Financial Services. (2023). *Cyber incident update*. https://www.latitudefinancial.com.au/cyber-incident/

- Office of the Australian Information Commissioner. (2022). *OAIC opens investigation into Optus data breach*. https://www.oaic.gov.au/newsroom/oaic-opens-investigation-into-optus-data-breach

- Office of the Australian Information Commissioner. (2023). *Notifiable Data Breaches Report: July to December 2022*. https://www.oaic.gov.au/privacy/notifiable-data-breaches/notifiable-data-breaches-publications

### Tool Documentation

- Kali Linux. (2024). *Kali Linux Documentation*. https://www.kali.org/docs/
- Metasploit. (2024). *Metasploit Documentation*. https://docs.metasploit.com/
- Nmap. (2024). *Nmap Reference Guide*. https://nmap.org/book/man.html
- PortSwigger. (2024). *Burp Suite Documentation*. https://portswigger.net/burp/documentation

---

*Last Updated: January 2026*

*Module: Cybersecurity Fundamentals – Week 08*
