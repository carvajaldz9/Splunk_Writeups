This document outlines commonly used Splunk queries for detecting and investigating cybersecurity threats. Each query is grouped by category and includes detailed purposes, expected behavior, and context for use.

---

## A. Authentication & Access Monitoring

### 1. Brute Force Detection

```spl
index=security (failed OR failure) (login OR authentication)
| stats count by src_ip, user
| sort -count
```

**Purpose:** Identify brute-force login attempts. This query searches for keywords like "failed" and "authentication" in logs, then aggregates counts of failures by `src_ip` and `user`. High counts may indicate repeated unauthorized login attempts.

### 2. Multiple Failed Windows Logins

```spl
index=windows EventCode=4625
| stats count by src_ip, user
| where count > 5
```

**Purpose:** Detect account compromise or password guessing on Windows systems. Event ID 4625 represents a failed login attempt. More than 5 from a single source or user suggests potential malicious activity.

### 3. Successful Login After Multiple Failures

```spl
(index=windows EventCode=4625 OR EventCode=4624)
| transaction user maxspan=5m
| search EventCode=4624 AND EventCode=4625
| table user, src_ip, _time, EventCode
```

**Purpose:** Identify suspicious logins that succeed after a sequence of failures. This could indicate brute-force success or credential stuffing.

### 4. Login from Unusual Geolocations

```spl
index=auth sourcetype=okta:auth OR sourcetype=duo
| iplocation src_ip
| stats dc(Country) as uniqueCountries by user
| where uniqueCountries > 2
```

**Purpose:** Detect potential account compromise from anomalous locations. If a single user logs in from multiple countries in a short period, it may indicate unauthorized access.

---

## B. Malware & Ransomware Detection

### 1. Ransomware Indicators

```spl
index=endpoint (process="*.exe" OR file_created="*.encrypted")
| stats count by host, process_name, file_path
```

**Purpose:** Flag ransomware behaviors by identifying executable processes and encrypted file creation, commonly seen in attacks like WannaCry or LockBit.

### 2. Malware-Related URLs

```spl
index=proxy (url="*malware*" OR url="*exploit*")
| table src_ip, dest_ip, url, user_agent
```

**Purpose:** Track access to known malicious URLs through proxy logs. Helpful in identifying users who may have downloaded malicious payloads.

### 3. Rare Executable Launches

```spl
index=endpoint sourcetype=processes
| stats count by process_name, user
| where count < 3
```

**Purpose:** Identify rare or unusual processes that could be part of malicious payloads or tools like Mimikatz.

### 4. PowerShell with Obfuscation

```spl
index=windows process_name="powershell.exe" command_line="*"
| search command_line="*EncodedCommand*"
| table user, host, command_line
```

**Purpose:** Detect obfuscated or encoded PowerShell commands, a common tactic in fileless malware attacks.

---

## C. Network Anomalies & Attacks

### 1. Denied Firewall Connections

```spl
index=firewall action=denied
| stats count by src_ip, dest_ip, dest_port
| sort -count
```

**Purpose:** Show sources frequently blocked by firewall rules, which could indicate port scans, exploit attempts, or reconnaissance activity.

### 2. High-Volume Data Transfer

```spl
index=netflow bytes > 1000000
| stats sum(bytes) by src_ip, dest_ip
| sort -sum(bytes)
```

**Purpose:** Identify potential data exfiltration events by flagging unusually large outbound transfers.

### 3. DNS Tunneling Detection

```spl
index=dns query="*"
| eval domain_length=len(query)
| stats avg(domain_length) as avg_len by src_ip
| where avg_len > 50
```

**Purpose:** Detect DNS tunneling, which uses long DNS queries to exfiltrate data covertly.

### 4. Port Scanning Behavior

```spl
index=firewall action=allowed
| stats dc(dest_port) by src_ip
| where dc(dest_port) > 50
```

**Purpose:** Identify potential port scanning by flagging IPs attempting to access many unique ports.

---

## D. Insider Threat Detection

### 1. Unusual File Modifications

```spl
index=fileshare (file_deleted OR file_modified)
| stats count by user, file_path
| where count > 10
```

**Purpose:** Detect users modifying or deleting a high number of files, which may suggest sabotage or data theft.

### 2. Malicious Email Attachments

```spl
index=email (attachment="*.exe" OR attachment="*.js")
| table sender, recipient, subject, attachment
```

**Purpose:** Find emails that contain potentially malicious executable or script files, often used in phishing attacks.

### 3. Off-Hours File Access

```spl
index=fileshare
| eval hour=strftime(_time, "%H")
| where hour < 6 OR hour > 20
| stats count by user, file_path
```

**Purpose:** Monitor file access outside normal business hours, a red flag for unauthorized activity.

### 4. Privileged Account Misuse

```spl
index=windows EventCode=4672
| stats count by user, src_ip
```

**Purpose:** Track use of privileged accounts (Event ID 4672), which may be used during insider attacks or lateral movement.

---

## E. Lateral Movement & Privilege Escalation

### 1. Pass-the-Hash/Golden Ticket Indicators

```spl
index=windows (EventCode=4624 OR EventCode=4769 OR EventCode=4776) LogonType=3
| stats count by user, src_ip, dest_ip
```

**Purpose:** Detect lateral movement using suspicious logon types and Kerberos service tickets, often abused during attacks.

### 2. Local Admin Privilege Escalation

```spl
index=windows EventCode=4673
| stats count by user, process_name
```

**Purpose:** Identify attempts to perform privileged operations that require elevated rights.

---

## F. Phishing Detection

### 1. Suspicious Links in Emails

```spl
index=email subject="*invoice*" OR body="*click here*"
| table sender, recipient, subject
```

**Purpose:** Flag emails using phishing keywords designed to lure users into clicking malicious links.

### 2. Newly Registered Domains Accessed

```spl
index=dns
| lookup domain_age_lookup domain AS query OUTPUT age_days
| where age_days < 30
```

**Purpose:** Detect access to newly registered domains, often used in phishing or command-and-control (C2).

---
