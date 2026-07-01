# 🛡️ MITRE ATT&CK Detection Lab

![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=for-the-badge)
![Splunk](https://img.shields.io/badge/Splunk-Enterprise-black?style=for-the-badge&logo=splunk)
![Sysmon](https://img.shields.io/badge/Microsoft-Sysmon-blue?style=for-the-badge&logo=windows)
![Status](https://img.shields.io/badge/Status-In%20Progress-yellow?style=for-the-badge)

## 📌 Project Overview

A hands-on home lab that simulates real-world cyberattacks using **Atomic Red Team**, detects them using **Sysmon** and **Splunk**, writes **SPL detection rules**, and maps every detection to the **MITRE ATT&CK framework**. This project replicates the exact workflow used by SOC analysts and threat detection engineers in enterprise environments.

---

## 🏗️ Lab Architecture

+-------------------------------------+         +-------------------------------------+
|          Windows 11 VM              |         |       Host Machine (Laptop)         |
|                                     |         |                                     |
|  +----------+   +--------------+   |  Port   |  +------------------------------+  |
|  |  Sysmon  |-->|  Universal   |   |  9997   |  |      Splunk Enterprise        |  |
|  | (Monitor)|   |  Forwarder   |---+-------->|  |     (SIEM / Dashboard)        |  |
|  +----------+   +--------------+   |         |  +------------------------------+  |
|                                    |         |                                     |
|  +------------------------------+  |         +-------------------------------------+
|  |      Atomic Red Team         |  |
|  |    (Attack Simulator)        |  |
|  +------------------------------+  |
+-------------------------------------+

---
## 🛠️ Tools & Technologies

| Tool | Version | Purpose |
|------|---------|---------|
| Splunk Enterprise | 10.4.0 | SIEM — log collection, search, dashboards |
| Sysmon | Latest (Sysinternals) | Windows endpoint monitoring |
| Splunk Universal Forwarder | 10.4.1 | Log forwarding from VM to Splunk |
| Atomic Red Team | Latest | ATT&CK technique simulation |
| Olaf Hartong Sysmon Config | Master | Production-grade Sysmon ruleset |
| VMware Workstation | — | Virtualization |
| Windows 11 (VM) | x64 | Target endpoint machine |

---

## 📅 Project Progress

| Day | Topic | Status |
|-----|-------|--------|
| Day 1 | Splunk + Sysmon + Universal Forwarder Setup | ✅ Complete |
| Day 2 | SPL Basics + Sysmon Event ID Analysis | 🔄 In Progress |
| Day 3 | Atomic Red Team Installation + Attack Simulations | ⏳ Pending |
| Day 4 | SPL Detection Rules — Part 1 | ⏳ Pending |
| Day 5 | SPL Detection Rules — Part 2 | ⏳ Pending |
| Day 6 | Splunk Threat Detection Dashboard | ⏳ Pending |
| Day 7 | ATT&CK Coverage Matrix + Final Report | ⏳ Pending |

---

## 📂 Daily Logs

<details>
<summary><b>📅 Day 1 — Splunk + Sysmon + Universal Forwarder Setup</b></summary>

<br>

### 🎯 Objective
Set up the complete log pipeline from scratch: install Splunk Enterprise on the host machine as the SIEM, install Sysmon on the Windows 11 VM as the endpoint monitor, install and configure the Universal Forwarder to ship Sysmon logs from the VM to Splunk over port 9997, and verify that data is flowing end-to-end.

---

### 🔧 Step 1 — Splunk Enterprise Installation & Configuration

**What was done:**
- Downloaded Splunk Enterprise 10.4.0 (.msi) on the host machine from splunk.com
- Installed Splunk using Local System account (not Domain account — host machine is not domain-joined)
- Created admin credentials during installation
- Splunk Web launched automatically at `http://127.0.0.1:8000`
- Configured Splunk to listen and receive incoming log data on **port 9997** (Settings → Forwarding and Receiving → Configure Receiving → Add new → 9997)

**Why port 9997:** This is the standard industry default port used by Splunk Universal Forwarder to ship data to a Splunk indexer. All VMs in this lab will forward their logs to this port.

<details>
<summary>📸 Screenshots — Splunk Installation & Configuration</summary>
<br>

**Screenshot 1 — Splunk Enterprise login page at 127.0.0.1:8000**
> Splunk Web launched successfully after installation. The login page confirms Splunk Enterprise is running as a service on the host machine on port 8000.

![Screenshot1](/Day1-Screenshots/Screenshot1.png)

---

**Screenshot 2 — Splunk Home Page after login**
> The Splunk home screen showing Search & Reporting, Dashboards, Alerts, and Reports — the main interface we will use throughout this project to search logs and build detections.

![Screenshot2](/Day1-Screenshots/Screenshot2.png)

---

**Screenshot 3 — Port 9997 configured as receiving port**
> Settings → Forwarding and Receiving → Configure Receiving showing port 9997 enabled and listening for incoming log data from the Universal Forwarder on the Windows 11 VM.

![Screenshot3](/Day1-Screenshots/Screenshot3.png)

</details>

---

### 🔧 Step 2 — Sysmon Installation on Windows 11 VM

**What was done:**
- Downloaded Sysmon from Microsoft Sysinternals (learn.microsoft.com/sysinternals/downloads/sysmon)
- Downloaded the Olaf Hartong sysmon-modular config (`sysmonconfig.xml`) from GitHub — this is a production-grade ruleset used in real SOC environments
- Created `C:\Sysmon` folder and placed both Sysmon executables and the config file there
- Fixed a Windows file extension issue (`.xml` was saving as `.html` due to browser download behavior — resolved by enabling "Show file extensions" in File Explorer and downloading the raw GitHub file directly)
- Installed Sysmon as a Windows service using:

```cmd
cd C:\Sysmon
Sysmon64.exe -i sysmonconfig.xml
```

- Sysmon accepted the EULA and started as a background service — confirmed with "Sysmon64 started" message

**What Sysmon does:** Acts as a CCTV camera on the endpoint. Once installed it silently records every process creation, network connection, file creation, registry modification, and DLL load — exactly the activities attackers perform. These events go into the Windows Event Log under `Microsoft-Windows-Sysmon/Operational`.

<details>
<summary>📸 Screenshots — Sysmon Installation</summary>
<br>

**Screenshot 15 — Sysmon official Microsoft Sysinternals download page**
> The official Microsoft page for Sysmon (System Monitor), written by Mark Russinovich and Thomas Garnier. Downloaded the 4.6 MB ZIP file from here.

![Screenshot15](/Day1-Screenshots/Screenshot15.png)

---

**Screenshot 4 — C:\Sysmon folder contents**
> The `C:\Sysmon` folder containing all required files: `Sysmon64.exe` (main executable for 64-bit systems), `Sysmon.exe` (32-bit), `Sysmon64a.exe`, `Eula.txt`, and `sysmonconfig.xml` (the Olaf Hartong detection ruleset).

![Screenshot4](/Day1-Screenshots/Screenshot4.jpeg)

---

**Screenshot 5 — Command Prompt showing Sysmon installation**
> Administrator Command Prompt showing `cd C:\Sysmon` navigation and `Sysmon64.exe -i sysmonconfig.xml` installation command. The `-i` flag means "install with this configuration file." Output confirms "Sysmon64 started" — Sysmon is now running as a Windows service.

![Screenshot5](/Day1-Screenshots/Screenshot5.png)

---

**Screenshot 6 — services.msc showing Sysmon64 running**
> Windows Services Manager (`services.msc`) confirming that Sysmon64 is installed as a Windows service with status "Running." This means Sysmon survives reboots and continuously monitors the endpoint without manual intervention.

![Screenshot6](/Day1-Screenshots/Screenshot6.png)

</details>

---

### 🔧 Step 3 — Universal Forwarder Installation & Configuration

**What was done:**
- Downloaded Splunk Universal Forwarder 10.4.1 (64-bit .msi, 150.93 MB) on the Windows 11 VM
- Installed using Local System account, selected Security Logs + Application Logs during setup
- During installation the receiving indexer IP/port entry did not save automatically — fixed by manually creating `outputs.conf`
- Created two configuration files manually in `C:\Program Files\SplunkUniversalForwarder\etc\system\local\`:

**inputs.conf** — tells the Forwarder what to collect (Sysmon logs):

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = false
index = main

**outputs.conf** — tells the Forwarder where to send data (Splunk on host):

[tcpout]
defaultGroup = default-autolb-group
[tcpout:default-autolb-group]
server = 192.168.119.1:9997
[tcpout-server://192.168.119.1:9997]

- Fixed a Windows file extension issue (.conf files were saving as .conf.txt — resolved by enabling "Show file extensions" in File Explorer and renaming correctly)
- Created a Windows Defender Firewall inbound rule on the host to allow TCP port 9997
- Verified network connectivity from VM to host using PowerShell: `Test-NetConnection -ComputerName 192.168.119.1 -Port 9997` → **TcpTestSucceeded: True**
- Restarted SplunkForwarder service using `net stop SplunkForwarder` and `net start SplunkForwarder`

**Why 192.168.119.1:** The Windows 11 VM uses NAT networking mode in VMware. The VMware VMnet8 virtual adapter on the host gets assigned `192.168.119.1` as the gateway — this is the address the VM uses to reach the host machine, and therefore where it sends its logs.

<details>
<summary>📸 Screenshots — Universal Forwarder Configuration</summary>
<br>

**Screenshot 16 — Splunk Universal Forwarder download page**
> Official Splunk download page for Universal Forwarder 10.4.1. Selected the 64-bit Windows .msi (150.93 MB) which supports Windows 10, Windows 11, and Windows Server editions.

![Screenshot16](/Day1-Screenshots/Screenshot16.png)

---

**Screenshot 7 — SplunkUniversalForwarder local config folder**
> File Explorer showing `C:\Program Files\SplunkUniversalForwarder\etc\system\local` containing both manually created configuration files: `inputs.conf` (1 KB) and `outputs.conf` (1 KB). These two files are the core of the Forwarder's behaviour.

![Screenshot7](/Day1-Screenshots/Screenshot7.png)

---

**Screenshot 8 — inputs.conf content in Notepad**
> The `inputs.conf` file telling the Universal Forwarder to collect logs from the Sysmon operational channel (`Microsoft-Windows-Sysmon/Operational`), send them to the `main` index in Splunk, and keep collection enabled (`disabled = false`).

![Screenshot8](/Day1-Screenshots/Screenshot8.png)

---

**Screenshot 9 — outputs.conf content in Notepad**
> The `outputs.conf` file telling the Universal Forwarder to send all collected logs to `192.168.119.1:9997` — the host machine's VMnet8 IP address on Splunk's receiving port. Without this file the Forwarder has no destination and sends nothing.

![Screenshot9](/Day1-Screenshots/Screenshot9.png)

---

**Screenshot 10 — Windows Defender Firewall inbound rule**
> Windows Defender Firewall with Advanced Security showing the manually created inbound rule "Splunk Receiving 9997" — allows TCP traffic on port 9997 from any address. This rule was necessary because the host firewall was silently blocking incoming connections from the VM, causing zero events in Splunk.

![Screenshot10](/Day1-Screenshots/Screenshot10.png)

---

**Screenshot 11 — PowerShell TcpTestSucceeded: True**
> PowerShell `Test-NetConnection` result confirming the Windows 11 VM (source: `192.168.119.140`, Interface: Ethernet 1 / NAT adapter) can successfully reach the host machine at `192.168.119.1` on port 9997. This ruled out network issues and confirmed the problem was configuration-only.

![Screenshot11](/Day1-Screenshots/Screenshot11.png)

</details>

---

### 🔧 Step 4 — Verification: Data Flowing into Splunk

**What was done:**
- Ran Splunk search: `index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"`
- Result: **3,700 Sysmon events** received in Splunk within minutes of Forwarder restart
- Confirmed fields: EventCode, Image, ComputerName (Shreya.shreya.com), ProcessId, Details, CreationUtcTime
- Pipeline confirmed working end-to-end: **Sysmon → Universal Forwarder → Splunk**

**Key Sysmon Event IDs observed:**
- **EventCode 3** — Network connection detected
- **EventCode 13** — Registry value set

<details>
<summary>📸 Screenshots — Verification</summary>
<br>

**Screenshot 12 — Splunk showing 3,700 Sysmon events**
> Splunk Search & Reporting showing 3,700 events returned for the Sysmon sourcetype query over the last 24 hours. The timeline bar chart confirms events are arriving continuously. This is the final proof that the entire pipeline (Sysmon → Forwarder → Splunk) is working correctly.

![Screenshot12](/Day1-Screenshots/Screenshot12.png)

---

**Screenshot 13 — Expanded Sysmon event showing all fields**
> A single Sysmon event expanded in Splunk showing all parsed fields: LogName, EventCode, EventType, ComputerName, and detailed process/network information. These fields are what we will search and filter in our SPL detection rules from Day 2 onwards.

![Screenshot13](/Day1-Screenshots/Screenshot13.png)

---

**Screenshot 14 — Splunk Interesting Fields panel**
> The left sidebar in Splunk showing automatically extracted "Interesting Fields" from the Sysmon events: ComputerName (1 value), EventCode (14 unique values), Image (98 unique process images), CreationUtcTime (100+ values). These fields confirm Splunk has correctly parsed the Sysmon log structure and is ready for detection queries.

![Screenshot14](/Day1-Screenshots/Screenshot14.png)

</details>

---

### ✅ Day 1 Summary

| Component | Status |
|-----------|--------|
| Splunk Enterprise installed on host | ✅ |
| Splunk receiving port 9997 configured | ✅ |
| Sysmon installed on Windows 11 VM | ✅ |
| Sysmon config (Olaf Hartong) applied | ✅ |
| Universal Forwarder installed on VM | ✅ |
| inputs.conf configured for Sysmon | ✅ |
| outputs.conf configured with host IP | ✅ |
| Firewall rule for port 9997 created | ✅ |
| Network connectivity verified | ✅ |
| 3,700 Sysmon events visible in Splunk | ✅ |

**Pipeline:** `Sysmon (Windows 11 VM)` → `Universal Forwarder` → `192.168.119.1:9997` → `Splunk Enterprise (Host)`

</details>

---

## 📜 License
This project is for educational purposes. Tools used are free and open-source or free-tier licensed.

## 👩‍💻 Author
**Shreya Singh Chauhan**
