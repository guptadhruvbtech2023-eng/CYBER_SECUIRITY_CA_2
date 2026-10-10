# Network Forensic Analysis of a RIG Exploit Kit Drive-by Infection Delivering KPOT Stealer
### Group G66 — B.Tech Cyber Security Theory CA-2 Project

---

## A. Project Overview

This project is a dedicated **Network Forensics and Security Operations Center (SOC) web application** built for **Group G66's B.Tech Cyber Security CA-2 case study**.

The primary objective is the forensic reconstruction and investigation of an automated drive-by compromise lifecycle:
1. **Drive-by Redirection:** An internal corporate endpoint (`10.0.76.109`, hostname `BANGKOK-8AC2-PC`, MAC `78:2b:cb:d4:a5:fe`) visits a compromised website containing obfuscated redirect code.
2. **Exploit Kit Delivery:** The client browser is redirected to the **RIG Exploit Kit** landing server (`37.46.135.170`), triggering silent client-side exploitation.
3. **Malware Payload Drop:** The exploit kit delivers a binary payload (`/payload.bin`) identified as the **KPOT Stealer** infostealer trojan.
4. **Command & Control (C2) Activity:** The malware conducts system discovery and queries DNS for malicious domain `fghjkmgru34.site` (resolving to `8.209.83.76`).
5. **Credential Exfiltration:** Stolen credentials and system telemetry are exfiltrated to the external server via outbound HTTP POST beacons targeting `/gate.php`.

The platform provides a dual-mode forensic engine capable of instantly running interactive synthetic demo data or analyzing real `.pcap` / `.pcapng` packet captures uploaded by an analyst.

---

## B. Features

- **SOC Overview Dashboard:** Real-time KPI summary (total packets, unique source/dest IPs, HTTP sessions, flagged events), protocol breakdown chart, traffic over time chart, top talkers IP distribution, and recent security alerts.
- **Real PCAP & PCAPNG Ingestion:** Drag-and-drop file uploader supporting standard network capture files with automatic SHA-256 evidence integrity hashing.
- **Packet Dissection & Search:** Search and filter packets by protocol (`HTTP`, `DNS`, `TCP`, `UDP`, `TLS/HTTPS`, `ARP`), source/destination IP, and suspicious flag status.
- **Deep Packet Inspection Modal:** Click any packet to inspect transport metadata, Ethernet MAC addresses, L7 decoded protocols (DNS query names, HTTP methods/URIs/hosts), and raw application payload snippets.
- **Corroborated Threat Intel (IOCs):** Automatic cross-correlation between Case Study reference indicators and ingested capture packets, verifying observed matches vs. uncorroborated leads.
- **Interactive Attack Timeline & Topology:** Chronological timeline separating directly observed packet evidence from analyst interpretation, accompanied by an interactive HTML5 Canvas network communication graph.
- **Forensic Investigation & MITRE ATT&CK Matrix:** Deep dissection of HTTP POST `/gate.php`, NIST SP 800-86 four-phase forensic breakdown, and ATT&CK tactic/technique mapping with confidence levels.
- **Interactive Incident Response Playbook:** 9-step NIST SP 800-61 Rev 2 containment and eradication checklist with completion percentage tracking and hardening recommendations.
- **Executive Forensic Report:** Clean, printable, academic report with browser print-to-PDF formatting.
- **CSV Data Export:** One-click CSV export for both filtered packet logs and the corroborated IOC table.

---

## C. Technologies Used

- **Backend:** Python 3.11, Flask 2.3+
- **Packet Parsing & Forensic Engine:** Scapy 2.8+ (pure-Python packet decoding engine)
- **Frontend:** HTML5, CSS3, JavaScript (ES6+)
- **Data Visualizations:** Chart.js 4+
- **Typography & Icons:** FontAwesome 6, Google Fonts (Inter & Fira Code)

---

## D. Prerequisites

Before running the application, make sure you have Python 3.10 or higher installed on your Windows computer.

To check your Python and pip versions, open PowerShell or Command Prompt and run:

```powershell
python --version
python -m pip --version
```

If Python is not recognised, see **Section K: Troubleshooting**.

---

## E. Installation

Follow these exact steps to set up the project on Windows:

1. Open **PowerShell** or **Command Prompt** and navigate to the project directory:

```powershell
cd G66-Network-Forensics
```

2. Create a virtual environment named `.venv`:

```powershell
python -m venv .venv
```

3. Activate the virtual environment:

- **In PowerShell:**
  ```powershell
  .venv\Scripts\activate
  ```
  *(Note: If PowerShell displays a script execution policy error, see the Command Prompt alternative below).*

- **In Command Prompt (cmd.exe) — Recommended alternative:**
  ```cmd
  .venv\Scripts\activate.bat
  ```

4. Upgrade `pip` to the latest version:

```powershell
python -m pip install --upgrade pip
```

5. Install the required dependencies:

```powershell
pip install -r requirements.txt
```

---

## F. Running the Application

To start the forensic SOC server:

```powershell
python app.py
```

The terminal will print:
```
======================================================================
 G66 NETWORK FORENSIC ANALYSIS PLATFORM
 Case Study: RIG Exploit Kit & KPOT Stealer Drive-by Infection
 Starting SOC web interface at http://127.0.0.1:5000
======================================================================
```

1. Open your web browser (Chrome, Edge, Firefox) and navigate to:
   **`http://127.0.0.1:5000`**
2. To stop the server at any time, press **`Ctrl+C`** in your terminal window.

---

## G. One-Click Startup (run.bat)

For quick demonstration, a double-clickable Windows batch file (`run.bat`) is included in the project folder:

1. Double-click **`run.bat`** in Windows File Explorer.
2. The batch script will automatically:
   - Check your Python installation.
   - Create and activate the `.venv` virtual environment if it does not already exist.
   - Install missing dependencies from `requirements.txt`.
   - Launch your default web browser directly to `http://127.0.0.1:5000`.
   - Start the Flask backend server.

---

## H. Demo Mode Instructions

The application loads in **DEMO DATA** mode immediately upon launch so you can demonstrate the project without needing to upload a file first:

1. **Inspect Dashboard:** Check KPI counters and view the interactive protocol doughnut, traffic volume line chart, and top talker bar chart.
2. **Inspect Packets:** Click **PCAP & Packets** in the sidebar. Filter by protocol (e.g. `HTTP` or `DNS`), filter by source IP `10.0.76.109`, or check **Flagged Only**. Click on any packet row to open the deep payload inspection modal.
3. **Verify IOCs:** Click **IOC Threat Intel** to examine the reference indicator table with verified matches in the synthetic capture.
4. **View Attack Chain:** Click **Attack Timeline** to observe the 5-stage conceptual attack chain and interactive network topology graph.
5. **Interactive IR Checklist:** Click **Incident Response** to check off containment steps; watch the completion percentage bar update automatically.
6. **Generate Report:** Click **Executive Report** and click the **Print / Save as PDF** button to preview or print the formatted forensic dossier.

---

## I. Real PCAP Analysis Instructions

To analyze a live or recorded network capture:

1. Navigate to the **PCAP & Packets** tab.
2. Drag and drop any `.pcap` or `.pcapng` file into the upload box (or click **Select File**).
3. The platform will:
   - Verify the file extension and enforce a 50MB file size safeguard.
   - Compute the cryptographic SHA-256 hash of the evidence.
   - Parse network frames with Scapy, extracting timestamps, IPs, ports, L7 protocols, DNS queries, and HTTP requests.
   - Correlate extracted traffic against the case study IOCs.
   - Switch the status pill to **`PCAP ANALYSIS (DIRECT EVIDENCE)`**.
4. **Traffic Visibility Note:**
   - Unencrypted protocols (`HTTP`, `DNS`, `ARP`, `TCP`) provide complete header and payload visibility.
   - Encrypted protocols (`TLS/HTTPS`) reveal outer endpoint IPs and handshake ports, but payload data remains encrypted by design.

A test capture file named **`test_case_study.pcap`** is included in the repository for testing real PCAP uploads immediately!

---

## J. Folder Structure

```
G66-Network-Forensics/
│
├── app.py                     # Flask web server, forensic parser, and REST API
├── requirements.txt           # Python dependencies (Flask, Scapy)
├── README.md                  # Comprehensive project documentation (this file)
├── run.bat                    # One-click Windows startup script
├── test_case_study.pcap       # Sample test capture file for upload verification
│
├── templates/
│   └── index.html             # Single-page SOC application HTML template
│
├── static/
│   ├── style.css              # Dark Navy SOC theme, KPI grids, and print stylesheet
│   └── app.js                 # Chart.js integration, canvas topology, and AJAX logic
│
└── uploads/                   # Staging directory for uploaded PCAP evidence files
```

---

## K. Troubleshooting

### 1. `python` is not recognised as an internal or external command
- **Cause:** Python is not added to the Windows system `PATH` variable.
- **Solution:** Reinstall Python from [python.org](https://www.python.org/downloads/) and check the box that says **"Add python.exe to PATH"** at the bottom of the installer window.

### 2. PowerShell script activation is disabled (`Execution_Policies`)
- **Cause:** Windows PowerShell restricts running unsigned scripts by default.
- **Solution:** Instead of changing system-wide security policies, activate the virtual environment using Command Prompt (`cmd.exe`):
  ```cmd
  .venv\Scripts\activate.bat
  ```
  Or run `python app.py` directly using the global Python interpreter.

### 3. Port 5000 already in use
- **Cause:** Another application or earlier instance of Flask is still running on port 5000.
- **Solution:** In PowerShell, find and terminate the process holding port 5000:
  ```powershell
  Get-Process -Id (Get-NetTCPConnection -LocalPort 5000).OwningProcess | Stop-Process -Force
  ```
  Or change the port in `app.py` line `app.run(..., port=5050)` and visit `http://127.0.0.1:5050`.

### 4. Scapy runtime warning `No libpcap provider available`
- **Cause:** Windows does not have WinPcap or Npcap installed for live wire sniffing.
- **Solution:** This is harmless for this project! PCAP file reading and parsing is performed entirely in user-space Python and does not require Npcap drivers.

### 5. File upload size limit error
- **Cause:** Uploaded PCAP exceeds 50MB.
- **Solution:** Filter or slice the capture in Wireshark (`File -> Export Specified Packets`) before uploading to retain the relevant infection time window.

---

## L. Security and Privacy

- **Local Processing:** All forensic analysis occurs strictly on `127.0.0.1` (localhost). No network traffic, evidence files, or IP addresses are sent to external third parties.
- **Evidence Preservation:** Uploaded files are saved to the isolated `uploads/` directory with SHA-256 hashes computed to preserve the digital chain of custody.
- **Safety Precaution:** The application inspects packet headers and payload byte sequences statically. It **never** executes payloads, connects to malicious IP addresses (`37.46.135.170`, `8.209.83.76`), or queries active threat domains in real time.

---

## M. Academic & Forensic Limitations

- **Demo Data vs. Direct Evidence:** Synthetic demo records are clearly labelled with the `DEMO DATA` status pill. Ingested PCAP captures are flagged with `PCAP ANALYSIS`.
- **Observed Evidence vs. Inferred Stages:** Network traffic provides definitive evidence of wire communications (DNS queries, HTTP POST beacons). Endpoint execution details (such as memory-injected shellcode or process injection) are forensic inferences requiring host-based memory/disk forensics for secondary confirmation.
- **Scope:** This tool is designed as an educational digital forensics demonstration platform for university evaluation.

---

## N. Academic Project Information

- **Institution:** B.Tech Cyber Security
- **Course:** Cyber Security — Theory CA-2 Case Study
- **Group:** Group G66
- **Project Title:** Network Forensic Analysis of a RIG Exploit Kit Drive-by Infection Delivering KPOT Stealer
- **Case Study Focus:** Forensic dissection of drive-by redirection, RIG exploit gate delivery, host compromise (`BANGKOK-8AC2-PC`), and KPOT Stealer C2 exfiltration.
