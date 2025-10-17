#### 🔍 Advanced Network Scanner & Profiler
### ⚡ "A complete, intelligent, and extensible LAN scanner — built for learning, auditing, and exploration." ### 
> A Python-based intelligent network scanner that discovers, profiles, and maps all devices on your local network — complete with OS, port, and vendor detection.

---

## 🚀 Overview

**Advanced Network Scanner & Profiler** is a powerful yet lightweight tool built with **Python**, **Scapy**, and **Nmap**.  
It automatically detects your network, scans for connected devices, identifies their operating systems and open services, and classifies them (Router / PC / VM / IoT).  

All scan results are exported in structured **CSV** and **JSON** reports, making it a practical tool for:
- Network administrators
- Cybersecurity analysts
- IT students or enthusiasts managing home or lab networks

---

## ✨ Features

- ⚡ **Automatic Network Detection** – Detects your active subnet or lets you select manually.
- 🧩 **ARP-Based Discovery** – Efficient LAN device detection with Scapy.
- 🧠 **OS & Service Fingerprinting** – Uses Nmap for deep analysis of devices.
- 🔍 **Smart Device Classification** – Labels Routers, PCs, VMs, and unknown IoT devices automatically.
- 🏷️ **Vendor Lookup** – Identifies manufacturers from MAC address prefixes.
- 💾 **Exports Results** – Saves detailed results in both `.csv` and `.json` formats.
- 🧑‍💻 **Interactive CLI** – Lets you pick an interface or CIDR block before scanning.
- 🧰 **Cross-Platform** – Works on **Windows, Linux, and macOS**.

---

## 🛠️ Installation
🔸 Step 1 – Clone the Repository
    git clone https://github.com/Srikarvit/Advanced-Network-Scanner-and-Profiler.git
    cd Advanced-Network-Scanner-and-Profiler

🔸 Step 2 – Install Dependencies - pip install -r requirements.txt

🔸 Step 3 – Run as Administrator

Windows (PowerShell): python network_scanner.py
Linux: sudo python3 network_scanner.py

⚠️ Some features (ARP & OS detection) require administrative privileges.

--- 

## Usage
- **In Automatic Mode** - python network_scanner.py
- **Interactive Mode** - python network_scanner.py --interactive
- **Scan a specific CIDR** - python network_scanner.py --cidr 192.168.1.0/24
- **Scan specific ports, faster mode, or disable nmap** - python network_scanner.py --cidr 192.168.1.0/24 --ports 22,80,443 --fast --no-nmap
- **Anonymize MAC addresses for public outputs (if implemented)** - python network_scanner.py --interactive --mask-mac --anon-method mask
- **To enable OS detection** - python network_scanner.py --os-detect --service-detect
- **Export results** - python network_scanner.py --export results/
--- 

# 🧠 How It Works
  ┌──────────────────────────────────────────┐
  │     Automatic Network Discovery          │
  │ (Finds Local Subnet via psutil/ipconfig) │
  └──────────────────────────────────────────┘
                  │
                  ▼
  ┌──────────────────────────────────────────┐
  │        ARP / ICMP Host Scanning          │
  │ (Discovers all live hosts on the subnet) │
  └──────────────────────────────────────────┘
                  │
                  ▼
  ┌──────────────────────────────────────────┐
  │    OS & Service Fingerprinting (Nmap)    │
  │ (Detects OS, Versions, and Open Ports)   │
  └──────────────────────────────────────────┘
                  │
                  ▼
┌──────────────────────────────────────────┐
│        Device Classification             │
│ (Router / IoT / VM / Workstation)        │
└──────────────────────────────────────────┘
                  │
                  ▼
┌──────────────────────────────────────────┐
│       Export Results (.CSV / .JSON)      │
└──────────────────────────────────────────┘

---

# 📁 Output Files
All results are stored automatically in the results/ directory:
File Type	Example File	Description
.csv	network_inventory_20251017_111749.csv	Easy to open in Excel or Google Sheets
.json	network_inventory_20251017_111749.json	Ideal for programmatic processing

--- 

# ⚙️ Tech Stack
Category	          Tools / Libraries
Language	          Python 3.x
Networking	        Scapy, psutil
Service Detection	  Nmap (optional), python-nmap
Data Handling	      csv, json, ipaddress, socket
Platforms	          Windows, Linux, macOS

---

## ⭐ Future Improvements
- 🌍 Add remote network range scanning
- 🧬 Integrate live dashboard visualization (Flask + Chart.js)
- 🧠 Implement passive detection via packet sniffing
- 🕹️ GUI mode with Tkinter or PyQt

---
## 🔐 Security & Legal

Important: Only scan networks and devices that you own or where you have explicit permission. Unauthorized scanning can be illegal and intrusive. This tool is intended for legitimate testing, inventory, and educational use.

--- 

### 1️⃣ Clone this repository
```bash
git clone https://github.com/<your-username>/network-scanner.git
cd network-scanner
