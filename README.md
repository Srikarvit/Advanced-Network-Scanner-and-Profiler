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
-Install dependencies in required.txt

--- 

## Usage
- **In Automatic Mode** - python network_scanner.py
- **Interactive Mode** - python network_scanner.py --interactive

--- 

## Sample Output
Available IPv4 interfaces:
  [0] Ethernet - xxx.xxx.xxx.xxx (netmask 255.xxx.xxx.xxx)
  [1] Wi-Fi - xxx.xxx.xxx.xxx (netmask 255.xxx.xxx.xxx)
Enter index of interface or CIDR (e.g., 192.68.1.2/24):
xxx.xxx.xxx.xxx/24
[+] ARP scanning xxx.xxx.xxx.xxx/24...
[+] Found 4 hosts. Starting profiling...

IP               MAC                  Hostname             Label              OS                     OpenPorts
------------------------------------------------------------------------------------------------------------------
IP Address 1    14:XX:XX:XX:XX:E3    Host_name            This PC            Microsoft Windows 10    139,445
IP Address 2    8C:XX:XX:XX:XX:04    gpon.net             Router             Linux 3.x               53,80,443
IP Address 3    44:XX:XX:XX:XX:8E    xxx.xxx.xxx.yyy      VM / Docker Host   Unknown                 -
IP Address 4    CE:XX:XX:XX:XX:89    xxx.xxx.xxx.yyy      Unknown Device     Unknown                 -

[+] Saved results to:
    📁 results/network_inventory_20251017_111749.csv
    📁 results/network_inventory_20251017_111749.json

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
Service Detection	  Nmap, python-nmap
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
