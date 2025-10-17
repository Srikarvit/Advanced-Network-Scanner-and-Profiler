#!/usr/bin/env python3
"""
Network Scanner (Inventory + Vendor lookup + Labeling + Port scan + optional nmap)

Features:
- Safe auto-detection of local network (prefers private addresses). Interactive selection available.
- ARP discovery using scapy (safe default: /24 only).
- MAC vendor lookup (macvendors API via requests) with a small local OUI fallback map.
- Automatic device labeling (Router, This PC, VM/Docker, Android/iPhone, Unknown).
- Threaded lightweight TCP connect port scan + banner grabbing (configurable ports).
- Optional nmap integration (python-nmap wrapper + nmap binary) for -sV -O (service + OS detection).
- Saves results to results/*.csv and results/*.json (unless --no-save).
- CLI flags: --interactive, --cidr, --ports, --no-nmap, --no-vendor-api, --no-save, --fast
"""
from __future__ import annotations
import scapy.all as scapy
import argparse
import ipaddress
import socket
import psutil
import sys
import os
import time
import csv
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Optional
# optional libs
try:
    import requests
except Exception:
    requests = None
try:
    import nmap  
except Exception:
    nmap = None

# -----------------------
# Config
# -----------------------
RESULTS_DIR = "results"
COMMON_PORTS = [21,22,23,25,53,80,110,139,143,161,389,443,445,587,631,3306,3389,5900,8080,8443]
MAC_VENDOR_API = "https://api.macvendors.com/{}"
TCP_TIMEOUT = 1.0
BANNER_TIMEOUT = 1.5
MAX_THREADS = 200

LOCAL_OUI = {
    "14:D4:24": "Dell / Realtek (likely laptop/PC)",
    "8C:DC:02": "Router/ISP ONT (common fiber ONT)",
    "24:E8:53": "Realme / Oppo / Android",
    "44:00:49": "Microsoft/Hyper-V / Docker VM",
    "E2:D9:34": "Virtual/unknown virtual adapter",
}

ROUTER_KEYWORDS = ("router", "gpon", "tp-link", "netgear", "linksys", "asus")

# -----------------------
# Utilities
# -----------------------
def ensure_results_dir():
    os.makedirs(RESULTS_DIR, exist_ok=True)

def now_ts():
    return time.strftime("%Y%m%d_%H%M%S")

def list_ipv4_interfaces() -> List[Tuple[str,str,str]]:
    out = []
    for iface, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            if a.family == socket.AF_INET and a.address and not a.address.startswith("127."):
                netmask = getattr(a, "netmask", "255.255.255.0")
                out.append((iface, a.address, netmask))
    return out

def format_mac(mac: str) -> str:
    return mac.upper()

# -----------------------
# Auto-detect / interactive selection
# -----------------------
def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False

def auto_detect_network() -> Tuple[Optional[str], Optional[str]]:
    candidates = list_ipv4_interfaces()
    for iface, addr, mask in candidates:
        if is_private_ip(addr):
            try:
                net = ipaddress.IPv4Network((addr, mask), strict=False)
                base = str(ipaddress.IPv4Network((str(net.network_address).rsplit('.',1)[0] + ".0/24"), strict=False))
                return base, addr
            except Exception:
                continue
    if candidates:
        first_iface, first_addr, first_mask = candidates[0]
        if first_addr.startswith("169.254."):
            return None, first_addr
        try:
            net = ipaddress.IPv4Network((first_addr, first_mask), strict=False)
            base = str(ipaddress.IPv4Network((str(net.network_address).rsplit('.',1)[0] + ".0/24"), strict=False))
            return base, first_addr
        except Exception:
            return None, first_addr
    return None, None

# -----------------------
# ARP discovery (safe)
# -----------------------
def safe_arp_scan(cidr: str, timeout: float = 2.0, verbose: bool = False) -> List[dict]:
    net = ipaddress.IPv4Network(cidr, strict=False)
    if net.prefixlen < 24:
        raise ValueError("Refusing to ARP-scan networks larger than /24 automatically. Provide a /24 or smaller with --cidr.")
    print(f"[+] ARP scanning {cidr} (timeout={timeout}s)...")
    try:
        answered, unanswered = scapy.arping(str(net), timeout=timeout, verbose=verbose)
    except PermissionError:
        raise
    except Exception as exc:
        print(f"[!] scapy.arping failed ({exc}); falling back to srp.")
        arp = scapy.ARP(pdst=str(net))
        ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        answered = scapy.srp(packet, timeout=timeout, verbose=False)[0]

    hosts = []
    for sent, recv in answered:
        ip = recv.psrc
        mac = format_mac(recv.hwsrc)
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = ip
        hosts.append({"ip": ip, "mac": mac, "hostname": hostname})
    return hosts

# -----------------------
# MAC vendor lookup + labeling
# -----------------------
def mac_vendor_lookup(mac: str, use_api: bool = True) -> str:
    mac = mac.upper()
    prefix = mac.replace("-", ":")[:8]
    # local OUI lookup first (fast)
    for pfx, vendor in LOCAL_OUI.items():
        if prefix.startswith(pfx):
            return vendor
    if use_api and requests:
        try:
            resp = requests.get(MAC_VENDOR_API.format(mac), timeout=2)
            if resp.status_code == 200 and resp.text.strip():
                return resp.text.strip()
        except Exception:
            pass
    return LOCAL_OUI.get(prefix, "Unknown")

def label_device(ip: str, mac: str, hostname: str, my_ip: str, vendor_hint: str) -> str:
    ip = ip.strip()
    hostname_l = hostname.lower() if isinstance(hostname, str) else ""
    vendor_l = vendor_hint.lower() if vendor_hint else ""
    mac_prefix = mac[:8]

    if ip == my_ip:
        return "This PC"

    if any(k in hostname_l for k in ROUTER_KEYWORDS):
        return "Router"
    if any(k in vendor_l for k in ("router", "routerboard", "isp", "ont", "fiberhome", "zte", "huawei")):
        return "Router"

    if mac_prefix in ("44:00:49",):
        return "VM / Docker Host"
    if "docker" in hostname_l or "vm" in hostname_l or "virtual" in hostname_l or "virtualbox" in hostname_l:
        return "VM / Docker Host"

    if "android" in hostname_l or "android" in vendor_l:
        return "Android Phone"
    if "iphone" in hostname_l or "ipad" in hostname_l or "apple" in vendor_l:
        return "Apple Device"

    if "realtek" in vendor_l or "intel" in vendor_l or "broadcom" in vendor_l:
        return "Laptop / Desktop"
    if "raspberry" in vendor_l:
        return "Embedded / IoT (Raspberry Pi)"

    return "Unknown Device"

# -----------------------
# Port scanning (fallback) + banner
# -----------------------
def try_banner(ip: str, port: int, timeout: float = BANNER_TIMEOUT) -> Optional[str]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        try:
            data = s.recv(1024)
            if data:
                return data.decode(errors='ignore').strip()
        except Exception:
            return None
        finally:
            s.close()
    except Exception:
        return None

def tcp_connect_scan(ip: str, ports: List[int], workers: int = 100) -> List[dict]:
    results = []
    def check_port(port: int):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(TCP_TIMEOUT)
            ok = s.connect_ex((ip, port)) == 0
            s.close()
            if ok:
                banner = try_banner(ip, port)
                return {"port": port, "banner": banner}
        except Exception:
            return None
        return None

    with ThreadPoolExecutor(max_workers=min(workers, max(10, len(ports)))) as ex:
        futures = {ex.submit(check_port, p): p for p in ports}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                results.append(res)
    return sorted(results, key=lambda x: x['port'])

# -----------------------
# Nmap integration (safe)
# -----------------------
def nmap_available() -> bool:
    if not nmap:
        return False
    try:
        scanner = nmap.PortScanner()
        return True
    except Exception:
        return False

def nmap_scan_host(ip: str, ports: List[int] | None = None) -> Optional[dict]:
    if not nmap:
        return None
    try:
        scanner = nmap.PortScanner()
    except Exception:
        return None
    args = "-sV -O -T4"
    if ports:
        args += " -p " + ",".join(str(p) for p in ports)
    try:
        scanner.scan(hosts=ip, arguments=args)
    except Exception:
        return None
    if ip not in scanner.all_hosts():
        return None
    host = scanner[ip]
    open_ports = []
    for proto in ("tcp",):
        if proto in host:
            for port_str, info in host[proto].items():
                if info.get("state") == "open":
                    open_ports.append({
                        "port": int(port_str),
                        "name": info.get("name"),
                        "product": info.get("product"),
                        "version": info.get("version"),
                        "extrainfo": info.get("extrainfo")
                    })
    os_name = "Unknown"
    try:
        osmatches = host.get("osmatch", [])
        if osmatches:
            os_name = osmatches[0].get("name", "Unknown")
    except Exception:
        os_name = "Unknown"
    return {"open_ports": open_ports, "os": os_name}

# -----------------------
# Orchestrator
# -----------------------
def profile_hosts(hosts: List[dict], my_ip: str, ports: List[int], use_nmap: bool, use_vendor_api: bool, fast: bool) -> List[dict]:
    results = []
    nmap_ok = use_nmap and nmap_available()
    if use_nmap and not nmap_ok:
        print("[!] nmap requested but not available; falling back to socket scan.")

    workers = 50 if fast else 200

    for h in hosts:
        ip = h['ip']
        mac = h['mac']
        hostname = h['hostname']
        vendor = mac_vendor_lookup(mac, use_api=use_vendor_api)
        label = label_device(ip, mac, hostname, my_ip, vendor)
        entry = {
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "vendor": vendor,
            "label": label,
            "os": "Unknown",
            "open_ports": []
        }
        print(f"[+] Profiling {ip} ({hostname}) -> {label}")

        if nmap_ok:
            nmres = nmap_scan_host(ip, ports=ports)
            if nmres:
                entry["open_ports"] = nmres.get("open_ports", [])
                entry["os"] = nmres.get("os", "Unknown")
                results.append(entry)
                continue

        entry["open_ports"] = tcp_connect_scan(ip, ports, workers=workers)
        try:
            pkt = scapy.IP(dst=ip)/scapy.ICMP()
            resp = scapy.sr1(pkt, timeout=1, verbose=False)
            if resp is not None:
                ttl = getattr(resp, "ttl", 0)
                if ttl >= 128:
                    entry["os"] = "Windows (likely)"
                elif 64 <= ttl < 128:
                    entry["os"] = "Linux/Unix (likely)"
                else:
                    entry["os"] = "Embedded/Network device (likely)"
            else:
                entry["os"] = "Unknown"
        except Exception:
            entry["os"] = "Unknown"

        results.append(entry)
    return results

# -----------------------
# Output helpers
# -----------------------
def save_csv(results: List[dict], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["IP","MAC","Hostname","Vendor","Label","OS","Open Ports (port:banner/product/version)"])
        for r in results:
            ports_text = "; ".join(
                f"{p['port']}:{(p.get('banner') or (p.get('product') or '') + '/' + (p.get('version') or '')).replace(',', ' ')}"
                for p in r["open_ports"]
            ) if r["open_ports"] else ""
            w.writerow([r["ip"], r["mac"], r["hostname"], r["vendor"], r["label"], r["os"], ports_text])

def save_json(results: List[dict], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

def print_summary(results: List[dict]) -> None:
    print()
    header = f"{'IP':<16} {'MAC':<20} {'Hostname':<24} {'Label':<18} {'OS':<22} {'OpenPorts'}"
    print(header)
    print("-"*len(header))
    for r in results:
        ports = ",".join(str(p['port']) for p in r['open_ports']) if r['open_ports'] else "-"
        print(f"{r['ip']:<16} {r['mac']:<20} {r['hostname']:<24} {r['label']:<18} {r['os']:<22} {ports}")

# -----------------------
# CLI
# -----------------------
def parse_args():
    p = argparse.ArgumentParser(description="Network Scanner (inventory + labeling + port scan + optional nmap)")
    p.add_argument("--interactive", action="store_true", help="Interactively choose interface")
    p.add_argument("--cidr", type=str, help="CIDR to scan (overrides detection), e.g. 192.168.1.0/24")
    p.add_argument("--ports", type=str, help="Comma-separated ports to scan (default common ports)")
    p.add_argument("--no-nmap", action="store_true", help="Disable nmap even if present")
    p.add_argument("--no-vendor-api", action="store_true", help="Disable mac vendor API (use local OUI only)")
    p.add_argument("--no-save", action="store_true", help="Do not save CSV/JSON results")
    p.add_argument("--fast", action="store_true", help="Use fewer threads / quicker scan (less CPU)")
    p.add_argument("--timeout", type=float, default=2.0, help="ARP timeout for discovery (seconds)")
    p.add_argument("--verbose", action="store_true", help="Enable scapy verbose output for ARP")
    return p.parse_args()

def main():
    args = parse_args()
    if args.cidr:
        try:
            net = ipaddress.IPv4Network(args.cidr, strict=False)
            if net.prefixlen < 24:
                print("[!] For safety, please provide a /24 or smaller (e.g. 192.168.1.0/24).")
                return
            cidr = str(net)
        except Exception as e:
            print(f"[!] Invalid CIDR: {e}")
            return
    else:
        auto_cidr, local_ip = auto_detect_network()
        if args.interactive:
            candidates = list_ipv4_interfaces()
            if not candidates:
                print("[!] No non-loopback IPv4 interfaces found. Use --cidr.")
                return
            print("\nAvailable IPv4 interfaces:")
            for i, (iface, addr, mask) in enumerate(candidates):
                print(f"  [{i}] {iface} - {addr} (netmask {mask})")
            choice = input("\nEnter index of interface, or CIDR, or 'q' to quit: ").strip()
            if choice.lower() in ("q","quit","exit"):
                return
            if choice.isdigit():
                idx = int(choice)
                if 0 <= idx < len(candidates):
                    iface, addr, mask = candidates[idx]
                    net = ipaddress.IPv4Network((addr, mask), strict=False)
                    cidr = str(ipaddress.IPv4Network((str(net.network_address).rsplit('.',1)[0] + ".0/24"), strict=False))
                else:
                    print("[!] Invalid index")
                    return
            else:
                try:
                    net = ipaddress.IPv4Network(choice, strict=False)
                    if net.prefixlen < 24:
                        print("[!] Please provide /24 or smaller.")
                        return
                    cidr = str(net)
                except Exception as e:
                    print(f"[!] Invalid CIDR: {e}")
                    return
        else:
            if auto_cidr is None:
                print(f"[!] Auto-detection found only link-local or no IP ({local_ip}). Use --cidr or --interactive.")
                return
            cidr = auto_cidr

    # local IP detection for labeling
    local_ip = None
    for iface, addr, mask in list_ipv4_interfaces():
        if cidr.startswith(addr.rsplit(".",1)[0]):
            local_ip = addr
            break
    if not local_ip:
        for iface, addr, mask in list_ipv4_interfaces():
            local_ip = addr
            break

    print(f"Detected & using CIDR: {cidr}")
    if os.name == "nt":
        print("[*] Tip: run PowerShell/CMD as Administrator for best ARP/TTL results.")

    use_vendor_api = (not args.no_vendor_api) and (requests is not None)
    if (not args.no_vendor_api) and (requests is None):
        print("[*] requests not installed; vendor API disabled automatically.")

    use_nmap = (not args.no_nmap) and (nmap is not None) and nmap_available()
    if (not args.no_nmap) and (nmap is not None) and (not nmap_available()):
        print("[*] python-nmap present but nmap binary not available on PATH - nmap disabled.")
    if args.no_nmap:
        use_nmap = False

    if use_nmap:
        print("[*] nmap detected and enabled for OS/service detection.")
    else:
        print("[*] nmap not used; falling back to lightweight port scan.")

    ports = COMMON_PORTS
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(",") if p.strip().isdigit()]
        except Exception:
            print("[!] Could not parse ports list; using default common ports.")

    try:
        hosts = safe_arp_scan(cidr, timeout=args.timeout, verbose=args.verbose)
    except PermissionError:
        print("[!] Permission error: ARP discovery requires Administrator/root privileges.")
        return
    except Exception as e:
        print(f"[!] ARP discovery failed: {e}")
        return

    if not hosts:
        print("[*] No hosts responded to ARP in the selected subnet.")
        return

    print(f"[+] Found {len(hosts)} hosts. Starting profiling (this may take a moment)...")

    results = profile_hosts(hosts, my_ip=local_ip, ports=ports, use_nmap=use_nmap, use_vendor_api=use_vendor_api, fast=args.fast)

    if not args.no_save:
        ensure_results_dir()
        ts = now_ts()
        csv_path = os.path.join(RESULTS_DIR, f"network_inventory_{ts}.csv")
        json_path = os.path.join(RESULTS_DIR, f"network_inventory_{ts}.json")
        try:
            save_csv(results, csv_path)
            save_json(results, json_path)
            print(f"[+] Saved CSV: {csv_path}")
            print(f"[+] Saved JSON: {json_path}")
        except Exception as e:
            print(f"[!] Failed to save results: {e}")
    else:
        print("[*] --no-save set; results will not be saved.")

    print_summary(results)
    print("\nDone.")

if __name__ == "__main__":
    main()

