# scapy_arp_test.py
from scapy.all import arping, conf
import ipaddress, sys

conf.verb = 2  # show packets
cidr = "172.16.211.0/24"
print("Using scapy version:", __import__("scapy").__version__)
print("Attempting ARP scan:", cidr)
answered, unanswered = arping(cidr, timeout=2, verbose=True)
print("Answered:", len(answered))
for s,r in answered:
    print(r.psrc, r.hwsrc)
