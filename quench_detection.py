from scapy.all import *
from scapy.packet import *


def check_and_inc(x, threshold=5):
    global count
    count += 1
    if count >= threshold:
        print(f"[ATTACK]: ICMP Source Quench attack detected! Total detected Quench packets: {count}")
    elif count < threshold and count > threshold - 3:
        print(f"[WARNING]: There might be an ICMP Source Quench attack. Total detected Quench packets: {count}")


count = 0
capture = sniff(filter="icmp", #iface="Ethernet 3",
                prn=lambda x: check_and_inc(x) if str(x.getlayer(ICMP).type) == "4" else None)
