from scapy.all import *
from scapy.packet import *

class Detector:
    # ***Written by Adam***
    # Contstructor for the Detector class.
    # Parameters:
    #       interface (str): Name of the interface to use for packet sniffing (e.g., "en0" or "Ethernet 3"). If only one interface exists, leave this parameter empty. Default: None.
    #       threshold (int): Number of ICMP Source Quench packets that constitute an attack. Default: 10.
    def __init__(self, interface = None, threshold = 10):
        self.interface = interface
        self.threshold = threshold
        self.count = 0


    # ***Written by Adam***
    # This function increments a counter everytime a Quench packet is detected.
    # When the # Quench packets is below self.threshold, the function displays an alert message to warn the user of a potential Quench attack.
    # When the # Quench packets exceeds self.threshold, the function displays a message informing the user of an ongoing Quench attack.
    # Parameters:
    #       x: Quench packet received by a call from the sniff() function
    def check_and_inc(self, x):
        self.count += 1
        if self.count >= self.threshold:
            print(f"[ATTACK]: ICMP Source Quench attack detected! Total detected Quench packets: {self.count}")
        elif self.count < self.threshold and self.count > 0:
            print(f"[WARNING]: There might be an ICMP Source Quench attack. Total detected Quench packets: {self.count}")


    # This function sniffs incoming packets, and only collects ICMP Source Quench packets (Type 4).
    # ***Toufic***: Added sniff function and filtered by "icmp"
    # ***Adam***: Filtered ICMP Source Quench packets, and added a call to "check_and_inc()" when a Quench packet is detected
    def detect(self):
        if self.interface != None:
            _ = sniff(filter = "icmp",
                            prn = lambda x: self.check_and_inc(x) if str(x.getlayer(ICMP).type) == "4" else None)
        else:
            _ = sniff(filter = "icmp",
                            iface = self.interface,
                            prn = lambda x: self.check_and_inc(x) if str(x.getlayer(ICMP).type) == "4" else None)




if __name__ == "__main__":
    d = Detector(interface = "Ethernet 3", threshold = 5) # Instantiate Detector on interface "Ethernet 3", and set detection threshold to 5.
    d.detect() # Call the detect() function to begin detection
