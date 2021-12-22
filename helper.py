#use arp protocol to modify mac address from mac table in victim and wifi
#enable ip forward (in attacker machine) to enable access to the internet for victim
#sysctl -w net.ipv4.ip_forward=1

import socket, struct
import scapy.layers.l2 as l2

class LanController:
    """
        This class does all actions in lan.
    """
    def __init__(self, interface):
        self.interface = interface
    
    def get_default_gateway_linux(self):
        """Find gateway ip address \n
        Attention: This function works only on linux.\n
        Returns:
            The ip address for default gateway
        """
        with open("/proc/net/route") as route_table:
            for line in route_table:
                fields = line.strip().split()
                if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                    continue

                return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))

    def get_mac_address(self, ip):
        """Find mac address for a specific ip using arp protocol \n
        Args:
            ip: ip address for that you want to find mac address

        Returns:
            The mac address for specified ip  
        """
        arp_request = l2.ARP(pdst=ip)
        #set mac address for broadcast
        broadcast = l2.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_packet = broadcast/arp_request
        #We use srp function instead of send because we use a custom Ether layer
        response = l2.srp(arp_packet, timeout=1, verbose=False)[0]
        if len(response) >= 1:
          return response[0][1].hwsrc
        return None


        



