import helper
import scapy.layers.l2 as l2
import scapy.all as scapy
import argparse

parser = argparse.ArgumentParser(description='Protector tool')
parser.add_argument("--interface", help="Network interface", required=True)
args = parser.parse_args()
interface = args.interface
lan_controller = helper.LanController(interface)


def process_packet(packet):
    if packet.haslayer(l2.ARP) and packet[l2.ARP].op == 2:
        true_mac = lan_controller.get_mac_address(packet[l2.ARP].psrc)
        response_mac = packet[l2.ARP].hwsrc
        if true_mac != response_mac and true_mac is not None:
            print("You are attacked")

scapy.sniff(iface=interface, store=False, prn=process_packet)