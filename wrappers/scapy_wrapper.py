from scapy.all import *
from scapy.layers.inet import IP, Ether, ICMP
from scapy.layers.l2 import ARP


class ScapyWrapper:
    def get_ip_gateway(self) -> str:
        packet = sr1(IP(dst="www.slashdot.org", ttl=0) / ICMP() / "XXXXXXXXXXX")
        return packet.src

    def get_arp_table(self, ip) -> list[dict[str, str]]:
        request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        answers_packets, unanswered_packets = srp(request, timeout=2, retry=1)
        print(answers_packets)
        result = []

        for sent, received in answers_packets:
            ip_address = received.psrc
            mac_address = received.hwsrc
            result.append({
                "ip_address": ip_address,
                "mac_address": mac_address,
            })

        return result
