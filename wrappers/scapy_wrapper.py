from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import sr1, srp


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
