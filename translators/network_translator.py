from models import Network


class NetworkTranslator:
    def __init__(self, hosts_translator):
        self.hosts_translator = hosts_translator

    def from_json(self, json: dict):
        network = Network()
        network.tcp_hosts = self.__get_hosts(json, "tcp_ports")
        network.udp_hosts = self.__get_hosts(json, "udp_ports")
        network.ip_hosts = self.__get_hosts(json, "ip_ports")
        return network

    def __get_hosts(self, json, key):
        hosts_json = json.get(f"{key}", {})\
            .get("nmaprun", {})\
            .get("host", [])
        return self.hosts_translator.from_json(hosts_json)