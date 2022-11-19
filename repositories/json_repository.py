import json


class JsonRepository:
    def write_to_json(
            self,
            filename: str,
            ip_address: str,
            hostname: str,
            networks_interfaces: list,
            current_network_interface: str,
            info_distribution_version: dict,
            info_core: str,
            arp_table: list,
            services_status: list,
            installed_packages: list,
            system_information: dict,
            tcp_ports: dict,
            udp_ports: dict,
            ip_ports: dict
    ) -> None:
        presented = {
            "ip_address": ip_address,
            "hostname": hostname,
            "networks_interfaces": networks_interfaces,
            "current_network_interface": current_network_interface,
            "distribution_version": info_distribution_version,
            "core": info_core,
            "arp_table": arp_table,
            "services_status": services_status,
            "installed_packages": installed_packages,
            "system_information": system_information,
            "tcp_ports": tcp_ports,
            "udp_ports": udp_ports,
            "ip_ports": ip_ports
        }
        with open(filename, "w") as file:
            json.dump(presented, file, indent=2)