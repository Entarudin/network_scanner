import json


class JsonRepository:
    def write_to_json(
            self,
            filename: str,
            ip: str,
            hostname: str,
            networks_interfaces: list,
            current_network_interface: str,
            info_distribution_version: dict,
            info_core: str,
            hosts: list,
            services_status: list,
            installed_packages: list,
            system_information: dict,
            tcp_ports: dict,
            udp_ports: dict,
            protocols: dict
    ) -> None:
        presented = {
            "ip": ip,
            "hostname": hostname,
            "networks_interfaces": networks_interfaces,
            "current_network_interface": current_network_interface,
            "distribution_version": info_distribution_version,
            "core": info_core,
            "hosts": hosts,
            "services_status": services_status,
            "installed_packages": installed_packages,
            "system_information": system_information,
            "tcp_ports": tcp_ports,
            "udp_ports": udp_ports,
            "protocols": protocols
        }
        with open(filename, "w") as file:
            json.dump(presented, file, indent=2)