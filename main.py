from reports_files import (
    REPORT_SYSTEM_INFORMATION_JSON,
    REPORT_SCAN_TCP_PORT_XML,
    REPORT_SCAN_UDP_PORT_XML,
    REPORT_SCAN_PROTOCOLS_XML,
    OUTPUT_RESULT_FILE
)
from structure import (
    get_ip_shell_executor,
    get_network_interfaces_executor,
    get_hosts_by_network_interface_executor,
    get_hostname_executor,
    get_distribution_version_executor,
    get_services_status_executor,
    get_installed_packages_executor,
    get_json_file_with_system_information_executor,
    get_info_core_executor,
    get_scan_xml_report_to_tcp_ports_executor,
    get_scan_xml_report_to_udp_ports_executor,
    get_scan_xml_report_to_protocols_executor,
    parse_result_shell_commands_service,
    json_service,
    xml_service,
    json_repository,
    scapy_wrapper
)

from dotenv import dotenv_values

config = dotenv_values()

REQUIREMENTS_FIELDS_REPORT_FILE = config['FIELDS_REPORT_FILE']


def get_network_interface_by_ip(list_interface: list, ip: str):
    for interface in list_interface:
        if ip not in interface:
            continue
        return interface.split(' ')[0]


def cast_ip_to_network_address(ip: str) -> str:
    return '.'.join(ip.split('.')[:-1]) + '.*'


def get_ip_address_with_subnet_by_current_network_interface(
        networks_interfaces: list, current_network_interface: str) -> str:
    for item in networks_interfaces:
        if item['name'] == current_network_interface:
            return item['ip']


def get_dict_by_fields(initial_dict: dict, fields: list) -> dict:
    return {
        key: value for key,
                       value in initial_dict.items()
        if key in fields
    }


def scan_network() -> dict:
    ip_address_without_subnet = get_ip_shell_executor.execute()
    list_network_interface = get_network_interfaces_executor.execute().split('\n')
    current_network_interface = get_network_interface_by_ip(list_network_interface, ip_address_without_subnet)
    hosts_string_output = get_hosts_by_network_interface_executor.execute(current_network_interface)
    list_hosts = parse_result_shell_commands_service.parse_hosts(hosts_string_output)
    hostname = get_hostname_executor.execute()
    distribution_version_string_output = get_distribution_version_executor.execute()
    service_status_string_output = get_services_status_executor.execute()
    installed_packages_string_output = get_installed_packages_executor.execute()
    get_json_file_with_system_information_executor.execute()

    dict_info_distribution_version = parse_result_shell_commands_service.parse_distribution_version_to_dict(
        distribution_version_string_output)

    networks_interfaces = parse_result_shell_commands_service.parse_list_network_interface(list_network_interface)
    info_core = get_info_core_executor.execute()

    list_services_status = parse_result_shell_commands_service.parse_services_status_to_list(
        service_status_string_output)

    list_installed_packages = parse_result_shell_commands_service.parse_installed_packages_to_list(
        installed_packages_string_output)

    dict_system_information = json_service.parse_json_to_dict(REPORT_SYSTEM_INFORMATION_JSON)
    network_address = cast_ip_to_network_address(ip_address_without_subnet)

    ip_address_with_subnet = get_ip_address_with_subnet_by_current_network_interface(networks_interfaces,
                                                                                     current_network_interface)

    arp_table = scapy_wrapper.get_arp_table(ip_address_with_subnet)

    get_scan_xml_report_to_tcp_ports_executor.execute(REPORT_SCAN_TCP_PORT_XML, network_address)
    tcp_ports = xml_service.to_dict(REPORT_SCAN_TCP_PORT_XML)

    get_scan_xml_report_to_udp_ports_executor.execute(REPORT_SCAN_UDP_PORT_XML, network_address)
    udp_ports = xml_service.to_dict(REPORT_SCAN_UDP_PORT_XML)

    get_scan_xml_report_to_protocols_executor.execute(REPORT_SCAN_PROTOCOLS_XML, network_address)
    ip_ports = xml_service.to_dict(REPORT_SCAN_PROTOCOLS_XML)

    return {
        "ip_address": ip_address_with_subnet,
        "hostname": hostname,
        "networks_interfaces": networks_interfaces,
        "current_network_interface": current_network_interface,
        "distribution_version": dict_info_distribution_version,
        "core": info_core,
        "arp_table": arp_table,
        "services_status": list_services_status,
        "installed_packages": list_installed_packages,
        "system_information": dict_system_information,
        "tcp_ports": tcp_ports,
        "udp_ports": udp_ports,
        "ip_ports": ip_ports
    }


def main():
    full_network_scanner_report = scan_network()
    list_requirements_fields = REQUIREMENTS_FIELDS_REPORT_FILE.split(",")

    network_scanner_report_with_requirements_fields = get_dict_by_fields(full_network_scanner_report,
                                                                         list_requirements_fields)

    json_repository.write_to_json(OUTPUT_RESULT_FILE, network_scanner_report_with_requirements_fields)


if __name__ == '__main__':
    main()
