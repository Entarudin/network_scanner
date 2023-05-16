from reports_files import (
    REPORT_SYSTEM_INFORMATION_JSON,
    REPORT_SCAN_TCP_PORT_XML,
    REPORT_SCAN_UDP_PORT_XML,
    REPORT_SCAN_PROTOCOLS_XML,
    NETWORK_DATA_RESULT_FILE,
    SFCS_RESULT_FILE
)
from structure import (
    get_ip_shell_executor,
    get_network_interfaces_executor,
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
from common import (
    get_network_interface_by_ip,
    get_ip_address_with_subnet_by_current_network_interface,
    cast_ip_to_network_address,
    get_applications,
    get_sfcs_data
)
from field_report_file import field_report_requirements

def scan_network() -> dict:
    result = {}
    ip_address_without_subnet = get_ip_shell_executor.execute()
    list_network_interface = get_network_interfaces_executor.execute().split('\n')
    networks_interfaces = parse_result_shell_commands_service.parse_list_network_interface(
        list_network_interface
    )
    current_network_interface = get_network_interface_by_ip(
        list_network_interface,
        ip_address_without_subnet
    )
    distribution_version_string_output = get_distribution_version_executor.execute()
    service_status_string_output = get_services_status_executor.execute()
    installed_packages_string_output = get_installed_packages_executor.execute()
    get_json_file_with_system_information_executor.execute()
    network_address = cast_ip_to_network_address(ip_address_without_subnet)
    ip_address_with_subnet = get_ip_address_with_subnet_by_current_network_interface(
        networks_interfaces,
        current_network_interface
    )

    if field_report_requirements["current_network_interface"]:
        result["current_network_interface"] = current_network_interface

    if field_report_requirements["hostname"]:
        hostname = get_hostname_executor.execute()
        result["hostname"] = hostname

    if field_report_requirements["distribution_version"]:
        dict_info_distribution_version =\
            parse_result_shell_commands_service.parse_distribution_version_to_dict(
                distribution_version_string_output
            )
        result["distribution_version"] = dict_info_distribution_version

    if field_report_requirements["networks_interfaces"]:
        networks_interfaces = \
            parse_result_shell_commands_service.parse_list_network_interface(
                list_network_interface
            )
        result["networks_interfaces"] = networks_interfaces

    if field_report_requirements['core']:
        info_core = get_info_core_executor.execute()
        result['core'] = info_core

    if field_report_requirements["services_status"]:
        list_services_status =\
            parse_result_shell_commands_service.parse_services_status_to_list(
                service_status_string_output
            )
        result["services_status"] = list_services_status

    if field_report_requirements['installed_packages']:
        list_installed_packages = \
            parse_result_shell_commands_service.parse_installed_packages_to_list(
                installed_packages_string_output
            )
        result["installed_packages"] = list_installed_packages

    if field_report_requirements["system_information"]:
        dict_system_information = \
            json_service.parse_json_to_dict(
                REPORT_SYSTEM_INFORMATION_JSON
            )
        result["system_information"] = dict_system_information

    if field_report_requirements["ip_address"]:
        result["ip_address"] = ip_address_with_subnet

    if field_report_requirements["arp_table"]:
        arp_table = scapy_wrapper.get_arp_table(ip_address_with_subnet)
        result["arp_table"] = arp_table

    if field_report_requirements["tcp_ports"]:
        get_scan_xml_report_to_tcp_ports_executor.execute(REPORT_SCAN_TCP_PORT_XML, network_address)
        tcp_ports = xml_service.to_dict(REPORT_SCAN_TCP_PORT_XML)
        result["tcp_ports"] = tcp_ports

    if field_report_requirements["udp_ports"]:
        get_scan_xml_report_to_udp_ports_executor.execute(REPORT_SCAN_UDP_PORT_XML, network_address)
        udp_ports = xml_service.to_dict(REPORT_SCAN_UDP_PORT_XML)
        result["udp_ports"] = udp_ports

    if field_report_requirements["ip_ports"]:
        get_scan_xml_report_to_protocols_executor.execute(REPORT_SCAN_PROTOCOLS_XML, network_address)
        ip_ports = xml_service.to_dict(REPORT_SCAN_PROTOCOLS_XML)
        result["ip_ports"] = ip_ports

    if field_report_requirements["applications"]:
        applications = get_applications()
        result["applications"] = applications

    return result



def main():
    network_scanner_report = scan_network()
    json_repository.write_to_json(NETWORK_DATA_RESULT_FILE, network_scanner_report)
    data = json_service.parse_json_to_dict(NETWORK_DATA_RESULT_FILE)
    sfcs_data_with_hosts = get_sfcs_data(data)
    json_repository.write_to_json(SFCS_RESULT_FILE, sfcs_data_with_hosts )

if __name__ == '__main__':
    main()
