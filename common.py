from models import SFCWithHosts
from shell_commands_executor import ShellCommandsExecutor
from structure import (
    get_version_application_executor,
    parse_result_shell_commands_service, \
    get_description_application_executor,
    get_list_applications_executor,
    network_translator,
    network_service,
    parser_report_to_sfc_service,
    sfcs_with_hosts_translators
)


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


def get_command_dependencies_packages(packet: str) -> str:
    return f"apt-cache policy $(apt-rdepends -p {packet} 2>| /dev/null|awk '/Depends/ {{print $2}}'  |sort " \
           "-u)|awk '/^[^ ]/ {package=$0 } /  Installed/ { print package " " $2 }'"

def get_dependencies_application_packages(application: str) -> list:
    result = []
    get_list_dependencies_packages_executor = ShellCommandsExecutor(get_command_dependencies_packages(application))
    dependencies_packages_output_string = get_list_dependencies_packages_executor.execute()
    if dependencies_packages_output_string:
        list_dependencies_application = dependencies_packages_output_string.split("\n")
        for item in list_dependencies_application:
            chunks = item.split(':')
            name_package = chunks[0]
            version = chunks[1]
            result.append({
                "name": name_package,
                "version": version
            })
    return result


def get_applications():
    result = []
    applications_output_string = get_list_applications_executor.execute()
    list_applications = parse_result_shell_commands_service.parse_applications_to_list(applications_output_string)
    for application in list_applications:
        version_application = get_version_application_by_name(application)
        if version_application:
            description_application = get_description_application_by_name(application)
            result.append({
                "application": {
                    "name": application,
                    "version": version_application,
                    "description": description_application
                }
            })
    return result


def get_version_application_by_name(application: str) -> str:
    version_application_output_string = get_version_application_executor.execute(application)
    version = parse_result_shell_commands_service.parse_application_version(version_application_output_string)
    return version


def get_description_application_by_name(application: str) -> str:
    description_application_output_string = get_description_application_executor.execute(application)
    description_application = parse_result_shell_commands_service. \
        parse_application_description(description_application_output_string)
    return description_application


def get_sfcs_data_with_hosts(network_scanner_report: dict):
    network = network_translator.from_json(network_scanner_report)
    network_with_ports = network_service.filter_out_network_with_ports(network)
    hosts = [*network_with_ports.tcp_hosts]

    sfcs_dictribution = parser_report_to_sfc_service.parse_distribution_version(
        network_scanner_report.get('distribution_version', {}))
    sfcs_installed_packets = parser_report_to_sfc_service.parse_installed_packages(
        network_scanner_report.get('installed_packages', []))
    sfcs_system_information = parser_report_to_sfc_service.parse_system_information(
        network_scanner_report.get('system_information', {}))
    sfcs = [*sfcs_dictribution, *sfcs_installed_packets, *sfcs_system_information]
    sfcs_with_hosts = SFCWithHosts()
    sfcs_with_hosts.hosts = hosts
    sfcs_with_hosts.sfcs = sfcs
    result = sfcs_with_hosts_translators.to_dict(sfcs_with_hosts)
    return result