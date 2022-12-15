from shell_commands_executor import ShellCommandsExecutor
from services import JsonService, XmlService, ParseResultShellCommandsService, ParseReportToSFCService, NetworkService
from repositories import JsonRepository
from translators import (
    SFCTranslator,
    ListTranslator,
    HostTranslator,
    PortTranslator,
    NetworkTranslator,
    SFCsWithHostsTranslator
)
from wrappers import ScapyWrapper
from commands import (
    GET_IP_COMMAND,
    GET_NETWORK_INTERFACES_COMMAND,
    GET_HOSTS_BY_INTERFACE_COMMAND,
    GET_HOSTNAME_COMMAND,
    GET_DISTRIBUTION_VERSION_COMMAND,
    GET_INFO_CORE_COMMAND,
    GET_SERVICES_STATUS_COMMAND,
    GET_INSTALL_PACKAGES_COMMAND,
    GET_SYSTEM_INFORMATION_COMMAND,
    SCAN_TCP_PORT_COMMAND,
    SCAN_UPD_PORT_COMMAND,
    SCAN_PROTOCOLS_COMMAND,
)

get_ip_shell_executor = ShellCommandsExecutor(GET_IP_COMMAND)
get_network_interfaces_executor = ShellCommandsExecutor(GET_NETWORK_INTERFACES_COMMAND)
get_hosts_by_network_interface_executor = ShellCommandsExecutor(GET_HOSTS_BY_INTERFACE_COMMAND)
get_hostname_executor = ShellCommandsExecutor(GET_HOSTNAME_COMMAND)
get_distribution_version_executor = ShellCommandsExecutor(GET_DISTRIBUTION_VERSION_COMMAND)
get_info_core_executor = ShellCommandsExecutor(GET_INFO_CORE_COMMAND)
get_services_status_executor = ShellCommandsExecutor(GET_SERVICES_STATUS_COMMAND)
get_installed_packages_executor = ShellCommandsExecutor(GET_INSTALL_PACKAGES_COMMAND)
get_json_file_with_system_information_executor = ShellCommandsExecutor(GET_SYSTEM_INFORMATION_COMMAND)
get_scan_xml_report_to_tcp_ports_executor = ShellCommandsExecutor(SCAN_TCP_PORT_COMMAND)
get_scan_xml_report_to_udp_ports_executor = ShellCommandsExecutor(SCAN_UPD_PORT_COMMAND)
get_scan_xml_report_to_protocols_executor = ShellCommandsExecutor(SCAN_PROTOCOLS_COMMAND)

sfc_translator = SFCTranslator()
sfcs_translator = ListTranslator(sfc_translator)

port_translator = PortTranslator()
ports_translator = ListTranslator(port_translator)

host_translator = HostTranslator(ports_translator)
hosts_translator = ListTranslator(host_translator)

network_translator = NetworkTranslator(hosts_translator)
network_service = NetworkService()

sfcs_with_hosts_translators = SFCsWithHostsTranslator(hosts_translator, sfcs_translator)

parse_result_shell_commands_service = ParseResultShellCommandsService()
json_service = JsonService()
xml_service = XmlService()
parser_report_to_sfc_service = ParseReportToSFCService()


json_repository = JsonRepository()
scapy_wrapper = ScapyWrapper()
