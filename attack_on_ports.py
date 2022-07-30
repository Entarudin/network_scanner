import subprocess
import json
import xmltodict

# MESSAGES_ON_PRINT
MESSAGE_START_SCANNING_PORT = """
ЗАПУЩЕН ПРОЦЕСС СКАНИРОВАНИЯ ПОРТОВ СЕТИ {}
"""

MESSAGE_CONTINUE_ATTACS = """
ХОТИТЕ ПРОДОЛЖИТЬ АТАКУ(yes/no)? : 
"""

MESSAGE_SELECT_PORT_ON_ATTACK = """
ВЫБЕРЕТИ ПОРТ ДЛЯ АТАКИ SYN FLOOD: 
"""

# REPORT NMAP COMMANDS XML
REPORT_SCAN_PORTS_XML = 'scan_port.xml'

# JSON OUTPUT
SCAN_REPORT_OUTPUT_JSON = 'result_scan_report.json'

# COMMANDS
GET_IP_COMMAND = 'hostname -I | awk \'{print $1}\''
SCAN_PORT_IN_NETWORK_ADDRESS = 'nmap -p- {} -oX'


def __execute_subprocess_command(command: str) -> str:
    result = subprocess.run(
        command,
        shell=True,
        stdout=subprocess.PIPE,
        encoding='utf-8',
    )
    return result.stdout.strip()


def get_ip_local_network() -> str:
    result_of_execution = __execute_subprocess_command(GET_IP_COMMAND)
    return result_of_execution


def get_scan_port_on_network_address(network_address: str) -> str:
    command = SCAN_PORT_IN_NETWORK_ADDRESS.format(network_address) + f" {REPORT_SCAN_PORTS_XML}"
    result_of_execution = __execute_subprocess_command(command)
    return result_of_execution


def cast_ip_to_network_address(ip: str) -> str:
    return ".".join(ip.split('.')[:-1]) + '.*'


def parse_xml_to_json(filename_xml: str, filename_json: str):
    f = open(filename_xml)
    xml_content = f.read()
    f.close()
    with open(filename_json, "w") as file:
        json.dumps(xmltodict.parse(xml_content), file , indent=2, sort_keys=True)

def main():
    ip = get_ip_local_network()
    network_address = cast_ip_to_network_address(ip)
    print(MESSAGE_START_SCANNING_PORT.format(network_address))
    scan_port = get_scan_port_on_network_address(network_address)
    parse_xml_to_json(REPORT_SCAN_PORTS_XML)
    # print(MESSAGE_CONTINUE_ATTACS)
    # print(MESSAGE_SELECT_PORT_ON_ATTACK)


if __name__ == '__main__':
    main()
