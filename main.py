import subprocess
import json

# NMAP REPORTS
NMAP_SCAN_PORT = 'scan_port.txt'
NMAP_SCAN_RROTOCOLS = 'scan_protocols.txt'

# COMMANDS
GET_NETWORK_INTERFACES_COMMAND = "ip addr | grep inet|grep -v 'inet6'|awk '{print $NF, $2}'"
GET_IP_COMMAND = 'hostname -I | awk \'{print $1}\''
GET_HOSTS_BY_INTERFACE_COMMAND = "arp-scan --interface={} --localnet"
GET_HOSTNAME_COMMAND = 'cat /etc/hostname'
SCAN_PORT_COMMAND = "nmap -sP {}/24"
SCAN_PROTOCOLS_ON_PORT_COMMAND = "nmap -sO {}/24"


def __execute_subprocess_command(command: str) -> str:
    result = subprocess.run(
        command,
        shell=True,
        stdout=subprocess.PIPE,
        encoding='utf-8',
    )
    return result.stdout.strip()


def get_hostname() -> str:
    result_of_execution = __execute_subprocess_command(GET_HOSTNAME_COMMAND)
    return result_of_execution


def get_ip_local_network() -> str:
    result_of_execution = __execute_subprocess_command(GET_IP_COMMAND)
    return result_of_execution


def get_network_interfaces():
    result_of_execution = __execute_subprocess_command(GET_NETWORK_INTERFACES_COMMAND)
    return result_of_execution


def get_scan_ports_to_output(ip: str):
    command = SCAN_PORT_COMMAND.format(ip) + f" -oN {NMAP_SCAN_PORT}"
    result_of_execution = __execute_subprocess_command(command)
    return result_of_execution


def get_scan_protocols_on_port_to_output(ip: str):
    command = SCAN_PROTOCOLS_ON_PORT_COMMAND.format(ip) + f" -oN {NMAP_SCAN_RROTOCOLS}"
    result_of_execution = __execute_subprocess_command(command)
    return result_of_execution


def get_hosts_by_network_interface(network_interface: str):
    command = GET_HOSTS_BY_INTERFACE_COMMAND.format(network_interface)
    result_of_execution = __execute_subprocess_command(command)
    return [host for host in result_of_execution.split('\n') if host]


def get_network_interface_by_ip(shell_output: str, ip: str):
    list_interface = shell_output.split('\n')
    for interface in list_interface:
        if ip not in interface:
            continue
        return interface.split(' ')[0]


def write_to_json(filename: str, ip: str, hosts: list[str], hostname: str) -> None:
    presented = {
        "ip": ip,
        "hosts": hosts,
        "hostname": hostname
    }
    with open(filename, "w") as file:
        json.dump(presented, file, indent=2)


def main():
    ip = get_ip_local_network()
    list_network_interface = get_network_interfaces()
    network_interface = get_network_interface_by_ip(list_network_interface, ip)
    list_hosts = get_hosts_by_network_interface(network_interface)
    hostname = get_hostname()
    get_scan_ports_to_output(ip)
    get_scan_protocols_on_port_to_output(ip)
    write_to_json("data.json", ip, list_hosts, hostname)


if __name__ == '__main__':
    main()
