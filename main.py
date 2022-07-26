import subprocess
import json

GET_NETWORK_INTERFACES = "ip addr | grep inet|grep -v 'inet6'|awk '{print $NF, $2}'"
GET_IP = 'hostname -I | awk \'{print $1}\''
SHELL_COMMAND = "arp-scan --interface={} --localnet"


def __execute_subprocess_command(command: str) -> str:
    result = subprocess.run(
        command,
        shell=True,
        stdout=subprocess.PIPE,
        encoding='utf-8',
    )
    return result.stdout.strip()


def get_ip_local_network() -> str:
    result_of_execution = __execute_subprocess_command(GET_IP)
    return result_of_execution


def get_network_interfaces():
    result_of_execution = __execute_subprocess_command(GET_NETWORK_INTERFACES)
    return result_of_execution


def get_hosts_by_network_interface(network_interface: str):
    command = SHELL_COMMAND.format(network_interface)
    result_of_execution = __execute_subprocess_command(command)
    return [host for host in result_of_execution.split('\n') if host]


def get_network_interface_by_ip(shell_output: str, ip: str):
    list_interface = shell_output.split('\n')
    for interface in list_interface:
        if ip not in interface:
            continue
        return interface.split(' ')[0]


def write_to_json(filename: str, ip: str, hosts: list[str]) -> None:
    presented = {
        "ip": ip,
        "hosts": hosts,
    }
    with open(filename, "w") as file:
        json.dump(presented, file, indent=2)


def main():
    ip = get_ip_local_network()
    list_network_interface = get_network_interfaces()
    network_interface = get_network_interface_by_ip(list_network_interface, ip)
    list_hosts = get_hosts_by_network_interface(network_interface)
    write_to_json("data.json", ip, list_hosts)


if __name__ == '__main__':
    main()
