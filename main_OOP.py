import subprocess
import json

GET_NETWORK_INTERFACES_COMMAND = "ip addr | grep inet|grep -v 'inet6'|awk '{print $NF, $2}'"
GET_IP_COMMAND = 'hostname -I | awk \'{print $1}\''
GET_HOSTS_BY_INTERFACE_COMMAND = "arp-scan --interface={} --localnet"


class ShellCommandsExecutor:
    def __init__(self, command: str):
        self.command = command

    def execute(self, *args) -> str:
        command = self.__format_command(self.command, args)
        result = subprocess.run(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            encoding='utf-8',
        )
        return result.stdout.strip()

    def __format_command(self, command: str, command_args: tuple) -> str:
        if not command_args:
            return command
        return command.format(*command_args)


def parse_hosts(command_output: str) -> list[str]:
    return [host for host in command_output.split('\n') if host]


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
    get_ip_shell_executor = ShellCommandsExecutor(GET_IP_COMMAND)
    get_network_interfaces_executor = ShellCommandsExecutor(GET_NETWORK_INTERFACES_COMMAND)
    get_hosts_by_network_interface_executor = ShellCommandsExecutor(GET_HOSTS_BY_INTERFACE_COMMAND)

    ip = get_ip_shell_executor.execute()
    list_network_interface = get_network_interfaces_executor.execute()
    network_interface = get_network_interface_by_ip(list_network_interface, ip)
    hosts_string_output = get_hosts_by_network_interface_executor.execute(network_interface)
    list_hosts = parse_hosts(hosts_string_output)

    write_to_json("data.json", ip, list_hosts)


if __name__ == '__main__':
    main()
