import subprocess
import json

GET_NETWORK_INTERFACES = "ip addr | grep inet|grep -v 'inet6'|awk '{print $NF, $2}'"
GET_IP = 'hostname -I | awk \'{print $1}\''


def get_ip_local_network():
    result = subprocess.run(GET_IP, shell=True, stdout=subprocess.PIPE, encoding='utf-8')
    return result.stdout.strip()


def get_network_interfaces():
    result = subprocess.run(GET_NETWORK_INTERFACES, shell=True, stdout=subprocess.PIPE, encoding='utf-8')
    return result.stdout.strip()


def get_hosts_by_network_interface(network_interface: str):
    shell_command = f"arp-scan --interface={network_interface} --localnet"
    result = subprocess.run(shell_command, shell=True, stdout=subprocess.PIPE, encoding='utf-8')
    return result.stdout.strip().split('\n')


def get_network_interface_by_id(shell_output: str, ip: str):
    list_interface = shell_output.split('\n')
    for interface in list_interface:
        if interface.find(ip) != -1:
            return interface.split(' ')[0]


def write_to_json(ip: str, hosts: str):
    aDict = {"ip": ip, "hosts": hosts}
    jsonString = json.dumps(aDict)
    jsonFile = open("data.json", "w")
    jsonFile.write(jsonString)
    jsonFile.close()


def main():
    ip = get_ip_local_network()
    list_network_interface = get_network_interfaces()
    network_interface = get_network_interface_by_id(list_network_interface, ip)
    list_hosts = get_hosts_by_network_interface(network_interface)
    write_to_json(ip, list_hosts)


if __name__ == '__main__':
    main()
