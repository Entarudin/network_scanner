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
