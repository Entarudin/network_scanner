class ParseResultShellCommandsService:
    def parse_hosts(self, command_output: str) -> list:
        return [host for host in command_output.split('\n') if host]

    def parse_list_network_interface(self, list_network_interface: list) -> list:
        result = []
        for item in list_network_interface:
            chunks = item.split(" ")
            name = chunks[0]
            ip = chunks[1]
            result.append({
                "name": name,
                "ip": ip
            })
        return result

    def parse_distribution_version_to_dict(self, command_output: str) -> dict:
        dict_info_distribution_version = {}
        list_distribution_version_with_tabs = command_output.split("\n")
        for item in list_distribution_version_with_tabs:
            chunks = item.split('\t')
            key = chunks[0].strip(':').lower()
            if 'distributor' in key:
                key = '_'.join(key.split(" "))
            value = chunks[1]
            dict_info_distribution_version[key] = value
        return dict_info_distribution_version

    def parse_services_status_to_list(self, command_output: str) -> list:
        result = []
        list_services_status = command_output.split('\n')
        for item in list_services_status:
            chunks = item.split('=')
            name = chunks[0]
            status = chunks[1]
            result.append({
                "name": name,
                "status": status
            })
        return result

    def parse_installed_packages_to_list(self, command_output: str) -> list:
        result = []
        list_installed_packages = command_output.split('\n')
        for item in list_installed_packages:
            chunks = item.split(' ')
            package = chunks[0]
            version = chunks[1]
            result.append({
                "name": package,
                "version": version
            })
        return result
