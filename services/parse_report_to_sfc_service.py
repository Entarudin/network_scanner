from models import SFC


class ParseReportToSFCService:
    def parse_distribution_version(self, distribution_version: dict):
        result = []
        sfc = SFC()
        sfc.name = distribution_version.get('distributor_id')
        sfc.version = distribution_version.get('release')
        result.append(sfc)
        return result

    def parse_installed_packages(self, installed_packages: list):
        result = []
        for packet in installed_packages:
            sfc = SFC()
            sfc.name = packet.get('name')
            sfc.version = packet.get('version')
            result.append(sfc)
        return result

    def parse_system_information(self, system_information: dict):
        result = []

        sfc = SFC()
        sfc.name = system_information.get('product')
        sfc.version = system_information.get('version')
        result.append(sfc)

        if system_information.get('children', []):
            for child_device in system_information.get('children', []):
                if child_device.get('product') and child_device.get('version'):
                    sfc = SFC()
                    sfc.name = child_device.get('product')
                    sfc.version = child_device.get('version')
                    result.append(sfc)

                if child_device.get('children', []):
                    for sub_module_child_device in child_device.get('children', []):
                        if sub_module_child_device.get('product') and sub_module_child_device.get('version'):
                            sfc = SFC()
                            sfc.name = sub_module_child_device.get('product')
                            sfc.version = sub_module_child_device.get('version')
                            result.append(sfc)

                        if sub_module_child_device.get('children', []):
                            for inner_sub_module_child_device in sub_module_child_device.get('children', []):
                                if inner_sub_module_child_device.get('product') and \
                                        inner_sub_module_child_device.get('version'):
                                    sfc = SFC()
                                    sfc.name = inner_sub_module_child_device.get('product')
                                    sfc.version = inner_sub_module_child_device.get('version')
                                    result.append(sfc)
        return result
