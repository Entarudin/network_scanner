import xmltodict


class XmlService:
    def to_dict(self, filename: str) -> dict:
        with open(filename) as file:
            content = file.read()
            dictionary = xmltodict.parse(content)
            return dictionary
