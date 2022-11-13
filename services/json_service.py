import json


class JsonService:
    def parse_json_to_dict(self, filename: str) -> dict:
        with open(filename) as json_file:
            data = json.load(json_file)
            return data
