import json


class JsonRepository:
    def write_to_json(self, filename: str, presented: dict) -> None:
        with open(filename, "w") as file:
            json.dump(presented, file, indent=2)
