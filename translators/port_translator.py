from models import Port


class PortTranslator:
    def from_json(self, json) -> Port:
        model = Port()
        model.port_id = json.get("@portid")
        model.status = json.get("state", {}).get("@state")
        model.service = json.get("service", {}).get("@name")
        model.protocol = json.get("@protocol")
        return model

    def to_dict(self, model: Port) -> dict:
        return {
            "port_id": model.port_id,
            "status": model.status,
            "service": model.service,
            "protocol": model.protocol
        }