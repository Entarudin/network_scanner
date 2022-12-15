from models import SFC


class SFCTranslator:
    def to_dict(self, model: SFC) -> dict:
        return {
            "name": model.name,
            "version": model.version
        }
