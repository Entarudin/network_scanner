class SFCTranslator:
    def to_dict(self, model) -> dict:
        return {
            "name": model.name,
            "version": model.version
        }
