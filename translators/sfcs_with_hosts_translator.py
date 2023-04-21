class SFCsWithHostsTranslator:
    def __init__(self, hosts_translator, sfcs_translator):
        self.hosts_translator = hosts_translator
        self.sfcs_translator = sfcs_translator

    def to_dict(self, model) -> dict:
        prezent = {
            "hosts": self.hosts_translator.to_dict(model.hosts),
            "sfcs": self.sfcs_translator.to_dict(model.sfcs)
        }
        return prezent
