from typing import Optional
from models import Ports


class Host:
    def __init__(self):
        self.ip_address: Optional[str] = None
        self.mac_address: Optional[str] = None
        self.ports: Optional[Ports] = None


Hosts = list[Host]