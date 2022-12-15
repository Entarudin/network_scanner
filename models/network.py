from typing import Optional
from .host import Hosts


class Network:
    def __init__(self):
        self.udp_hosts: Optional[Hosts] = None
        self.tcp_hosts: Optional[Hosts] = None
        self.ip_hosts: Optional[Hosts] = None
