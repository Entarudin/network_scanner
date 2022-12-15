from typing import Optional
from models import SFC, Host


class SFCWithHosts:
    def __init__(self):
        self.sfcs: Optional[list[SFC]] = None
        self.hosts: Optional[list[Host]] = None
