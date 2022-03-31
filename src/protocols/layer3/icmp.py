from ctypes import c_ubyte, c_uint8, c_uint16

from src.protocols import Protocol


class ICMP(Protocol):           
    _fields_ = [
        ("type", c_uint8),      # Control message type
        ("code", c_uint8),      # Control message subtype
        ("chksum", c_uint16),   # Header checksum
        ("rest", c_ubyte * 4)   # Rest of header 
    ]
    header_len = 8
    icmp_types = {0: "REPLY", 8: "REQUEST"}

    def __init__(self, packet: bytes):
        super().__init__(packet)
        # Limit implementation to ICMP ECHO
        self.type_txt = self.icmp_types.get(self.type, "OTHER")
