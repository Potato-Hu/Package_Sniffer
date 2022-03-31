import itertools
from socket import PF_PACKET, SOCK_RAW, ntohs, socket
from typing import Generator

import src.protocols as protocols
from src.output import OutputToScreen
import time
import numpy as np


Count = np.linspace(1, 10, 10)
class Decoder:
    def __init__(self, interface: str):
        """Decodes packets incoming from a given interface.
        """
        self._interface = interface
        self.data = None
        self.protocol_queue = ["Ethernet"]

    def execute(self) -> Generator:
        """Yields a decoded packet as an instance of Protocol."""
        with socket(PF_PACKET, SOCK_RAW, ntohs(0x0003)) as sock:
            if self._interface is not None:
                sock.bind((self._interface, 0))
            for self.packet_num in Count:
                raw_packet = sock.recv(9000)
                start = 0
                for proto in self.protocol_queue:
                    proto_class = getattr(protocols, proto)
                    end = start + proto_class.header_len
                    protocol = proto_class(raw_packet[start:end])
                    setattr(self, proto.lower(), protocol)
                    if protocol.encapsulated_proto is None:
                        break
                    self.protocol_queue.append(protocol.encapsulated_proto)
                    start = end
                self.data = raw_packet[end:]
                yield self
                del self.protocol_queue[1:]



class PacketSniffer:
    def __init__(self, interface: str):
        """Monitor a network interface for incoming data, decode it and
        send to pre-defined output methods.

        :param interface: Interface from which packets will be captured
            and decoded.
        """
        self._observers = list()
        self._decoder = Decoder(interface)

    def register(self, observer) -> None:
        """Register an observer for processing/output of decoded
        packets."""
        self._observers.append(observer)

    def _notify_all(self, *args, **kwargs) -> None:
        """Send a decoded packet to all registered observers."""
        [observer.update(*args, **kwargs) for observer in self._observers]

    def execute(self, display_data: bool) -> None:
        OutputToScreen(subject=self, display_data=display_data)
        t1 = time.time()
        try:
            print("\n[>>>]Start Packet Sniffer Now. Please Waiting for Data... \n")
            [self._notify_all(packet) for packet in self._decoder.execute()]
        except KeyboardInterrupt:   
            raise SystemExit("Stop Packet Sniffer...")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Network packet sniffer")
    parser.add_argument(
        "-i", "--interface",
        type=str,
        default=None,
        help="Interface from which packets will be captured (monitors all "
             "available interfaces by default)."
    )
    parser.add_argument(
        "-d", "--display-data",
        action="store_true",
        help="Output packet data during capture."
    )
    _args = parser.parse_args()

    PacketSniffer(_args.interface).execute(_args.display_data)
