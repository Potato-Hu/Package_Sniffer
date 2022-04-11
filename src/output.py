from ossaudiodev import SNDCTL_TMR_SOURCE
import time
from abc import ABC, abstractmethod

from numpy import TooHardError, save
from pkg_resources import SOURCE_DIST


class OutputMethod(ABC):
    """Format the output"""

    i = " " * 4  # Basic indentation 

    def __init__(self, subject):
        subject.register(self)

    @abstractmethod
    def update(self, *args, **kwargs):
        pass

def save_to_file(file_name, contents):
    fh = open(file_name, 'a')
    fh.write(contents + '\n')
    fh.close()

class OutputToScreen(OutputMethod):
    def __init__(self, subject, *, display_data: bool):
        super().__init__(subject)
        self.p = None
        self.display_data = display_data
        save_to_file('abc.txt', display_data)
        
    def update(self, packet):
        self.p = packet
        self._display_output_header()
        self._display_packet_info()
        self._display_packet_contents()

    def _display_output_header(self):
        local_time = time.strftime("%H:%M:%S", time.localtime())
        print(f"[>] Packet #{self.p.packet_num} at {local_time}:")

    def _display_packet_info(self):
        for proto in self.p.protocol_queue:
            getattr(self, f"_display_{proto.lower()}_data")()

    def _display_ethernet_data(self):
        print("{0}[+] Ethernet {1:.>23} -> {2}".format(self.i,
                                                       self.p.ethernet.source,
                                                       self.p.ethernet.dest))


    def _display_ipv4_data(self):
        print("{0}[+] IPv4 {1:.>27} -> {2: <15} | "
              "PROTO: {3} TTL: {4}".format(self.i,
                                           self.p.ipv4.source,
                                           self.p.ipv4.dest,
                                           self.p.ipv4.encapsulated_proto,
                                           self.p.ipv4.ttl))

    def _display_ipv6_data(self):
        print("{0}[+] IPv6 {1:.>27} -> {2: <15}".format(self.i,
                                                        self.p.ipv6.source,
                                                        self.p.ipv6.dest))

    def _display_arp_data(self):
        if self.p.arp.oper == 1:  # ARP Request
            print("{0}[+] ARP Who has {1:.>18} ? "
                  "-> Tell {2}".format(self.i,
                                       self.p.arp.target_proto,
                                       self.p.arp.source_proto))
        else:                     # ARP Reply
            print("{0}[+] ARP {1:.>28} -> "
                  "Is at {2}".format(self.i,
                                     self.p.arp.source_proto,
                                     self.p.arp.source_hdwr))

    def _display_tcp_data(self):
        print("{0}[+] TCP {1:.>28} -> {2: <15} | "
              "Flags: {3} > {4}".format(self.i,
                                        self.p.tcp.sport,
                                        self.p.tcp.dport,
                                        self.p.tcp.flag_hex,
                                        self.p.tcp.flag_txt))

    def _display_udp_data(self):
        print("{0}[+] UDP {1:.>27} -> {2}".format(self.i,
                                                  self.p.udp.sport,
                                                  self.p.udp.dport))

    def _display_icmp_data(self):
        print("{0}[+] ICMP {1:.>27} -> {2: <15} | "
              "Type: {3}".format(self.i,
                                 self.p.ipv4.source,
                                 self.p.ipv4.dest,
                                 self.p.icmp.type_txt))

    def _display_packet_contents(self):
        if self.display_data is True:
            print(f"{self.i}[+] DATA:")
            data = (self.p.data.decode(errors="ignore").
                    replace("\n", f"\n{self.i * 2}"))
            print(f"{self.i}{data}")
