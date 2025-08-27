from struct import pack

from scapy.layers.l2 import Ether
from scapy.packet import Packet, bind_layers
from scapy.fields import XShortField

class GOOSE(Packet):
    name = "GOOSE"
    fields_desc = [
        XShortField("appid", 0),
        XShortField("length", 8),
        XShortField("reserved1", 0),
        XShortField("reserved2", 0),
    ]

    def post_build(self, packet, payload):
        goose_pdu_length = len(packet) + len(payload)
        packet = packet[:2] + pack('!H', goose_pdu_length) + packet[4:]
        return packet + payload

    def extract_padding(self, s):
        return s, b""

bind_layers(Ether, GOOSE, type=0x88b8)