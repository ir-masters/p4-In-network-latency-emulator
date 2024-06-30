from scapy.all import *
import sys, os

TYPE_CUSTOMDATA = 0x1313
TYPE_IPV4 = 0x0800


class CustomData(Packet):
    name = "CustomData"
    fields_desc = [
        ShortField("proto_id", 0),
        ShortField("content_id", 101),
        ShortField("ingress_num", 0),
        ByteField("egress_num", 0),
        XLongField("hop_latency", 0),
    ]

    def mysummary(self):
        return self.sprintf(
            "content_id=%content_id% ingress_num=%ingress_num% egress_num=%egress_num% hop_latency=%hop_latency%"
        )


bind_layers(Ether, CustomData, type=TYPE_CUSTOMDATA)
bind_layers(CustomData, IP, proto_id=TYPE_IPV4)
