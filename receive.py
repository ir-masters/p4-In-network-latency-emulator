#!/usr/bin/env python
import sys
import struct
import os

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR
from customdata_header import CustomData

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print ("Cannot find eth0 interface")
        exit(1)
    return iface

def handle_pkt(pkt):
    if CustomData in pkt or (TCP in pkt and pkt[TCP].dport == 1234):
        print("got a packet")
        custom_data = pkt[CustomData]
        if custom_data is not None:
            print("CustomData content_id = ", custom_data.content_id)
            print("CustomData ingress_num = ", custom_data.ingress_num)
            print("CustomData egress_num = ", custom_data.egress_num)
            print("CustomData hop_latency = ", custom_data.hop_latency)
            print("CustomData arrival_time = ", custom_data.arrival_time)
            print("CustomData departure_time = ", custom_data.departure_time)
            print("Delay = ",( custom_data.departure_time - custom_data.arrival_time ) / 1000000)
        else:
            print("TCP packet")
            pkt.show2()
        # pkt.show2()
#        hexdump(pkt)
#        print "len(pkt) = ", len(pkt)
        sys.stdout.flush()


def main():
    iface = get_if()
    print ("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()