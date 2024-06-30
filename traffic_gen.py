#!/usr/bin/env python
import argparse
import socket
import time

from scapy.all import sendp, get_if_list, get_if_hwaddr, Ether, IP, TCP
from customdata_header import CustomData


def get_if():
    ifs = get_if_list()
    iface = None
    for i in ifs:
        if "eth0" in i:
            iface = i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("ip_addr", type=str, help="The destination IP address to use")
    parser.add_argument("message", type=str, help="The message to include in packet")
    parser.add_argument(
        "--custom_id", type=int, default=None, help="The ID of the custom content"
    )
    parser.add_argument("num_packets", type=int, help="The number of packets to send")
    parser.add_argument(
        "latencies", type=int, nargs="+", help="List of hop latencies for each packet"
    )
    args = parser.parse_args()

    if len(args.latencies) != args.num_packets:
        print(
            "The number of latencies provided must match the number of packets to be sent."
        )
        exit(1)

    addr = socket.gethostbyname(args.ip_addr)
    custom_id = args.custom_id
    iface = get_if()

    for i in range(args.num_packets):
        hop_latency = args.latencies[i]
        pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff")
        pkt = pkt / CustomData(
            content_id=custom_id, ingress_num=0, egress_num=0, hop_latency=hop_latency
        )
        pkt = pkt / IP(dst=addr) / args.message

        print(
            f"Sending packet {i+1}/{args.num_packets} with hop latency {hop_latency} ns"
        )
        pkt.show2()
        sendp(pkt, iface=iface, verbose=False)
        print(f"Packet {i+1} sent with timestamp: ", time.time())
        time.sleep(
            0.1
        )  # Add a small delay between packet transmissions to avoid overwhelming the network


if __name__ == "__main__":
    main()
