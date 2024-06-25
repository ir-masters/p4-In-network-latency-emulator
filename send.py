from scapy.all import sendp, get_if_list, get_if_hwaddr, Ether, IP, UDP
import random
import sys
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

def traffic_generator(dst_ip, num_packets, latency_min, latency_max):
    iface = get_if()
    for _ in range(num_packets):
        # Generate a random latency value within the specified range
        latency_value = random.randint(latency_min, latency_max)
        # Encode the latency value in the TOS field
        pkt = pkt / CustomData(content_id=101, hop_latency=latency_value, ingress_num=0, egress_num=0, egress_num=0)
        pkt = pkt / IP(dst=dst_ip)
        sendp(pkt, iface=iface)
        print(f"Sent packet with encoded latency {latency_value} to {dst_ip}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python send.py <dst_ip> <num_packets>")
        sys.exit(1)
    else:
        dst_name = sys.argv[1]
        num_packets = int(sys.argv[2])

    latency_min = 1  # Minimum latency value
    latency_max = 255  # Maximum latency value
    traffic_generator(dst_name, num_packets, latency_min, latency_max)
