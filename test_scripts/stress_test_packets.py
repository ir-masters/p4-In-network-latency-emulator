from scapy.all import *
import random

def generate_stress_test_packets(interface, num_packets):
    packets = []
    for i in range(num_packets):
        hop_latency = random.randint(1, 1000000)
        pkt = Ether()/IP(dst="10.0.0.1", ttl=64, id=hop_latency)/Raw(load=f"Stress Test Packet {i}")
        packets.append(pkt)
    sendp(packets, iface=interface)
    print(f"Sent {len(packets)} stress test packets")

if __name__ == "__main__":
    interface = "eth0"
    num_packets = 1000
    generate_stress_test_packets(interface, num_packets)
