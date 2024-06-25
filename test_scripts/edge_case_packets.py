from scapy.all import *

def generate_edge_case_packets(interface):
    packets = [
        Ether()/IP(dst="10.0.0.1", ttl=64, id=1)/Raw(load="Low Latency Test Packet"),
        Ether()/IP(dst="10.0.0.1", ttl=64, id=1000000)/Raw(load="High Latency Test Packet")
    ]
    sendp(packets, iface=interface)
    print(f"Sent {len(packets)} edge case test packets")

if __name__ == "__main__":
    interface = "eth0"
    generate_edge_case_packets(interface)
