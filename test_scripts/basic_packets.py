from scapy.all import *

def generate_basic_packets(interface):
    packets = [
        Ether()/IP(dst="10.0.0.1", ttl=64, id=1000)/Raw(load="Basic Test Packet 1"),
        Ether()/IP(dst="10.0.0.1", ttl=128, id=2000)/Raw(load="Basic Test Packet 2")
    ]
    sendp(packets, iface=interface)
    print(f"Sent {len(packets)} basic test packets")

if __name__ == "__main__":
    interface = "h1-eth0"
    generate_basic_packets(interface)
