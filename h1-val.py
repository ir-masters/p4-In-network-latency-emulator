from scapy.all import *
import time
import netifaces

# Define a custom layer for hop latency header
class HopLatencyHeader(Packet):
    name = "HopLatencyHeader"
    fields_desc = [
        XBitField("hopLatency", 0, 48)
    ]

# Define a custom layer for recirculation flag header
class RecirculationFlagHeader(Packet):
    name = "RecirculationFlagHeader"
    fields_desc = [
        BitField("isRecirculated", 0, 8)
    ]

# Define a custom layer for max recirc header
class MaxRecircHeader(Packet):
    name = "MaxRecircHeader"
    fields_desc = [
        BitField("maxRecirc", 5, 8)
    ]

def get_mac_address(interface):
    return netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr']

def send_latency_packets(interface, expected_latencies, dst_ip):
    sent_times = []
    for hop_latency in expected_latencies:
        send_time = time.time()
        print(f"Sending packet with hop latency {hop_latency} at {send_time}")
        pkt = Ether()/IP(dst=dst_ip, ttl=64, id=hop_latency)/HopLatencyHeader(hopLatency=hop_latency)/RecirculationFlagHeader(isRecirculated=0)/MaxRecircHeader(maxRecirc=5)
        sendp(pkt, iface=interface)
        sent_times.append((hop_latency, send_time))
        print(f"Sent packet with hop latency {hop_latency} at {send_time}")
    return sent_times

if __name__ == "__main__":
    interface = "h1-eth0"
    expected_latencies = [0, 100]
    dst_ip = "10.0.0.2"  # IP address of h2
    sent_times = send_latency_packets(interface, expected_latencies, dst_ip)
    
    # Debug: Print sent_times
    print("\nSent Times:")
    for hop_latency, send_time in sent_times:
        print(f"Hop Latency: {hop_latency}, Send Time: {send_time}")
