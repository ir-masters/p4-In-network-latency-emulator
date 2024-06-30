from scapy.all import *
import time
import threading

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

def validate_latency(interface, expected_latencies):
    results = []

    def handle_packet(packet):
        arrival_time = time.time()
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            hop_latency = ip_layer.id
            if packet.haslayer(RecirculationFlagHeader):
                recirc_flag = packet[RecirculationFlagHeader].isRecirculated
                if recirc_flag:
                    return  # Skip recirculated packets
            results.append((hop_latency, arrival_time))

    sniff_thread = threading.Thread(target=sniff, kwargs={'iface': interface, 'prn': handle_packet, 'timeout': 20})
    sniff_thread.start()
    sniff_thread.join()

    # Debug: Print received times
    print("\nReceived Times:")
    for hop_latency, arrival_time in results:
        print(f"Hop Latency: {hop_latency}, Arrival Time: {arrival_time}")
    
    return results

if __name__ == "__main__":
    interface = "h2-eth0"
    expected_latencies = [0, 6000]
    received_times = validate_latency(interface, expected_latencies)
    
    # Match sent and received packets
    print("\nMatching Sent and Received Packets:")
    for hop_latency, arrival_time in received_times:
        print(f"Packet with hop latency {hop_latency} arrived at {arrival_time}")
