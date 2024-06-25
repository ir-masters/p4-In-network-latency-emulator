from scapy.all import *
import time
import threading
import netifaces

def get_mac_address(interface):
    return netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr']

def validate_latency(interface, expected_latencies):
    unique_id = "unique_test_id_123456"  # More distinctive unique identifier
    source_mac = get_mac_address(interface)
    results = []

    def handle_packet(packet):
        arrival_time = time.time()
        if packet.haslayer(Ether) and packet[Ether].src == source_mac and packet.haslayer(IP) and packet.haslayer(Raw):
            ip_layer = packet[IP]
            raw_layer = packet[Raw]
            try:
                payload = raw_layer.load.decode('utf-8', errors='ignore')
                if unique_id in payload:
                    hop_latency = ip_layer.id
                    results.append((hop_latency, arrival_time))
                    print(f"Captured packet with hop latency {hop_latency} at {arrival_time}")
                # else:
                #     print(f"Ignored packet with unknown payload")
            except Exception as e:
                print(f"Error processing packet: {e}")

    sniff_thread = threading.Thread(target=sniff, kwargs={'iface': interface, 'prn': handle_packet, 'timeout': 10})
    sniff_thread.start()

    time.sleep(2)  # Allow sniffing to start
    sent_times = []
    for hop_latency in expected_latencies:
        send_time = time.time()
        pkt = Ether(src=source_mac)/IP(dst="10.0.0.1", ttl=64, id=hop_latency)/Raw(load=f"{unique_id} Validation Test Packet {hop_latency}")
        sendp(pkt, iface=interface)
        sent_times.append((hop_latency, send_time))
        print(f"Sent packet with hop latency {hop_latency} at {send_time}")
    
    sniff_thread.join()

    # Debug: Print sent_times and results
    print("\nSent Times:")
    for hop_latency, send_time in sent_times:
        print(f"Hop Latency: {hop_latency}, Send Time: {send_time}")

    print("\nReceived Times:")
    for hop_latency, arrival_time in results:
        print(f"Hop Latency: {hop_latency}, Arrival Time: {arrival_time}")
    
    # Match sent and received packets
    for hop_latency, arrival_time in results:
        try:
            send_time = next(t for t in sent_times if t[0] == hop_latency)[1]
            print(f"Packet with hop latency {hop_latency} sent at {send_time} arrived at {arrival_time}, delay: {arrival_time - send_time}")
        except StopIteration:
            print(f"Error: Couldn't find send time for packet with hop latency {hop_latency}")

if __name__ == "__main__":
    interface = "h1-eth0"
    expected_latencies = [0, 1000, 10000, 65535]
    validate_latency(interface, expected_latencies)
