from scapy.all import *
import time

def consistency_test(interface, hop_latency, num_packets):
    results = []

    def handle_packet(packet):
        arrival_time = time.time()
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            if ip_layer.id == hop_latency:
                results.append(arrival_time)
    
    sniff_thread = threading.Thread(target=sniff, kwargs={'iface': interface, 'prn': handle_packet, 'count': num_packets})
    sniff_thread.start()

    time.sleep(2)  # Allow sniffing to start
    for _ in range(num_packets):
        pkt = Ether()/IP(dst="10.0.0.1", ttl=64, id=hop_latency)/Raw(load=f"Consistency Test Packet {hop_latency}")
        sendp(pkt, iface=interface)
    
    sniff_thread.join()

    for i, arrival_time in enumerate(results):
        print(f"Packet {i+1} with hop latency {hop_latency} arrived at {arrival_time}")

if __name__ == "__main__":
    interface = "eth0"
    hop_latency = 5000
    num_packets = 10
    consistency_test(interface, hop_latency, num_packets)
