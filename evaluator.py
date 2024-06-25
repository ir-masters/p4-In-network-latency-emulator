from scapy.all import *
import time
import threading

def generate_ipv4_packet(dst_ip, ttl, hop_latency):
    pkt = Ether() / IP(dst=dst_ip, ttl=ttl) / Raw(load="Test packet with IPv4")
    pkt[IP].id = hop_latency  # Embedding hop latency in IP ID field for testing
    return pkt

def generate_customdata_packet(dst_mac, proto_id, content_id, ingress_num, egress_num, hop_latency):
    ether = Ether(dst=dst_mac)
    customdata = struct.pack("!HHBBQ", proto_id, content_id, ingress_num, egress_num, hop_latency)
    pkt = ether / Raw(load=customdata) / Raw(load="Test packet with custom data")
    return pkt

def send_test_packets(interface):
    # Generate IPv4 packets with varying TTL and hop latency values
    ipv4_packets = [generate_ipv4_packet("10.0.0.1", ttl, hop_latency) 
                    for ttl, hop_latency in zip(range(1, 6), range(100, 6555, 800))]

    # Generate custom data packets with varying hop latency values
    custom_packets = [generate_customdata_packet("00:11:22:33:44:55", 0x1313, i, 1, 1, hop_latency) 
                      for i, hop_latency in zip(range(1, 6), range(100, 6555, 800))]

    # Combine all packets
    all_packets = ipv4_packets + custom_packets

    # Send packets
    sendp(all_packets, iface=interface)
    print(f"Sent {len(all_packets)} packets")

def handle_packet(packet, results):
    # Log the arrival time and packet details
    arrival_time = time.time()
    
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        hop_latency = ip_layer.id
        results.append({
            'type': 'IPv4',
            'src': ip_layer.src,
            'dst': ip_layer.dst,
            'ttl': ip_layer.ttl,
            'hop_latency': hop_latency,
            'arrival_time': arrival_time
        })
    elif packet.haslayer(Raw) and len(packet[Raw]) >= 14:
        # Assuming custom data packet if it's a Raw layer with at least 14 bytes (Ethernet header size)
        ether_layer = packet[Ether]
        custom_data = packet[Raw].load[0:14]  # Extract the custom data part
        proto_id, content_id, ingress_num, egress_num, hop_latency = struct.unpack("!HHBBQ", custom_data)
        results.append({
            'type': 'CustomData',
            'dst': ether_layer.dst,
            'proto_id': proto_id,
            'content_id': content_id,
            'ingress_num': ingress_num,
            'egress_num': egress_num,
            'hop_latency': hop_latency,
            'arrival_time': arrival_time
        })

def receive_packets(interface, count, results):
    print(f"Listening for packets on interface {interface}...")
    sniff(iface=interface, prn=lambda x: handle_packet(x, results), count=count)
    print("Finished capturing packets.")

def evaluate_results(results):
    for result in results:
        if result['type'] == 'IPv4':
            print(f"Received IPv4 packet: src={result['src']}, dst={result['dst']}, ttl={result['ttl']}, "
                  f"hop_latency={result['hop_latency']}, arrival_time={result['arrival_time']}")
        elif result['type'] == 'CustomData':
            print(f"Received Custom Data packet: dst={result['dst']}, proto_id={result['proto_id']}, "
                  f"content_id={result['content_id']}, ingress_num={result['ingress_num']}, "
                  f"egress_num={result['egress_num']}, hop_latency={result['hop_latency']}, "
                  f"arrival_time={result['arrival_time']}")
def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

if __name__ == "__main__":
    # Replace with your network interface name
    interface = get_if()
    # Number of packets to capture
    packet_count = 10
    results = []

    # Start packet receiving in a separate thread
    receiver_thread = threading.Thread(target=receive_packets, args=(interface, packet_count, results))
    receiver_thread.start()

    # Allow some time for the receiver to start
    time.sleep(2)

    # Send test packets
    send_test_packets(interface)

    # Wait for the receiver thread to finish
    receiver_thread.join()

    # Evaluate the results
    evaluate_results(results)
