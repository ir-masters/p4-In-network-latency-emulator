from scapy.all import *

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
    ipv4_packets = [generate_ipv4_packet("10.0.0.2", ttl, hop_latency) 
                    for ttl, hop_latency in zip(range(1, 6), range(100, 600, 100))]

    # Generate custom data packets with varying hop latency values
    # custom_packets = [generate_customdata_packet("00:00:00:02:01:00", 0x1313, i, 1, 1, hop_latency) 
                    #   for i, hop_latency in zip(range(1, 6), range(100, 600, 100))]

    # Combine all packets
    all_packets = ipv4_packets
    # + custom_packets

    # Send packets
    sendp(all_packets, iface=interface)
    print(f"Sent {len(all_packets)} packets")

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print ("Cannot find eth0 interface")
        exit(1)
    return iface

if __name__ == "__main__":
    # Replace with your network interface name
    interface = get_if()
    print(f"Using interface {interface}")
    send_test_packets(interface)
