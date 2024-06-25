from scapy.all import *
import time

def handle_packet(packet):
    # Log the arrival time and packet details
    arrival_time = time.time()
    
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"Received IPv4 packet: src={ip_layer.src}, dst={ip_layer.dst}, ttl={ip_layer.ttl}, "
              f"id={ip_layer.id}, arrival_time={arrival_time}")
    elif packet.haslayer(Raw) and len(packet[Raw]) >= 14:
        # Assuming custom data packet if it's a Raw layer with at least 14 bytes (Ethernet header size)
        ether_layer = packet[Ether]
        custom_data = packet[Raw].load[0:14]  # Extract the custom data part
        proto_id, content_id, ingress_num, egress_num, hop_latency = struct.unpack("!HHBBQ", custom_data)
        print(f"Received Custom Data packet: dst={ether_layer.dst}, proto_id={proto_id}, "
              f"content_id={content_id}, ingress_num={ingress_num}, egress_num={egress_num}, "
              f"hop_latency={hop_latency}, arrival_time={arrival_time}")
    else:
        print(f"Received unknown packet type: {packet.summary()}, arrival_time={arrival_time}")

def receive_packets(interface, count):
    print(f"Listening for packets on interface {interface}...")
    sniff(iface=interface, prn=handle_packet, count=count)
    print("Finished capturing packets.")

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
    # Number of packets to capture
    packet_count = 10
    receive_packets(interface, packet_count)
