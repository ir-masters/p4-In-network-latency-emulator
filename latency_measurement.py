from scapy.all import sniff, IP
import time

# Configuration
INTERFACE = 'eth0'  # Interface to sniff on
EXPECTED_DELAY = 100  # Expected delay in milliseconds
PACKET_COUNT = 100  # Number of packets to capture

def handle_packet(packet):
    if IP in packet:
        # Assuming the payload contains the original send timestamp in the first bytes
        original_send_time = float(packet[IP].payload.load.decode('utf-8'))
        actual_arrival_time = time.time()

        # Convert expected delay to seconds
        expected_delay_seconds = EXPECTED_DELAY / 1000.0

        # Calculate expected arrival time based on original send time and expected delay
        expected_arrival_time = original_send_time + expected_delay_seconds

        # Calculate deviation
        deviation = actual_arrival_time - expected_arrival_time

        print(f"Packet ID: {packet[IP].id}, Expected Arrival: {expected_arrival_time}, Actual Arrival: {actual_arrival_time}, Deviation: {deviation} seconds")

def main():
    print("Starting packet capture...")
    sniff(iface=INTERFACE, prn=handle_packet, count=PACKET_COUNT)

if __name__ == "__main__":
    main()
