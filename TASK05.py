from scapy.all import sniff, IP, Raw
from datetime import datetime

protocols = {1: "ICMP", 6: "TCP", 17: "UDP"}

def packet_callback(packet):
    try:
        if IP in packet:
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = ip_layer.proto
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            packet_size = len(packet)
            
            protocol_name = protocols.get(protocol, f"Unknown ({protocol})")

            print(f"[{timestamp}] Protocol: {protocol_name}")
            print(f"Source IP: {src_ip} -> Destination IP: {dst_ip}")
            print(f"Packet Size: {packet_size} bytes")

            if Raw in packet:
                try:
                    payload = packet[Raw].load.decode(errors="ignore")
                    print(f"Payload: {payload}")
                except Exception as decode_error:
                    print(f"Raw Payload: {packet[Raw].load} (Decode Error: {decode_error})")
            else:
                print("No Payload Data")
            
            print("-" * 50)  
        else:
            print("Non-IP Packet Captured\n")
    except Exception as callback_error:
        print(f"Error in packet processing: {callback_error}\n")

def start_sniffing():
    print("Starting packet sniffer... Press Ctrl+C to stop.")
    try:
        sniff(filter="ip", prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\nPacket sniffing stopped gracefully.")
    except Exception as sniff_error:
        print(f"An unexpected error occurred while sniffing: {sniff_error}")

if __name__ == "__main__":
    start_sniffing()
