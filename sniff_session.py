from scapy.all import sniff, TCP, Raw, conf, wrpcap

# List to store captured packets
captured_packets = []

def packet_callback(packet):
    if packet.haslayer(TCP):
        print(f"Packet captured: {packet.summary()}")
        if packet.haslayer(Raw):
            print(f"Raw data: {packet[Raw].load}")
        # Append packet to the list
        captured_packets.append(packet)

# Start sniffing and store packets in 'captured_packets' list
sniff(iface='lo0', prn=packet_callback, store=0)

# After sniffing is stopped, save packets to a pcap file
wrpcap('sniffed_packets.pcap', captured_packets)
print("Packets saved to 'sniffed_packets.pcap'")