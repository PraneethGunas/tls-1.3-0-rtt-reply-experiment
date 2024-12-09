from scapy.all import *

def reply_client_hello(pcap_file):
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"Error reading pcap file: {e}")
        return

    second_client_hello = False
    for i, packet in enumerate(packets):
        # Check for TLS handshake packets using TCP and raw layers
        if TCP in packet:  # HTTPS port
            try:
                # Try to parse the raw payload as TLS
                if Raw in packet:
                    raw_data = packet[Raw].load
                    # Check for TLS Handshake record type (22)
                    if len(raw_data) > 5 and raw_data[0] == 22:
                        # Check for ClientHello message type (1)
                        if raw_data[5] == 1:
                            print(f"ClientHello packet found! {i}")
                            print(f"Packet summary: {packet.summary()}")
                            if second_client_hello:
                                server_ip = packet[IP].dst
                                server_port = packet[TCP].dport

                                initial_seq = 1000
                                ip = IP(dst=server_ip)
                                # Establish a TCP connection with the server
                                syn = ip/TCP(sport=58512, dport=server_port, flags="S", seq=initial_seq)
                                syn_ack = sr1(syn, timeout=3)

                                ack_pkt = ip/TCP(sport=58512, dport=server_port, flags="A", 
                                                seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq+1)
                                send(ack_pkt)

                                seq_for_data = syn_ack[TCP].ack  
                                ack_for_data = syn_ack[TCP].seq+1 

                                # Tweaking the ClientHello packet
                                client_hello_pkt = ip/TCP(sport=58512, dport=server_port, flags="PA", 
                                                        seq=seq_for_data, ack=ack_for_data)/Raw(load=raw_data)
                                # Reply the ClientHello packet
                                send(client_hello_pkt)
                            else:
                                second_client_hello = True

            except Exception as e:
                print(f"Error parsing packet: {e}")

# Path to your pcap file
pcap_file_path = "sniffed_packets.pcap" # save this file in the same directory as this script (atleast for this example)

# Extract and display the ClientHello
extract_client_hello(pcap_file_path)