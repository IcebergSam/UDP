# Sam Ahsan
# 3357 asn3
# 24 nov 2019

import binascii
import socket
import struct
import sys
import hashlib

UDP_IP = "127.0.0.1"
UDP_PORT = 5005
unpacker = struct.Struct('I I 8s 32s')


#Create the socket and listen
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # internet, UDP
sock.bind((UDP_IP, UDP_PORT))

while True:
    #Receive Data
    data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
    UDP_Packet = unpacker.unpack(data)

    print("received from:", addr)
    print("received message:", UDP_Packet)

    #Create the Checksum for comparison
    values = (UDP_Packet[0],UDP_Packet[1],UDP_Packet[2])
    packer = struct.Struct('I I 8s')
    packed_data = packer.pack(*values)
    chksum =  bytes(hashlib.md5(packed_data).hexdigest(), encoding="UTF-8")
   
    #Compare Checksums to test for corrupt data
    ACK = 1
    if UDP_Packet[3] == chksum:
        print('CheckSums Match, Packet OK')
        SEQ = UDP_Packet[1] #update SEQ iff correct&&uncorrupted packet
    else:
        print('Checksums Do Not Match, Packet Corrupt')
    
    #send ACK, seq, data in a new packet
    data = UDP_Packet[2]
    values = (ACK,SEQ,data)
    packer = struct.Struct('I I 8s')
    packed_data = packer.pack(*values)
    chksum =  bytes(hashlib.md5(packed_data).hexdigest(), encoding="UTF-8")
    values = (ACK, SEQ, data, chksum)
    UDP_Packet_Data = struct.Struct('I I 8s 32s')
    UDP_Packet = UDP_Packet_Data.pack(*values)
    sock.sendto(UDP_Packet, addr)
    print('Packet sent: ', unpacker.unpack(UDP_Packet))
