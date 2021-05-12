# Sam Ahsan
# 250866576
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

print("UDP target IP:", UDP_IP)
print("UDP target port:", UDP_PORT)

def isACK(ack): 
	return (ack == 1)

def createChksum(ack, seq, data):
	#Create the Checksum
	values = (ack,seq,data)
	UDP_Data = struct.Struct('I I 8s')
	packed_data = UDP_Data.pack(*values)
	chksum =  bytes(hashlib.md5(packed_data).hexdigest(), encoding="UTF-8")
	return chksum

def sendPckt(ack, seq, data):
	#Build the UDP Packet
	values = (ack, seq, data, createChksum(ack, seq, data))
	UDP_Packet_Data = struct.Struct('I I 8s 32s')
	UDP_Packet = UDP_Packet_Data.pack(*values)

	#Send the UDP Packet
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # internet, UDP
	sock.sendto(UDP_Packet, (UDP_IP, UDP_PORT)) # sending packet to server
	sock.settimeout(0.009) # start timer, 9ms
	print('Packet Sent: ', unpacker.unpack(UDP_Packet))
	return sock # return socket so we can stop the timer from recv function

def recvPckt(sock):
	try:
		recvd, addr = sock.recvfrom(1024)
		sock.settimeout(None) #stop timer
		print('received msg: ', unpacker.unpack(recvd))
	except socket.timeout: 
		print('Timer expired, resending packet...')
		return recvPckt(sock) # if timer reaches 0, resend the same packet
	return unpacker.unpack(recvd) # return packet on successful delivery

# the data to send in each of the packets
DATA1 = b'NCC-1701'
DATA2 = b'NCC-1422'
DATA3 = b'NCC-1017'

#send first packet (seq=0) and receive ack0
recvPckt1 = recvPckt(sendPckt(0, 0, DATA1))
#compare ack, seq and checksums between sent/response
if isACK(recvPckt1[0]) and recvPckt1[1] == 0 and recvPckt1[3] == createChksum(1, 0, DATA1):
	print('Checksums Match, First Packet OK')

#send second packet (seq=1) and receive ack1
recvPckt2 = recvPckt(sendPckt(0, 1, DATA2))
#compare ack, seq and checksums between sent/response
if isACK(recvPckt2[0]) and recvPckt2[1] == 1 and recvPckt2[3] == createChksum(1, 1, DATA2):
	print('Checksums Match, Second Packet OK')

#send third packet (seq=0) and receive ack0
recvPckt3 = recvPckt(sendPckt(0, 0, DATA3))
#compare ack, seq and checksums between sent/response
if isACK(recvPckt1[0]) and recvPckt1[1] == 0 and recvPckt1[3] == createChksum(1, 0, DATA1):
	print('Checksums Match, Third Packet OK')
