#!/usr/bin/env python3

import socket
import struct 
import textwrap
import time
import sys

TAB1 = "\t - "
TAB2 = "\t\t - "
TAB3 = "\t\t\t - "
TAB4 = "\t\t\t\t - "

DATA_TAB1 = "\t "
DATA_TAB2 = "\t\t "
DATA_TAB3 = "\t\t\t "
DATA_TAB4 = "\t\t\t\t "

SLEEP_TIME = 2

# Convert bytes to mac address
def getMacAddr(bytesAddr):
    bytesStr = map('{:02x}'.format, bytesAddr)
    return ':'.join(bytesStr).upper()

# Take raw data and return dest and source mac address, protocol and other data (layer 2 - frames)
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return getMacAddr(dest_mac), getMacAddr(src_mac), socket.htons(proto), data[14:]

# Convert bytes to IPv4 address
def getIPv4(bytesAddr):
    bytesStr = map(str, bytesAddr)
    return '.'.join(bytesStr)

# Parse IPv4 data packets (layer 3 - packets)
def ipv4_packet(data):
    version_and_header_length = data[0]
    version = version_and_header_length>>4;
    header_length = (version_and_header_length & 15)*4;
    ttl, proto, src, target = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
    return version, header_length, ttl, proto, getIPv4(src), getIPv4(target), data[header_length:]

# Parse ICMP packets(Internet Control Message Protocol)
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack("! B B H", data[:4])
    return icmp_type, code, checksum, data[4:]

# Parse TCP packets(Transmission Control Protocol)
def tcp_packet(data):
    (src_port, dest_port, sequence, acknowledgement, offset_and_reserved_and_flags) =  struct.unpack("! H H L L H", data[:14])
    offset = (offset_and_reserved_and_flags>>12)*4
    flag_urg = (offset_and_reserved_and_flags & 32)>>5
    flag_ack = (offset_and_reserved_and_flags & 16)>>4
    flag_psh = (offset_and_reserved_and_flags & 8)>>3
    flag_rst = (offset_and_reserved_and_flags & 4)>>2
    flag_syn = (offset_and_reserved_and_flags & 2)>>1
    flag_fin = (offset_and_reserved_and_flags & 1)>>0

    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:];

# Parse UDP packets(User Datagram Protocol)
def udp_packet(data):
    src_port, dest_port, size = struct.unpack("! H H 2x H", data[:8])
    return src_port, dest_port, size, data[8:];

def wrap_line(prefix, string, size=72):
    size-=len(prefix)
    if isinstance(string, bytes):
        #string = "".join(r'\x{:02}'.format(byte) for byte in string)
        string = "".join('{:02x}'.format(byte) for byte in string)
        if(size%2):
            size-=1

    return "\n".join(prefix+line for line in textwrap.wrap(string, size));

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    args = sys.argv
    tcp_only = False;
    udp_only = False;
    icmp_only = False;
    if len(args)==2 and args[1]=="-t":
        tcp_only = True;
    if len(args)==2 and args[1]=="-i":
        icmp_only = True;
    if len(args)==2 and args[1]=="-u":
        udp_only = True;
    if len(args)>2:
        print("Too many arguments")
        return
    while True:
        raw_data, addr = conn.recvfrom(65536);
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data);
        if tcp_only==True:
            (version, header_length, ttl, proto, src, target, dataaa) =  ipv4_packet(data);
            if eth_proto!=8 or proto!=6:
                continue
        if udp_only==True:
            (version, header_length, ttl, proto, src, target, dataaa) =  ipv4_packet(data);
            if eth_proto!=8 or proto!=17:
                continue
        if icmp_only==True:
            (version, header_length, ttl, proto, src, target, dataaa) =  ipv4_packet(data);
            if eth_proto!=8 or proto!=1:
                continue
        print("\nEthernet frame: ")
        print(f"{TAB1}Destination: {dest_mac}");
        print(f"{TAB1}Source: {src_mac}");
        print(f"{TAB1}Protocol: {eth_proto}");
        
        # IPv4
        if eth_proto==8:
            (version, header_length, ttl, proto, src, target, data) =  ipv4_packet(data);
            print(f"{DATA_TAB1}# IPv4 Packet: ")
            print(f"{TAB2}Version: {version}")
            print(f"{TAB2}Header Length: {header_length}")
            print(f"{TAB2}TTL: {ttl}")
            print(f"{TAB2}Protocol: {proto}")
            print(f"{TAB2}Source IP: {src}")
            print(f"{TAB2}Destination IP: {target}")
            
            # ICMP
            if proto==1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(DATA_TAB2+"# ICMP Packet: ")
                print(f"{TAB3}ICMP Type: {icmp_type}")
                print(f"{TAB3}Code: {code}")
                print(f"{TAB3}Checksum: {checksum}")
                #print(f"{TAB3}Data:")
                #print(wrap_line(DATA_TAB3, data))

            # TCP
            elif proto==6:
                (src_port, dest_port, sequence, acknowledgement, 
                flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, 
                flag_fin, data) = tcp_packet(data)
                print(DATA_TAB2+"# TCP Packet: ")
                print(f"{TAB3}Source Port: {src_port}")
                print(f"{TAB3}Destination Port: {dest_port}")
                print(f"{TAB3}Sequence: {sequence}")
                print(f"{TAB3}Acknowledgement: {acknowledgement}")
                print(f"{TAB3}Flags: ")
                print(f"{TAB4}URG: [{flag_urg}] ACK: [{flag_ack}] PSH: [{flag_psh}] RST: [{flag_rst}] SYN: [{flag_syn}] FIN: [{flag_fin}] ")
                #print(f"{TAB3}Data:")
                #print(wrap_line(DATA_TAB3, data))

            # UDP
            elif proto==17:
                src_port, dest_port, size, data = udp_packet(data)
                print(DATA_TAB2+"# UDP Packet: ")
                print(f"{TAB3}Source Port: {src_port}")
                print(f"{TAB3}Destination Port: {dest_port}")
                print(f"{TAB3}Length: {size}")
                #print(f"{TAB3}Data:")
                #print(wrap_line(DATA_TAB3, data))

            #else:
            #    print(f"{TAB2}Data:")
            #    print(wrap_line(DATA_TAB2, data))
        
        time.sleep(SLEEP_TIME)


main();

