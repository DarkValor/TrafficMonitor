# Monitors all traffic. Received data will be unpacked according to their protocol. 
# The payload will be packed and saved in the capture.pcap file.

import socket, struct
from cap import Pcap


def main():
    # Create pcap file
    pcap = Pcap('capture.pcap')
    # Create an AF_PACKET type raw socket. (socket.ntohs(3) = every packet)
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    # Receive packets
    while True:
        # Receive all information and store it in raw_data and addr. 65535 is largest buffersize
        raw_data, addr = conn.recvfrom(65535)
        # Write data to pcap file
        pcap.write(raw_data)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print(f'\nEthernet Frame: \nDestination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}')

        # IPv4
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print(f'IPv4 Packet:\nVersion: {version}, Header Length: {header_length}, TTL: {ttl}, Protocol: {proto}, Source: {src}, Target: {target}')

            # ICMP
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(f'ICMP Packet:\nType: {icmp_type}, Code: {code}, Checksum: {checksum}')
                print(f'Data:\n{data}')

            # TCP
            elif proto == 6:
                (src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
                print(f'TCP Segment:\nSource Port: {src_port}, Destination Port: {dest_port}, Sequence: {sequence}, Acknowledgement: {acknowledgement}')
                print(f'Flags:\nURG: {flag_urg}, ACK: {flag_ack}, PSH: {flag_psh}, RST: {flag_rst}, SYN: {flag_syn}, FIN: {flag_fin}')
                print(f'Data:\n{data}')

            # UDP
            elif proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print(f'UDP Segment:\nSource Port: {src_port}, Destination Port: {dest_port}, Length: {length}')
                print(f'Data:\n{data}')

            # Other
            else:
                print(f'Data:\n{data}')

        else:
            print(f'Data:\n{data}')


# Unpack ethernet frame.
def ethernet_frame(data):
    # '! 6s 6s H' is the format in which the first 14 bytes will be unpacked into.
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Return properly formatted MAC address
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

# Unpacks IPv4 packets
def ipv4_packet(data):
    version_header_length = data[0]
    # First 8 bytes = version and header length. Shift bits to the right by 4 to push out header length and get the version.
    version = version_header_length >> 4
    # Give header length. (Used to determine where the payload starts)
    header_length = (version_header_length & 15) * 4
    # '! 8x B B 2x 4s 4s' is the format in which the first 20 bytes will be unpacked into. (Which is all the header info)
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

# Returns properly formatted IPv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))

# Unpacks ICMP packet
def icmp_packet(data):
    # '! B B H' is the format in which the first 4 bytes will be unpacked into.
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpacks TCP fragments
def tcp_segment(data):
    # '! H H L L H' is the format in which the first 14 bytes will be unpacked into.
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    # Shift bits to the right by 12 to push out reserved and flags to get the offset.
    offset = (offset_reserved_flags >> 12) * 4
    # Define all flags
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = (offset_reserved_flags & 1)
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

# Unpacks UDP segment
def udp_segment(data):
    # '! H H 2x H' is the format in which the first 8 bytes will be unpacked into.
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

main()
