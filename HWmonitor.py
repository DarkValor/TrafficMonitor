import socket, struct


def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65565)

        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print(f'\nAn error has caused your traffic monitor to monitor the undead realm instead!\nThere are monsters from portal {dest_mac} coming to fuck you up! Run! they found your computer! {src_mac}\nYou have atleast {eth_proto} monsters chasing you!')

        # 8 for IPv4
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print(f'Undead army:\nZombies: {version}, Skeletons: {header_length}, Werewolves: {ttl}, Ghosts: {proto} and some other creepy shit.\nThey have traced your computer and found your location at {src}! They are coming from {target}.')

            # ICMP
            if proto == 1:
                icmp_type, code, checksum, data = icmp_pacet(data)
                print(f'Undead army:\nGhosts: {icmp_type}, Zombies: {code}, Vampires {checksum}. They are coming to haunt your dreams and touch you in your sleep.')
                print(f'Data:\n{data}')

            # TCP
            elif proto == 6:
                (src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
                print(f'Ghosts are coming through your router with viruses!\nGhosts coming from port: {src_port}, Ghost arrived at port: {dest_port}, Viruses installed: {sequence}, Processes crashed: {acknowledgement}')
                print(f'Your statistics:\nGhosts killed: {flag_urg}, Zombies killed: {flag_ack}, Skeletons killed: {flag_psh}\nVampires killed: {flag_rst}, Will to live: {flag_syn}, Seconds past without crying of fear: {flag_fin}')
                print(f'Data:\n{data}')

            # UDP
            elif proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print(f'Ghosts are stealing your data!\nSource Port: {src_port}, Destination Port: {dest_port}, Programs stolen: {length}')
                print(f'Data:\n{data}')

            # Other
            else:
                print(f'Data:\n{data}')

        else:
            print(f'Data:\n{data}')


# Unpack ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Return properly formatted MAC address
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

# Unpacks IPv4 packets
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

# Returns properly formatted IPv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))

# Unpacks ICMP packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpacks TCP fragments
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = (offset_reserved_flags & 1)
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

# Unpacks UDP segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

main()
