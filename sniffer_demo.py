import socket
import struct
import textwrap


#refer ipv4 packet header
# Unpack ethernet frame
def unpack_ethernet_frame(data):
    dest_mac, source_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return parse_mac(dest_mac), parse_mac(source_mac), socket.htons(proto), data[14:]

def parse_mac(mac_bytes):
    mac_str = map("{:02x}".format, mac_bytes)
    return ':'.join(mac_str).upper()

def socket_connection():
    return socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

def unpack_ip4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15 ) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, parse_ipv4(src), parse_ipv4(target), data[header_length:]

def parse_ipv4(ip_bytes):
    return '.'.join(map(str,ip_bytes))

# refer icmp packet
def unpack_icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# refer tcp ip packet
def unpack_tcp_packet(data):
    (src_port, des_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('!  H  H L L H', data[:14])
    offset = ( offset_reserved_flags >> 12 ) * 4
    flag_urg = ( offset_reserved_flags & 32 ) >> 5
    flag_ack = ( offset_reserved_flags & 16 ) >> 4
    flag_psh = ( offset_reserved_flags & 8 ) >> 3
    flag_rst = ( offset_reserved_flags & 4 ) >> 2
    flag_syn = ( offset_reserved_flags & 2) >> 1
    flag_fin = ( offset_reserved_flags & 1 )
    return src_port, des_port, sequence, acknowledgment, offset, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[14:]

def unpack_udp_packet(data):
    src_port, des_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, des_port, size, data[8:]

def main():
    conn = socket_connection()
    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, source_mac, eth_proto, data = unpack_ethernet_frame(raw_data)
        print("\nEthernet Frame: ")
        print(f"Destination MAC: {dest_mac}")
        print(f"Source MAC: {source_mac}")
        print(f"Protocol: {eth_proto}")

        if eth_proto == 8:
            version, header_length, ttl, proto, src, target, data = unpack_ip4_packet(data)
            print(f"IPV4 Frame:\nVersion: {version}\nHeader: {header_length}\nTTL:{ttl}\n")
            print(f"Protocol: {proto}\Source: {src}\Target: {target}\n\n")
            if proto == 1:
                icmp_type, code, checksum, data = unpack_icmp_packet(data)
                print("ICMP packet frame:\n")
                print(f"\tICMP Type: {icmp_type}\nCode: {code}\nChecksum: {checksum}\n\tData: {data}\n\n")
            if proto == 6:
                src_port, des_port, sequence, acknowledgment, offset, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = unpack_tcp_packet(data)
                print("TCP packet frame:\n")
                print(f"\tSource Port: {src_port}\nDestination Port: {des_port}\n")
                print(f"\tSequence: {sequence}\nAcknowledgment: {acknowledgment}\n")
                print(f"\tOffset: {offset}\nAcknowledgment: {acknowledgment}\n")
                print(f"\tflag_urg: {flag_urg}\nflag_ack: {flag_ack}\nflag_psh: {flag_psh}\nflag_rst: {flag_rst}\n")
                print(f"\tflag_syn: {flag_syn}\nflag_fin: {flag_fin}\n")
                print(f"\tData: {data}\n\n")
            if proto == 17:
                src_port, des_port, size, data = unpack_udp_packet(data)
                print("UDP Packet Frame:\n")
                print(f"\tSource Port: {src_port}\nDestination Port: {des_port}\nSize: {size}\n")
                print(f"\tData: {data}\n\n")

if __name__ == "__main__":
    main()





