import socket
import struct
import textwrap
import time
import csv
from collections import defaultdict

def get_mac_addr(bytes_addr):
    return ':'.join(format(b, '02x') for b in bytes_addr)

def ipv4(addr):
    return '.'.join(map(str, addr))

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def ipv4_packet(data):
    version_header_length = data[0]
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('!8xBB2x4s4s', data[:20])
    return ipv4(src), ipv4(target), proto, data[header_length:]

def tcp_segment(data):
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('!HHLLH', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    return src_port, dest_port, sequence, acknowledgment, data[offset:]

def udp_segment(data):
    src_port, dest_port, size = struct.unpack('!HHH2x', data[:8])
    return src_port, dest_port, data[8:]

def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('!BBH', data[:4])
    return icmp_type, code, checksum, data[4:]

def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(f'\\x{byte:02x}' for byte in string)
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

def sniff(filter_protocol=None, save_to_csv=False, csv_filename='packets.csv'):
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    counters = defaultdict(int)
    packet_list = []

    print("Sniffer started... Press Ctrl+C to stop.")

    try:
        while True:
            raw_data, addr = conn.recvfrom(65536)
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            if eth_proto != 8:
                continue  # Skip non IPv4 packets
            src_ip, dest_ip, proto, data = ipv4_packet(data)
            protocol_name = 'Other'
            if proto == 1:
                protocol_name = 'ICMP'
            elif proto == 6:
                protocol_name = 'TCP'
            elif proto == 17:
                protocol_name = 'UDP'
            else:
                protocol_name = f'Proto {proto}'

            if filter_protocol and filter_protocol.lower() != protocol_name.lower():
                continue

            counters['total'] += 1
            counters[protocol_name] += 1

            print(f"\n[{timestamp}] Ethernet Frame:")
            print(f"  Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}")
            print(f"  IPv4 Packet:")
            print(f"    Source IP: {src_ip}, Destination IP: {dest_ip}, Protocol: {protocol_name}")

            summary = {
                'timestamp': timestamp,
                'src_mac': src_mac,
                'dest_mac': dest_mac,
                'src_ip': src_ip,
                'dest_ip': dest_ip,
                'protocol': protocol_name,
                'details': ''
            }

            if proto == 6:
                src_port, dest_port, sequence, acknowledgment, payload = tcp_segment(data)
                print("    TCP Segment:")
                print(f"      Source Port: {src_port}, Destination Port: {dest_port}")
                print(f"      Sequence: {sequence}, Acknowledgment: {acknowledgment}")
                print(f"      Data:\n{format_multi_line('        ', payload)}")
                summary['details'] = f"TCP src_port={src_port} dst_port={dest_port} seq={sequence} ack={acknowledgment}"
            elif proto == 17:
                src_port, dest_port, payload = udp_segment(data)
                print("    UDP Segment:")
                print(f"      Source Port: {src_port}, Destination Port: {dest_port}")
                print(f"      Data:\n{format_multi_line('        ', payload)}")
                summary['details'] = f"UDP src_port={src_port} dst_port={dest_port}"
            elif proto == 1:
                icmp_type, code, checksum, payload = icmp_packet(data)
                print("    ICMP Packet:")
                print(f"      Type: {icmp_type}, Code: {code}, Checksum: {checksum}")
                print(f"      Data:\n{format_multi_line('        ', payload)}")
                summary['details'] = f"ICMP type={icmp_type} code={code} checksum={checksum}"
            else:
                print(f"    Other IPv4 Data:\n{format_multi_line('        ', data)}")
                summary['details'] = "Other IPv4 protocol data"

            if save_to_csv:
                packet_list.append(summary)

    except KeyboardInterrupt:
        print("\nSniffer stopped.")
        print("\n--- Packet Summary ---")
        for key, count in counters.items():
            print(f"{key}: {count}")

        if save_to_csv and packet_list:
            keys = packet_list[0].keys()
            with open(csv_filename, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=keys)
                writer.writeheader()
                writer.writerows(packet_list)
            print(f"\nCaptured packet summary saved to {csv_filename}")

if __name__ == "__main__":
    # To filter for TCP only, call sniff(filter_protocol='TCP')
    # To save captured summaries to CSV, call sniff(save_to_csv=True)
    sniff()
