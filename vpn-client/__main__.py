#!/usr/bin/env python3

import socket
import time
import select
from src.ip_parser import ip_parser

HOST = "127.0.0.1"
PORT = 65432
IP_PARSER = ip_parser()

def main():
    with socket.socket(family=socket.AF_PACKET, type=socket.SOCK_RAW, proto=socket.htons(3)) as ether_socket:
        while True:
            ready_socks, _, _ = select.select([ether_socket], [], [], 10)
            for s in ready_socks:
                frame, _ = s.recvfrom(65535) #why this port?
                
                

if __name__ == '__main__':
    main()
#ether_sock = socket.socket(family=socket.AF_PACKET, type=socket.SOCK_RAW, proto=socket.htons(3))
#    #ether_sock.bind(("eth1", 0))
#    while True:
#        ready_socks, _, _ = select.select([ether_sock], [], [], 5)
#        if not ready_socks:
#            print("5 seconds passed without seeing link-layer traffic", file=sys.stderr)
#        for s in ready_socks:
#            frame, _ = s.recvfrom(65535)
#
#            # Ethernet handling
#            src_mac, dst_mac, eth_type, eth_header, eth_payload = parse_ethernet(frame)
#            dump_ethernet_to_console(src_mac, dst_mac, eth_type, frame)
#            if eth_type != 0x0800: # IPv4 Ethertype code here.
#                print("Frame with ethernet type 0x{:04X} received; skipping further processing\n\n".format(
#                      eth_type))
#                continue
#
#            # IPv4 handling
#            # We can be certain that eth_payload is an IPv4 datagram now.
#            src_addr, dst_addr, protocol, ttl, ip_hdr_checksum, ip_header, segment = parse_ipv4(eth_payload)
#            checksum_valid = verify_checksum(ip_header)
#            dump_ipv4_to_console(src_addr, dst_addr, ttl, protocol, ip_hdr_checksum, checksum_valid)
#
#            # We can actually *verify* checksum validity for both TCP and UDP
#            # before looking at the protocol, because the pseudo headers are
#            # identical and checksum verification doesn't require us to parse
#            # it out of the header.
#            transport_layer_checksum_valid = verify_checksum(
#                build_pseudo_header_prefix(src_addr, dst_addr, protocol, len(segment))
#                + segment)
#
#            if protocol == 17:  # UDP protocol number
#                # UDP handling
#                (udp_src_port, udp_dst_port, udp_length, udp_checksum,
#                 udp_data_length, udp_header, udp_payload) = parse_udp(segment)
#                dump_udp_to_console(udp_src_port, udp_dst_port,
#                                    udp_length, udp_data_length,
#                                    udp_checksum, transport_layer_checksum_valid)
#                dump_payload_to_console(udp_payload)
#
#            elif protocol == 6: # TCP protocol number
#                # TCP handling
#                (tcp_src_port, tcp_dst_port, tcp_seq_num, tcp_ack_num, tcp_flags,
#                 tcp_window, tcp_checksum, tcp_header, tcp_payload) = parse_tcp(segment)
#                dump_tcp_to_console(tcp_src_port, tcp_dst_port,
#                                    tcp_seq_num, tcp_ack_num,
#                                    tcp_flags, tcp_window,
#                                    tcp_checksum, transport_layer_checksum_valid)
#                dump_payload_to_console(tcp_payload)
#
#            else:
#                print("IPv4 datagram with protocol number {} received; skipping further processing\n\n".format(
#                      protocol))