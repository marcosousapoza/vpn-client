import ipaddress
import struct

class ip_parser:
    def __init__(self) -> None:

        pass
    def parse_ipv4(packet):
        """
        Parse the IPv4 packet header, return the parsed header fields we want, the
        header in its entirety, and the IPv4 payload.

        You do NOT have to handle any kind of datagram fragmentation or reassembly!

        Already implemented by us, no need to change.
        """
        # Determine the header length
        header_length_in_bytes = (packet[0] & 0x0F) * 4
        # Split the header from the payload
        header = packet[:header_length_in_bytes]
        payload = packet[header_length_in_bytes:]
        # Unpack the relevant fields from the header
        (ttl, protocol, hdr_checksum, src, dst) = struct.unpack_from("!8xBBHLL", header)
        # Coerce the addresses into "IPv4Address" objects
        src_addr = ipaddress.IPv4Address(src)
        dst_addr = ipaddress.IPv4Address(dst)
        return src_addr, dst_addr, protocol, ttl, hdr_checksum, header, payload