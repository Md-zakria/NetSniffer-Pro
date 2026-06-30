"""Packet parsing helpers for Ethernet, IPv4, TCP, UDP, and ICMP."""

from __future__ import annotations

import datetime
import socket
import struct


def mac_addr(raw_bytes: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw_bytes).upper()


def ipv4_addr(raw_bytes: bytes) -> str:
    return ".".join(str(b) for b in raw_bytes)


def payload_preview(payload: bytes, limit: int = 64) -> str:
    preview = payload[:limit]
    return "".join(chr(b) if 32 <= b < 127 else "." for b in preview)


def payload_hex_dump(payload: bytes, limit: int = 128) -> str:
    clipped = payload[:limit]
    return " ".join(f"{byte:02x}" for byte in clipped)


def parse_ethernet(raw_data: bytes) -> dict[str, object]:
    dest, src, proto = struct.unpack("! 6s 6s H", raw_data[:14])
    return {
        "dest_mac": mac_addr(dest),
        "src_mac": mac_addr(src),
        "proto": socket.htons(proto),
        "payload": raw_data[14:],
    }


def parse_ipv4(raw_data: bytes) -> dict[str, object]:
    version_ihl = raw_data[0]
    ihl = (version_ihl & 0xF) * 4
    ttl, proto, src, dest = struct.unpack("! 8x B B 2x 4s 4s", raw_data[:20])
    return {
        "version": version_ihl >> 4,
        "ihl": ihl,
        "ttl": ttl,
        "proto": proto,
        "src": ipv4_addr(src),
        "dest": ipv4_addr(dest),
        "payload": raw_data[ihl:],
    }


def parse_icmp(raw_data: bytes) -> dict[str, object]:
    icmp_type, code, checksum = struct.unpack("! B B H", raw_data[:4])
    return {
        "type": icmp_type,
        "code": code,
        "checksum": checksum,
        "payload": raw_data[4:],
    }


def parse_tcp(raw_data: bytes) -> dict[str, object]:
    src_port, dest_port, seq, ack, offset_flags = struct.unpack("! H H L L H", raw_data[:14])
    offset = (offset_flags >> 12) * 4
    flag_urg = (offset_flags & 32) >> 5
    flag_ack = (offset_flags & 16) >> 4
    flag_psh = (offset_flags & 8) >> 3
    flag_rst = (offset_flags & 4) >> 2
    flag_syn = (offset_flags & 2) >> 1
    flag_fin = offset_flags & 1
    return {
        "src_port": src_port,
        "dest_port": dest_port,
        "seq": seq,
        "ack": ack,
        "flags": {
            "URG": flag_urg,
            "ACK": flag_ack,
            "PSH": flag_psh,
            "RST": flag_rst,
            "SYN": flag_syn,
            "FIN": flag_fin,
        },
        "payload": raw_data[offset:],
    }


def parse_udp(raw_data: bytes) -> dict[str, object]:
    src_port, dest_port, size = struct.unpack("! H H 2x H", raw_data[:8])
    return {
        "src_port": src_port,
        "dest_port": dest_port,
        "size": size,
        "payload": raw_data[8:],
    }


def build_packet_record(count: int, eth: dict[str, object], ip: dict[str, object], transport: dict[str, object], protocol_name: str) -> dict[str, object]:
    timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    source = f"{ip['src']}:{transport.get('src_port', '')}".rstrip(":")
    destination = f"{ip['dest']}:{transport.get('dest_port', '')}".rstrip(":")

    if protocol_name == "TCP":
        active = [flag for flag, enabled in transport["flags"].items() if enabled]
        summary = (
            f":{transport['src_port']} -> :{transport['dest_port']} | "
            f"Seq:{transport['seq']} Ack:{transport['ack']} | Flags:[{' '.join(active) if active else 'None'}]"
        )
    elif protocol_name == "UDP":
        summary = f":{transport['src_port']} -> :{transport['dest_port']} | Size:{transport['size']}"
    else:
        summary = f"Type:{transport['type']} Code:{transport['code']} Checksum:{transport['checksum']}"

    preview = payload_preview(transport.get("payload", b""))
    payload = transport.get("payload", b"")
    payload_hex = payload_hex_dump(payload)
    details = [
        f"Packet #{count} | {timestamp}",
        f"ETH: {eth['src_mac']} -> {eth['dest_mac']}",
        f"IP : {ip['src']} -> {ip['dest']} | TTL:{ip['ttl']} | Proto:{ip['proto']}",
        f"{protocol_name}: {summary}",
    ]
    if preview:
        details.append(f"DATA: {preview}")
    if payload_hex:
        details.append(f"HEX : {payload_hex}")

    return {
        "count": count,
        "timestamp": timestamp,
        "protocol": protocol_name,
        "source": source,
        "destination": destination,
        "summary": summary,
        "preview": preview,
        "payload_hex": payload_hex,
        "details": "\n".join(details),
        "eth": eth,
        "ip": ip,
        "transport": transport,
        "log_line": f"[{timestamp}] #{count} {protocol_name} {source} -> {destination} | {summary} | {preview}",
    }
