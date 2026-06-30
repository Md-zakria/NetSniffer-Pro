"""Raw socket capture worker used by the UI. Networking behavior is preserved."""

from __future__ import annotations

import os
import queue
import socket
import threading

from .parser import build_packet_record, parse_ethernet, parse_icmp, parse_ipv4, parse_tcp, parse_udp

LOG_FILE = "sniffer_log.txt"


def get_capture_ip() -> str:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("8.8.8.8", 80))
        return probe.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        probe.close()


def open_capture_socket():
    if os.name == "nt":
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        conn.bind((get_capture_ip(), 0))
        conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        return conn, "windows"

    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    return conn, "linux"


def close_capture_socket(conn, mode):
    try:
        if mode == "windows":
            conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    except Exception:
        pass
    try:
        conn.close()
    except Exception:
        pass


class CaptureWorker(threading.Thread):
    def __init__(self, output_queue: queue.Queue, stop_event: threading.Event, protocol_filter=None, max_packets: int = 0):
        super().__init__(daemon=True)
        self.output_queue = output_queue
        self.stop_event = stop_event
        self.protocol_filter = protocol_filter
        self.max_packets = max_packets

    def run(self):
        conn = None
        mode = None
        try:
            conn, mode = open_capture_socket()
            conn.settimeout(0.5)
        except Exception as exc:
            self.output_queue.put({"type": "error", "message": str(exc)})
            return

        packet_count = 0
        proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}

        try:
            with open(LOG_FILE, "w", encoding="utf-8") as log_file:
                log_file.write(f"Network Sniffer Log - {os.linesep}")
                log_file.write("=" * 70 + os.linesep)

                while not self.stop_event.is_set():
                    try:
                        raw_data, _ = conn.recvfrom(65536)
                    except socket.timeout:
                        continue
                    except OSError as exc:
                        self.output_queue.put({"type": "error", "message": str(exc)})
                        break

                    if mode == "linux":
                        eth = parse_ethernet(raw_data)
                        if eth["proto"] != 0x0800:
                            continue
                        ip = parse_ipv4(eth["payload"])
                    else:
                        eth = {"src_mac": "N/A", "dest_mac": "N/A", "proto": 0x0800, "payload": raw_data}
                        ip = parse_ipv4(raw_data)

                    protocol_name = proto_map.get(ip["proto"])
                    if not protocol_name:
                        continue
                    if self.protocol_filter and protocol_name != self.protocol_filter:
                        continue

                    if protocol_name == "TCP":
                        transport = parse_tcp(ip["payload"])
                    elif protocol_name == "UDP":
                        transport = parse_udp(ip["payload"])
                    else:
                        transport = parse_icmp(ip["payload"])

                    packet_count += 1
                    record = build_packet_record(packet_count, eth, ip, transport, protocol_name)
                    log_file.write(record["log_line"] + os.linesep)
                    log_file.flush()
                    self.output_queue.put({"type": "packet", "record": record})

                    if self.max_packets and packet_count >= self.max_packets:
                        self.output_queue.put({"type": "status", "message": f"Reached max packet limit ({self.max_packets})."})
                        break
        finally:
            if conn is not None:
                close_capture_socket(conn, mode)
            self.output_queue.put({"type": "stopped", "count": packet_count})
