#!/usr/bin/env python3
"""
NetSniffer Pro — Network Analysis Suite
Advanced Packet Capture & Analysis Tool
Author: Muhammad Zakria
"""

import csv
import ctypes
import datetime
import json
import os
import queue
import socket
import struct
import subprocess
import sys
import textwrap
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk


# ═══════════════════════════════════════════════════════════════════════════════
# THEME
# ═══════════════════════════════════════════════════════════════════════════════
class T:
    BG0   = "#0B1220"
    BG1   = "#111827"
    BG2   = "#182230"
    BG3   = "#1A2540"
    HOVER = "#243041"
    BDR   = "#2C3443"
    SEL   = "#1E40AF"

    ACC   = "#2563EB"
    ACC_H = "#1D4ED8"
    ACC_P = "#1E40AF"

    OK    = "#22C55E"
    OK_H  = "#16A34A"
    WARN  = "#F59E0B"
    ERR   = "#EF4444"
    ERR_H = "#DC2626"
    INFO  = "#06B6D4"

    FG0   = "#F9FAFB"
    FG1   = "#9CA3AF"
    FG2   = "#6B7280"

    P_TCP   = "#3B82F6"
    P_UDP   = "#8B5CF6"
    P_ICMP  = "#EC4899"
    P_HTTP  = "#22C55E"
    P_HTTPS = "#14B8A6"
    P_DNS   = "#F59E0B"
    P_ARP   = "#6B7280"

    UI   = "Segoe UI"
    MONO = "Consolas"


PROTO_ROW_BG = {
    "TCP":   "#0D1B35",
    "UDP":   "#160D35",
    "ICMP":  "#2D0A1E",
    "HTTP":  "#0A2018",
    "HTTPS": "#071E1E",
    "DNS":   "#251800",
    "ARP":   "#141414",
}

PROTO_FG = {
    "TCP":   T.P_TCP,
    "UDP":   T.P_UDP,
    "ICMP":  T.P_ICMP,
    "HTTP":  T.P_HTTP,
    "HTTPS": T.P_HTTPS,
    "DNS":   T.P_DNS,
    "ARP":   T.P_ARP,
}

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════
LOG_FILE = "sniffer_log.txt"
MAX_PACKETS = 0


# ═══════════════════════════════════════════════════════════════════════════════
# HELPERS  (logic unchanged)
# ═══════════════════════════════════════════════════════════════════════════════
def mac_addr(raw_bytes):
    return ":".join(f"{b:02x}" for b in raw_bytes).upper()


def ipv4_addr(raw_bytes):
    return ".".join(str(b) for b in raw_bytes)


def format_multi_line(prefix, data, size=80):
    size -= len(prefix)
    if isinstance(data, bytes):
        data = "".join(r"\x{:02x}".format(b) if b < 32 or b > 126 else chr(b) for b in data)
    return "\n".join([prefix + line for line in textwrap.wrap(data, size)])


def payload_preview(payload, limit=64):
    preview = payload[:limit]
    return "".join(chr(b) if 32 <= b < 127 else "." for b in preview)


def payload_hex_dump(payload, limit=128):
    clipped = payload[:limit]
    return " ".join(f"{byte:02x}" for byte in clipped)


def get_capture_ip():
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("8.8.8.8", 80))
        return probe.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        probe.close()


# ═══════════════════════════════════════════════════════════════════════════════
# PARSERS  (unchanged)
# ═══════════════════════════════════════════════════════════════════════════════
def parse_ethernet(raw_data):
    dest, src, proto = struct.unpack("! 6s 6s H", raw_data[:14])
    return {
        "dest_mac": mac_addr(dest),
        "src_mac":  mac_addr(src),
        "proto":    socket.htons(proto),
        "payload":  raw_data[14:],
    }


def parse_ipv4(raw_data):
    version_ihl = raw_data[0]
    ihl = (version_ihl & 0xF) * 4
    ttl, proto, src, dest = struct.unpack("! 8x B B 2x 4s 4s", raw_data[:20])
    return {
        "version": version_ihl >> 4,
        "ihl":     ihl,
        "ttl":     ttl,
        "proto":   proto,
        "src":     ipv4_addr(src),
        "dest":    ipv4_addr(dest),
        "payload": raw_data[ihl:],
    }


def parse_icmp(raw_data):
    icmp_type, code, checksum = struct.unpack("! B B H", raw_data[:4])
    return {
        "type":     icmp_type,
        "code":     code,
        "checksum": checksum,
        "payload":  raw_data[4:],
    }


def parse_tcp(raw_data):
    src_port, dest_port, seq, ack, offset_flags = struct.unpack("! H H L L H", raw_data[:14])
    offset = (offset_flags >> 12) * 4
    return {
        "src_port":  src_port,
        "dest_port": dest_port,
        "seq":       seq,
        "ack":       ack,
        "flags": {
            "URG": (offset_flags & 32) >> 5,
            "ACK": (offset_flags & 16) >> 4,
            "PSH": (offset_flags & 8)  >> 3,
            "RST": (offset_flags & 4)  >> 2,
            "SYN": (offset_flags & 2)  >> 1,
            "FIN":  offset_flags & 1,
        },
        "payload": raw_data[offset:],
    }


def parse_udp(raw_data):
    src_port, dest_port, size = struct.unpack("! H H 2x H", raw_data[:8])
    return {
        "src_port":  src_port,
        "dest_port": dest_port,
        "size":      size,
        "payload":   raw_data[8:],
    }


def build_packet_record(count, eth, ip, transport, protocol_name):
    timestamp   = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    src_port_s  = str(transport.get("src_port",  ""))
    dst_port_s  = str(transport.get("dest_port", ""))
    source      = f"{ip['src']}:{src_port_s}".rstrip(":")
    destination = f"{ip['dest']}:{dst_port_s}".rstrip(":")

    if protocol_name == "TCP":
        active  = [f for f, v in transport["flags"].items() if v]
        summary = (
            f":{transport['src_port']} → :{transport['dest_port']}  "
            f"Seq:{transport['seq']}  Ack:{transport['ack']}  "
            f"[{' '.join(active) if active else 'None'}]"
        )
    elif protocol_name == "UDP":
        summary = (
            f":{transport['src_port']} → :{transport['dest_port']}  "
            f"Len:{transport['size']}"
        )
    else:
        summary = (
            f"Type:{transport['type']}  Code:{transport['code']}  "
            f"Checksum:0x{transport['checksum']:04x}"
        )

    preview     = payload_preview(transport.get("payload", b""))
    payload     = transport.get("payload", b"")
    payload_hex = payload_hex_dump(payload)
    raw_bytes   = payload[:512]
    pkt_len     = len(payload)

    lines = [
        f"  ┌─ Packet #{count}   {timestamp}",
        f"  │",
        f"  ├─ ETHERNET FRAME",
        f"  │    Src MAC  :  {eth['src_mac']}",
        f"  │    Dst MAC  :  {eth['dest_mac']}",
        f"  │",
        f"  ├─ IPV4",
        f"  │    Src IP   :  {ip['src']}",
        f"  │    Dst IP   :  {ip['dest']}",
        f"  │    TTL      :  {ip['ttl']}",
        f"  │    Protocol :  {ip['proto']}",
        f"  │",
        f"  └─ {protocol_name}",
    ]

    if protocol_name == "TCP":
        active = [f for f, v in transport["flags"].items() if v]
        lines += [
            f"       Src Port :  {transport['src_port']}",
            f"       Dst Port :  {transport['dest_port']}",
            f"       Seq      :  {transport['seq']}",
            f"       Ack      :  {transport['ack']}",
            f"       Flags    :  [{' '.join(active) if active else 'None'}]",
        ]
    elif protocol_name == "UDP":
        lines += [
            f"       Src Port :  {transport['src_port']}",
            f"       Dst Port :  {transport['dest_port']}",
            f"       Length   :  {transport['size']}",
        ]
    else:
        lines += [
            f"       Type     :  {transport['type']}",
            f"       Code     :  {transport['code']}",
            f"       Checksum :  0x{transport['checksum']:04x}",
        ]

    if preview:
        lines += ["", f"  PAYLOAD (ASCII):", f"  {preview}"]

    return {
        "count":       count,
        "timestamp":   timestamp,
        "protocol":    protocol_name,
        "source":      source,
        "destination": destination,
        "src_ip":      ip["src"],
        "dst_ip":      ip["dest"],
        "src_port":    src_port_s,
        "dst_port":    dst_port_s,
        "length":      pkt_len,
        "summary":     summary,
        "preview":     preview,
        "payload_hex": payload_hex,
        "raw_bytes":   raw_bytes,
        "details":     "\n".join(lines),
        "log_line":    f"[{timestamp}] #{count} {protocol_name} {source} -> {destination} | {summary} | {preview}",
    }


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


# ═══════════════════════════════════════════════════════════════════════════════
# CAPTURE WORKER  (unchanged)
# ═══════════════════════════════════════════════════════════════════════════════
class CaptureWorker(threading.Thread):
    def __init__(self, output_queue, stop_event, protocol_filter=None, max_packets=0):
        super().__init__(daemon=True)
        self.output_queue    = output_queue
        self.stop_event      = stop_event
        self.protocol_filter = protocol_filter
        self.max_packets     = max_packets

    def run(self):
        conn = mode = None
        try:
            conn, mode = open_capture_socket()
            conn.settimeout(0.5)
        except Exception as exc:
            msg = str(exc)
            if "10013" in msg or "forbidden" in msg.lower() or "permission" in msg.lower():
                msg = (
                    "[WinError 10013] Access denied — raw socket requires Administrator.\n\n"
                    "Please restart NetSniffer Pro by right-clicking its shortcut and\n"
                    "choosing  'Run as Administrator'."
                )
            self.output_queue.put({"type": "error", "message": msg})
            return

        packet_count = 0
        proto_map    = {6: "TCP", 17: "UDP", 1: "ICMP"}

        try:
            with open(LOG_FILE, "w", encoding="utf-8") as log_f:
                log_f.write(f"NetSniffer Pro — Capture Log\n{datetime.datetime.now()}\n{'=' * 70}\n")
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
                        ip  = parse_ipv4(raw_data)

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
                    log_f.write(record["log_line"] + "\n")
                    log_f.flush()
                    self.output_queue.put({"type": "packet", "record": record})

                    if self.max_packets and packet_count >= self.max_packets:
                        self.output_queue.put({"type": "status", "message": f"Reached limit ({self.max_packets} packets)."})
                        break
        finally:
            if conn is not None:
                close_capture_socket(conn, mode)
            self.output_queue.put({"type": "stopped", "count": packet_count})


# ═══════════════════════════════════════════════════════════════════════════════
# UI COMPONENTS
# ═══════════════════════════════════════════════════════════════════════════════
class ModernButton(tk.Canvas):
    """Rounded animated button drawn on Canvas."""

    def __init__(self, parent, text="", command=None, icon="",
                 width=120, height=36, radius=7,
                 bg=T.ACC, hover_bg=T.ACC_H, press_bg=None,
                 fg=T.FG0, font_size=10, bold=True, **kw):
        try:
            canvas_bg = parent.cget("bg")
        except Exception:
            canvas_bg = T.BG0
        super().__init__(parent, width=width, height=height,
                         bg=canvas_bg, highlightthickness=0, bd=0, **kw)
        self._label    = f"{icon}  {text}" if icon else text
        self._cmd      = command
        self._bg       = bg
        self._hover    = hover_bg
        self._press    = press_bg or T.ACC_P
        self._fg       = fg
        self._r        = radius
        self._bw       = width
        self._bh       = height
        self._font     = (T.UI, font_size, "bold" if bold else "normal")
        self._disabled = False
        self._draw(bg)
        self.bind("<Enter>",          self._on_enter)
        self.bind("<Leave>",          self._on_leave)
        self.bind("<ButtonPress-1>",  self._on_press)
        self.bind("<ButtonRelease-1>",self._on_release)

    def _rr(self, x1, y1, x2, y2, r, **kw):
        pts = [x1+r,y1, x2-r,y1, x2,y1, x2,y1+r,
               x2,y2-r, x2,y2, x2-r,y2, x1+r,y2,
               x1,y2, x1,y2-r, x1,y1+r, x1,y1]
        return self.create_polygon(pts, smooth=True, **kw)

    def _draw(self, fill):
        self.delete("all")
        self._rr(1, 1, self._bw-1, self._bh-1, self._r, fill=fill, outline="")
        self.create_text(self._bw//2, self._bh//2, text=self._label,
                         fill=self._fg if not self._disabled else T.FG2,
                         font=self._font)

    def _on_enter(self, _=None):
        if not self._disabled: self._draw(self._hover)

    def _on_leave(self, _=None):
        if not self._disabled: self._draw(self._bg)

    def _on_press(self, _=None):
        if not self._disabled: self._draw(self._press)

    def _on_release(self, _=None):
        if not self._disabled:
            self._draw(self._hover)
            if self._cmd:
                self._cmd()

    def configure_state(self, state):
        self._disabled = (state == "disabled")
        self._draw(T.BG3 if self._disabled else self._bg)

    def set_colors(self, bg, hover_bg=None):
        self._bg    = bg
        self._hover = hover_bg or bg
        self._draw(bg)


class PulseDot(tk.Canvas):
    """Animated pulsing status dot."""

    def __init__(self, parent, size=10, color=T.OK, **kw):
        # pop 'bg' from kw first so we don't pass it twice to Canvas
        cbg = kw.pop("bg", None)
        if cbg is None:
            try:
                cbg = parent.cget("bg")
            except Exception:
                cbg = T.BG0
        super().__init__(parent, width=size, height=size,
                         bg=cbg, highlightthickness=0, **kw)
        self._sz     = size
        self._color  = color
        self._muted  = T.FG2
        self._active = False
        self._phase  = True
        self._job    = None
        self._draw(self._muted)

    def _draw(self, c):
        self.delete("all")
        p = 1
        self.create_oval(p, p, self._sz-p, self._sz-p, fill=c, outline="")

    def start(self):
        self._active = True
        self._pulse()

    def stop(self):
        self._active = False
        if self._job:
            self.after_cancel(self._job)
            self._job = None
        self._draw(self._muted)

    def _pulse(self):
        if not self._active:
            return
        self._draw(self._color if self._phase else "#1C2A1A")
        self._phase = not self._phase
        self._job   = self.after(550, self._pulse)


class Separator(tk.Frame):
    def __init__(self, parent, orient="vertical", **kw):
        if orient == "vertical":
            super().__init__(parent, bg=T.BDR, width=1, **kw)
        else:
            super().__init__(parent, bg=T.BDR, height=1, **kw)


# ═══════════════════════════════════════════════════════════════════════════════
# SIDEBAR
# ═══════════════════════════════════════════════════════════════════════════════
_NAV = [
    ("◈", "Dashboard"),
    ("▤", "Packets"),
    ("▦", "Statistics"),
    ("⊕", "Connections"),
    ("≡", "Logs"),
    ("⇥", "Export"),
    ("⚙", "Settings"),
    ("◎", "About"),
]


class Sidebar(tk.Frame):
    def __init__(self, parent, on_select=None, **kw):
        super().__init__(parent, bg=T.BG1, width=220, **kw)
        self.pack_propagate(False)
        self._on_select = on_select
        self._active    = "Packets"
        self._frames    = {}
        self._dot       = None
        self._stat_lbl  = None
        self._pkt_lbl   = None
        self._iface_lbl = None
        self._build()

    # ── build ──────────────────────────────────────────────────────
    def _build(self):
        # Brand
        brand = tk.Frame(self, bg=T.BG1, height=70)
        brand.pack(fill="x")
        brand.pack_propagate(False)
        tk.Label(brand, text="⬡", font=(T.UI, 22), bg=T.BG1, fg=T.ACC).place(x=16, y=16)
        tk.Label(brand, text="NetSniffer Pro", font=(T.UI, 12, "bold"), bg=T.BG1, fg=T.FG0).place(x=50, y=17)
        tk.Label(brand, text="Packet Analyzer", font=(T.UI, 8), bg=T.BG1, fg=T.FG2).place(x=51, y=40)

        Separator(self, orient="horizontal").pack(fill="x", padx=14, pady=(0, 6))

        tk.Label(self, text="MENU", font=(T.UI, 7, "bold"),
                 bg=T.BG1, fg=T.FG2).pack(anchor="w", padx=18, pady=(6, 4))

        for icon, label in _NAV:
            self._make_item(icon, label)

        Separator(self, orient="horizontal").pack(fill="x", padx=14, pady=8)

        # Status card
        card = tk.Frame(self, bg=T.BG2, padx=12, pady=10)
        card.pack(fill="x", padx=10, pady=2)

        tk.Label(card, text="CAPTURE STATUS", font=(T.UI, 7, "bold"),
                 bg=T.BG2, fg=T.FG2).pack(anchor="w")

        row = tk.Frame(card, bg=T.BG2)
        row.pack(fill="x", pady=(6, 0))
        self._dot = PulseDot(row, bg=T.BG2)
        self._dot.pack(side="left")
        self._stat_lbl = tk.Label(row, text="Idle", font=(T.UI, 10, "bold"),
                                  bg=T.BG2, fg=T.FG2)
        self._stat_lbl.pack(side="left", padx=(6, 0))

        self._pkt_lbl = tk.Label(card, text="Packets:  0",
                                 font=(T.UI, 9), bg=T.BG2, fg=T.FG1)
        self._pkt_lbl.pack(anchor="w", pady=(4, 0))

        self._iface_lbl = tk.Label(card, text="Interface:  —",
                                   font=(T.UI, 8), bg=T.BG2, fg=T.FG2, wraplength=185)
        self._iface_lbl.pack(anchor="w", pady=(2, 0))

    def _make_item(self, icon, label):
        active = (label == self._active)
        bg = T.BG3 if active else T.BG1
        fg = T.FG0 if active else T.FG1

        f = tk.Frame(self, bg=bg, height=42, cursor="hand2")
        f.pack(fill="x", padx=6, pady=1)
        f.pack_propagate(False)

        bar_c = T.ACC if active else bg
        tk.Frame(f, bg=bar_c, width=3).pack(side="left", fill="y")
        tk.Label(f, text=icon, font=(T.UI, 12), bg=bg,
                 fg=T.ACC if active else T.FG2, width=3).pack(side="left", padx=(6, 2))
        tk.Label(f, text=label, font=(T.UI, 10, "bold" if active else "normal"),
                 bg=bg, fg=fg).pack(side="left")

        self._frames[label] = (f, icon)
        for w in [f] + list(f.winfo_children()):
            w.bind("<Enter>", lambda e, lbl=label: self._hover(lbl, True))
            w.bind("<Leave>", lambda e, lbl=label: self._hover(lbl, False))
            w.bind("<Button-1>", lambda e, lbl=label: self._select(lbl))

    def _hover(self, label, entering):
        if label == self._active:
            return
        data = self._frames.get(label)
        if not data:
            return
        f, _ = data
        bg = T.HOVER if entering else T.BG1
        try:
            f.configure(bg=bg)
            for w in f.winfo_children():
                w.configure(bg=bg)
        except tk.TclError:
            pass

    def _select(self, label):
        if label == self._active:
            return
        self._active = label
        if self._on_select:
            self._on_select(label)
        # Refresh
        for w in list(self.winfo_children()):
            w.destroy()
        self._frames.clear()
        self._dot = self._stat_lbl = self._pkt_lbl = self._iface_lbl = None
        self._build()

    # ── public ────────────────────────────────────────────────────
    def update_status(self, live, count=0, iface=""):
        if self._dot:
            if live:
                self._dot.start()
                if self._stat_lbl:
                    self._stat_lbl.configure(text="Live", fg=T.OK)
            else:
                self._dot.stop()
                if self._stat_lbl:
                    self._stat_lbl.configure(text="Idle", fg=T.FG2)
        if self._pkt_lbl:
            self._pkt_lbl.configure(text=f"Packets:  {count:,}")
        if self._iface_lbl and iface:
            self._iface_lbl.configure(text=f"Interface:  {iface}")


# ═══════════════════════════════════════════════════════════════════════════════
# PACKET TABLE
# ═══════════════════════════════════════════════════════════════════════════════
_COLS = [
    ("num",      "#",        58,  "center"),
    ("time",     "Time",     112, "w"),
    ("proto",    "Protocol", 86,  "center"),
    ("src",      "Source IP",155, "w"),
    ("dst",      "Dest IP",  155, "w"),
    ("sport",    "Src Port", 72,  "center"),
    ("dport",    "Dst Port", 72,  "center"),
    ("length",   "Len",      58,  "center"),
    ("info",     "Info",     420, "w"),
]


class PacketTable(tk.Frame):
    def __init__(self, parent, on_select=None, on_save=None, **kw):
        super().__init__(parent, bg=T.BG2, **kw)
        self._on_select = on_select
        self._on_save   = on_save
        self._sort_col  = None
        self._sort_rev  = False
        self._build()
        self._setup_tags()

    def _build(self):
        # Header strip
        hdr = tk.Frame(self, bg=T.BG2, height=36)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="  ⊟  LIVE PACKET CAPTURE",
                 font=(T.UI, 10, "bold"), bg=T.BG2, fg=T.FG0).pack(side="left", padx=6, pady=6)

        # Tree frame
        tf = tk.Frame(self, bg=T.BG0)
        tf.pack(fill="both", expand=True)

        cols = [c[0] for c in _COLS]
        self.tree = ttk.Treeview(tf, columns=cols, show="headings",
                                 selectmode="browse", style="Pkg.Treeview")
        for cid, heading, w, anc in _COLS:
            self.tree.heading(cid, text=heading, command=lambda c=cid: self._sort(c))
            self.tree.column(cid, width=w, anchor=anc,
                             stretch=(cid == "info"), minwidth=36)

        vsb = ttk.Scrollbar(tf, orient="vertical", command=self.tree.yview,
                            style="Pkg.Vertical.TScrollbar")
        hsb = ttk.Scrollbar(tf, orient="horizontal", command=self.tree.xview,
                            style="Pkg.Horizontal.TScrollbar")
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tf.grid_rowconfigure(0, weight=1)
        tf.grid_columnconfigure(0, weight=1)

        self.tree.bind("<<TreeviewSelect>>", self._sel_evt)
        self.tree.bind("<Button-3>",         self._ctx_menu)

        # Context menu
        self._menu = tk.Menu(self, tearoff=0, bg=T.BG2, fg=T.FG0,
                             activebackground=T.ACC, activeforeground=T.FG0,
                             relief="flat", bd=1)
        self._menu.add_command(label="   Copy Row",            command=self._copy_row)
        self._menu.add_command(label="   Copy Source IP",      command=self._copy_src)
        self._menu.add_command(label="   Copy Destination IP", command=self._copy_dst)
        self._menu.add_separator()
        self._menu.add_command(label="   Save Packet Details", command=lambda: self._on_save and self._on_save())
        self._menu.add_command(label="   Clear Selection",     command=lambda: self.tree.selection_remove(self.tree.selection()))

    def _setup_tags(self):
        for proto, rbg in PROTO_ROW_BG.items():
            self.tree.tag_configure(proto, foreground=PROTO_FG[proto], background=rbg)
        self.tree.tag_configure("even", background=T.BG2)
        self.tree.tag_configure("odd",  background=T.BG1)

    def _sel_evt(self, _=None):
        if self._on_select:
            sel = self.tree.selection()
            if sel:
                self._on_select(sel[0])

    def _sort(self, col):
        self._sort_rev = (not self._sort_rev) if self._sort_col == col else False
        self._sort_col = col
        rows = [(self.tree.set(k, col), k) for k in self.tree.get_children()]
        try:
            rows.sort(key=lambda x: int(x[0]), reverse=self._sort_rev)
        except ValueError:
            rows.sort(key=lambda x: x[0].lower(), reverse=self._sort_rev)
        for i, (_, k) in enumerate(rows):
            self.tree.move(k, "", i)

    def _ctx_menu(self, ev):
        row = self.tree.identify_row(ev.y)
        if row:
            self.tree.selection_set(row)
            self._menu.tk_popup(ev.x_root, ev.y_root)

    def _copy_row(self):
        sel = self.tree.selection()
        if sel:
            self.clipboard_clear()
            self.clipboard_append("\t".join(str(v) for v in self.tree.item(sel[0], "values")))

    def _copy_src(self):
        sel = self.tree.selection()
        if sel:
            self.clipboard_clear()
            self.clipboard_append(self.tree.set(sel[0], "src"))

    def _copy_dst(self):
        sel = self.tree.selection()
        if sel:
            self.clipboard_clear()
            self.clipboard_append(self.tree.set(sel[0], "dst"))

    # ── public ────────────────────────────────────────────────────
    def insert_record(self, record):
        proto = record["protocol"]
        tag   = proto if proto in PROTO_ROW_BG else "odd"
        iid   = self.tree.insert("", "end", tags=(tag,), values=(
            record["count"],
            record["timestamp"],
            record["protocol"],
            record.get("src_ip", ""),
            record.get("dst_ip", ""),
            record.get("src_port", ""),
            record.get("dst_port", ""),
            record.get("length", ""),
            record["summary"],
        ))
        return iid

    def clear(self):
        self.tree.delete(*self.tree.get_children())

    def selected_iid(self):
        sel = self.tree.selection()
        return sel[0] if sel else None

    def count(self):
        return len(self.tree.get_children())


# ═══════════════════════════════════════════════════════════════════════════════
# DETAILS PANEL
# ═══════════════════════════════════════════════════════════════════════════════
class DetailsPanel(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, bg=T.BG1, **kw)
        self._build()

    def _build(self):
        hdr = tk.Frame(self, bg=T.BG1, height=34)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="  ◈  PACKET DETAILS",
                 font=(T.UI, 10, "bold"), bg=T.BG1, fg=T.FG0).pack(side="left", padx=8, pady=6)
        Separator(self, orient="horizontal").pack(fill="x")

        self._txt = tk.Text(self, wrap="word", bg=T.BG1, fg="#CBD5E1",
                            insertbackground=T.FG0, relief="flat",
                            font=(T.MONO, 10), padx=12, pady=8,
                            state="disabled", cursor="arrow",
                            selectbackground=T.SEL)
        vsb = ttk.Scrollbar(self, orient="vertical", command=self._txt.yview,
                            style="Pkg.Vertical.TScrollbar")
        self._txt.configure(yscrollcommand=vsb.set)
        self._txt.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self._txt.tag_configure("key",   foreground=T.FG1)
        self._txt.tag_configure("val",   foreground=T.FG0)
        self._txt.tag_configure("tree",  foreground=T.ACC)
        self._txt.tag_configure("data",  foreground="#86EFAC")

    def set_text(self, text):
        self._txt.configure(state="normal")
        self._txt.delete("1.0", "end")
        if text:
            self._txt.insert("end", text)
        self._txt.configure(state="disabled")

    def clear(self):
        self.set_text("")


# ═══════════════════════════════════════════════════════════════════════════════
# HEX VIEWER
# ═══════════════════════════════════════════════════════════════════════════════
class HexViewer(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, bg=T.BG0, **kw)
        self._build()

    def _build(self):
        hdr = tk.Frame(self, bg=T.BG0, height=34)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="  HEX VIEWER",
                 font=(T.UI, 10, "bold"), bg=T.BG0, fg=T.FG0).pack(side="left", padx=8, pady=6)

        copy = tk.Label(hdr, text="⊞ Copy", font=(T.UI, 9),
                        bg=T.BG0, fg=T.ACC, cursor="hand2")
        copy.pack(side="right", padx=10)
        copy.bind("<Button-1>", self._copy)

        Separator(self, orient="horizontal").pack(fill="x")

        col_hdr = tk.Frame(self, bg=T.BG1)
        col_hdr.pack(fill="x")
        tk.Label(col_hdr,
                 text="  Offset    00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f    ASCII",
                 font=(T.MONO, 9), bg=T.BG1, fg=T.FG2).pack(side="left", pady=2, padx=2)

        Separator(self, orient="horizontal").pack(fill="x")

        self._txt = tk.Text(self, wrap="none", bg="#070E1C", fg="#93C5FD",
                            insertbackground=T.FG0, relief="flat",
                            font=(T.MONO, 10), padx=6, pady=6,
                            state="disabled", cursor="arrow",
                            selectbackground=T.SEL)
        vsb = ttk.Scrollbar(self, orient="vertical", command=self._txt.yview,
                            style="Pkg.Vertical.TScrollbar")
        hsb = ttk.Scrollbar(self, orient="horizontal", command=self._txt.xview,
                            style="Pkg.Horizontal.TScrollbar")
        self._txt.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self._txt.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self._txt.tag_configure("off",   foreground="#4B5563")
        self._txt.tag_configure("byte",  foreground="#93C5FD")
        self._txt.tag_configure("zero",  foreground="#1F2937")
        self._txt.tag_configure("sep",   foreground="#374151")
        self._txt.tag_configure("ascii", foreground="#86EFAC")

    def set_data(self, hex_str="", raw_bytes=b""):
        self._txt.configure(state="normal")
        self._txt.delete("1.0", "end")
        if raw_bytes:
            self._render(raw_bytes[:512])
        elif hex_str:
            try:
                parts = hex_str.split()
                data  = bytes(int(p, 16) for p in parts if p)
                self._render(data[:512])
            except (ValueError, TypeError):
                self._txt.insert("end", hex_str)
        self._txt.configure(state="disabled")

    def _render(self, data):
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            self._txt.insert("end", f"  {i:04x}", "off")
            self._txt.insert("end", "    ", "sep")
            for j, b in enumerate(chunk):
                if j == 8:
                    self._txt.insert("end", " ", "sep")
                tag = "zero" if b == 0 else "byte"
                self._txt.insert("end", f"{b:02x} ", tag)
            if len(chunk) < 16:
                pad = (16 - len(chunk)) * 3 + (1 if len(chunk) <= 8 else 0)
                self._txt.insert("end", " " * pad)
            self._txt.insert("end", "  │  ", "sep")
            asc = "".join(chr(b) if 32 <= b < 127 else "\xb7" for b in chunk)
            self._txt.insert("end", asc, "ascii")
            self._txt.insert("end", "\n")

    def clear(self):
        self._txt.configure(state="normal")
        self._txt.delete("1.0", "end")
        self._txt.configure(state="disabled")

    def _copy(self, _=None):
        txt = self._txt.get("1.0", "end").strip()
        if txt:
            self.clipboard_clear()
            self.clipboard_append(txt)


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN APPLICATION
# ═══════════════════════════════════════════════════════════════════════════════
class NetworkSnifferGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("NetSniffer Pro — Enterprise Network Analysis Suite")
        self.geometry("1640x960")
        self.minsize(1400, 860)
        self.configure(bg=T.BG0)

        # State
        self.packet_queue    = queue.Queue()
        self.stop_event      = threading.Event()
        self.worker          = None
        self.capturing       = False
        self.packet_count    = 0
        self.row_records     = {}
        self.packet_history  = []
        self._capture_start  = None

        self._setup_styles()
        self._build_menubar()
        self._build_header()
        self._build_toolbar()
        self._build_body()
        self._build_statusbar()

        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.after(100,  self._poll_queue)
        self.after(1000, self._tick_clock)
        self.after(1000, self._tick_duration)

    # ── STYLES ────────────────────────────────────────────────────
    def _setup_styles(self):
        s = ttk.Style(self)
        try:
            s.theme_use("clam")
        except tk.TclError:
            pass

        s.configure("Pkg.Treeview",
                    background=T.BG2, foreground=T.FG0,
                    fieldbackground=T.BG2, borderwidth=0,
                    font=(T.UI, 10), rowheight=30)
        s.configure("Pkg.Treeview.Heading",
                    background=T.BG1, foreground=T.FG1,
                    borderwidth=0, relief="flat",
                    font=(T.UI, 9, "bold"))
        s.map("Pkg.Treeview",
              background=[("selected", T.SEL)],
              foreground=[("selected", T.FG0)])
        s.map("Pkg.Treeview.Heading",
              background=[("active", T.HOVER)])

        for orient in ("Vertical", "Horizontal"):
            s.configure(f"Pkg.{orient}.TScrollbar",
                        background=T.BG2, troughcolor=T.BG0,
                        bordercolor=T.BG0, arrowcolor=T.FG2,
                        relief="flat", width=10)
            s.map(f"Pkg.{orient}.TScrollbar",
                  background=[("active", T.HOVER)])

        s.configure("Dark.TCombobox",
                    background=T.BG2, foreground=T.FG0,
                    fieldbackground=T.BG2, selectbackground=T.SEL,
                    arrowcolor=T.FG1, bordercolor=T.BDR,
                    insertcolor=T.FG0, font=(T.UI, 10))
        s.map("Dark.TCombobox",
              fieldbackground=[("readonly", T.BG2)],
              background=[("active", T.HOVER)])

    # ── MENUBAR ───────────────────────────────────────────────────
    def _build_menubar(self):
        m = tk.Menu(self, bg=T.BG1, fg=T.FG0,
                    activebackground=T.ACC, activeforeground=T.FG0,
                    relief="flat", bd=0)

        def sub():
            return tk.Menu(m, tearoff=0, bg=T.BG2, fg=T.FG0,
                           activebackground=T.ACC, activeforeground=T.FG0)

        fm = sub()
        fm.add_command(label="  Open Log File",       command=self.open_log_file)
        fm.add_command(label="  Export as CSV",        command=self.export_packets_csv)
        fm.add_command(label="  Export as JSON",       command=self.export_packets_json)
        fm.add_command(label="  Save Packet Details",  command=self.save_selected_details)
        fm.add_separator()
        fm.add_command(label="  Clear View",           command=self.clear_view)
        fm.add_separator()
        fm.add_command(label="  Exit",                 command=self.on_close)
        m.add_cascade(label="File", menu=fm)

        cm = sub()
        cm.add_command(label="  Start Capture", command=self.start_capture)
        cm.add_command(label="  Stop Capture",  command=self.stop_capture)
        cm.add_command(label="  Clear",         command=self.clear_view)
        m.add_cascade(label="Capture", menu=cm)

        vm = sub()
        vm.add_command(label="  Dark Theme (active)", command=lambda: None)
        m.add_cascade(label="View", menu=vm)

        hm = sub()
        hm.add_command(label="  About NetSniffer Pro", command=self._show_about)
        m.add_cascade(label="Help", menu=hm)

        self.config(menu=m)

    # ── HEADER ────────────────────────────────────────────────────
    def _build_header(self):
        hdr = tk.Frame(self, bg=T.BG1, height=56)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)

        # Left brand
        brand = tk.Frame(hdr, bg=T.BG1)
        brand.pack(side="left", padx=20, pady=8)
        tk.Label(brand, text="⬡", font=(T.UI, 22), bg=T.BG1, fg=T.ACC).pack(side="left")
        tf = tk.Frame(brand, bg=T.BG1)
        tf.pack(side="left", padx=(10, 0))
        tk.Label(tf, text="NetSniffer Pro", font=(T.UI, 14, "bold"),
                 bg=T.BG1, fg=T.FG0).pack(anchor="w")
        tk.Label(tf, text="Network Packet Capture & Analysis",
                 font=(T.UI, 8), bg=T.BG1, fg=T.FG2).pack(anchor="w")

        # Right chips
        right = tk.Frame(hdr, bg=T.BG1)
        right.pack(side="right", padx=16, pady=10)

        # Clock
        self._clock_lbl = tk.Label(right, text="", font=(T.UI, 10, "bold"),
                                   bg=T.BG1, fg=T.FG1)
        self._clock_lbl.pack(side="right", padx=(8, 0))

        # Live chip
        live_chip = tk.Frame(right, bg=T.BG2, padx=12, pady=5,
                             highlightthickness=1, highlightbackground=T.BDR)
        live_chip.pack(side="right", padx=4)
        self._hdr_dot = PulseDot(live_chip, bg=T.BG2)
        self._hdr_dot.pack(side="left")
        self._hdr_status = tk.Label(live_chip, text="IDLE",
                                    font=(T.UI, 9, "bold"), bg=T.BG2, fg=T.FG2)
        self._hdr_status.pack(side="left", padx=(6, 0))

        # Packet count chip
        cnt_chip = tk.Frame(right, bg=T.BG2, padx=12, pady=5,
                            highlightthickness=1, highlightbackground=T.BDR)
        cnt_chip.pack(side="right", padx=4)
        self._hdr_count = tk.Label(cnt_chip, text="0 packets",
                                   font=(T.UI, 9, "bold"), bg=T.BG2, fg=T.FG1)
        self._hdr_count.pack()

        # Interface chip
        iface_chip = tk.Frame(right, bg=T.BG2, padx=12, pady=5,
                              highlightthickness=1, highlightbackground=T.BDR)
        iface_chip.pack(side="right", padx=4)
        self._iface_val = get_capture_ip()
        tk.Label(iface_chip, text=f"  {self._iface_val}",
                 font=(T.UI, 9), bg=T.BG2, fg=T.FG1).pack()

        Separator(self, orient="horizontal").pack(fill="x")

    # ── TOOLBAR ───────────────────────────────────────────────────
    def _build_toolbar(self):
        bar = tk.Frame(self, bg=T.BG0, height=62)
        bar.pack(fill="x")
        bar.pack_propagate(False)

        # ── RIGHT side first (so it reserves space before left expands) ──
        r = tk.Frame(bar, bg=T.BG0)
        r.pack(side="right", fill="y", padx=10, pady=10)
        ModernButton(r, text="About", icon="◎",
                     command=self._show_about,
                     bg=T.BG3, hover_bg=T.HOVER,
                     width=82, height=42, font_size=9).pack(side="right")
        ModernButton(r, text="Open Log", icon="≡",
                     command=self.open_log_file,
                     bg=T.BG3, hover_bg=T.HOVER,
                     width=96, height=42, font_size=9).pack(side="right", padx=(0, 6))

        # ── LEFT side ────────────────────────────────────────────
        inn = tk.Frame(bar, bg=T.BG0)
        inn.pack(side="left", fill="y", padx=10, pady=10)

        # Start / Stop
        self.btn_start = ModernButton(
            inn, text="Start", icon="▶",
            command=self.start_capture,
            bg=T.OK, hover_bg=T.OK_H, press_bg="#14532D",
            width=108, height=42, font_size=10)
        self.btn_start.pack(side="left", padx=(0, 4))

        self.btn_stop = ModernButton(
            inn, text="Stop", icon="◼",
            command=self.stop_capture,
            bg=T.BG3, hover_bg=T.HOVER,
            width=100, height=42, font_size=10)
        self.btn_stop.pack(side="left", padx=(0, 10))
        self.btn_stop.configure_state("disabled")

        Separator(inn, orient="vertical", height=34).pack(side="left", pady=4)

        # Protocol filter
        tk.Label(inn, text="Proto", font=(T.UI, 9),
                 bg=T.BG0, fg=T.FG2).pack(side="left", padx=(10, 4))
        self.protocol_var = tk.StringVar(value="All")
        ttk.Combobox(
            inn, textvariable=self.protocol_var,
            values=["All", "TCP", "UDP", "ICMP"],
            state="readonly", width=7,
            style="Dark.TCombobox"
        ).pack(side="left", padx=(0, 10))

        Separator(inn, orient="vertical", height=34).pack(side="left", pady=4)

        # Search
        tk.Label(inn, text="⌕", font=(T.UI, 13),
                 bg=T.BG0, fg=T.FG2).pack(side="left", padx=(10, 3))
        self.search_var = tk.StringVar()
        s_wrap = tk.Frame(inn, bg=T.BG2,
                          highlightthickness=1,
                          highlightbackground=T.BDR,
                          highlightcolor=T.ACC)
        s_wrap.pack(side="left", padx=(0, 10))
        self._search_ent = tk.Entry(
            s_wrap, textvariable=self.search_var,
            bg=T.BG2, fg=T.FG0, insertbackground=T.FG0,
            relief="flat", font=(T.UI, 10), width=22, bd=0)
        self._search_ent.pack(pady=7, padx=6)
        self._search_ent.bind("<KeyRelease>", self.apply_search_filter)

        Separator(inn, orient="vertical", height=34).pack(side="left", pady=4)

        # Max packets
        tk.Label(inn, text="Max", font=(T.UI, 9),
                 bg=T.BG0, fg=T.FG2).pack(side="left", padx=(10, 4))
        self.max_packets_var = tk.StringVar(value="0")
        mp_wrap = tk.Frame(inn, bg=T.BG2,
                           highlightthickness=1,
                           highlightbackground=T.BDR)
        mp_wrap.pack(side="left", padx=(0, 10))
        tk.Entry(mp_wrap, textvariable=self.max_packets_var,
                 bg=T.BG2, fg=T.FG0, insertbackground=T.FG0,
                 relief="flat", font=(T.UI, 10), width=6, bd=0
                 ).pack(pady=7, padx=6)

        Separator(inn, orient="vertical", height=34).pack(side="left", pady=4)

        # Quick-action buttons
        for text, icon, cmd, bw in [
            ("Clear",   "⊗", self.clear_view,            80),
            ("Export",  "⇥", self.export_packets_csv,    88),
            ("Save",    "⊞", self.save_selected_details, 76),
        ]:
            ModernButton(inn, text=text, icon=icon, command=cmd,
                         bg=T.BG3, hover_bg=T.HOVER,
                         width=bw, height=42, font_size=9
                         ).pack(side="left", padx=(6, 0))

        Separator(self, orient="horizontal").pack(fill="x")

    # ── BODY ──────────────────────────────────────────────────────
    def _build_body(self):
        body = tk.Frame(self, bg=T.BG0)
        body.pack(fill="both", expand=True)

        self.sidebar = Sidebar(body, on_select=self._nav_select)
        self.sidebar.pack(side="left", fill="y")
        Separator(body, orient="vertical").pack(side="left", fill="y")

        self._content_host = tk.Frame(body, bg=T.BG0)
        self._content_host.pack(side="left", fill="both", expand=True)

        self._pages: dict = {}
        self._current_page = None
        self._build_all_pages(self._content_host)
        self._show_page("Packets")
        self.after(120, lambda: self._vpane.sash_place(0, 0, 560))

    # ── PAGE SWITCHER ─────────────────────────────────────────────
    def _build_all_pages(self, host):
        self._pages["Dashboard"]   = self._build_page_dashboard(host)
        self._pages["Packets"]     = self._build_page_packets(host)
        self._pages["Statistics"]  = self._build_page_statistics(host)
        self._pages["Connections"] = self._build_page_connections(host)
        self._pages["Logs"]        = self._build_page_logs(host)
        self._pages["Export"]      = self._build_page_export(host)
        self._pages["Settings"]    = self._build_page_settings(host)
        self._pages["About"]       = self._build_page_about(host)
        for p in self._pages.values():
            p.pack_forget()

    def _show_page(self, label):
        if self._current_page:
            self._current_page.pack_forget()
        page = self._pages.get(label)
        if page:
            page.pack(fill="both", expand=True)
            self._current_page = page

    # ── PAGE: PACKETS ─────────────────────────────────────────────
    def _build_page_packets(self, host):
        page = tk.Frame(host, bg=T.BG0)

        self._vpane = tk.PanedWindow(page, orient="vertical",
                                     bg=T.BDR, sashwidth=5,
                                     sashrelief="flat", sashpad=0)
        self._vpane.pack(fill="both", expand=True, padx=8, pady=8)

        tbl_frame = tk.Frame(self._vpane, bg=T.BG0)
        self._vpane.add(tbl_frame, minsize=180)
        self.pkt_table = PacketTable(
            tbl_frame,
            on_select=self._on_row_select,
            on_save=self.save_selected_details)
        self.pkt_table.pack(fill="both", expand=True)

        bot_frame = tk.Frame(self._vpane, bg=T.BG0)
        self._vpane.add(bot_frame, minsize=140)

        self._hpane = tk.PanedWindow(bot_frame, orient="horizontal",
                                     bg=T.BDR, sashwidth=5,
                                     sashrelief="flat", sashpad=0)
        self._hpane.pack(fill="both", expand=True)

        det_frame = tk.Frame(self._hpane, bg=T.BG1)
        self._hpane.add(det_frame, minsize=200)
        self.details_panel = DetailsPanel(det_frame)
        self.details_panel.pack(fill="both", expand=True)

        hex_frame = tk.Frame(self._hpane, bg=T.BG0)
        self._hpane.add(hex_frame, minsize=200)
        self.hex_viewer = HexViewer(hex_frame)
        self.hex_viewer.pack(fill="both", expand=True)

        return page

    # ── PAGE: DASHBOARD ───────────────────────────────────────────
    def _build_page_dashboard(self, host):
        page = tk.Frame(host, bg=T.BG0)

        hdr = tk.Frame(page, bg=T.BG0)
        hdr.pack(fill="x", padx=20, pady=(18, 10))
        tk.Label(hdr, text="⬡  Dashboard", font=(T.UI, 16, "bold"),
                 bg=T.BG0, fg=T.FG0).pack(side="left")
        tk.Label(hdr, text="Real-time capture overview",
                 font=(T.UI, 10), bg=T.BG0, fg=T.FG2).pack(side="left", padx=(14, 0), pady=(4, 0))

        # Stat cards
        cards_row = tk.Frame(page, bg=T.BG0)
        cards_row.pack(fill="x", padx=16, pady=(0, 14))
        self._dash_cards = {}
        for key, title, color in [
            ("total", "Total Packets", T.ACC),
            ("tcp",   "TCP Packets",   T.P_TCP),
            ("udp",   "UDP Packets",   T.P_UDP),
            ("icmp",  "ICMP Packets",  T.P_ICMP),
        ]:
            card = tk.Frame(cards_row, bg=T.BG2, padx=22, pady=18)
            card.pack(side="left", fill="both", expand=True, padx=6)
            tk.Label(card, text=title, font=(T.UI, 9), bg=T.BG2, fg=T.FG2).pack(anchor="w")
            val = tk.Label(card, text="0", font=(T.UI, 30, "bold"), bg=T.BG2, fg=color)
            val.pack(anchor="w", pady=(4, 0))
            pct = tk.Label(card, text="—", font=(T.UI, 9), bg=T.BG2, fg=T.FG2)
            pct.pack(anchor="w")
            self._dash_cards[key] = (val, pct)

        # Two-column tables
        cols_frame = tk.Frame(page, bg=T.BG0)
        cols_frame.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        for attr, title in [("_dash_src_tree", "  TOP SOURCE IPs"),
                             ("_dash_dst_tree", "  TOP DESTINATION IPs")]:
            col = tk.Frame(cols_frame, bg=T.BG0)
            col.pack(side="left", fill="both", expand=True, padx=6)
            tk.Label(col, text=title, font=(T.UI, 10, "bold"),
                     bg=T.BG2, fg=T.FG0).pack(fill="x", ipady=6)
            f = tk.Frame(col, bg=T.BG2)
            f.pack(fill="both", expand=True, pady=(1, 0))
            tree = ttk.Treeview(f, columns=("IP Address", "Packets", "Protocol"),
                                show="headings", style="Pkg.Treeview", selectmode="none")
            for c, w in [("IP Address", 200), ("Packets", 80), ("Protocol", 90)]:
                tree.heading(c, text=c)
                tree.column(c, width=w, anchor="w" if c == "IP Address" else "center")
            vsb = ttk.Scrollbar(f, orient="vertical", command=tree.yview,
                                style="Pkg.Vertical.TScrollbar")
            tree.configure(yscrollcommand=vsb.set)
            tree.pack(side="left", fill="both", expand=True)
            vsb.pack(side="right", fill="y")
            setattr(self, attr, tree)

        return page

    def _refresh_dashboard(self):
        total = len(self.packet_history)
        counts = {"TCP": 0, "UDP": 0, "ICMP": 0}
        src_counts, dst_counts = {}, {}
        src_proto,  dst_proto  = {}, {}
        for r in self.packet_history:
            p = r["protocol"]
            if p in counts:
                counts[p] += 1
            s = r.get("src_ip", "")
            d = r.get("dst_ip", "")
            if s:
                src_counts[s] = src_counts.get(s, 0) + 1
                src_proto[s]  = p
            if d:
                dst_counts[d] = dst_counts.get(d, 0) + 1
                dst_proto[d]  = p

        def pct(n):
            return f"{n / total * 100:.1f}%" if total else "—"

        self._dash_cards["total"][0].configure(text=f"{total:,}")
        self._dash_cards["total"][1].configure(text="packets captured")
        for key in ("tcp", "udp", "icmp"):
            n = counts[key.upper()]
            self._dash_cards[key][0].configure(text=f"{n:,}")
            self._dash_cards[key][1].configure(text=pct(n))

        self._dash_src_tree.delete(*self._dash_src_tree.get_children())
        for ip, cnt in sorted(src_counts.items(), key=lambda x: -x[1])[:12]:
            self._dash_src_tree.insert("", "end",
                values=(ip, cnt, src_proto.get(ip, "")),
                tags=(src_proto.get(ip, ""),))

        self._dash_dst_tree.delete(*self._dash_dst_tree.get_children())
        for ip, cnt in sorted(dst_counts.items(), key=lambda x: -x[1])[:12]:
            self._dash_dst_tree.insert("", "end",
                values=(ip, cnt, dst_proto.get(ip, "")),
                tags=(dst_proto.get(ip, ""),))

    # ── PAGE: STATISTICS ──────────────────────────────────────────
    def _build_page_statistics(self, host):
        page = tk.Frame(host, bg=T.BG0)

        hdr = tk.Frame(page, bg=T.BG0)
        hdr.pack(fill="x", padx=20, pady=(18, 12))
        tk.Label(hdr, text="▤  Statistics", font=(T.UI, 16, "bold"),
                 bg=T.BG0, fg=T.FG0).pack(side="left")
        ModernButton(hdr, text="Refresh", icon="↺",
                     command=self._refresh_statistics,
                     bg=T.ACC, hover_bg=T.ACC_H,
                     width=100, height=34, font_size=9).pack(side="right")

        f = tk.Frame(page, bg=T.BG0)
        f.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        cols = ("Protocol", "Packets", "Percentage", "Avg Length", "Total Bytes")
        self._stats_tree = ttk.Treeview(f, columns=cols, show="headings",
                                        style="Pkg.Treeview")
        widths = {"Protocol": 130, "Packets": 110, "Percentage": 150,
                  "Avg Length": 150, "Total Bytes": 150}
        for c in cols:
            self._stats_tree.heading(c, text=c)
            self._stats_tree.column(c, width=widths[c], anchor="center")

        vsb = ttk.Scrollbar(f, orient="vertical", command=self._stats_tree.yview,
                            style="Pkg.Vertical.TScrollbar")
        self._stats_tree.configure(yscrollcommand=vsb.set)
        self._stats_tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        return page

    def _refresh_statistics(self):
        self._stats_tree.delete(*self._stats_tree.get_children())
        total = len(self.packet_history)
        proto_data: dict = {}
        for r in self.packet_history:
            p = r["protocol"]
            ln = r.get("length", 0) or 0
            if p not in proto_data:
                proto_data[p] = {"count": 0, "total": 0}
            proto_data[p]["count"] += 1
            proto_data[p]["total"] += ln
        for proto, d in sorted(proto_data.items(), key=lambda x: -x[1]["count"]):
            cnt  = d["count"]
            tot  = d["total"]
            avg  = int(tot / cnt) if cnt else 0
            pct  = f"{cnt / total * 100:.1f}%" if total else "0%"
            self._stats_tree.insert("", "end", tags=(proto,),
                values=(proto, f"{cnt:,}", pct, f"{avg} B", f"{tot:,} B"))

    # ── PAGE: CONNECTIONS ─────────────────────────────────────────
    def _build_page_connections(self, host):
        page = tk.Frame(host, bg=T.BG0)

        hdr = tk.Frame(page, bg=T.BG0)
        hdr.pack(fill="x", padx=20, pady=(18, 12))
        tk.Label(hdr, text="⊙  Connections", font=(T.UI, 16, "bold"),
                 bg=T.BG0, fg=T.FG0).pack(side="left")
        ModernButton(hdr, text="Refresh", icon="↺",
                     command=self._refresh_connections,
                     bg=T.ACC, hover_bg=T.ACC_H,
                     width=100, height=34, font_size=9).pack(side="right")

        f = tk.Frame(page, bg=T.BG0)
        f.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        cols = ("Source IP", "Dest IP", "Protocol", "Src Port", "Dst Port", "Packets")
        self._conn_tree = ttk.Treeview(f, columns=cols, show="headings",
                                       style="Pkg.Treeview")
        widths = {"Source IP": 180, "Dest IP": 180, "Protocol": 100,
                  "Src Port": 90, "Dst Port": 90, "Packets": 80}
        for c in cols:
            self._conn_tree.heading(c, text=c)
            self._conn_tree.column(c, width=widths[c], anchor="center")

        vsb = ttk.Scrollbar(f, orient="vertical", command=self._conn_tree.yview,
                            style="Pkg.Vertical.TScrollbar")
        self._conn_tree.configure(yscrollcommand=vsb.set)
        self._conn_tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        return page

    def _refresh_connections(self):
        self._conn_tree.delete(*self._conn_tree.get_children())
        conns: dict = {}
        for r in self.packet_history:
            key = (r.get("src_ip", ""), r.get("dst_ip", ""), r["protocol"],
                   r.get("src_port", ""), r.get("dst_port", ""))
            conns[key] = conns.get(key, 0) + 1
        for (src, dst, proto, sp, dp), cnt in sorted(conns.items(), key=lambda x: -x[1])[:300]:
            self._conn_tree.insert("", "end", tags=(proto,),
                                   values=(src, dst, proto, sp, dp, cnt))

    # ── PAGE: LOGS ────────────────────────────────────────────────
    def _build_page_logs(self, host):
        page = tk.Frame(host, bg=T.BG0)

        hdr = tk.Frame(page, bg=T.BG0)
        hdr.pack(fill="x", padx=20, pady=(18, 8))
        tk.Label(hdr, text="≡  Logs", font=(T.UI, 16, "bold"),
                 bg=T.BG0, fg=T.FG0).pack(side="left")
        ModernButton(hdr, text="Open File", icon="⊟",
                     command=self.open_log_file,
                     bg=T.BG3, hover_bg=T.HOVER,
                     width=108, height=34, font_size=9).pack(side="right")
        ModernButton(hdr, text="Refresh", icon="↺",
                     command=self._refresh_logs,
                     bg=T.ACC, hover_bg=T.ACC_H,
                     width=100, height=34, font_size=9).pack(side="right", padx=(0, 6))

        txt_frame = tk.Frame(page, bg=T.BG0)
        txt_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        self._log_text = tk.Text(txt_frame, wrap="none", bg=T.BG1, fg="#86EFAC",
                                 insertbackground=T.FG0, relief="flat",
                                 font=(T.MONO, 10), padx=14, pady=10,
                                 state="disabled")
        vsb = ttk.Scrollbar(txt_frame, orient="vertical",
                            command=self._log_text.yview,
                            style="Pkg.Vertical.TScrollbar")
        hsb = ttk.Scrollbar(txt_frame, orient="horizontal",
                            command=self._log_text.xview,
                            style="Pkg.Horizontal.TScrollbar")
        self._log_text.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self._log_text.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        txt_frame.grid_rowconfigure(0, weight=1)
        txt_frame.grid_columnconfigure(0, weight=1)
        return page

    def _refresh_logs(self):
        self._log_text.configure(state="normal")
        self._log_text.delete("1.0", "end")
        if os.path.exists(LOG_FILE):
            try:
                with open(LOG_FILE, "r", encoding="utf-8") as f:
                    self._log_text.insert("end", f.read())
                self._log_text.see("end")
            except Exception as e:
                self._log_text.insert("end", f"Error reading log: {e}")
        else:
            self._log_text.insert("end", "No log file found yet. Start a capture first.")
        self._log_text.configure(state="disabled")

    # ── PAGE: EXPORT ──────────────────────────────────────────────
    def _build_page_export(self, host):
        page = tk.Frame(host, bg=T.BG0)

        # Header
        hdr = tk.Frame(page, bg=T.BG0)
        hdr.pack(fill="x", padx=24, pady=(18, 12))
        tk.Label(hdr, text="⇥  Export", font=(T.UI, 15, "bold"),
                 bg=T.BG0, fg=T.FG0).pack(side="left")
        tk.Label(hdr, text="Save captured packets in multiple formats",
                 font=(T.UI, 9), bg=T.BG0, fg=T.FG2).pack(side="left", padx=(14, 0), pady=(3, 0))

        export_items = [
            ("CSV Spreadsheet", "↗",
             "Compatible with Excel & Google Sheets  ·  All packet fields included",
             ".csv", self.export_packets_csv, T.OK),
            ("JSON Data", "{ }",
             "Structured JSON array  ·  Ideal for scripting and APIs",
             ".json", self.export_packets_json, T.ACC),
            ("Packet Details  (TXT)", "≡",
             "Human-readable text report of the currently selected packet",
             ".txt", self.save_selected_details, T.WARN),
            ("Live Capture Log", "⊟",
             "Open the auto-generated capture log in your default text editor",
             ".txt", self.open_log_file, T.P_UDP),
        ]

        for title, icon, desc, ext, cmd, color in export_items:
            row = tk.Frame(page, bg=T.BG2)
            row.pack(fill="x", padx=24, pady=5)

            # Color accent bar on left
            tk.Frame(row, bg=color, width=4).pack(side="left", fill="y")

            # Icon
            tk.Label(row, text=icon, font=(T.UI, 18), bg=T.BG2,
                     fg=color, width=4).pack(side="left", padx=(10, 0), pady=16)

            # Text block
            txt = tk.Frame(row, bg=T.BG2)
            txt.pack(side="left", fill="both", expand=True, padx=(6, 16), pady=14)
            tk.Label(txt, text=title, font=(T.UI, 11, "bold"),
                     bg=T.BG2, fg=T.FG0, anchor="w").pack(fill="x")
            tk.Label(txt, text=desc, font=(T.UI, 9),
                     bg=T.BG2, fg=T.FG2, anchor="w").pack(fill="x", pady=(2, 0))
            tk.Label(txt, text=f"Format: {ext}", font=(T.UI, 8),
                     bg=T.BG2, fg=T.FG2, anchor="w").pack(fill="x", pady=(2, 0))

            # Button
            btn_wrap = tk.Frame(row, bg=T.BG2)
            btn_wrap.pack(side="right", padx=18, pady=14)
            ModernButton(btn_wrap, text=f"Export {ext.upper()}", command=cmd,
                         bg=color, hover_bg=color,
                         width=130, height=36, font_size=9).pack()

        return page

    # ── PAGE: SETTINGS ────────────────────────────────────────────
    def _build_page_settings(self, host):
        page = tk.Frame(host, bg=T.BG0)

        hdr = tk.Frame(page, bg=T.BG0)
        hdr.pack(fill="x", padx=20, pady=(18, 8))
        tk.Label(hdr, text="⚙  Settings", font=(T.UI, 16, "bold"),
                 bg=T.BG0, fg=T.FG0).pack(side="left")

        def section_lbl(text):
            tk.Label(page, text=f"  {text}", font=(T.UI, 9, "bold"),
                     bg=T.BG2, fg=T.FG2).pack(fill="x", padx=20, pady=(12, 0), ipady=5)

        def row(label, widget_fn):
            r = tk.Frame(page, bg=T.BG0)
            r.pack(fill="x", padx=28, pady=5)
            tk.Label(r, text=label, font=(T.UI, 10), bg=T.BG0,
                     fg=T.FG0, width=32, anchor="w").pack(side="left")
            widget_fn(r)

        section_lbl("CAPTURE DEFAULTS")

        def proto_w(r):
            ttk.Combobox(r, textvariable=self.protocol_var,
                         values=["All", "TCP", "UDP", "ICMP"],
                         state="readonly", width=12,
                         style="Dark.TCombobox").pack(side="left")
        row("Default Protocol Filter", proto_w)

        def maxpkt_w(r):
            f = tk.Frame(r, bg=T.BG2, padx=6,
                         highlightthickness=1, highlightbackground=T.BDR)
            f.pack(side="left")
            tk.Entry(f, textvariable=self.max_packets_var,
                     bg=T.BG2, fg=T.FG0, insertbackground=T.FG0,
                     relief="flat", font=(T.UI, 10), width=10, bd=0
                     ).pack(pady=6, padx=2)
        row("Max Packets  (0 = unlimited)", maxpkt_w)

        section_lbl("APPEARANCE")

        def theme_w(r):
            tk.Label(r, text="Dark  (only theme)", font=(T.UI, 10),
                     bg=T.BG0, fg=T.FG2).pack(side="left")
        row("Theme", theme_w)

        def font_w(r):
            tk.Label(r, text="Segoe UI  /  Consolas", font=(T.UI, 10),
                     bg=T.BG0, fg=T.FG2).pack(side="left")
        row("Font Family", font_w)

        section_lbl("APPLICATION INFO")

        for lbl, val in [("Version", "NetSniffer Pro  v2.0"),
                         ("Author",  "Muhammad Zakria"),
                         ("Project", "Personal Cybersecurity Tool")]:
            def make_w(v=val):
                def w(r):
                    tk.Label(r, text=v, font=(T.UI, 10), bg=T.BG0, fg=T.FG2).pack(side="left")
                return w
            row(lbl, make_w())

        return page

    # ── PAGE: ABOUT ───────────────────────────────────────────────
    def _build_page_about(self, host):
        page = tk.Frame(host, bg=T.BG0)

        wrap = tk.Frame(page, bg=T.BG0)
        wrap.place(relx=0.5, rely=0.5, anchor="center")

        # Logo + title
        hdr = tk.Frame(wrap, bg=T.BG2, padx=60, pady=18)
        hdr.pack(fill="x", pady=(0, 2))
        tk.Label(hdr, text="⬡", font=(T.UI, 36), bg=T.BG2, fg=T.ACC).pack()
        tk.Label(hdr, text="NetSniffer Pro",
                 font=(T.UI, 20, "bold"), bg=T.BG2, fg=T.FG0).pack(pady=(2, 0))
        tk.Label(hdr, text="v2.0  ·  Network Packet Capture & Analysis",
                 font=(T.UI, 9), bg=T.BG2, fg=T.FG2).pack(pady=(3, 0))

        # Author
        auth = tk.Frame(wrap, bg=T.BG3, padx=60, pady=12)
        auth.pack(fill="x", pady=2)
        tk.Label(auth, text="Muhammad Zakria",
                 font=(T.UI, 12, "bold"), bg=T.BG3, fg=T.FG0).pack()
        tk.Label(auth, text="Personal Cybersecurity Project",
                 font=(T.UI, 9), bg=T.BG3, fg=T.FG2).pack(pady=(2, 0))

        # Features
        feat = tk.Frame(wrap, bg=T.BG2, padx=40, pady=12)
        feat.pack(fill="x", pady=2)
        for line in [
            "Live packet capture  ·  TCP / UDP / ICMP parsing",
            "Real-time search  ·  Protocol filter  ·  Packet limit",
            "Wireshark hex dump  ·  Structured packet details",
            "CSV & JSON export  ·  Auto log  ·  Admin launcher",
        ]:
            tk.Label(feat, text=line, font=(T.UI, 9),
                     bg=T.BG2, fg=T.FG2).pack(pady=2)

        return page

    # ── STATUS BAR ────────────────────────────────────────────────
    def _build_statusbar(self):
        Separator(self, orient="horizontal").pack(fill="x", side="bottom")
        sb = tk.Frame(self, bg=T.BG1, height=26)
        sb.pack(fill="x", side="bottom")
        sb.pack_propagate(False)

        def item(text, fg=T.FG2):
            lbl = tk.Label(sb, text=text, font=(T.UI, 8),
                           bg=T.BG1, fg=fg)
            lbl.pack(side="left", padx=10, pady=4)
            return lbl

        def sep():
            tk.Frame(sb, bg=T.BDR, width=1, height=14).pack(side="left", pady=6)

        self._sb_state    = item("○  Ready")
        sep()
        self._sb_iface    = item(f"  {self._iface_val}")
        sep()
        self._sb_captured = item("Captured: 0")
        sep()
        self._sb_disp     = item("Displayed: 0")
        sep()
        self._sb_dur      = item("Duration: —")

        tk.Label(sb, text="NetSniffer Pro  v2.0  ·  Muhammad Zakria",
                 font=(T.UI, 8), bg=T.BG1, fg=T.FG2).pack(side="right", padx=12)

    # ── TIMERS ────────────────────────────────────────────────────
    def _tick_clock(self):
        self._clock_lbl.configure(text=datetime.datetime.now().strftime("%H:%M:%S"))
        self.after(1000, self._tick_clock)

    def _tick_duration(self):
        if self.capturing and self._capture_start:
            e = int(time.time() - self._capture_start)
            h, r = divmod(e, 3600)
            mn, s = divmod(r, 60)
            self._sb_dur.configure(text=f"Duration: {h:02d}:{mn:02d}:{s:02d}")
        elif not self.capturing and self._capture_start is None:
            self._sb_dur.configure(text="Duration: —")
        self.after(1000, self._tick_duration)

    # ── EVENT HANDLERS ────────────────────────────────────────────
    def _nav_select(self, label):
        self._show_page(label)
        if label == "Dashboard":
            self._refresh_dashboard()
        elif label == "Statistics":
            self._refresh_statistics()
        elif label == "Connections":
            self._refresh_connections()
        elif label == "Logs":
            self._refresh_logs()

    def _on_row_select(self, iid):
        record = self.row_records.get(iid)
        if record:
            self.details_panel.set_text(record["details"])
            self.hex_viewer.set_data(record["payload_hex"], record.get("raw_bytes", b""))

    def set_status(self, msg):
        self._sb_state.configure(text=f"  {msg}")

    def _set_capturing_ui(self, live):
        if live:
            self.btn_start.configure_state("disabled")
            self.btn_stop.configure_state("normal")
            self.btn_stop.set_colors(T.ERR, T.ERR_H)
            self._hdr_dot.start()
            self._hdr_status.configure(text="LIVE", fg=T.OK)
            self.sidebar.update_status(True, 0, self._iface_val)
            self._sb_state.configure(text="  ●  Capturing", fg=T.OK)
        else:
            self.btn_start.configure_state("normal")
            self.btn_stop.configure_state("disabled")
            self.btn_stop.set_colors(T.BG3, T.HOVER)
            self._hdr_dot.stop()
            self._hdr_status.configure(text="IDLE", fg=T.FG2)
            self.sidebar.update_status(False, self.packet_count, self._iface_val)
            self._sb_state.configure(text=f"  ○  Stopped  ({self.packet_count:,} packets)", fg=T.FG2)

    def start_capture(self):
        if self.capturing:
            return
        try:
            max_pkts = int(self.max_packets_var.get().strip() or "0")
            if max_pkts < 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid value", "Max packets must be 0 or a positive integer.")
            return

        filt = self.protocol_var.get().strip().upper()
        if filt == "ALL":
            filt = None

        self.stop_event.clear()
        self.packet_queue = queue.Queue()
        self.worker = CaptureWorker(self.packet_queue, self.stop_event,
                                    protocol_filter=filt, max_packets=max_pkts)
        self.worker.start()
        self.capturing      = True
        self._capture_start = time.time()
        self._set_capturing_ui(True)
        self.set_status("Capturing packets in real time…")

    def stop_capture(self):
        if not self.capturing:
            return
        self.stop_event.set()
        self.capturing = False
        self._set_capturing_ui(False)
        self.set_status(f"Capture stopped — {self.packet_count:,} packets total.")

    def clear_view(self):
        self.pkt_table.clear()
        self.row_records.clear()
        self.packet_history.clear()
        self.packet_count = 0
        self.details_panel.clear()
        self.hex_viewer.clear()
        self._hdr_count.configure(text="0 packets")
        self._sb_captured.configure(text="Captured: 0")
        self._sb_disp.configure(text="Displayed: 0")
        self.set_status("View cleared.")

    def open_log_file(self):
        if not os.path.exists(LOG_FILE):
            messagebox.showinfo("Not found", f"{LOG_FILE} does not exist yet.")
            return
        try:
            if hasattr(os, "startfile"):
                os.startfile(os.path.abspath(LOG_FILE))
            else:
                subprocess.Popen(["xdg-open", os.path.abspath(LOG_FILE)])
        except Exception as exc:
            messagebox.showerror("Open failed", str(exc))

    def export_packets_csv(self):
        if not self.packet_history:
            messagebox.showinfo("Nothing to export", "No packets captured yet.")
            return
        path = filedialog.asksaveasfilename(
            title="Export as CSV", defaultextension=".csv",
            filetypes=(("CSV files", "*.csv"), ("All files", "*.*")),
            initialfile="network_packets.csv")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["#", "Timestamp", "Protocol", "Source IP", "Dest IP",
                             "Src Port", "Dst Port", "Length", "Summary", "Preview"])
                for r in self.packet_history:
                    w.writerow([r["count"], r["timestamp"], r["protocol"],
                                r.get("src_ip", ""), r.get("dst_ip", ""),
                                r.get("src_port", ""), r.get("dst_port", ""),
                                r.get("length", ""), r["summary"], r["preview"]])
            self.set_status(f"Exported {len(self.packet_history):,} packets → CSV.")
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc))

    def export_packets_json(self):
        if not self.packet_history:
            messagebox.showinfo("Nothing to export", "No packets captured yet.")
            return
        path = filedialog.asksaveasfilename(
            title="Export as JSON", defaultextension=".json",
            filetypes=(("JSON files", "*.json"), ("All files", "*.*")),
            initialfile="network_packets.json")
        if not path:
            return
        try:
            out = [{
                "count": r["count"], "timestamp": r["timestamp"],
                "protocol": r["protocol"],
                "source_ip": r.get("src_ip", ""), "dest_ip": r.get("dst_ip", ""),
                "src_port": r.get("src_port", ""), "dst_port": r.get("dst_port", ""),
                "length": r.get("length", ""),
                "summary": r["summary"], "preview": r["preview"],
                "hex": r.get("payload_hex", ""),
            } for r in self.packet_history]
            with open(path, "w", encoding="utf-8") as f:
                json.dump(out, f, indent=2)
            self.set_status(f"Exported {len(self.packet_history):,} packets → JSON.")
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc))

    def save_selected_details(self):
        rec = self._selected_record()
        if not rec:
            messagebox.showinfo("No selection", "Select a packet first.")
            return
        path = filedialog.asksaveasfilename(
            title="Save packet details", defaultextension=".txt",
            filetypes=(("Text files", "*.txt"), ("All files", "*.*")),
            initialfile=f"packet_{rec['count']}_details.txt")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(rec["details"] + "\n\n")
                f.write(f"Source:      {rec['source']}\n")
                f.write(f"Destination: {rec['destination']}\n")
                f.write(f"Summary:     {rec['summary']}\n")
                f.write(f"Preview:     {rec['preview']}\n")
                if rec.get("payload_hex"):
                    f.write(f"\nHex Dump:\n{rec['payload_hex']}\n")
            self.set_status(f"Saved packet #{rec['count']} details.")
        except OSError as exc:
            messagebox.showerror("Save failed", str(exc))

    def _selected_record(self):
        iid = self.pkt_table.selected_iid()
        return self.row_records.get(iid) if iid else None

    def _matches_search(self, record):
        q = self.search_var.get().strip().lower()
        if not q:
            return True
        hay = " ".join([
            str(record.get("count", "")),
            record.get("timestamp", ""),
            record.get("protocol", ""),
            record.get("source", ""),
            record.get("destination", ""),
            record.get("src_ip", ""),
            record.get("dst_ip", ""),
            str(record.get("src_port", "")),
            str(record.get("dst_port", "")),
            record.get("summary", ""),
            record.get("details", ""),
            record.get("preview", ""),
            record.get("payload_hex", ""),
        ]).lower()
        return q in hay

    def _insert_record_row(self, record):
        iid = self.pkt_table.insert_record(record)
        self.row_records[iid] = record
        return iid

    def _refresh_tree(self):
        self.pkt_table.clear()
        self.row_records.clear()
        for r in self.packet_history:
            if self._matches_search(r):
                self._insert_record_row(r)
        self._sb_disp.configure(text=f"Displayed: {self.pkt_table.count():,}")

    def apply_search_filter(self, _=None):
        self._refresh_tree()
        self.set_status(f"Filter applied — {self.pkt_table.count():,} packets visible.")

    # ── QUEUE PROCESSOR ───────────────────────────────────────────
    def _poll_queue(self):
        try:
            while True:
                ev = self.packet_queue.get_nowait()
                t  = ev.get("type")
                if t == "packet":
                    self._insert_packet(ev["record"])
                elif t == "status":
                    self.set_status(ev["message"])
                elif t == "error":
                    self.set_status("Capture error")
                    messagebox.showerror("Capture Error", ev["message"])
                    self.stop_capture()
                elif t == "stopped":
                    if self.capturing:
                        self.stop_capture()
        except queue.Empty:
            pass
        self.after(100, self._poll_queue)

    def _insert_packet(self, record):
        self.packet_count = record["count"]
        self.packet_history.append(record)

        if self._matches_search(record):
            iid = self._insert_record_row(record)
            self.pkt_table.tree.see(iid)
            self.pkt_table.tree.selection_set(iid)
            self.pkt_table.tree.focus(iid)
            self.details_panel.set_text(record["details"])
            self.hex_viewer.set_data(record["payload_hex"], record.get("raw_bytes", b""))

        self._hdr_count.configure(text=f"{self.packet_count:,} packets")
        self.sidebar.update_status(True, self.packet_count)
        self._sb_captured.configure(text=f"Captured: {self.packet_count:,}")
        self._sb_disp.configure(text=f"Displayed: {self.pkt_table.count():,}")
        self.set_status(f"  {record['protocol']}  packet #{self.packet_count:,}")

    # ── ABOUT ─────────────────────────────────────────────────────
    def _show_about(self):
        win = tk.Toplevel(self)
        win.title("About NetSniffer Pro")
        win.configure(bg=T.BG1)
        win.geometry("500x380")
        win.resizable(False, False)
        win.transient(self)
        win.grab_set()

        # Icon + name
        top = tk.Frame(win, bg=T.BG1)
        top.pack(fill="x", padx=40, pady=(28, 0))
        tk.Label(top, text="⬡", font=(T.UI, 42), bg=T.BG1, fg=T.ACC).pack(side="left")
        titles = tk.Frame(top, bg=T.BG1)
        titles.pack(side="left", padx=(16, 0), pady=6)
        tk.Label(titles, text="NetSniffer Pro",
                 font=(T.UI, 20, "bold"), bg=T.BG1, fg=T.FG0).pack(anchor="w")
        tk.Label(titles, text="Network Packet Capture & Analysis  —  v2.0",
                 font=(T.UI, 9), bg=T.BG1, fg=T.FG2).pack(anchor="w", pady=(2, 0))

        Separator(win, orient="horizontal").pack(fill="x", padx=30, pady=(20, 0))

        # Author row
        info = tk.Frame(win, bg=T.BG1)
        info.pack(fill="x", padx=40, pady=(14, 0))
        tk.Label(info, text="Author", font=(T.UI, 9), bg=T.BG1,
                 fg=T.FG2, width=12, anchor="w").grid(row=0, column=0, sticky="w")
        tk.Label(info, text="Muhammad Zakria", font=(T.UI, 9, "bold"),
                 bg=T.BG1, fg=T.FG0).grid(row=0, column=1, sticky="w")
        tk.Label(info, text="Project", font=(T.UI, 9), bg=T.BG1,
                 fg=T.FG2, width=12, anchor="w").grid(row=1, column=0, sticky="w", pady=(4, 0))
        tk.Label(info, text="Personal Cybersecurity Tool", font=(T.UI, 9),
                 bg=T.BG1, fg=T.FG1).grid(row=1, column=1, sticky="w", pady=(4, 0))

        Separator(win, orient="horizontal").pack(fill="x", padx=30, pady=(18, 0))

        # Features
        feat = tk.Frame(win, bg=T.BG1)
        feat.pack(fill="x", padx=40, pady=(14, 0))
        tk.Label(feat, text="Features", font=(T.UI, 9, "bold"),
                 bg=T.BG1, fg=T.FG2).pack(anchor="w", pady=(0, 6))
        for line in [
            "Live raw packet capture  ·  TCP / UDP / ICMP parsing",
            "Real-time search & protocol filter  ·  Max packet limit",
            "Wireshark-style hex dump  ·  Structured packet details",
            "CSV & JSON export  ·  Auto log file  ·  Admin-aware launch",
        ]:
            tk.Label(feat, text=line, font=(T.UI, 9),
                     bg=T.BG1, fg=T.FG2).pack(anchor="w", pady=1)

        tk.Frame(win, bg=T.BG1).pack(expand=True)
        ModernButton(win, text="Close", command=win.destroy,
                     bg=T.ACC, hover_bg=T.ACC_H,
                     width=100, height=36).pack(pady=(0, 22))

    def on_close(self):
        self.stop_capture()
        self.after(150, self.destroy)


# ═══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════
def _is_admin() -> bool:
    """Return True if the process has administrator / root privileges."""
    try:
        if os.name == "nt":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def _relaunch_as_admin():
    """Re-launch the current script elevated (Windows UAC prompt)."""
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(sys.argv), None, 1
    )


def main():
    if not _is_admin():
        # Show a GUI prompt so the user knows what to do
        _root = tk.Tk()
        _root.withdraw()
        answer = messagebox.askyesno(
            title="Administrator Privileges Required",
            message=(
                "NetSniffer Pro needs Administrator privileges to capture raw network packets.\n\n"
                "Windows blocks raw socket access for normal users.\n\n"
                "Click  YES  to relaunch as Administrator (UAC prompt will appear).\n"
                "Click  NO   to exit."
            ),
            icon="warning",
        )
        _root.destroy()
        if answer:
            _relaunch_as_admin()
        sys.exit(0)

    app = NetworkSnifferGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
