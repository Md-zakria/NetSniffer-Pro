"""Packet details panel with collapsible sections."""

from __future__ import annotations

import customtkinter as ctk

from themes import colors


class PacketDetailsPanel(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color=colors.CARDS, corner_radius=18)
        self._labels: dict[str, ctk.CTkLabel] = {}
        self._build()

    def _build(self) -> None:
        ctk.CTkLabel(self, text="Packet Details", font=("Segoe UI Variable", 18, "bold")).pack(anchor="w", padx=16, pady=(16, 6))
        self.container = ctk.CTkScrollableFrame(self, fg_color=colors.PANELS, corner_radius=16)
        self.container.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        for section in ["Ethernet", "IPv4", "TCP", "UDP", "ICMP", "ARP", "Payload", "Checksum", "Flags", "Options"]:
            card = ctk.CTkFrame(self.container, fg_color=colors.CARDS, corner_radius=14)
            card.pack(fill="x", pady=6)
            ctk.CTkLabel(card, text=section, font=("Segoe UI Variable", 14, "bold")).pack(anchor="w", padx=14, pady=(10, 2))
            label = ctk.CTkLabel(card, text="Waiting for packet selection...", justify="left", wraplength=560, text_color=colors.SECONDARY_TEXT)
            label.pack(anchor="w", padx=14, pady=(0, 12))
            self._labels[section] = label

    def set_record(self, record: dict[str, object]) -> None:
        eth = record.get("eth", {})
        ip = record.get("ip", {})
        transport = record.get("transport", {})
        self._labels["Ethernet"].configure(text=f"Source MAC: {eth.get('src_mac', '')}\nDestination MAC: {eth.get('dest_mac', '')}\nProtocol: {eth.get('proto', '')}")
        self._labels["IPv4"].configure(text=f"Source: {ip.get('src', '')}\nDestination: {ip.get('dest', '')}\nTTL: {ip.get('ttl', '')}\nIHL: {ip.get('ihl', '')}")
        self._labels["TCP"].configure(text=str(transport) if record.get("protocol") == "TCP" else "No TCP fields")
        self._labels["UDP"].configure(text=str(transport) if record.get("protocol") == "UDP" else "No UDP fields")
        self._labels["ICMP"].configure(text=str(transport) if record.get("protocol") == "ICMP" else "No ICMP fields")
        self._labels["ARP"].configure(text="ARP details are surfaced when available.")
        self._labels["Payload"].configure(text=record.get("preview", ""))
        self._labels["Checksum"].configure(text=f"Checksum: {transport.get('checksum', 'N/A')}")
        self._labels["Flags"].configure(text=str(transport.get("flags", {})))
        self._labels["Options"].configure(text="TCP/IP options are displayed here when parsed.")

    def clear(self) -> None:
        for label in self._labels.values():
            label.configure(text="Waiting for packet selection...")
