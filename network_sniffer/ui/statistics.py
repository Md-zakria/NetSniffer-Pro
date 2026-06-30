"""Real-time statistics panel for packet telemetry."""

from __future__ import annotations

from collections import Counter

import customtkinter as ctk

from themes import colors


class StatisticsPanel(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color=colors.CARDS, corner_radius=18)
        self.counts = Counter()
        self._build()

    def _build(self) -> None:
        ctk.CTkLabel(self, text="Live Statistics", font=("Segoe UI Variable", 18, "bold")).pack(anchor="w", padx=16, pady=(16, 8))
        self.body = ctk.CTkScrollableFrame(self, fg_color=colors.PANELS, corner_radius=16)
        self.body.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        self.total_label = ctk.CTkLabel(self.body, text="Packets Captured: 0", text_color=colors.TEXT)
        self.total_label.pack(anchor="w", padx=14, pady=(12, 4))
        self.protocol_label = ctk.CTkLabel(self.body, text="Top Protocols: -", text_color=colors.SECONDARY_TEXT)
        self.protocol_label.pack(anchor="w", padx=14, pady=(4, 12))

    def ingest(self, record: dict[str, object]) -> None:
        self.counts[record.get("protocol", "Unknown")] += 1
        self.total_label.configure(text=f"Packets Captured: {sum(self.counts.values())}")
        self.protocol_label.configure(text=f"Top Protocols: {dict(self.counts.most_common(5))}")

    def reset(self) -> None:
        self.counts.clear()
        self.total_label.configure(text="Packets Captured: 0")
        self.protocol_label.configure(text="Top Protocols: -")
