"""Sidebar navigation used by the application shell."""

from __future__ import annotations

import customtkinter as ctk

from themes import colors


class Sidebar(ctk.CTkFrame):
    def __init__(self, master, on_navigation):
        super().__init__(master, width=260, fg_color=colors.CARDS, corner_radius=0)
        self.on_navigation = on_navigation
        self.grid_propagate(False)
        self._build()

    def _build(self) -> None:
        title = ctk.CTkLabel(self, text="Network Sniffer", text_color=colors.TEXT, font=("Segoe UI Variable", 24, "bold"))
        subtitle = ctk.CTkLabel(self, text="Enterprise Traffic Analyzer", text_color=colors.SECONDARY_TEXT, font=("Segoe UI Variable", 12))
        title.pack(anchor="w", padx=20, pady=(24, 4))
        subtitle.pack(anchor="w", padx=20, pady=(0, 18))

        self.buttons: list[ctk.CTkButton] = []
        items = [
            ("Dashboard", "Dashboard"),
            ("Packets", "Packets"),
            ("Connections", "Connections"),
            ("Statistics", "Statistics"),
            ("Live Monitor", "Live Monitor"),
            ("Export", "Export"),
            ("Logs", "Logs"),
            ("Settings", "Settings"),
            ("About", "About"),
        ]

        for label, destination in items:
            button = ctk.CTkButton(
                self,
                text=label,
                height=42,
                fg_color="transparent",
                hover_color=colors.PANELS,
                text_color=colors.TEXT,
                anchor="w",
                corner_radius=12,
                command=lambda dest=destination: self.on_navigation(dest),
            )
            button.pack(fill="x", padx=14, pady=4)
            self.buttons.append(button)

        self.status_card = ctk.CTkFrame(self, fg_color=colors.PANELS, corner_radius=16)
        self.status_card.pack(fill="x", padx=16, pady=(24, 16), side="bottom")
        ctk.CTkLabel(self.status_card, text="Capture Status", font=("Segoe UI Variable", 14, "bold")).pack(anchor="w", padx=16, pady=(14, 4))
        self.live_label = ctk.CTkLabel(self.status_card, text="Live", text_color=colors.SUCCESS)
        self.live_label.pack(anchor="w", padx=16)
        self.runtime_label = ctk.CTkLabel(self.status_card, text="Runtime: 00:00:00", text_color=colors.SECONDARY_TEXT)
        self.runtime_label.pack(anchor="w", padx=16, pady=(4, 0))
        self.cpu_label = ctk.CTkLabel(self.status_card, text="CPU: 0%", text_color=colors.SECONDARY_TEXT)
        self.cpu_label.pack(anchor="w", padx=16, pady=(4, 0))
        self.ram_label = ctk.CTkLabel(self.status_card, text="RAM: 0%", text_color=colors.SECONDARY_TEXT)
        self.ram_label.pack(anchor="w", padx=16, pady=(4, 14))
