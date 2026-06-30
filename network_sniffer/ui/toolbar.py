"""Top action toolbar for capture control and search."""

from __future__ import annotations

import customtkinter as ctk

from themes import colors


class Toolbar(ctk.CTkFrame):
    def __init__(self, master, actions):
        super().__init__(master, fg_color=colors.PANELS, corner_radius=0, height=72)
        self.actions = actions
        self._search_text = ctk.StringVar(value="")
        self._protocol = ctk.StringVar(value="All")
        self._max_packets = ctk.StringVar(value="0")
        self.search_entry: ctk.CTkEntry | None = None
        self._build()

    @property
    def search_text(self) -> str:
        return self._search_text.get().strip()

    @property
    def protocol_filter(self) -> str | None:
        value = self._protocol.get().strip()
        return None if value == "All" else value

    @property
    def max_packets(self) -> str:
        return self._max_packets.get().strip()

    def _build(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=0)

        left = ctk.CTkFrame(self, fg_color="transparent")
        left.grid(row=0, column=0, sticky="ew", padx=16, pady=14)

        buttons = [
            ("Start Capture", self.actions["start"], colors.SUCCESS),
            ("Stop Capture", self.actions["stop"], colors.DANGER),
            ("Pause", self.actions["pause"], colors.ORANGE),
            ("Refresh", self.actions["refresh"], colors.ACCENT),
            ("Clear", self.actions["clear"], colors.PURPLE),
            ("Export", self.actions["export"], colors.ACCENT),
            ("Open Log", self.actions["open_log"], colors.ACCENT),
            ("Filter", self.actions["filter"], colors.ORANGE),
        ]

        for label, command, color in buttons:
            ctk.CTkButton(
                left,
                text=label,
                command=command,
                fg_color=color,
                hover_color=color,
                corner_radius=14,
                height=40,
                width=132,
            ).pack(side="left", padx=6)

        search_panel = ctk.CTkFrame(self, fg_color="transparent")
        search_panel.grid(row=0, column=1, sticky="e", padx=16, pady=14)
        ctk.CTkOptionMenu(search_panel, values=["All", "TCP", "UDP", "ICMP"], variable=self._protocol, width=100).pack(side="left", padx=8)
        self.search_entry = ctk.CTkEntry(search_panel, textvariable=self._search_text, width=300, placeholder_text="Search IP, MAC, port, payload...")
        self.search_entry.pack(side="left", padx=8)
        ctk.CTkEntry(search_panel, textvariable=self._max_packets, width=110, placeholder_text="Max packets").pack(side="left", padx=8)

    def focus_search(self) -> None:
        if self.search_entry is not None:
            self.search_entry.focus_set()
