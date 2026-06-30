"""Bottom status bar for connection and telemetry state."""

from __future__ import annotations

import customtkinter as ctk

from themes import colors


class StatusBar(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color=colors.PANELS, corner_radius=0, height=40)
        self.grid_propagate(False)
        self._build()

    def _build(self) -> None:
        self.interface = ctk.CTkLabel(self, text="Interface: -")
        self.packets = ctk.CTkLabel(self, text="Packets: 0")
        self.displayed = ctk.CTkLabel(self, text="Displayed: 0")
        self.state = ctk.CTkLabel(self, text="State: Idle")
        self.clock = ctk.CTkLabel(self, text="00:00:00")
        self.runtime = ctk.CTkLabel(self, text="Runtime: 00:00:00")
        for widget in (self.interface, self.packets, self.displayed, self.state, self.clock, self.runtime):
            widget.pack(side="left", padx=14)

    def set_state(self, value: str) -> None:
        self.state.configure(text=f"State: {value}")

    def set_packets(self, packets: int, displayed: int) -> None:
        self.packets.configure(text=f"Packets: {packets}")
        self.displayed.configure(text=f"Displayed: {displayed}")

    def set_displayed(self, value: int) -> None:
        self.displayed.configure(text=f"Displayed: {value}")

    def set_runtime(self, value: str) -> None:
        self.runtime.configure(text=f"Runtime: {value}")

    def set_clock(self, value: str) -> None:
        self.clock.configure(text=value)
