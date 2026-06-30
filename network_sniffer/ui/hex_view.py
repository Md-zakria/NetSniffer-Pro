"""Professional hex viewer panel."""

from __future__ import annotations

import customtkinter as ctk

from themes import colors, fonts


class HexView(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color=colors.CARDS, corner_radius=18)
        self._build()

    def _build(self) -> None:
        ctk.CTkLabel(self, text="Hex Viewer", font=("Segoe UI Variable", 18, "bold")).pack(anchor="w", padx=16, pady=(16, 8))
        self.textbox = ctk.CTkTextbox(self, fg_color=colors.PANELS, text_color=colors.TEXT, font=fonts.MONO_FONT, corner_radius=16)
        self.textbox.pack(fill="both", expand=True, padx=16, pady=(0, 16))

    def set_record(self, record: dict[str, object]) -> None:
        self.textbox.delete("1.0", "end")
        self.textbox.insert("end", record.get("payload_hex", ""))

    def clear(self) -> None:
        self.textbox.delete("1.0", "end")
