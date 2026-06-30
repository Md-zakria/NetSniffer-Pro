"""Packet table backed by ttk.Treeview embedded in a modern frame."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

import customtkinter as ctk

from themes import colors


class PacketTable(ctk.CTkFrame):
    def __init__(self, master, on_select, on_right_click):
        super().__init__(master, fg_color=colors.CARDS, corner_radius=18)
        self.on_select = on_select
        self.on_right_click = on_right_click
        self.records: list[dict[str, object]] = []
        self._row_map: dict[str, dict[str, object]] = {}
        self._build()

    def _build(self) -> None:
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=16, pady=(16, 8))
        ctk.CTkLabel(header, text="Packet Table", font=("Segoe UI Variable", 18, "bold")).pack(side="left")
        ctk.CTkLabel(header, text="Live packet stream", text_color=colors.SECONDARY_TEXT).pack(side="right")

        container = ctk.CTkFrame(self, fg_color=colors.PANELS, corner_radius=16)
        container.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        columns = ("count", "timestamp", "protocol", "source_ip", "source_port", "dest_ip", "dest_port", "ttl", "length", "flags", "info", "status")
        self.tree = ttk.Treeview(container, columns=columns, show="headings", selectmode="browse")
        style = ttk.Style()
        style.configure("Treeview", background="#111827", fieldbackground="#111827", foreground="#F9FAFB", rowheight=30, borderwidth=0)
        style.configure("Treeview.Heading", background="#182235", foreground="#F9FAFB", relief="flat")

        labels = {
            "count": "#",
            "timestamp": "Timestamp",
            "protocol": "Protocol",
            "source_ip": "Source IP",
            "source_port": "Source Port",
            "dest_ip": "Destination IP",
            "dest_port": "Destination Port",
            "ttl": "TTL",
            "length": "Length",
            "flags": "Flags",
            "info": "Info",
            "status": "Status",
        }
        widths = {
            "count": 60,
            "timestamp": 130,
            "protocol": 90,
            "source_ip": 180,
            "source_port": 100,
            "dest_ip": 180,
            "dest_port": 100,
            "ttl": 70,
            "length": 90,
            "flags": 140,
            "info": 340,
            "status": 100,
        }
        for column in columns:
            self.tree.heading(column, text=labels[column], command=lambda c=column: self.sort_by(c, False))
            self.tree.column(column, width=widths[column], anchor="w", stretch=True)

        scrollbar = ttk.Scrollbar(container, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.tree.bind("<<TreeviewSelect>>", self._handle_select)
        self.tree.bind("<Button-3>", self._handle_right_click)

    def _handle_select(self, _event=None) -> None:
        selected = self.tree.selection()
        if not selected:
            return
        record = self._row_map.get(selected[0])
        if record:
            self.on_select(record)

    def _handle_right_click(self, event) -> None:
        item = self.tree.identify_row(event.y)
        if not item:
            return
        self.tree.selection_set(item)
        record = self._row_map.get(item)
        if record:
            menu = tk.Menu(self, tearoff=0)
            menu.add_command(label="Save Packet", command=lambda: self.on_right_click(record, "save"))
            menu.add_command(label="Copy Packet", command=lambda: self.on_right_click(record, "copy"))
            menu.add_command(label="Export Packet", command=lambda: self.on_right_click(record, "export"))
            menu.tk_popup(event.x_root, event.y_root)

    def clear(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._row_map.clear()

    def set_records(self, records: list[dict[str, object]]) -> None:
        self.clear()
        self.records = records
        for record in records:
            row_id = self.tree.insert(
                "",
                "end",
                values=(
                    record.get("count", ""),
                    record.get("timestamp", ""),
                    record.get("protocol", ""),
                    record.get("source", "").split(":")[0],
                    record.get("source", "").split(":")[1] if ":" in str(record.get("source", "")) else "",
                    record.get("destination", "").split(":")[0],
                    record.get("destination", "").split(":")[1] if ":" in str(record.get("destination", "")) else "",
                    record.get("ip", {}).get("ttl", ""),
                    len(str(record.get("preview", ""))),
                    record.get("summary", ""),
                    record.get("details", "")[:80],
                    "Ready",
                ),
            )
            self._row_map[row_id] = record

    def sort_by(self, column: str, reverse: bool) -> None:
        items = [(self.tree.set(child, column), child) for child in self.tree.get_children("")]
        items.sort(reverse=reverse)
        for index, (_value, child) in enumerate(items):
            self.tree.move(child, "", index)
        self.tree.heading(column, command=lambda c=column: self.sort_by(c, not reverse))
