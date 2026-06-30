"""CustomTkinter application shell for the Network Sniffer UI."""

from __future__ import annotations

import datetime as _dt
import os
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox

import customtkinter as ctk

from capture.packet_capture import CaptureWorker
from themes.dark import apply_dark_theme, get_theme_tokens
from utils.export import export_hex_dump, export_packet_text, export_packets_csv, export_packets_json
from utils.helpers import packet_matches_query, safe_int
from ui.hex_view import HexView
from ui.packet_details import PacketDetailsPanel
from ui.packet_table import PacketTable
from ui.sidebar import Sidebar
from ui.statusbar import StatusBar
from ui.statistics import StatisticsPanel
from ui.toolbar import Toolbar


class NetworkSnifferApp(ctk.CTk):
    """Premium desktop shell for live packet inspection."""

    def __init__(self) -> None:
        apply_dark_theme()
        super().__init__()
        self.theme = get_theme_tokens()

        self.title("Network Sniffer")
        self.geometry("1700x950")
        self.minsize(1700, 950)
        self.configure(fg_color=self.theme["bg"])

        self.packet_queue: queue.Queue = queue.Queue()
        self.stop_event = threading.Event()
        self.worker: CaptureWorker | None = None
        self.capturing = False
        self.capture_started_at: _dt.datetime | None = None
        self.packet_history: list[dict[str, object]] = []
        self.filtered_history: list[dict[str, object]] = []
        self.selected_record: dict[str, object] | None = None

        self.sidebar = Sidebar(self, on_navigation=self._on_navigation)
        self.toolbar = Toolbar(self, self._toolbar_actions())
        self.packet_table: PacketTable | None = None
        self.packet_details: PacketDetailsPanel | None = None
        self.hex_view: HexView | None = None
        self.statistics: StatisticsPanel | None = None
        self.statusbar = StatusBar(self)

        self._build_layout()
        self._bind_shortcuts()
        self.after(75, self._poll_queue)
        self.after(1000, self._update_clock)

    def _build_layout(self) -> None:
        self.sidebar.grid(row=0, column=0, rowspan=3, sticky="nsew")
        self.toolbar.grid(row=0, column=1, sticky="nsew")

        main = ctk.CTkFrame(self, fg_color=self.theme["bg"], corner_radius=0)
        main.grid(row=1, column=1, sticky="nsew")
        main.grid_columnconfigure(0, weight=3)
        main.grid_columnconfigure(1, weight=2)
        main.grid_rowconfigure(0, weight=1)

        left = ctk.CTkFrame(main, fg_color=self.theme["card"], corner_radius=18)
        right = ctk.CTkFrame(main, fg_color=self.theme["card"], corner_radius=18)
        left.grid(row=0, column=0, sticky="nsew", padx=(16, 8), pady=16)
        right.grid(row=0, column=1, sticky="nsew", padx=(8, 16), pady=16)
        left.grid_rowconfigure(1, weight=1)
        left.grid_columnconfigure(0, weight=1)
        right.grid_rowconfigure(0, weight=1)
        right.grid_rowconfigure(1, weight=1)
        right.grid_columnconfigure(0, weight=1)

        self.statistics = StatisticsPanel(left)
        self.packet_table = PacketTable(left, on_select=self._on_packet_selected, on_right_click=self._on_packet_right_click)
        self.packet_details = PacketDetailsPanel(right)
        self.hex_view = HexView(right)

        self.statistics.grid(row=0, column=0, sticky="nsew", padx=16, pady=(16, 8))
        self.packet_table.grid(row=1, column=0, sticky="nsew", padx=16, pady=(8, 16))

        self.packet_details.grid(row=0, column=0, sticky="nsew", padx=16, pady=(16, 8))
        self.hex_view.grid(row=1, column=0, sticky="nsew", padx=16, pady=(8, 16))

        self.statusbar.grid(row=2, column=1, sticky="nsew")

        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(1, weight=1)

    def _toolbar_actions(self) -> dict[str, callable]:
        return {
            "start": self.start_capture,
            "stop": self.stop_capture,
            "pause": self.pause_capture,
            "refresh": self.refresh_view,
            "clear": self.clear_view,
            "export": self.export_menu,
            "open_log": self.open_log_file,
            "filter": self.apply_filter,
            "search": self.apply_search,
        }

    def _bind_shortcuts(self) -> None:
        self.bind("<Control-f>", lambda _e: self.toolbar.focus_search())
        self.bind("<Control-r>", lambda _e: self.refresh_view())
        self.bind("<Control-e>", lambda _e: self.export_menu())
        self.bind("<F5>", lambda _e: self.start_capture())
        self.bind("<F6>", lambda _e: self.stop_capture())
        self.bind("<Escape>", lambda _e: self.pause_capture())

    def run(self) -> None:
        self._set_ready_state()
        self.mainloop()

    def _set_ready_state(self) -> None:
        self.statusbar.set_state("Idle")
        self.statusbar.set_packets(0, 0)
        self.statusbar.set_runtime("00:00:00")

    def start_capture(self) -> None:
        if self.capturing:
            return

        max_packets = safe_int(self.toolbar.max_packets, 0)
        protocol_filter = self.toolbar.protocol_filter

        self.stop_event.clear()
        self.packet_queue = queue.Queue()
        self.worker = CaptureWorker(self.packet_queue, self.stop_event, protocol_filter=protocol_filter, max_packets=max_packets)
        self.worker.start()
        self.capturing = True
        self.capture_started_at = _dt.datetime.now()
        self.statusbar.set_state("Live")

    def stop_capture(self) -> None:
        if not self.capturing:
            return
        self.stop_event.set()
        self.capturing = False
        self.statusbar.set_state("Stopped")

    def pause_capture(self) -> None:
        self.stop_capture()

    def refresh_view(self) -> None:
        self.apply_search()

    def clear_view(self) -> None:
        self.packet_history.clear()
        self.filtered_history.clear()
        if self.packet_table:
            self.packet_table.clear()
        if self.packet_details:
            self.packet_details.clear()
        if self.hex_view:
            self.hex_view.clear()
        self.selected_record = None
        if self.statistics:
            self.statistics.reset()
        self.statusbar.set_packets(0, 0)

    def open_log_file(self) -> None:
        path = os.path.abspath("sniffer_log.txt")
        if not os.path.exists(path):
            messagebox.showinfo("Log file", "No log file has been created yet.")
            return
        try:
            if hasattr(os, "startfile"):
                os.startfile(path)
            else:
                import subprocess

                subprocess.Popen(["xdg-open", path])
        except Exception as exc:
            messagebox.showerror("Open log file failed", str(exc))

    def apply_filter(self) -> None:
        self.apply_search()

    def apply_search(self) -> None:
        query = self.toolbar.search_text
        self.filtered_history = [record for record in self.packet_history if packet_matches_query(record, query)]
        if self.packet_table:
            self.packet_table.set_records(self.filtered_history)
        self.statusbar.set_displayed(len(self.filtered_history))

    def export_menu(self) -> None:
        if not self.packet_history:
            messagebox.showinfo("Export", "No packets available yet.")
            return

        file_path = filedialog.asksaveasfilename(
            title="Export capture",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("JSON", "*.json"), ("Text", "*.txt"), ("Hex Dump", "*.hex"), ("All files", "*.*")],
        )
        if not file_path:
            return

        lower = file_path.lower()
        if lower.endswith(".json"):
            export_packets_json(self.packet_history, file_path)
        elif lower.endswith(".txt"):
            export_packet_text(self.selected_record or self.packet_history[-1], file_path)
        elif lower.endswith(".hex"):
            export_hex_dump(self.selected_record or self.packet_history[-1], file_path)
        else:
            export_packets_csv(self.packet_history, file_path)

    def _on_navigation(self, destination: str) -> None:
        self.statusbar.set_state(destination)

    def _on_packet_selected(self, record: dict[str, object]) -> None:
        self.selected_record = record
        if self.packet_details:
            self.packet_details.set_record(record)
        if self.hex_view:
            self.hex_view.set_record(record)

    def _on_packet_right_click(self, record: dict[str, object], action: str) -> None:
        if action == "save":
            file_path = filedialog.asksaveasfilename(title="Save packet", defaultextension=".txt")
            if file_path:
                export_packet_text(record, file_path)

    def _poll_queue(self) -> None:
        try:
            while True:
                event = self.packet_queue.get_nowait()
                event_type = event.get("type")

                if event_type == "packet":
                    record = event["record"]
                    self.packet_history.append(record)
                    self.statistics.ingest(record)
                    self.statusbar.set_packets(len(self.packet_history), len(self.filtered_history))
                    self.apply_search()
                    if self.selected_record is None:
                        self._on_packet_selected(record)
                elif event_type == "status":
                    self.statusbar.set_state(event.get("message", ""))
                elif event_type == "error":
                    self.statusbar.set_state("Capture error")
                    messagebox.showerror("Capture error", event.get("message", "Unknown error"))
                    self.stop_capture()
                elif event_type == "stopped":
                    self.stop_capture()
        except queue.Empty:
            pass

        self.after(75, self._poll_queue)

    def _update_clock(self) -> None:
        self.statusbar.set_clock(_dt.datetime.now().strftime("%H:%M:%S"))
        if self.capture_started_at:
            delta = _dt.datetime.now() - self.capture_started_at
            seconds = int(delta.total_seconds())
            self.statusbar.set_runtime(f"{seconds // 3600:02d}:{(seconds % 3600) // 60:02d}:{seconds % 60:02d}")
        self.after(1000, self._update_clock)
