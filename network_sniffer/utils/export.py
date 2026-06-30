"""Export helpers for packets and packet details."""

from __future__ import annotations

import csv
import json


def export_packets_csv(records: list[dict[str, object]], file_path: str) -> None:
    with open(file_path, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["Count", "Timestamp", "Protocol", "Source", "Destination", "Summary", "Preview"])
        for record in records:
            writer.writerow([
                record.get("count", ""),
                record.get("timestamp", ""),
                record.get("protocol", ""),
                record.get("source", ""),
                record.get("destination", ""),
                record.get("summary", ""),
                record.get("preview", ""),
            ])


def export_packets_json(records: list[dict[str, object]], file_path: str) -> None:
    with open(file_path, "w", encoding="utf-8") as json_file:
        json.dump(records, json_file, indent=2)


def export_packet_text(record: dict[str, object], file_path: str) -> None:
    with open(file_path, "w", encoding="utf-8") as text_file:
        text_file.write(record.get("details", ""))
        text_file.write("\n")
        text_file.write(f"Source: {record.get('source', '')}\n")
        text_file.write(f"Destination: {record.get('destination', '')}\n")
        text_file.write(f"Summary: {record.get('summary', '')}\n")
        text_file.write(f"Preview: {record.get('preview', '')}\n")


def export_hex_dump(record: dict[str, object], file_path: str) -> None:
    with open(file_path, "w", encoding="utf-8") as text_file:
        text_file.write(record.get("payload_hex", ""))
