"""Dark theme bootstrap for CustomTkinter."""

from __future__ import annotations

import customtkinter as ctk

from . import colors


def apply_dark_theme() -> None:
    ctk.set_appearance_mode("Dark")
    ctk.set_default_color_theme("blue")
    ctk.set_widget_scaling(1.0)
    ctk.set_window_scaling(1.0)


def get_theme_tokens() -> dict[str, str]:
    return {
        "bg": colors.PRIMARY_BACKGROUND,
        "card": colors.CARDS,
        "panel": colors.PANELS,
        "accent": colors.ACCENT,
        "hover": colors.HOVER,
        "text": colors.TEXT,
        "muted": colors.SECONDARY_TEXT,
        "border": colors.BORDERS,
    }
