"""
About Page Module.
Application information and attribution.
"""
import customtkinter as ctk

from ui.themes.tokens import Theme
from ui.widgets.controls import page_header, surface_panel

try:
    from core.constants import VERSION, APP_NAME, AUTHOR
except ImportError:
    APP_NAME = "Network Analyzer & Security Scanner"
    VERSION = "1.0.0"
    AUTHOR = "Vikash Jakhar & Anisha Verma"


class AboutPage(ctk.CTkFrame):
    """Application information panel."""

    def __init__(self, parent, app_window, ctlr):
        super().__init__(parent, fg_color="transparent")
        self.controller = app_window

        self.grid_columnconfigure(0, weight=1)

        header = page_header(self, "About", "Application details and dependencies")
        header.grid(row=0, column=0, sticky="ew", padx=Theme.PAD_PAGE, pady=(Theme.PAD_PAGE, 8))

        panel = surface_panel(self)
        panel.grid(row=1, column=0, sticky="nsew", padx=Theme.PAD_PAGE, pady=(8, Theme.PAD_PAGE))
        panel.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            panel, text=APP_NAME,
            font=Theme.font(16, "bold"),
            text_color=Theme.TEXT_PRIMARY,
            anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=Theme.PAD_CARD, pady=(Theme.PAD_CARD, 4))

        ctk.CTkLabel(
            panel, text=f"Version {VERSION}",
            font=Theme.font(12),
            text_color=Theme.TEXT_MUTED,
            anchor="w",
        ).grid(row=1, column=0, sticky="w", padx=Theme.PAD_CARD, pady=2)

        ctk.CTkLabel(
            panel, text=f"Built by {AUTHOR}",
            font=Theme.font(12),
            text_color=Theme.TEXT_SECONDARY,
            anchor="w",
        ).grid(row=2, column=0, sticky="w", padx=Theme.PAD_CARD, pady=2)

        ctk.CTkFrame(panel, height=1, fg_color=Theme.BORDER).grid(
            row=3, column=0, sticky="ew", padx=Theme.PAD_CARD, pady=16,
        )

        description = (
            "A defensive network security toolkit for mapping local networks, "
            "auditing open ports, capturing live traffic, and generating security reports.\n\n"
            "Designed for educational use, security labs, and network diagnostics. "
            "Operates exclusively on authorized private networks."
        )
        ctk.CTkLabel(
            panel, text=description,
            font=Theme.font(12),
            text_color=Theme.TEXT_SECONDARY,
            justify="left", wraplength=560, anchor="w",
        ).grid(row=4, column=0, sticky="w", padx=Theme.PAD_CARD, pady=4)

        ctk.CTkLabel(
            panel, text="Dependencies",
            font=Theme.font(12, "bold"),
            text_color=Theme.TEXT_MUTED,
            anchor="w",
        ).grid(row=5, column=0, sticky="w", padx=Theme.PAD_CARD, pady=(20, 6))

        deps = (
            "CustomTkinter — Desktop interface framework\n"
            "Scapy — Packet capture and network mapping\n"
            "Matplotlib — Traffic visualization\n"
            "ReportLab — PDF report generation\n"
            "SQLite — Local data persistence"
        )
        ctk.CTkLabel(
            panel, text=deps,
            font=Theme.font(11),
            text_color=Theme.TEXT_MUTED,
            justify="left", anchor="w",
        ).grid(row=6, column=0, sticky="w", padx=Theme.PAD_CARD, pady=(0, 6))

        ctk.CTkFrame(panel, height=1, fg_color=Theme.BORDER).grid(
            row=7, column=0, sticky="ew", padx=Theme.PAD_CARD, pady=12,
        )

        ctk.CTkLabel(
            panel, text="Links",
            font=Theme.font(12, "bold"),
            text_color=Theme.TEXT_MUTED,
            anchor="w",
        ).grid(row=8, column=0, sticky="w", padx=Theme.PAD_CARD, pady=(0, 6))

        links = (
            "GitHub       — <your-repo-url>\n"
            "License       — MIT\n"
            "Support       — <your-email>"
        )
        ctk.CTkLabel(
            panel, text=links,
            font=Theme.font(11),
            text_color=Theme.TEXT_MUTED,
            justify="left", anchor="w",
        ).grid(row=9, column=0, sticky="w", padx=Theme.PAD_CARD, pady=(0, Theme.PAD_CARD))
