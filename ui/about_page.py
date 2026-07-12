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
            panel, text="Developed by",
            font=Theme.font(11),
            text_color=Theme.TEXT_MUTED,
            anchor="w",
        ).grid(row=2, column=0, sticky="w", padx=Theme.PAD_CARD, pady=(6, 2))

        authors_frame = ctk.CTkFrame(panel, fg_color="transparent")
        authors_frame.grid(row=3, column=0, sticky="w", padx=Theme.PAD_CARD, pady=(0, 2))

        import os
        from PIL import Image

        # Path helper to load icon image files
        def _load_icon(light_name, dark_name, size=(16, 16)):
            try:
                base_dir = os.path.dirname(os.path.dirname(__file__))
                light_path = os.path.join(base_dir, "assets", light_name)
                dark_path = os.path.join(base_dir, "assets", dark_name)
                return ctk.CTkImage(
                    light_image=Image.open(light_path),
                    dark_image=Image.open(dark_path),
                    size=size
                )
            except Exception as e:
                return None

        github_icon = _load_icon("github_dark.png", "github_light.png")
        linkedin_icon = _load_icon("linkedin_dark.png", "linkedin_light.png")

        def _author_row(parent, name, github_url, linkedin_url, row):
            f = ctk.CTkFrame(parent, fg_color="transparent")
            f.grid(row=row, column=0, sticky="w", pady=3)
            ctk.CTkLabel(f, text=f"  {name}", font=Theme.font(12, "bold"),
                         text_color=Theme.TEXT_PRIMARY, anchor="w").pack(side="left")
            
            if github_icon and github_url:
                gh = ctk.CTkLabel(f, text="", image=github_icon, cursor="hand2")
                gh.pack(side="left", padx=(10, 0))
                gh.bind("<Button-1>", lambda e, u=github_url: __import__("webbrowser").open(u))
            elif github_url:
                gh = ctk.CTkLabel(f, text="  GitHub", font=Theme.font(11),
                                  text_color=Theme.ACCENT, cursor="hand2", anchor="w")
                gh.pack(side="left", padx=(8, 0))
                gh.bind("<Button-1>", lambda e, u=github_url: __import__("webbrowser").open(u))
                gh.bind("<Enter>", lambda e: gh.configure(text_color=Theme.ACCENT_HOVER))
                gh.bind("<Leave>", lambda e: gh.configure(text_color=Theme.ACCENT))
                
            if linkedin_icon and linkedin_url:
                li = ctk.CTkLabel(f, text="", image=linkedin_icon, cursor="hand2")
                li.pack(side="left", padx=(8, 0))
                li.bind("<Button-1>", lambda e, u=linkedin_url: __import__("webbrowser").open(u))
            elif linkedin_url:
                li = ctk.CTkLabel(f, text="  LinkedIn", font=Theme.font(11),
                                  text_color=Theme.ACCENT, cursor="hand2", anchor="w")
                li.pack(side="left", padx=(6, 0))
                li.bind("<Button-1>", lambda e, u=linkedin_url: __import__("webbrowser").open(u))
                li.bind("<Enter>", lambda e: li.configure(text_color=Theme.ACCENT_HOVER))
                li.bind("<Leave>", lambda e: li.configure(text_color=Theme.ACCENT))

        _author_row(authors_frame, "Vikash Jakhar",
                    "https://github.com/VikashJakhar444",
                    "https://www.linkedin.com/in/vikash-jakhar-1a417b361/", 0)
        _author_row(authors_frame, "Anisha Verma",
                    "https://github.com/anishaverma3858-hue",
                    None, 1)


        ctk.CTkFrame(panel, height=1, fg_color=Theme.BORDER).grid(
            row=4, column=0, sticky="ew", padx=Theme.PAD_CARD, pady=16,
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
        ).grid(row=5, column=0, sticky="w", padx=Theme.PAD_CARD, pady=4)

        ctk.CTkLabel(
            panel, text="Dependencies",
            font=Theme.font(12, "bold"),
            text_color=Theme.TEXT_MUTED,
            anchor="w",
        ).grid(row=6, column=0, sticky="w", padx=Theme.PAD_CARD, pady=(20, 6))

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
        ).grid(row=7, column=0, sticky="w", padx=Theme.PAD_CARD, pady=(0, 6))

        ctk.CTkFrame(panel, height=1, fg_color=Theme.BORDER).grid(
            row=8, column=0, sticky="ew", padx=Theme.PAD_CARD, pady=12,
        )

        ctk.CTkLabel(
            panel, text="Links",
            font=Theme.font(12, "bold"),
            text_color=Theme.TEXT_MUTED,
            anchor="w",
        ).grid(row=9, column=0, sticky="w", padx=Theme.PAD_CARD, pady=(0, 6))

        # Clickable links
        link_frame = ctk.CTkFrame(panel, fg_color="transparent")
        link_frame.grid(row=10, column=0, sticky="w", padx=Theme.PAD_CARD, pady=(0, Theme.PAD_CARD))

        def _link_btn(parent, label, text, url, row):
            row_frame = ctk.CTkFrame(parent, fg_color="transparent")
            row_frame.grid(row=row, column=0, sticky="w", pady=2)
            ctk.CTkLabel(
                row_frame, text=label,
                font=Theme.font(11),
                text_color=Theme.TEXT_MUTED,
                width=90, anchor="w",
            ).pack(side="left")
            btn = ctk.CTkLabel(
                row_frame, text=text,
                font=Theme.font(11),
                text_color=Theme.ACCENT,
                cursor="hand2", anchor="w",
            )
            btn.pack(side="left")
            btn.bind("<Button-1>", lambda e: __import__("webbrowser").open(url if url.startswith("http") else f"https://{url}"))
            btn.bind("<Enter>", lambda e: btn.configure(text_color=Theme.ACCENT_HOVER))
            btn.bind("<Leave>", lambda e: btn.configure(text_color=Theme.ACCENT))

        _link_btn(link_frame, "Repository — ", "NetAnalyzer", "github.com/VikashJakhar444/NetAnalyzer", 0)
        ctk.CTkLabel(
            link_frame, text="License    —  MIT",
            font=Theme.font(11), text_color=Theme.TEXT_MUTED, anchor="w",
        ).grid(row=1, column=0, sticky="w", pady=2)
