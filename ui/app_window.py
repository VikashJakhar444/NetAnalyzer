"""
Main Application Window Module.
Premium shell with sidebar navigation, contextual header, and page routing.
"""
import sys
from datetime import datetime
import customtkinter as ctk

from ui.dashboard import DashboardPage
from ui.scanner_page import NetworkScannerPage
from ui.port_page import PortScannerPage
from ui.packet_page import PacketSnifferPage
from ui.reports_page import ReportsPage
from ui.settings_page import SettingsPage
from ui.about_page import AboutPage
from ui.log_viewer_page import LogViewerPage
from ui.topology_page import TopologyPage
from ui.themes.tokens import Theme
from ui.widgets.controls import section_label, status_badge

try:
    from core.event_bus import EventBus
    from core.thread_manager import ThreadManager
    from core.database import DatabaseManager
    from core.controller import Controller
    from core.helpers import get_local_subnet, get_default_interface
    from core.logger import logger
    from core.constants import APP_NAME, VERSION
except ImportError:
    APP_NAME = "Network Analyzer"
    VERSION = "1.0.0"

    from core.compat import DummyLogger

    logger = DummyLogger()


# Navigation structure — grouped by purpose
NAV_SECTIONS = [
    ("Overview", [
        ("Dashboard", "DashboardPage"),
    ]),
    ("Analysis", [
        ("Device Scanner", "NetworkScannerPage"),
        ("Port Scanner", "PortScannerPage"),
        ("Packet Capture", "PacketSnifferPage"),
        ("Topology", "TopologyPage"),
    ]),
    ("Output", [
        ("Reports", "ReportsPage"),
    ]),
    ("System", [
        ("Log Viewer", "LogViewerPage"),
        ("Settings", "SettingsPage"),
        ("About", "AboutPage"),
    ]),
]


class AppWindow(ctk.CTk):
    """Primary application window."""

    def __init__(self):
        super().__init__()

        self.title(APP_NAME)
        self.geometry("1200x740")
        self.minsize(1060, 640)

        self.event_bus = EventBus()
        self.thread_mgr = ThreadManager()
        self.db = DatabaseManager()
        self.controller = Controller()
        self._current_page = None
        self.protocol("WM_DELETE_WINDOW", self.on_exit)

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_main_area()
        self._init_pages()
        self._bind_events()
        self._clock_timer_id = None
        self._start_clock()

        self.show_frame("DashboardPage")

    def _build_sidebar(self):
        self.sidebar = ctk.CTkFrame(
            self, width=Theme.SIDEBAR_WIDTH, corner_radius=0,
            fg_color=Theme.BG_SIDEBAR, border_width=0,
        )
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)
        self.sidebar.grid_rowconfigure(99, weight=1)

        # Brand block
        brand_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        brand_frame.grid(row=0, column=0, sticky="ew", padx=20, pady=(28, 24))

        ctk.CTkLabel(
            brand_frame, text="NetAnalyzer",
            font=Theme.font(18, "bold"),
            text_color=Theme.TEXT_PRIMARY,
            anchor="w",
        ).pack(anchor="w")

        ctk.CTkLabel(
            brand_frame, text="Network Security",
            font=Theme.font(11),
            text_color=Theme.TEXT_MUTED,
            anchor="w",
        ).pack(anchor="w", pady=(1, 0))

        # Separator
        ctk.CTkFrame(self.sidebar, height=1, fg_color=Theme.BORDER).grid(
            row=1, column=0, sticky="ew", padx=16,
        )

        # Navigation
        self.nav_buttons = {}
        row = 2
        first_section = True
        for section_title, items in NAV_SECTIONS:
            if not first_section:
                ctk.CTkFrame(self.sidebar, height=1, fg_color=Theme.BORDER).grid(
                    row=row, column=0, sticky="ew", padx=16, pady=(8, 4),
                )
                row += 1
            first_section = False

            section_label(self.sidebar, section_title).grid(
                row=row, column=0, sticky="w", padx=20, pady=(10, 4),
            )
            row += 1

            for label, target in items:
                btn = ctk.CTkButton(
                    self.sidebar, text=f" {label}", anchor="w",
                    height=32, corner_radius=Theme.RADIUS_SM,
                    fg_color="transparent",
                    text_color=Theme.TEXT_SECONDARY,
                    hover_color=Theme.BG_SURFACE_ALT,
                    font=Theme.font(12),
                    command=lambda t=target: self.show_frame(t),
                )
                btn.grid(row=row, column=0, sticky="ew", padx=20, pady=1)
                self.nav_buttons[target] = btn
                row += 1

        # Exit
        ctk.CTkFrame(self.sidebar, height=1, fg_color=Theme.BORDER).grid(
            row=98, column=0, sticky="ew", padx=16, pady=(8, 0),
        )

        self.exit_btn = ctk.CTkButton(
            self.sidebar, text="  Exit", anchor="w",
            height=36, corner_radius=Theme.RADIUS_SM,
            fg_color="transparent",
            text_color=Theme.DANGER,
            hover_color=Theme.DANGER_SUBTLE,
            font=Theme.font(12),
            command=self.on_exit,
        )
        self.exit_btn.grid(row=99, column=0, sticky="sew", padx=12, pady=(8, 20))

        # Version footer
        ctk.CTkLabel(
            self.sidebar, text=f"v{VERSION}",
            font=Theme.font(10),
            text_color=Theme.TEXT_MUTED,
        ).grid(row=100, column=0, pady=(0, 16))

    def _build_main_area(self):
        self.main = ctk.CTkFrame(self, fg_color=Theme.BG_APP, corner_radius=0)
        self.main.grid(row=0, column=1, sticky="nsew")
        self.main.grid_columnconfigure(0, weight=1)

        # Header
        self.header = ctk.CTkFrame(
            self.main, height=Theme.HEADER_HEIGHT, corner_radius=0,
            fg_color=Theme.BG_HEADER,
        )
        self.header.grid(row=0, column=0, sticky="ew", padx=0, pady=0)
        self.header.grid_propagate(False)
        self.header.grid_columnconfigure(0, weight=1)

        # Bottom 1px border line inside header
        ctk.CTkFrame(self.header, height=1, fg_color=Theme.BORDER, corner_radius=0).place(
            relx=0, rely=1.0, anchor="sw", relwidth=1,
        )

        # Inner wrapper with top/bottom padding so content is not stuck to top
        self.hdr_inner = ctk.CTkFrame(self.header, fg_color="transparent")
        self.hdr_inner.pack(fill="both", expand=True, padx=Theme.PAD_PAGE, pady=0)
        self.hdr_inner.grid_columnconfigure(1, weight=1)
        self.hdr_inner.grid_rowconfigure(0, weight=1)

        nic, local_ip = get_default_interface()
        self.net_lbl = ctk.CTkLabel(
            self.hdr_inner,
            text=f"{nic}  ·  {local_ip}",
            font=Theme.font(12),
            text_color=Theme.TEXT_SECONDARY,
        )
        self.net_lbl.grid(row=0, column=0, padx=(0, 24), pady=0, sticky="w")

        self.status_badge = status_badge(self.hdr_inner, "Ready", variant="success")
        self.status_badge.grid(row=0, column=2, padx=(0, 16), pady=0, sticky="e")

        self.clock_lbl = ctk.CTkLabel(
            self.hdr_inner, text="",
            font=Theme.font(11),
            text_color=Theme.TEXT_MUTED,
        )
        self.clock_lbl.grid(row=0, column=3, padx=(0, 4), pady=0, sticky="e")

        # Workspace
        self.main.grid_rowconfigure(1, weight=1)
        self.workspace = ctk.CTkFrame(self.main, fg_color="transparent")
        self.workspace.grid(row=1, column=0, sticky="nsew")
        self.workspace.grid_columnconfigure(0, weight=1)
        self.workspace.grid_rowconfigure(0, weight=1)

        # Status bar
        self.status_bar = ctk.CTkFrame(
            self.main, height=Theme.STATUS_HEIGHT, corner_radius=0,
            fg_color=Theme.BG_STATUS,
            border_width=1, border_color=Theme.BORDER,
        )
        self.status_bar.grid(row=2, column=0, sticky="ew")
        self.status_bar.grid_propagate(False)

        self.status_lbl = ctk.CTkLabel(
            self.status_bar, text="All systems operational",
            font=Theme.font(10),
            text_color=Theme.TEXT_MUTED,
        )
        self.status_lbl.grid(row=0, column=0, padx=Theme.PAD_PAGE, pady=0, sticky="w")

    def _init_pages(self):
        self.frames = {}
        for PageClass in (
            DashboardPage, NetworkScannerPage, PortScannerPage,
            PacketSnifferPage, TopologyPage, ReportsPage, LogViewerPage,
            SettingsPage, AboutPage,
        ):
            page_name = PageClass.__name__
            frame = PageClass(self.workspace, self, self.controller)
            self.frames[page_name] = frame
            frame.grid(row=0, column=0, sticky="nsew")

    def _bind_events(self):
        self.event_bus.subscribe("SCAN_STARTED", lambda d: self._on_scan_status(f"Scanning {d}"))
        self.event_bus.subscribe("SCAN_FINISHED", lambda d: self._on_scan_status("Scan complete"))
        self.event_bus.subscribe(
            "PORT_SCAN_STARTED",
            lambda d: self._on_scan_status(f"Port scan: {d.get('target_ip')}"),
        )
        self.event_bus.subscribe(
            "PORT_SCAN_FINISHED",
            lambda d: self._on_scan_status(f"Port scan complete"),
        )
        self.event_bus.subscribe(
            "SNIFFER_STARTED",
            lambda d: self._on_scan_status(f"Capturing on {d}", active=True),
        )
        self.event_bus.subscribe(
            "SNIFFER_FINISHED",
            lambda c: self._on_scan_status(f"Capture stopped — {c} packets"),
        )
        self.event_bus.subscribe("SCAN_ERROR", lambda m: self._on_error_status(str(m)))
        self.event_bus.subscribe("PORT_SCAN_ERROR", lambda m: self._on_error_status(str(m)))
        self.event_bus.subscribe("SNIFFER_ERROR", lambda m: self._on_error_status(str(m)))

    def _on_scan_status(self, message: str, active: bool = False):
        self.update_status(message)
        variant = "info" if active else "success"
        try:
            self.after(10, lambda: self._update_badge(message, variant))
        except Exception:
            pass

    def _on_error_status(self, message: str):
        self.update_status(message)
        try:
            self.after(10, lambda: self._update_badge(message[:28], "error"))
        except Exception:
            pass

    def _update_badge(self, text: str, variant: str):
        self.status_badge.destroy()
        self.status_badge = status_badge(self.hdr_inner, text[:28], variant=variant)
        self.status_badge.grid(row=0, column=2, padx=(0, 16), pady=0, sticky="e")

    def _start_clock(self):
        self._tick_clock()

    def _tick_clock(self):
        now = datetime.now().strftime("%H:%M:%S")
        self.clock_lbl.configure(text=now)
        self._clock_timer_id = self.after(1000, self._tick_clock)

    def show_frame(self, page_name: str):
        # Notify previous page it's no longer visible
        if self._current_page and self._current_page in self.frames:
            prev = self.frames[self._current_page]
            if hasattr(prev, "notify_hidden"):
                prev.notify_hidden()

        self.frames[page_name].tkraise()
        self._current_page = page_name

        for target, btn in self.nav_buttons.items():
            if target == page_name:
                btn.configure(
                    fg_color=Theme.ACCENT_SUBTLE,
                    text_color=Theme.ACCENT,
                    font=Theme.font(12, "bold"),
                )
            else:
                btn.configure(
                    fg_color="transparent",
                    text_color=Theme.TEXT_SECONDARY,
                    font=Theme.font(12),
                )

        frame = self.frames[page_name]
        if hasattr(frame, "refresh_dashboard"):
            frame.refresh_dashboard()
        if hasattr(frame, "refresh_reports_table"):
            frame.refresh_reports_table()
        if hasattr(frame, "refresh_data"):
            frame.refresh_data()

    def update_status(self, message: str):
        try:
            self.after(10, lambda: self.status_lbl.configure(text=message))
        except Exception:
            pass

    def on_exit(self):
        logger.info("Application exit triggered.")
        if self._clock_timer_id is not None:
            self.after_cancel(self._clock_timer_id)
        self.controller.shutdown()
        self.destroy()
        sys.exit(0)
