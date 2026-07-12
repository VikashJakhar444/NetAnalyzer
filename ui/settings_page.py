"""
Settings Page Module.
Application configuration with grouped preferences.
"""
import os
import sys
from tkinter import filedialog
import customtkinter as ctk

from ui.themes.tokens import Theme
from ui.widgets.controls import (
    page_header, surface_panel, form_label, form_entry,
    option_menu, primary_button, secondary_button,
)

try:
    from config.config import ConfigurationManager
    from core.logger import logger
except ImportError:
    from core.compat import DummyLogger
    logger = DummyLogger()


class SettingsPage(ctk.CTkFrame):
    """Application settings panel."""

    def __init__(self, parent, app_window, ctlr):
        super().__init__(parent, fg_color="transparent")
        self.controller = app_window
        self.ctlr = ctlr
        self.event_bus = ctlr.event_bus
        self.config_mgr = ConfigurationManager()

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = page_header(
            self, "Settings",
            "Configure scanning behavior, appearance, and output paths",
        )
        header.grid(row=0, column=0, sticky="ew", padx=Theme.PAD_PAGE, pady=(Theme.PAD_PAGE, 8))

        panel = surface_panel(self)
        panel.grid(row=1, column=0, sticky="nsew", padx=Theme.PAD_PAGE, pady=8)
        panel.grid_columnconfigure(1, weight=1)

        self.theme_var = ctk.StringVar(value="dark")
        self.timeout_var = ctk.StringVar(value="2")
        self.limit_var = ctk.StringVar(value="1000")
        self.subnet_var = ctk.StringVar(value="")
        self.path_var = ctk.StringVar(value="")

        # Register number validation before fields that use it
        self._vcmd = self.register(self._validate_number)

        self._add_field(panel, 0, "Appearance", "theme_menu", "option", "Interface color scheme")
        self._add_field(panel, 1, "Connection Timeout", "timeout_entry", "entry_num", "Seconds before scan timeout")
        self._add_field(panel, 2, "Packet Limit", "limit_entry", "entry_num", "Max packets per capture session")
        self._add_field(panel, 3, "Default Subnet", "subnet_entry", "entry", "Pre-filled network range for scans")

        # Reports path with browse
        self._add_field(panel, 4, "Reports Path", "path_frame", "custom", "Directory for generated exports")
        entry_frame = ctk.CTkFrame(self.path_frame, fg_color="transparent")
        entry_frame.grid(row=0, column=0, sticky="ew")
        entry_frame.grid_columnconfigure(0, weight=1)
        self.path_entry = form_entry(entry_frame, width=400, textvariable=self.path_var)
        self.path_entry.grid(row=0, column=0, sticky="ew")
        secondary_button(entry_frame, "Browse", self._on_browse_path, width=70).grid(
            row=0, column=1, padx=(6, 0))

        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.grid(row=2, column=0, sticky="ew", padx=Theme.PAD_PAGE, pady=(8, Theme.PAD_PAGE))

        primary_button(btn_frame, "Save Changes", self.on_save_settings, width=140).grid(row=0, column=0, padx=(0, 8))
        secondary_button(btn_frame, "Reset Defaults", self.on_reset_settings, width=130).grid(row=0, column=1)

        self._status_label = ctk.CTkLabel(
            btn_frame, text="", font=Theme.font(10),
            text_color=Theme.SUCCESS, anchor="w",
        )
        self._status_label.grid(row=0, column=2, padx=(16, 0), sticky="w")

        self.load_values()

    def _on_theme_changed(self, choice):
        theme = choice.lower()
        ctk.set_appearance_mode(theme)
        self.event_bus.publish("THEME_CHANGED", {})

    def _validate_number(self, value):
        return value == "" or value.isdigit()

    def _add_field(self, parent, row, label, attr, field_type, hint):
        form_label(parent, label).grid(
            row=row, column=0, padx=(Theme.PAD_CARD, 12), pady=14, sticky="nw",
        )

        field_frame = ctk.CTkFrame(parent, fg_color="transparent")
        field_frame.grid(row=row, column=1, padx=(0, Theme.PAD_CARD), pady=14, sticky="ew")
        field_frame.grid_columnconfigure(0, weight=1)

        if field_type == "option":
            widget = option_menu(field_frame, ["Dark", "Light"],
                                 variable=self.theme_var, width=140,
                                 command=self._on_theme_changed)
            widget.grid(row=0, column=0, sticky="w")
            setattr(self, attr, widget)
        elif field_type == "entry_num":
            widget = form_entry(field_frame, width=140,
                                textvariable=getattr(self, attr.replace("_entry", "_var")),
                                validate="key", validatecommand=(self._vcmd, "%P"))
            widget.grid(row=0, column=0, sticky="w")
            setattr(self, attr, widget)
        elif field_type == "entry":
            widget = form_entry(field_frame, width=140,
                                textvariable=getattr(self, attr.replace("_entry", "_var")))
            widget.grid(row=0, column=0, sticky="w")
            setattr(self, attr, widget)
        elif field_type == "custom":
            setattr(self, attr, field_frame)

        ctk.CTkLabel(
            field_frame, text=hint,
            font=Theme.font(11), text_color=Theme.TEXT_MUTED, anchor="w",
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))

    def _on_browse_path(self):
        parent = self.winfo_toplevel()
        selected = filedialog.askdirectory(
            parent=parent,
            title="Select Reports Directory",
            initialdir=self.path_var.get() or os.getcwd(),
        )
        if selected:
            self.path_var.set(selected)

    def load_values(self):
        self.config_mgr.load()
        self.theme_var.set(self.config_mgr.get("theme", "dark").capitalize())
        self.timeout_var.set(str(self.config_mgr.get("timeout", 2)))
        self.limit_var.set(str(self.config_mgr.get("packet_limit", 1000)))
        self.subnet_var.set(self.config_mgr.get("default_network", ""))
        self.path_var.set(self.config_mgr.get("report_path", ""))

    def on_save_settings(self):
        theme = self.theme_var.get().lower()
        timeout = self.timeout_var.get().strip()
        limit = self.limit_var.get().strip()
        subnet = self.subnet_var.get().strip()
        path = self.path_var.get().strip()

        errors = []
        if not timeout or not timeout.isdigit() or not (1 <= int(timeout) <= 300):
            errors.append("Timeout must be 1-300")
        if not limit or not limit.isdigit() or not (1 <= int(limit) <= 100000):
            errors.append("Packet limit must be 1-100000")
        if not path:
            errors.append("Reports path cannot be empty")
        elif ".." in path or path.startswith("~"):
            errors.append("Reports path must not contain '..' or '~'")
        else:
            try:
                abs_path = os.path.abspath(path)
                system_dirs = [
                    os.environ.get("SystemRoot", "C:\\Windows"),
                    os.environ.get("ProgramFiles", "C:\\Program Files"),
                    os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"),
                ]
                for sd in system_dirs:
                    if abs_path.lower().startswith(sd.lower()):
                        errors.append("Reports path must not point to system directories")
                        break
            except Exception:
                errors.append("Invalid reports path")

        if errors:
            self._status_label.configure(text="; ".join(errors), text_color=Theme.DANGER)
            return

        try:
            self.config_mgr.set("theme", theme)
            self.config_mgr.set("timeout", timeout)
            self.config_mgr.set("packet_limit", limit)
            self.config_mgr.set("default_network", subnet)
            self.config_mgr.set("report_path", path)
        except Exception as e:
            logger.error(f"Failed to save settings: {e}")
            self._status_label.configure(text="Save failed. Check values and try again.", text_color=Theme.DANGER)
            return

        self.load_values()
        self._status_label.configure(text="Settings saved", text_color=Theme.SUCCESS)
        self.controller.update_status("Settings saved")
        self.event_bus.publish("THEME_CHANGED", {})

    def on_reset_settings(self):
        self.config_mgr.reset()
        ctk.set_appearance_mode(self.config_mgr.get("theme", "dark"))
        self.load_values()
        self._status_label.configure(text="Reset to defaults", text_color=Theme.TEXT_MUTED)
        self.controller.update_status("Settings reset to defaults")
        self.event_bus.publish("THEME_CHANGED", {})
