import os
import sys
import customtkinter as ctk

from ui.themes.tokens import Theme
from ui.widgets.controls import (
    page_header, surface_panel, primary_button, secondary_button, danger_button,
    option_menu, form_entry,
)

try:
    from core.constants import LOG_FILE
    from core.logger import logger
except ImportError:
    from pathlib import Path
    LOG_FILE = Path(__file__).resolve().parent.parent / "logs" / "scanner.log"
    from core.compat import DummyLogger
    logger = DummyLogger()


LEVEL_COLORS = {
    "DEBUG": Theme.TEXT_MUTED,
    "INFO": Theme.SUCCESS,
    "WARNING": Theme.WARNING,
    "ERROR": Theme.DANGER,
    "CRITICAL": Theme.DANGER,
}


class LogViewerPage(ctk.CTkFrame):
    def __init__(self, parent, app_window, ctlr):
        super().__init__(parent, fg_color="transparent")
        self.controller = app_window
        self._timer_id = None
        self._all_lines = []

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        header = page_header(self, "Log Viewer", "Application runtime logs with live monitoring")
        header.grid(row=0, column=0, sticky="ew", padx=Theme.PAD_PAGE, pady=(Theme.PAD_PAGE, 8))

        toolbar = ctk.CTkFrame(self, fg_color="transparent")
        toolbar.grid(row=1, column=0, sticky="ew", padx=Theme.PAD_PAGE, pady=(0, 8))
        toolbar.grid_columnconfigure(3, weight=1)

        filter_frame = ctk.CTkFrame(toolbar, fg_color="transparent")
        filter_frame.grid(row=0, column=0, sticky="w")

        ctk.CTkLabel(filter_frame, text="Level", font=Theme.font(12),
                      text_color=Theme.TEXT_SECONDARY).pack(side=ctk.LEFT, padx=(0, 6))
        self._level_var = ctk.StringVar(value="ALL")
        self._level_menu = option_menu(filter_frame, ["ALL", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                                       variable=self._level_var, width=110,
                                       command=self._on_filter_changed)
        self._level_menu.pack(side=ctk.LEFT, padx=(0, 12))

        ctk.CTkLabel(filter_frame, text="Search", font=Theme.font(12),
                      text_color=Theme.TEXT_SECONDARY).pack(side=ctk.LEFT, padx=(0, 6))
        self._search_var = ctk.StringVar()
        self._search_var.trace_add("write", self._on_filter_changed)
        self._search_entry = form_entry(filter_frame, width=200, textvariable=self._search_var,
                                        placeholder_text="Type to filter logs...")
        self._search_entry.pack(side=ctk.LEFT)

        action_frame = ctk.CTkFrame(toolbar, fg_color="transparent")
        action_frame.grid(row=0, column=4, sticky="e")

        self._info_lbl = ctk.CTkLabel(action_frame, text="", font=Theme.font(11),
                                       text_color=Theme.TEXT_MUTED)
        self._info_lbl.pack(side=ctk.LEFT, padx=(0, 12))

        primary_button(action_frame, "Refresh", self._refresh, width=80).pack(side=ctk.LEFT, padx=(0, 6))
        secondary_button(action_frame, "Copy", self._copy_logs, width=70).pack(side=ctk.LEFT, padx=(0, 6))
        danger_button(action_frame, "Clear", self._clear_logs, width=70).pack(side=ctk.LEFT)

        panel = surface_panel(self)
        panel.grid(row=2, column=0, sticky="nsew", padx=Theme.PAD_PAGE, pady=(0, Theme.PAD_PAGE))
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_rowconfigure(0, weight=1)

        self._textbox = ctk.CTkTextbox(
            panel, wrap="none", font=Theme.font(11),
            fg_color=Theme.BG_INPUT, text_color=Theme.TEXT_PRIMARY,
            corner_radius=Theme.RADIUS_SM,
        )
        self._textbox.grid(row=0, column=0, sticky="nsew", padx=1, pady=1)

        for level, color in LEVEL_COLORS.items():
            light, dark = color
            tag_color = light if Theme.is_dark() else dark
            self._textbox._textbox.tag_configure(level, foreground=tag_color)

        self._refresh()
        self._start_auto_refresh()

    def _on_filter_changed(self, *_):
        self._apply_filter()

    def _apply_filter(self):
        self._textbox.delete("1.0", "end")
        level_filter = self._level_var.get()
        search_text = self._search_var.get().lower()

        count = 0
        for line in self._all_lines:
            if level_filter != "ALL":
                level_tag = f"[{level_filter}]"
                if level_tag not in line:
                    continue
            if search_text and search_text not in line.lower():
                continue

            line_level = "DEBUG"
            for lvl in ["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"]:
                if f"[{lvl}]" in line:
                    line_level = lvl
                    break

            self._textbox.insert("end", line, line_level)
            count += 1

        self._info_lbl.configure(text=f"{count} / {len(self._all_lines)} lines")

    def _refresh(self):
        log_path = str(LOG_FILE)
        if not os.path.isfile(log_path):
            self._all_lines = ["[INFO] [log_viewer] - Log file not found. Waiting for log entries...\n"]
            self._info_lbl.configure(text="0 lines")
            self._apply_filter()
            return

        try:
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                raw = f.read()
            self._all_lines = raw.splitlines(keepends=True)
        except Exception as e:
            self._all_lines = [f"[ERROR] [log_viewer] - Failed to read log: {e}\n"]

        size = os.path.getsize(log_path)
        size_str = f"{size / 1024:.1f} KB" if size < 1024 * 1024 else f"{size / (1024*1024):.1f} MB"
        self._info_lbl.configure(text=f"{size_str}  ·  {len(self._all_lines)} total")
        self._apply_filter()

    def _copy_logs(self):
        text = self._textbox.get("1.0", "end-1c")
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)
            self.controller.update_status("Logs copied to clipboard")

    def _clear_logs(self):
        popup = ctk.CTkToplevel(self)
        popup.title("Clear Logs")
        popup.geometry("360x160")
        popup.transient(self)
        popup.grab_set()
        popup.resizable(False, False)

        frame = surface_panel(popup)
        frame.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(
            frame, text="Clear all log entries?",
            font=Theme.font(14, "bold"),
            text_color=Theme.TEXT_PRIMARY,
        ).pack(pady=(16, 4))

        ctk.CTkLabel(
            frame, text="This will empty the log file permanently.",
            font=Theme.font(11),
            text_color=Theme.TEXT_MUTED,
        ).pack(pady=(0, 16))

        btn_row = ctk.CTkFrame(frame, fg_color="transparent")
        btn_row.pack()

        danger_button(btn_row, "Clear", lambda: self._do_clear(popup), width=100).pack(
            side=ctk.LEFT, padx=(0, 8))
        secondary_button(btn_row, "Cancel", popup.destroy, width=100).pack(side=ctk.LEFT)

    def _do_clear(self, popup):
        popup.destroy()
        try:
            open(str(LOG_FILE), "w", encoding="utf-8").close()
            logger.info("Log file cleared by user")
        except Exception as e:
            logger.error(f"Failed to clear log file: {e}")
        self._refresh()
        self.controller.update_status("Log file cleared")

    def _start_auto_refresh(self):
        self._refresh()
        self._timer_id = self.after(5000, self._start_auto_refresh)

    def destroy(self):
        if self._timer_id:
            self.after_cancel(self._timer_id)
            self._timer_id = None
        super().destroy()
