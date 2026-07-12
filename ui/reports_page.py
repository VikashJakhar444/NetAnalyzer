"""
Reports Page Module.
Audit report generation and export management.
"""
import os
import sys
import tkinter as tk
from tkinter import filedialog, messagebox
from datetime import datetime
import customtkinter as ctk

from ui.themes.tokens import Theme
from ui.widgets.controls import (
    page_header, surface_panel, primary_button,
    secondary_button, danger_button,
)
from ui.widgets.tables import DataTable

from core.logger import logger


class ReportsPage(ctk.CTkFrame):
    """Report generation and archive panel."""

    def __init__(self, parent, app_window, ctlr):
        super().__init__(parent, fg_color="transparent")
        self.controller = app_window
        self.ctlr = ctlr
        self.event_bus = ctlr.event_bus
        self._report_map = {}

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        header = page_header(
            self, "Reports",
            "Generate audit documents and manage export history",
        )
        header.grid(row=0, column=0, sticky="ew", padx=Theme.PAD_PAGE, pady=(Theme.PAD_PAGE, 8))

        # Row 1: Generate buttons
        generate = surface_panel(self)
        generate.grid(row=1, column=0, sticky="ew", padx=Theme.PAD_PAGE, pady=(8, 4))
        for col in range(3):
            generate.grid_columnconfigure(col, weight=1)

        self.btn_pdf = primary_button(generate, "PDF Report", self._confirm_generate_pdf, width=0)
        self.btn_pdf.grid(row=0, column=0, padx=(Theme.PAD_CARD, 6), pady=Theme.PAD_CARD, sticky="ew")

        self.btn_csv = secondary_button(generate, "CSV Export", self._confirm_generate_csv, width=0)
        self.btn_csv.grid(row=0, column=1, padx=6, pady=Theme.PAD_CARD, sticky="ew")

        self.btn_json = secondary_button(generate, "JSON Export", self._confirm_generate_json, width=0)
        self.btn_json.grid(row=0, column=2, padx=(6, Theme.PAD_CARD), pady=Theme.PAD_CARD, sticky="ew")

        # Row 2: Table
        table_outer = surface_panel(self)
        table_outer.grid(row=2, column=0, sticky="nsew", padx=Theme.PAD_PAGE, pady=(8, Theme.PAD_PAGE))
        table_outer.grid_columnconfigure(0, weight=1)
        table_outer.grid_rowconfigure(0, weight=1)

        self.table = DataTable(
            table_outer,
            columns=("date", "filename", "format", "score"),
            headings={
                "date": "Created", "filename": "Filename", "format": "Type",
                "score": "Security Score",
            },
            column_config={
                "date": {"width": 140, "anchor": "center"},
                "filename": {"width": 280, "anchor": "w"},
                "format": {"width": 70, "anchor": "center"},
                "score": {"width": 120, "anchor": "center"},
            },
            style_name="Reports.Treeview",
        )
        self.table.grid(row=0, column=0, sticky="nsew", padx=4, pady=4)
        self.table.tree.bind("<Double-1>", self._on_report_double_click)

        # Right-click context menu
        _dark = Theme.is_dark()
        self._ctx_menu = tk.Menu(
            self, tearoff=0,
            bg=Theme.BG_SURFACE[1] if _dark else Theme.BG_SURFACE[0],
            fg=Theme.TEXT_PRIMARY[1] if _dark else Theme.TEXT_PRIMARY[0],
            activebackground=Theme.BG_SURFACE_ALT[1] if _dark else Theme.BG_SURFACE_ALT[0],
            activeforeground=Theme.TEXT_PRIMARY[1] if _dark else Theme.TEXT_PRIMARY[0],
            font=Theme.font(11),
        )
        self._ctx_menu.add_command(label="Open", command=self._ctx_open_selected)
        self._ctx_menu.add_command(label="Save As...", command=self._ctx_saveas_selected)
        self._ctx_menu.add_separator()
        self._ctx_menu.add_command(label="Delete", command=self._ctx_delete_selected)
        self.table.tree.bind("<Button-3>", self._on_context_menu)

        self.refresh_reports_table()

        self.event_bus.subscribe("DEVICES_CLEARED", self._on_data_changed)
        self.event_bus.subscribe("PORT_DATA_CLEARED", self._on_data_changed)
        self.event_bus.subscribe("PACKET_DATA_CLEARED", self._on_data_changed)
        self.event_bus.subscribe("SCAN_FINISHED", self._on_data_changed)
        self.event_bus.subscribe("REPORT_DELETED", self._on_data_changed)

    def destroy(self):
        self.event_bus.unsubscribe("DEVICES_CLEARED", self._on_data_changed)
        self.event_bus.unsubscribe("PORT_DATA_CLEARED", self._on_data_changed)
        self.event_bus.unsubscribe("PACKET_DATA_CLEARED", self._on_data_changed)
        self.event_bus.unsubscribe("SCAN_FINISHED", self._on_data_changed)
        self.event_bus.unsubscribe("REPORT_DELETED", self._on_data_changed)
        super().destroy()

    def _on_data_changed(self, _data=None):
        self.after(10, self.refresh_reports_table)

    def _selected_report(self):
        sel = self.table.tree.selection()
        if not sel:
            return None
        return self._report_map.get(sel[0])

    def _on_context_menu(self, event):
        item = self.table.tree.identify_row(event.y)
        if item:
            self.table.tree.selection_set(item)
            self._ctx_menu.tk_popup(event.x_root, event.y_root)

    def _ctx_open_selected(self):
        r = self._selected_report()
        if r:
            self._open_report_by_id(r["report_id"])

    def _ctx_saveas_selected(self):
        r = self._selected_report()
        if r:
            self._saveas_report_by_id(r["report_id"])

    def _ctx_delete_selected(self):
        r = self._selected_report()
        if r:
            self._delete_report_by_id(r["report_id"])

    def _set_buttons_enabled(self, enabled: bool):
        for btn in (self.btn_pdf, self.btn_csv, self.btn_json):
            btn.configure(state="normal" if enabled else "disabled")

    def refresh_reports_table(self):
        self.table.refresh_theme()
        self.table.clear()
        self._report_map.clear()
        try:
            for r in self.ctlr.get_reports_history():
                score_val = r["security_score"] if r["security_score"] is not None else "\u2014"
                item_id = self.table.insert((
                    r["created_at"], r["filename"], r["format"],
                    score_val,
                ))
                self._report_map[item_id] = r
        except Exception as e:
            logger.error(f"Failed to load reports: {e}")

    def _open_report_detail_popup(self, r):
        win = ctk.CTkToplevel(self)
        win.title(f"Report: {r['filename']}")
        win.geometry("420x280")
        win.transient(self)
        win.grab_set()
        win.grid_columnconfigure(0, weight=0, minsize=100)
        win.grid_columnconfigure(1, weight=1)

        fields = [
            ("Filename", r["filename"]),
            ("Type", r["format"]),
            ("Score", str(r["security_score"]) if r["security_score"] is not None else "\u2014"),
            ("Created", r["created_at"]),
        ]
        for i, (label, value) in enumerate(fields):
            ctk.CTkLabel(win, text=label + ":", font=Theme.font(11, "bold"),
                         text_color=Theme.TEXT_SECONDARY).grid(
                row=i, column=0, sticky="e", padx=(16, 8), pady=(8, 0))
            ctk.CTkLabel(win, text=str(value), font=Theme.font(11),
                         text_color=Theme.TEXT_PRIMARY, wraplength=280,
                         anchor="w", justify="left").grid(
                row=i, column=1, sticky="ew", padx=(0, 16), pady=(8, 0))

        btn_frame = ctk.CTkFrame(win, fg_color="transparent")
        btn_frame.grid(row=len(fields) + 1, column=0, columnspan=2,
                       pady=(16, 12))

        rid = r["report_id"]
        primary_button(btn_frame, "Open", lambda: self._open_and_close(win, rid), width=90).pack(
            side=ctk.LEFT, padx=6)
        secondary_button(btn_frame, "Save As", lambda: self._saveas_and_close(win, rid), width=90).pack(
            side=ctk.LEFT, padx=6)
        danger_button(btn_frame, "Delete", lambda: self._delete_and_close(win, rid), width=90).pack(
            side=ctk.LEFT, padx=6)

    def _open_and_close(self, win, report_id):
        win.destroy()
        self._open_report_by_id(report_id)

    def _saveas_and_close(self, win, report_id):
        win.destroy()
        self._saveas_report_by_id(report_id)

    def _delete_and_close(self, win, report_id):
        win.destroy()
        self._delete_report_by_id(report_id)

    def _on_report_double_click(self, _event):
        r = self._selected_report()
        if r:
            self._open_report_detail_popup(r)

    def _open_report_by_id(self, report_id):
        filepath = self.ctlr.get_report_filepath(report_id)
        if not filepath:
            self.controller.update_status("Report file not found on disk")
            return
        os.startfile(filepath)
        self.controller.update_status("Opening report...")

    def _saveas_report_by_id(self, report_id):
        filepath = self.ctlr.get_report_filepath(report_id)
        if not filepath:
            self.controller.update_status("Report file not found on disk")
            return
        parent = self.winfo_toplevel()
        default_name = os.path.basename(filepath)
        dest = filedialog.asksaveasfilename(
            parent=parent,
            initialfile=default_name,
            defaultextension=os.path.splitext(default_name)[1],
            filetypes=[("All Files", "*.*")],
            title="Save Report As",
        )
        if dest:
            try:
                with open(filepath, "rb") as src_f:
                    with open(dest, "wb") as dst_f:
                        dst_f.write(src_f.read())
                self.controller.update_status(f"Report saved to: {os.path.basename(dest)}")
            except Exception as e:
                logger.error(f"Could not save report: {e}")
                messagebox.showerror("Save Error", "Could not save the report. Check permissions and available disk space.")

    def _delete_report_by_id(self, report_id):
        r = self.ctlr.get_report_detail(report_id)
        if not r:
            return
        confirm = messagebox.askyesno(
            "Delete Report",
            f"Delete \"{r['filename']}\" from history and disk?",
            icon="warning",
        )
        if confirm:
            self.ctlr.delete_report(report_id)
            self.refresh_reports_table()
            self.controller.update_status(f"Report deleted: {r['filename']}")

    # ── Generate (with confirmation popup) ──

    def _confirm_generate(self, fmt: str, ext: str, callback):
        """Shows a confirmation popup before generating a report."""
        descriptions = {
            "PDF": "Full security audit report with executive summary, device listing,\nopen ports table, and remediation recommendations.",
            "CSV": "Tabular export of all discovered devices and their open ports\nwith risk ratings, suitable for spreadsheet analysis.",
            "JSON": "Complete machine-readable data dump including devices,\nport scans, protocol distribution, and recommendations.",
        }
        win = ctk.CTkToplevel(self)
        win.title(f"Generate {fmt} Report")
        win.geometry("420x240")
        win.transient(self)
        win.grab_set()
        win.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            win, text=f"Generate {fmt} Report?",
            font=Theme.font(15, "bold"), text_color=Theme.TEXT_PRIMARY,
        ).grid(row=0, column=0, pady=(18, 4))

        ctk.CTkLabel(
            win, text=descriptions.get(fmt, ""),
            font=Theme.font(11), text_color=Theme.TEXT_SECONDARY,
            justify="left",
        ).grid(row=1, column=0, padx=24, pady=(4, 12))

        info = ctk.CTkLabel(
            win, text="This will include all currently scanned data from the database.",
            font=Theme.font(10), text_color=Theme.TEXT_MUTED,
        )
        info.grid(row=2, column=0, padx=24, pady=(0, 12))

        btn_frame = ctk.CTkFrame(win, fg_color="transparent")
        btn_frame.grid(row=3, column=0, pady=(4, 16))

        primary_button(btn_frame, "Generate", lambda: self._do_generate(win, ext, callback), width=100).pack(
            side=ctk.LEFT, padx=8)
        secondary_button(btn_frame, "Cancel", lambda: win.destroy(), width=100).pack(
            side=ctk.LEFT, padx=8)

    def _do_generate(self, win, ext, callback):
        win.destroy()
        callback(f"network_scan_report_{int(datetime.now().timestamp())}.{ext}")

    def _confirm_generate_pdf(self):
        self._confirm_generate("PDF", "pdf", self._run_generate_pdf)

    def _confirm_generate_csv(self):
        self._confirm_generate("CSV", "csv", self._run_generate_csv)

    def _confirm_generate_json(self):
        self._confirm_generate("JSON", "json", self._run_generate_json)

    def _run_generate_pdf(self, filename):
        self._set_buttons_enabled(False)
        self.controller.update_status("Generating PDF report...")
        try:
            path = self.ctlr.generate_pdf_report(filename)
            if path:
                self.controller.update_status(f"PDF report saved: {filename}")
            else:
                self.controller.update_status("PDF generation failed")
            self.refresh_reports_table()
        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            self.controller.update_status("PDF generation failed")
        finally:
            self._set_buttons_enabled(True)

    def _run_generate_csv(self, filename):
        self._set_buttons_enabled(False)
        self.controller.update_status("Generating CSV export...")
        try:
            path = self.ctlr.generate_csv_report(filename)
            if path:
                self.controller.update_status(f"CSV export saved: {filename}")
            else:
                self.controller.update_status("CSV export failed")
            self.refresh_reports_table()
        except Exception as e:
            logger.error(f"CSV export failed: {e}")
            self.controller.update_status("CSV generation failed")
        finally:
            self._set_buttons_enabled(True)

    def _run_generate_json(self, filename):
        self._set_buttons_enabled(False)
        self.controller.update_status("Generating JSON export...")
        try:
            path = self.ctlr.generate_json_report(filename)
            if path:
                self.controller.update_status(f"JSON export saved: {filename}")
            else:
                self.controller.update_status("JSON export failed")
            self.refresh_reports_table()
        except Exception as e:
            logger.error(f"JSON export failed: {e}")
            self.controller.update_status("JSON generation failed")
        finally:
            self._set_buttons_enabled(True)


