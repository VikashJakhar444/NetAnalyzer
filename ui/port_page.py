"""
Port Scanner Page Module.
TCP port auditing with risk classification.
"""
import sys
import tkinter as tk
import customtkinter as ctk

from ui.themes.tokens import Theme
from ui.widgets.controls import (
    page_header, surface_panel, form_label, form_entry,
    option_menu, combo_box, primary_button, secondary_button, danger_button,
)
from ui.widgets.tables import DataTable

try:
    from core.logger import logger
    from core.validators import validate_ip
except ImportError:
    from core.compat import DummyLogger
    logger = DummyLogger()


class PortScannerPage(ctk.CTkFrame):
    """TCP port audit panel."""

    def __init__(self, parent, app_window, ctlr):
        super().__init__(parent, fg_color="transparent")
        self.controller = app_window
        self.ctlr = ctlr
        self.event_bus = ctlr.event_bus

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        header = page_header(
            self, "Port Scanner",
            "Identify open services and assess exposure risk on a target host",
        )
        header.grid(row=0, column=0, sticky="ew", padx=Theme.PAD_PAGE, pady=(Theme.PAD_PAGE, 8))

        control = surface_panel(self)
        control.grid(row=1, column=0, sticky="ew", padx=Theme.PAD_PAGE, pady=8)

        # Left panel: labels, entries, dropdowns
        left = ctk.CTkFrame(control, fg_color="transparent")
        left.pack(side=ctk.LEFT, fill=ctk.BOTH, expand=True)

        form_label(left, "Target").grid(row=0, column=0, padx=(Theme.PAD_CARD, 6), pady=Theme.PAD_CARD, sticky="w")
        self.ip_entry = combo_box(left, values=["127.0.0.1", "::1"], width=160)
        self.ip_entry.set("127.0.0.1")
        self.ip_entry.grid(row=0, column=1, padx=4, pady=Theme.PAD_CARD, sticky="w")

        self.port_start_var = ctk.StringVar(value="1")
        self.port_start = form_entry(left, width=45, placeholder_text="1", textvariable=self.port_start_var)
        self.port_start.grid(row=0, column=2, padx=2, pady=Theme.PAD_CARD, sticky="w")

        self.port_end_var = ctk.StringVar(value="94")
        self.port_end = form_entry(left, width=45, placeholder_text="1024", textvariable=self.port_end_var)
        self.port_end.grid(row=0, column=3, padx=2, pady=Theme.PAD_CARD, sticky="w")

        self.scan_mode_var = ctk.StringVar(value="Quick")
        self.scan_mode_var.trace_add("write", lambda *_: self._on_mode_change(self.scan_mode_var.get()))
        self.scan_mode = option_menu(left, ["Quick", "Full", "Extreme", "Custom"], width=70,
                                     variable=self.scan_mode_var)
        self.scan_mode.grid(row=0, column=4, padx=6, pady=Theme.PAD_CARD, sticky="w")

        form_label(left, "Proto").grid(row=0, column=5, padx=(6, 4), pady=Theme.PAD_CARD, sticky="w")
        self.protocol = option_menu(left, ["TCP", "UDP"], width=50, command=lambda v: self._on_protocol_change(v))
        self.protocol.grid(row=0, column=6, padx=2, pady=Theme.PAD_CARD, sticky="w")

        # Right panel: action buttons, always anchored to right edge
        right = ctk.CTkFrame(control, fg_color="transparent")
        right.pack(side=ctk.RIGHT, fill=ctk.Y, padx=(0, 2))

        self.start_btn = primary_button(right, "Scan", self.on_start_scan, width=70)
        self.start_btn.pack(side=ctk.LEFT, padx=(3, 3), pady=Theme.PAD_CARD)

        self.stop_btn = danger_button(right, "Abort", self.on_stop_scan, width=60, state="disabled")
        self.stop_btn.pack(side=ctk.LEFT, padx=(3, 3), pady=Theme.PAD_CARD)

        self.clean_btn = secondary_button(right, "Clean", self.on_clean_table, width=55)
        self.clean_btn.pack(side=ctk.LEFT, padx=(3, 3), pady=Theme.PAD_CARD)
        self.export_btn = primary_button(right, "Export CSV", self.on_export_csv, width=80)
        self.export_btn.pack(side=ctk.LEFT, padx=(3, 3), pady=Theme.PAD_CARD)

        self.progress_bar = ctk.CTkProgressBar(
            self, mode="determinate", height=3,
            progress_color=Theme.ACCENT, fg_color=Theme.BORDER,
        )
        self.progress_bar.grid(row=2, column=0, sticky="ew", padx=Theme.PAD_PAGE, pady=(4, 0))
        self.progress_bar.set(0)

        table_outer = surface_panel(self)
        table_outer.grid(row=3, column=0, sticky="nsew", padx=Theme.PAD_PAGE, pady=(8, Theme.PAD_PAGE))
        table_outer.grid_columnconfigure(0, weight=1)
        table_outer.grid_rowconfigure(0, weight=1)

        self.table = DataTable(
            table_outer,
            columns=("port", "protocol", "service", "state", "risk", "banner"),
            headings={
                "port": "Port", "protocol": "Protocol", "service": "Service",
                "state": "State", "risk": "Risk", "banner": "Banner",
            },
            column_config={
                "port": {"width": 70, "anchor": "center"},
                "protocol": {"width": 80, "anchor": "center"},
                "service": {"width": 110, "anchor": "center"},
                "state": {"width": 80, "anchor": "center"},
                "risk": {"width": 90, "anchor": "center"},
                "banner": {"width": 260, "anchor": "w"},
            },
            style_name="Port.Treeview",
        )
        self.table.grid(row=0, column=0, sticky="nsew", padx=4, pady=4)
        self.table.tree.bind("<Double-1>", self._on_port_double_click)

        self.table.tag_configure("High", foreground=Theme.RISK_HIGH[1] if Theme.is_dark() else Theme.RISK_HIGH[0])
        self.table.tag_configure("Medium", foreground=Theme.RISK_MEDIUM[1] if Theme.is_dark() else Theme.RISK_MEDIUM[0])
        self.table.tag_configure("Low", foreground=Theme.RISK_LOW[1] if Theme.is_dark() else Theme.RISK_LOW[0])
        self.table.tag_configure("None", foreground=Theme.RISK_NONE[1] if Theme.is_dark() else Theme.RISK_NONE[0])

        self.event_bus.subscribe("PORT_DISCOVERED", self._on_port_discovered_event)
        self.event_bus.subscribe("PORT_SCAN_PROGRESS", self._on_port_scan_progress_event)
        self.event_bus.subscribe("PORT_SCAN_FINISHED", self._on_port_scan_finished_event)
        self.event_bus.subscribe("PORT_SCAN_ERROR", self._on_port_scan_error_event)
        self.event_bus.subscribe("DEVICE_DISCOVERED", self._on_device_discovered)
        self.event_bus.subscribe("DEVICES_CLEARED", self._on_devices_cleared)
        self.event_bus.subscribe("PORT_DATA_CLEARED", self._on_port_data_cleared)

        self._table_items = {}
        self._alerted_ports = set()
        self._on_mode_change("Quick")

    def destroy(self):
        self.event_bus.unsubscribe("PORT_DISCOVERED", self._on_port_discovered_event)
        self.event_bus.unsubscribe("PORT_SCAN_PROGRESS", self._on_port_scan_progress_event)
        self.event_bus.unsubscribe("PORT_SCAN_FINISHED", self._on_port_scan_finished_event)
        self.event_bus.unsubscribe("PORT_SCAN_ERROR", self._on_port_scan_error_event)
        self.event_bus.unsubscribe("DEVICE_DISCOVERED", self._on_device_discovered)
        self.event_bus.unsubscribe("DEVICES_CLEARED", self._on_devices_cleared)
        self.event_bus.unsubscribe("PORT_DATA_CLEARED", self._on_port_data_cleared)
        super().destroy()

    def _quick_port_count(self) -> int:
        try:
            if self.protocol.get() == "UDP":
                from core.constants import TOP_COMMON_UDP_PORTS
                return len(set(TOP_COMMON_UDP_PORTS))
            from core.constants import TOP_COMMON_PORTS
            return len(set(TOP_COMMON_PORTS))
        except Exception:
            return 100

    def _on_protocol_change(self, choice: str):
        self._on_mode_change(self.scan_mode_var.get())

    def _on_mode_change(self, choice: str):
        if choice == "Quick":
            cnt = self._quick_port_count()
            self.port_start_var.set("1")
            self.port_end_var.set(str(cnt))
            self.port_start.configure(state="disabled")
            self.port_end.configure(state="disabled")
        elif choice == "Full":
            self.port_start_var.set("1")
            self.port_end_var.set("1024")
            self.port_start.configure(state="disabled")
            self.port_end.configure(state="disabled")
        elif choice == "Extreme":
            self.port_start_var.set("1")
            self.port_end_var.set("65535")
            self.port_start.configure(state="disabled")
            self.port_end.configure(state="disabled")
        else:
            self.port_start.configure(state="normal")
            self.port_end.configure(state="normal")

    def on_start_scan(self):
        ip = self.ip_entry.get().strip()
        mode = self.scan_mode_var.get()
        proto = self.protocol.get()
        if not ip:
            return

        if not validate_ip(ip):
            logger.error(f"Invalid IP: {ip}")
            self.controller.update_status(f"Invalid IP address — {ip}")
            return

        custom_list = None
        if mode == "Custom":
            try:
                start = int(self.port_start_var.get())
                end = int(self.port_end_var.get())
                if not (1 <= start <= 65535 and 1 <= end <= 65535):
                    raise ValueError("Port out of 1–65535 range")
                if start > end:
                    start, end = end, start
                custom_list = list(range(start, end + 1))
            except ValueError:
                self.controller.update_status("Invalid port range (1–65535)")
                return

        # Remove only table rows matching this protocol (preserves other protocol results)
        for key, item_id in list(self._table_items.items()):
            if key[1] == proto:
                self.table.tree.delete(item_id)
                del self._table_items[key]

        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.ip_entry.configure(state="readonly")
        if mode != "Custom":
            self.port_start.configure(state="disabled")
            self.port_end.configure(state="disabled")
        self.scan_mode.configure(state="disabled")
        self.protocol.configure(state="disabled")
        self.progress_bar.set(0)
        self.ctlr.start_port_scan(ip, mode, custom_list, protocol=proto)

    def on_stop_scan(self):
        self.ctlr.stop_port_scan()
        self.on_ui_reset()

    def on_clean_table(self):
        win = ctk.CTkToplevel(self)
        win.title("Confirm Clean")
        win.geometry("360x160")
        win.transient(self)
        win.grab_set()
        win.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(win, text="Delete all port scan data?",
                     font=Theme.font(14, "bold")).grid(row=0, column=0, pady=(20, 4))
        ctk.CTkLabel(win, text="Devices will be preserved.",
                     font=Theme.font(11), text_color=Theme.TEXT_SECONDARY).grid(row=1, column=0, pady=(0, 16))
        btn_frame = ctk.CTkFrame(win, fg_color="transparent")
        btn_frame.grid(row=2, column=0)
        secondary_button(btn_frame, "Cancel", win.destroy, width=80).pack(side=ctk.LEFT, padx=6)
        danger_button(btn_frame, "Clean", lambda: (win.destroy(), self._do_clean()), width=80).pack(side=ctk.LEFT, padx=6)

    def _do_clean(self):
        self.table.clear()
        self._table_items.clear()
        self.ctlr.clean_port_scan_data()

    def on_export_csv(self):
        items = []
        for item_id in self.table.get_children():
            vals = self.table.item(item_id, "values")
            items.append(vals)
        if not items:
            self.controller.update_status("No port data to export")
            return
        from datetime import datetime
        default_name = f"ports_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        path = tk.filedialog.asksaveasfilename(
            parent=self, title="Export Ports CSV",
            defaultextension=".csv", initialfile=default_name,
            filetypes=[("CSV files", "*.csv")]
        )
        if not path:
            return
        try:
            import csv
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Port", "Protocol", "Service", "State", "Risk", "Banner"])
                for v in items:
                    writer.writerow([v[0], v[1], v[2], v[3], v[4], v[5]])
            self.controller.update_status(f"Exported {len(items)} ports to {path}")
        except Exception as e:
            logger.error(f"Port export failed: {e}")
            self.controller.update_status("Export failed")

    def on_ui_reset(self):
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.ip_entry.configure(state="normal")
        self.scan_mode.configure(state="normal")
        self.protocol.configure(state="normal")
        self.progress_bar.set(0)
        self._on_mode_change(self.scan_mode.get())

    def _on_port_discovered_event(self, data: dict):
        port_info = data.get("port_info")
        if not port_info:
            return
        self.after(10, self._insert_port, port_info)
        risk = port_info.get("risk", "None")
        ip = data.get("target_ip", "")
        port = port_info.get("port", 0)
        proto = port_info.get("protocol", "TCP")
        alert_key = (ip, port, proto)
        if risk == "High" and alert_key not in self._alerted_ports:
            self._alerted_ports.add(alert_key)
            self.after(10, self._show_alert, ip, port, proto)

    def _insert_port(self, p: dict):
        key = (p["port"], p["protocol"])
        if key in self._table_items:
            self.table.tree.delete(self._table_items[key])
        risk = p["risk"]
        item_id = self.table.insert((
            p["port"], p["protocol"], p["service"], p["state"], risk, p["banner"] or "—",
        ), tags=(risk,))
        self._table_items[key] = item_id

    def _show_alert(self, ip, port, proto):
        win = ctk.CTkToplevel(self)
        win.title("High Risk Port Alert")
        win.geometry("380x180")
        win.transient(self)
        win.grab_set()
        win.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(win, text="⚠ High Risk Port Detected",
                     font=Theme.font(16, "bold"), text_color=Theme.DANGER).grid(
            row=0, column=0, pady=(20, 4))
        ctk.CTkLabel(win, text=f"{proto} port {port} is open on {ip}",
                     font=Theme.font(12), text_color=Theme.TEXT_PRIMARY).grid(
            row=1, column=0, pady=(0, 8))
        ctk.CTkLabel(win, text="This service has known security vulnerabilities.",
                     font=Theme.font(11), text_color=Theme.TEXT_SECONDARY).grid(
            row=2, column=0, pady=(0, 16))
        ctk.CTkButton(win, text="Dismiss", command=win.destroy,
                      fg_color=Theme.ACCENT, width=80).grid(row=3, column=0, pady=(0, 16))

    def _on_port_scan_progress_event(self, data: dict):
        progress = data.get("progress", 0) / 100.0
        self.after(10, lambda: self.progress_bar.set(progress))

    def _on_port_scan_error_event(self, message):
        logger.error(f"Port scan error: {message}")
        self.after(10, lambda: self.controller.update_status(f"Port scan error: {message}"))
        self.after(10, self.on_ui_reset)

    def _on_port_scan_finished_event(self, data: dict):
        self.after(100, self._resort_table)
        self.after(300, self.on_ui_reset)

    def _resort_table(self):
        try:
            items = [(self.table.item(item_id, "values"), item_id) for item_id in self.table.get_children()]
            state_order = {"Open": 0, "Open|Filtered": 1, "Closed": 2}
            proto_order = {"TCP": 0, "UDP": 1}
            items.sort(key=lambda x: (
                state_order.get(x[0][3], 99),
                proto_order.get(x[0][1], 99),
                int(x[0][0]),
            ))
            for i, (_, item_id) in enumerate(items):
                self.table.tree.move(item_id, "", i)
        except Exception as e:
            logger.error(f"Resort failed: {e}")

    def _on_devices_cleared(self, _data=None):
        self.after(10, self._refresh_ip_dropdown)

    def _on_port_data_cleared(self, _data=None):
        self._table_items.clear()
        self.after(10, self.table.clear)

    _DEFAULT_IPS = {"127.0.0.1", "::1", ""}

    def _on_device_discovered(self, device: dict):
        ip = device.get("ip_address", "")
        if ip and self.ip_entry.get().strip() in self._DEFAULT_IPS:
            self.after(10, lambda: self._set_target_ip(ip))

    def _set_target_ip(self, ip: str):
        self.ip_entry.set(ip)

    def _refresh_ip_dropdown(self):
        try:
            devices = self.ctlr.get_devices()
            ips = [d["ip_address"] for d in devices]
            for default in ("127.0.0.1", "::1"):
                if default not in ips:
                    ips.insert(0, default)
            self.ip_entry.configure(values=ips)
            current = self.ip_entry.get().strip()
            if current in self._DEFAULT_IPS and len(ips) > 2:
                self._set_target_ip(ips[2])
            elif current not in ips:
                self._set_target_ip("127.0.0.1")
        except Exception:
            pass

    def _on_port_double_click(self, event):
        selected = self.table.tree.selection()
        if not selected:
            return
        vals = self.table.item(selected[0], "values")
        self._show_port_detail(vals)

    def _show_port_detail(self, vals):
        port = int(vals[0])
        protocol = vals[1]
        ip = self.ip_entry.get().strip()
        detail = self.ctlr.get_port_detail(ip, port, protocol)
        cves = self.ctlr.get_device_vulnerabilities(ip)
        port_cves = [e for e in cves.get("entries", []) if e.get("port") == port]
        win = ctk.CTkToplevel(self)
        win.title(f"Port {vals[0]} / {vals[1]}")
        win.geometry("500x500")
        win.transient(self)
        win.grab_set()
        win.grid_columnconfigure(0, weight=0, minsize=100)
        win.grid_columnconfigure(1, weight=1)

        risk_colors = {"High": Theme.RISK_HIGH, "Medium": Theme.RISK_MEDIUM,
                       "Low": Theme.RISK_LOW, "None": Theme.RISK_NONE}
        scan_time = detail["scan_time"] if detail else "\u2014"
        hostname = detail.get("hostname", "\u2014") if detail else "\u2014"
        fields = [
            ("Port", vals[0]),
            ("Protocol", vals[1]),
            ("Service", vals[2]),
            ("State", vals[3]),
            ("Risk", vals[4]),
            ("Banner", vals[5]),
            ("IP Address", ip),
            ("Device", hostname),
            ("Scan Time", scan_time),
        ]
        row_idx = 0
        for label, value in fields:
            ctk.CTkLabel(win, text=label + ":", font=Theme.font(11, "bold"),
                         text_color=Theme.TEXT_SECONDARY).grid(
                row=row_idx, column=0, sticky="e", padx=(16, 8), pady=(6, 0))
            is_risk = label == "Risk"
            if is_risk:
                clr = risk_colors.get(vals[4], Theme.TEXT_PRIMARY)
                c = clr[1] if Theme.is_dark() else clr[0]
            else:
                c = Theme.TEXT_PRIMARY
            ctk.CTkLabel(win, text=str(value), font=Theme.font(11),
                         text_color=c, wraplength=320,
                         anchor="w", justify="left").grid(
                row=row_idx, column=1, sticky="ew", padx=(0, 16), pady=(6, 0))
            row_idx += 1

        if port_cves:
            ctk.CTkLabel(win, text="CVEs:", font=Theme.font(11, "bold"),
                         text_color=Theme.TEXT_SECONDARY).grid(
                row=row_idx, column=0, sticky="ne", padx=(16, 8), pady=(10, 0))
            cve_frame = ctk.CTkScrollableFrame(win, height=140, fg_color="transparent")
            cve_frame.grid(row=row_idx, column=1, sticky="ew", padx=(0, 16), pady=(10, 0))
            for cve in port_cves:
                severity_color = {"Critical": "#DC2626", "High": "#EA580C",
                                  "Medium": "#D97706", "Low": "#16A34A"}.get(cve.get("severity", ""), Theme.TEXT_PRIMARY)
                cve_header = f"[{cve.get('severity','')}] {cve.get('cve','')}  CVSS {cve.get('cvss','')}"
                ctk.CTkLabel(cve_frame, text=cve_header, font=Theme.font(10, "bold"),
                             text_color=severity_color, wraplength=320,
                             anchor="w", justify="left").pack(anchor="w", pady=(3, 0))
                ctk.CTkLabel(cve_frame, text=cve.get("cvss_vector", ""), font=Theme.font(9),
                             text_color=Theme.TEXT_MUTED, wraplength=320,
                             anchor="w", justify="left").pack(anchor="w", pady=0)
                ctk.CTkLabel(cve_frame, text=cve.get("description", ""), font=Theme.font(9),
                             text_color=Theme.TEXT_SECONDARY, wraplength=320,
                             anchor="w", justify="left").pack(anchor="w", pady=(1, 2))
                solution = cve.get("solution", "")
                if solution:
                    ctk.CTkLabel(cve_frame, text=f"Fix: {solution}", font=Theme.font(9),
                                 text_color="#16A34A", wraplength=320,
                                 anchor="w", justify="left").pack(anchor="w", pady=(0, 4))
            row_idx += 1

    def refresh_data(self):
        """Reloads historical port scans from database. Also fills IP dropdown from discovered devices."""
        self.table.refresh_theme()
        self.table.tag_configure("High", foreground=Theme.RISK_HIGH[1] if Theme.is_dark() else Theme.RISK_HIGH[0])
        self.table.tag_configure("Medium", foreground=Theme.RISK_MEDIUM[1] if Theme.is_dark() else Theme.RISK_MEDIUM[0])
        self.table.tag_configure("Low", foreground=Theme.RISK_LOW[1] if Theme.is_dark() else Theme.RISK_LOW[0])
        self.table.tag_configure("None", foreground=Theme.RISK_NONE[1] if Theme.is_dark() else Theme.RISK_NONE[0])
        self.table.clear()
        self._table_items.clear()
        try:
            for s in self.ctlr.get_port_scans():
                key = (s["port"], s["protocol"])
                if key in self._table_items:
                    continue
                item_id = self.table.insert((
                    s["port"], s["protocol"], s["service"], s["state"],
                    s["risk"], s.get("banner") or "—",
                ), tags=(s["risk"],))
                self._table_items[key] = item_id
            self._resort_table()
        except Exception as e:
            logger.error(f"Failed to refresh ports: {e}")
        self._refresh_ip_dropdown()
