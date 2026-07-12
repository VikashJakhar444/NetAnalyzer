"""
Network Scanner Page Module.
Subnet discovery with device listing, IP range filter, search.
"""
import ipaddress
import json
import sys
import tkinter as tk
from pathlib import Path
import customtkinter as ctk

from ui.themes.tokens import Theme
from ui.widgets.controls import (
    page_header, surface_panel, form_label, form_entry,
    option_menu, primary_button, danger_button, secondary_button,
)
from ui.widgets.tables import DataTable

try:
    from core.helpers import get_local_subnet
    from core.logger import logger
    from core.validators import validate_network
except ImportError:
    from core.compat import DummyLogger
    logger = DummyLogger()


class NetworkScannerPage(ctk.CTkFrame):
    """Subnet device discovery panel with range filter, search, and export."""

    def __init__(self, parent, app_window, ctlr):
        super().__init__(parent, fg_color="transparent")
        self.controller = app_window
        self.ctlr = ctlr
        self.event_bus = ctlr.event_bus
        self._device_count = 0
        self._all_item_ids = []
        self._data_cleared = False

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        # ── Header ──
        header = page_header(
            self, "Device Scanner",
            "Discover active hosts on your local network segment",
        )
        header.grid(row=0, column=0, sticky="ew", padx=Theme.PAD_PAGE, pady=(Theme.PAD_PAGE, 8))
        # ── Control panel ──
        self.control = surface_panel(self)
        self.control.grid(row=1, column=0, sticky="ew", padx=Theme.PAD_PAGE, pady=8)
        self.control.grid_columnconfigure(0, weight=1)

        # Sub-frame for Row 0 controls
        self.row0_frame = ctk.CTkFrame(self.control, fg_color="transparent")
        self.row0_frame.grid(row=0, column=0, sticky="ew", pady=(Theme.PAD_CARD, 2))
        self.row0_frame.grid_columnconfigure(8, weight=1)  # Spacer column

        # Row 0: Subnet + IPv6 toggle + mode + spacer + start/stop/clear
        form_label(self.row0_frame, "Subnet").grid(row=0, column=0, padx=(Theme.PAD_CARD, 6), pady=Theme.PAD_CARD, sticky="w")
        self.subnet_entry = form_entry(self.row0_frame, width=100, placeholder_text="e.g. 192.168.1.0/24 or fd00::/8")
        self._v4_subnet = get_local_subnet(version=4)
        self._v6_subnet_raw = get_local_subnet(version=6)
        self._v6_subnet = self._v6_subnet_raw if self._v6_subnet_raw not in ("::1/128", "fd00::/64") else "fd00::/8"
        self._use_ipv6 = tk.BooleanVar(value=False)
        self.subnet_entry.insert(0, self._v4_subnet)
        self.subnet_entry.grid(row=0, column=1, padx=4, pady=Theme.PAD_CARD, sticky="w")

        def _toggle_ip_version():
            if self._use_ipv6.get():
                self.subnet_entry.delete(0, "end")
                self.subnet_entry.insert(0, self._v6_subnet)
            else:
                self.subnet_entry.delete(0, "end")
                self.subnet_entry.insert(0, self._v4_subnet)
        self._v6_toggle = ctk.CTkCheckBox(
            self.row0_frame, text="IPv6", variable=self._use_ipv6, command=_toggle_ip_version,
            font=Theme.font(11), text_color=Theme.TEXT_SECONDARY,
            onvalue=True, offvalue=False,
        )
        self._v6_toggle.grid(row=0, column=2, padx=(0, 4), pady=Theme.PAD_CARD, sticky="w")

        self.scan_mode = tk.StringVar(value="Quick")
        self.mode_quick_rb = ctk.CTkRadioButton(
            self.row0_frame, text="Quick", variable=self.scan_mode, value="Quick",
            font=Theme.font(12), text_color=Theme.TEXT_SECONDARY,
        )
        self.mode_quick_rb.grid(row=0, column=3, padx=4, pady=Theme.PAD_CARD, sticky="w")
        
        self.mode_full_rb = ctk.CTkRadioButton(
            self.row0_frame, text="Full", variable=self.scan_mode, value="Full",
            font=Theme.font(12), text_color=Theme.TEXT_SECONDARY,
        )
        self.mode_full_rb.grid(row=0, column=4, padx=4, pady=Theme.PAD_CARD, sticky="w")

        # Column 8 is the spacer with weight=1

        self.start_btn = primary_button(self.row0_frame, "Start", self.on_start_scan, width=75)
        self.start_btn.grid(row=0, column=9, padx=2, pady=Theme.PAD_CARD, sticky="e")
        
        self.stop_btn = danger_button(self.row0_frame, "Stop", self.on_stop_scan, width=70, state="disabled")
        self.stop_btn.grid(row=0, column=10, padx=2, pady=Theme.PAD_CARD, sticky="e")
        
        self.clear_btn = secondary_button(self.row0_frame, "Clear", self.on_clear_table, width=60)
        self.clear_btn.grid(row=0, column=11, padx=2, pady=Theme.PAD_CARD, sticky="e")
        
        self.export_btn = primary_button(self.row0_frame, "Export CSV", self.on_export_csv, width=85)
        self.export_btn.grid(row=0, column=12, padx=(2, 6), pady=Theme.PAD_CARD, sticky="e")

        # Sub-frame for Row 1 controls
        self.row1_frame = ctk.CTkFrame(self.control, fg_color="transparent")
        self.row1_frame.grid(row=1, column=0, sticky="ew", pady=(2, Theme.PAD_CARD))

        # Row 1: IP range filter + Profile selection
        form_label(self.row1_frame, "IP Range").grid(row=0, column=0, padx=(Theme.PAD_CARD, 6), pady=(0, Theme.PAD_CARD), sticky="w")
        self.range_from = form_entry(self.row1_frame, width=100, placeholder_text="From")
        self.range_from.grid(row=0, column=1, padx=4, pady=(0, Theme.PAD_CARD), sticky="w")

        ctk.CTkLabel(
            self.row1_frame, text="to", font=Theme.font(12),
            text_color=Theme.TEXT_SECONDARY,
        ).grid(row=0, column=2, padx=2, pady=(0, Theme.PAD_CARD))
        self.range_to = form_entry(self.row1_frame, width=100, placeholder_text="To")
        self.range_to.grid(row=0, column=3, padx=4, pady=(0, Theme.PAD_CARD), sticky="w")

        self._profiles_file = Path(__file__).resolve().parent.parent / "config" / "scan_profiles.json"
        self._load_profiles()
        self.profile_var = tk.StringVar(value="Default")
        form_label(self.row1_frame, "Profile").grid(row=0, column=5, padx=(20, 4), pady=(0, Theme.PAD_CARD), sticky="w")
        self.profile_menu = option_menu(self.row1_frame, self._profile_names, variable=self.profile_var,
                                        width=80, command=self._on_profile_selected)
        self.profile_menu.grid(row=0, column=6, padx=2, pady=(0, Theme.PAD_CARD), sticky="w")
        self.profile_save_btn = secondary_button(self.row1_frame, "Save \u25BC", self._on_save_profile, width=50)
        self.profile_save_btn.grid(row=0, column=7, padx=2, pady=(0, Theme.PAD_CARD), sticky="w")

        # Row 2: Search filter + count
        search_row = ctk.CTkFrame(self.control, fg_color="transparent")
        search_row.grid(row=2, column=0, columnspan=12, sticky="ew", padx=0, pady=(0, Theme.PAD_CARD))
        search_row.grid_columnconfigure(1, weight=1)
        form_label(search_row, "Search").grid(row=0, column=0, padx=(Theme.PAD_CARD, 6), sticky="w")
        self.search_var = tk.StringVar(value="")
        self.search_var.trace_add("write", self._on_search)
        self.search_entry = form_entry(
            search_row, width=200, placeholder_text="Filter by IP, hostname, vendor...",
        )
        self.search_entry.configure(textvariable=self.search_var)
        self.search_entry.grid(row=0, column=1, padx=4, sticky="ew")
        self.count_lbl = ctk.CTkLabel(
            search_row, text="Devices: 0",
            font=Theme.font(12, "bold"),
            text_color=Theme.TEXT_SECONDARY,
        )
        self.count_lbl.grid(row=0, column=2, padx=(16, Theme.PAD_CARD), sticky="w")

        # ── Progress bar ──
        self.progress_bar = ctk.CTkProgressBar(
            self, mode="determinate", height=3,
            progress_color=Theme.ACCENT, fg_color=Theme.BORDER,
        )
        self.progress_bar.grid(row=2, column=0, sticky="ew", padx=Theme.PAD_PAGE, pady=(4, 0))
        self.progress_bar.set(0)
        self._prog_dir = 1
        self._prog_val = 0.0
        self._prog_anim = None
        self._prog_reset = None

        # ── Table ──
        table_outer = surface_panel(self)
        table_outer.grid(row=3, column=0, sticky="nsew", padx=Theme.PAD_PAGE, pady=(6, Theme.PAD_PAGE))
        table_outer.grid_columnconfigure(0, weight=1)
        table_outer.grid_rowconfigure(0, weight=1)

        self.table = DataTable(
            table_outer,
            columns=("ip", "mac", "hostname", "vendor", "status", "rtt"),
            headings={
                "ip": "IP Address", "mac": "MAC Address", "hostname": "Hostname",
                "vendor": "Vendor", "status": "Status", "rtt": "Latency",
            },
            column_config={
                "ip": {"width": 180, "anchor": "center"},
                "mac": {"width": 150, "anchor": "center"},
                "hostname": {"width": 160, "anchor": "w"},
                "vendor": {"width": 160, "anchor": "w"},
                "status": {"width": 80, "anchor": "center"},
                "rtt": {"width": 90, "anchor": "center"},
            },
            style_name="Scanner.Treeview",
        )
        self.table.grid(row=0, column=0, sticky="nsew", padx=4, pady=4)
        self.table.tree.bind("<Double-1>", self._on_device_double_click)
        self.table.tree.bind("<Button-3>", self._on_right_click)

        # ── Events ──
        self.event_bus.subscribe("DEVICE_DISCOVERED", self._on_device_discovered_event)
        self.event_bus.subscribe("SCAN_FINISHED", self._on_scan_finished_event)
        self.event_bus.subscribe("SCAN_ERROR", self._on_scan_error_event)
        self.event_bus.subscribe("SCAN_PROGRESS", self._on_scan_progress_event)
        self.event_bus.subscribe("DEVICE_TRUSTED_TOGGLED", self._on_device_trusted_toggled)

    def destroy(self):
        self._stop_progress_anim()
        self.event_bus.unsubscribe("DEVICE_DISCOVERED", self._on_device_discovered_event)
        self.event_bus.unsubscribe("SCAN_FINISHED", self._on_scan_finished_event)
        self.event_bus.unsubscribe("SCAN_ERROR", self._on_scan_error_event)
        self.event_bus.unsubscribe("SCAN_PROGRESS", self._on_scan_progress_event)
        self.event_bus.unsubscribe("DEVICE_TRUSTED_TOGGLED", self._on_device_trusted_toggled)
        super().destroy()

    # ── Scan lifecycle ──

    def on_start_scan(self):
        target_subnet = self.subnet_entry.get().strip()
        mode = self.scan_mode.get()
        if not target_subnet:
            return

        if not validate_network(target_subnet):
            logger.error(f"Invalid subnet: {target_subnet}")
            self.controller.update_status(f"Invalid subnet format — {target_subnet}")
            return

        # Build optional IP range list
        range_from = self.range_from.get().strip()
        range_to = self.range_to.get().strip()
        target_ips = None
        if range_from and range_to:
            try:
                start_ip = ipaddress.ip_address(range_from)
                end_ip = ipaddress.ip_address(range_to)
                if start_ip.version != 4 or end_ip.version != 4:
                    self.controller.update_status("IP range only supported for IPv4")
                    return
                start = int(start_ip)
                end = int(end_ip)
                if start > end:
                    start, end = end, start
                target_ips = [str(ipaddress.IPv4Address(ip)) for ip in range(start, end + 1)]
            except Exception:
                self.controller.update_status("Invalid IP range")
                return

        # Clear old devices before new scan
        self._device_count = 0
        self._all_item_ids.clear()
        self.table.clear()
        self._update_count()
        self.ctlr.clear_devices()
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.subnet_entry.configure(state="disabled")
        self.range_from.configure(state="disabled")
        self.range_to.configure(state="disabled")
        self.search_entry.configure(state="disabled")
        self.ctlr.start_subnet_scan(target_subnet, mode, target_ips)
        self._start_progress_anim()

    def _start_progress_anim(self):
        if self._prog_reset:
            try:
                self.after_cancel(self._prog_reset)
            except Exception:
                pass
            self._prog_reset = None
        self._prog_val = 0.02
        self._prog_dir = 1
        self.progress_bar.set(0.02)
        self._tick_progress()

    def _stop_progress_anim(self):
        if self._prog_anim:
            try:
                self.after_cancel(self._prog_anim)
            except Exception:
                pass
            self._prog_anim = None
        if self._prog_reset:
            try:
                self.after_cancel(self._prog_reset)
            except Exception:
                pass
            self._prog_reset = None
        self.progress_bar.set(1)
        self._prog_reset = self.after(200, self._finish_progress)

    def _finish_progress(self):
        self._prog_reset = None
        self.progress_bar.set(0)

    def _tick_progress(self):
        self._prog_val += 0.035 * self._prog_dir
        if self._prog_val >= 0.95:
            self._prog_val = 0.95
            self._prog_dir = -1
        elif self._prog_val <= 0.05:
            self._prog_val = 0.05
            self._prog_dir = 1
        self.progress_bar.set(self._prog_val)
        self._prog_anim = self.after(50, self._tick_progress)

    def on_stop_scan(self):
        self.ctlr.stop_subnet_scan()
        self.on_ui_reset()

    def on_ui_reset(self):
        self._stop_progress_anim()
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.subnet_entry.configure(state="normal")
        self.range_from.configure(state="normal")
        self.range_to.configure(state="normal")
        self.search_entry.configure(state="normal")

    # ── Table operations ──

    def on_clear_table(self):
        win = ctk.CTkToplevel(self)
        win.title("Confirm Clear")
        win.geometry("360x160")
        win.transient(self)
        win.grab_set()
        win.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(win, text="Clear all discovered devices?",
                     font=Theme.font(14, "bold")).grid(row=0, column=0, pady=(20, 4))
        ctk.CTkLabel(win, text="Port scan data will be preserved.",
                     font=Theme.font(11), text_color=Theme.TEXT_SECONDARY).grid(row=1, column=0, pady=(0, 16))
        btn_frame = ctk.CTkFrame(win, fg_color="transparent")
        btn_frame.grid(row=2, column=0)
        secondary_button(btn_frame, "Cancel", win.destroy, width=80).pack(side=ctk.LEFT, padx=6)
        danger_button(btn_frame, "Clear", lambda: (win.destroy(), self._do_clear()), width=80).pack(side=ctk.LEFT, padx=6)

    def _do_clear(self):
        self.ctlr.stop_subnet_scan()
        self.table.clear()
        self._all_item_ids.clear()
        self._device_count = 0
        self._update_count()
        self.ctlr.clear_devices()
        self.on_ui_reset()
        self.controller.update_status("Device history cleared")

    def on_export_csv(self):
        devices = self.ctlr.get_devices()
        if not devices:
            self.controller.update_status("No devices to export")
            return
        from datetime import datetime
        default_name = f"devices_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        path = tk.filedialog.asksaveasfilename(
            parent=self, title="Export Devices CSV",
            defaultextension=".csv", initialfile=default_name,
            filetypes=[("CSV files", "*.csv")]
        )
        if not path:
            return
        try:
            import csv
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["IP Address", "MAC Address", "Hostname", "Vendor", "Status", "Latency (ms)"])
                for d in devices:
                    rtt = f"{d.get('response_time', 0) * 1000:.1f}" if d.get("response_time") else ""
                    writer.writerow([
                        d.get("ip_address", ""), d.get("mac_address", ""),
                        d.get("hostname", ""), d.get("vendor", ""),
                        d.get("status", ""), rtt,
                    ])
            self.controller.update_status(f"Exported {len(devices)} devices to {path}")
        except Exception as e:
            logger.error(f"Export failed: {e}")
            self.controller.update_status("Export failed")

    # ── Search filter ──

    def _on_right_click(self, event):
        selected = self.table.tree.selection()
        if not selected:
            return
        vals = self.table.item(selected[0], "values")
        ip = vals[0]
        detail = self.ctlr.get_device_detail(ip)
        trusted = detail.get("trusted", 0) if detail else 0
        menu = tk.Menu(self, tearoff=0,
                       bg="#FFFFFF" if not Theme.is_dark() else "#1A1A1D",
                       fg="#18181B" if not Theme.is_dark() else "#F4F4F5",
                       activebackground="#2563EB",
                       activeforeground="#FFFFFF",
                       font=("Segoe UI", 11))
        status = "Trusted \u2713" if trusted else "Mark Trusted"
        menu.add_command(label=status, command=lambda: self._toggle_trusted(ip))
        menu.add_separator()
        menu.add_command(label="Show Details", command=lambda: self._show_device_detail(vals))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _toggle_trusted(self, ip):
        result = self.ctlr.toggle_device_trusted(ip)
        if result is True:
            self.controller.update_status(f"{ip} marked as trusted")
        elif result is False:
            self.controller.update_status(f"{ip} removed from trusted")
        else:
            self.controller.update_status(f"Failed to toggle trusted for {ip}")

    def _on_device_trusted_toggled(self, data):
        ip = data.get("ip", "")
        trusted = data.get("trusted", False)
        # Refresh the displayed table data
        self.refresh_data()

    def _on_device_double_click(self, event):
        selected = self.table.tree.selection()
        if not selected:
            return
        vals = self.table.item(selected[0], "values")
        self._show_device_detail(vals)

    def _show_device_detail(self, vals):
        ip = vals[0]
        detail = self.ctlr.get_device_detail(ip)
        trusted = detail.get("trusted", 0) if detail else 0
        win = ctk.CTkToplevel(self)
        win.title(f"Device \u2014 {ip}")
        win.geometry("440x440")
        win.transient(self)
        win.grab_set()
        win.grid_columnconfigure(0, weight=0, minsize=110)
        win.grid_columnconfigure(1, weight=1)

        first_seen = (detail["first_seen"] or "\u2014") if detail else "\u2014"
        last_seen = (detail["last_seen"] or "\u2014") if detail else "\u2014"
        port_count = detail["open_port_count"] if detail else 0
        risk_bd = detail.get("risk_breakdown", {}) if detail else {}
        last_scan = detail.get("last_port_scan", "\u2014") if detail else "\u2014"
        risk_parts = [f"{k}: {v}" for k, v in sorted(risk_bd.items()) if v > 0]
        tcp_cnt = detail.get("tcp_open", 0) if detail else 0
        udp_cnt = detail.get("udp_open", 0) if detail else 0

        fields = [
            ("IP Address", vals[0]),
            ("MAC Address", vals[1] if vals[1] != "\u2014" else "\u2014"),
            ("Hostname", vals[2]),
            ("Vendor", vals[3]),
            ("Status", vals[4]),
            ("Latency", vals[5]),
        ]
        extra = [
            ("Open Ports", f"TCP: {tcp_cnt} / UDP: {udp_cnt} (Total: {port_count})"),
            ("Risk Breakdown", ", ".join(risk_parts) if risk_parts else "\u2014"),
            ("Last Port Scan", str(last_scan)),
            ("First Seen", first_seen),
            ("Last Seen", last_seen),
            ("Trusted", "Yes" if trusted else "No"),
        ]
        all_fields = fields + extra
        for i, (label, value) in enumerate(all_fields):
            ctk.CTkLabel(win, text=label + ":", font=Theme.font(11, "bold"),
                         text_color=Theme.TEXT_SECONDARY).grid(
                row=i, column=0, sticky="e", padx=(16, 8), pady=(8, 0))
            clr = Theme.SUCCESS if vals[4] == "Online" else Theme.TEXT_MUTED
            use_clr = clr if label == "Status" else Theme.TEXT_PRIMARY
            ctk.CTkLabel(win, text=str(value), font=Theme.font(11),
                         text_color=use_clr,
                         anchor="w", justify="left", wraplength=260).grid(
                row=i, column=1, sticky="ew", padx=(0, 16), pady=(8, 0))

        btn_row = len(all_fields)
        btn_text = "Remove Trust" if trusted else "Mark as Trusted"
        btn = ctk.CTkButton(win, text=btn_text,
                            fg_color=Theme.SUCCESS if not trusted else Theme.TEXT_MUTED,
                            width=120, height=28,
                            command=lambda: (self._toggle_trusted(ip), win.destroy()))
        btn.grid(row=btn_row, column=0, columnspan=2, pady=(12, 16))

    def _on_search(self, *args):
        query = self.search_var.get().strip().lower()
        for item_id in self._all_item_ids:
            vals = [str(v).lower() for v in self.table.item(item_id)["values"]]
            if not query or any(query in v for v in vals):
                try:
                    self.table.reattach(item_id, "", "end")
                except Exception:
                    pass
            else:
                try:
                    self.table.detach(item_id)
                except Exception:
                    pass

    # ── Event handlers ──

    def _on_device_discovered_event(self, device: dict):
        self.after(0, self._insert_device, device)

    def _insert_device(self, d: dict):
        try:
            rtt_str = f"{d.get('response_time', 0) * 1000:.1f} ms" if d.get("response_time") else "\u2014"
            trusted = d.get("trusted", 0)
            tags = ("trusted",) if trusted else ()
            item_id = self.table.insert((
                d.get("ip_address", "?"), d.get("mac_address") or "\u2014",
                d.get("hostname") or "\u2014", d.get("vendor") or "\u2014",
                d.get("status", "Online"), rtt_str,
            ), tags=tags)
            self._all_item_ids.append(item_id)
            self._device_count += 1
            self._update_count()
        except Exception as e:
            logger.error(f"Failed to insert device row: {e}")

    def _on_scan_progress_event(self, completed, total):
        def _update():
            self.controller.update_status(f"Scanning... {completed}/{total} hosts checked")
            if total > 0:
                self.progress_bar.set(completed / total)
        self.after(0, _update)

    def _on_scan_error_event(self, message):
        logger.error(f"Scan error: {message}")
        self.after(0, self._stop_progress_anim)
        self.after(0, lambda: self.controller.update_status(f"Scan error: {message}"))
        self.after(0, self.on_ui_reset)

    def _on_scan_finished_event(self, devices):
        self.after(0, self._stop_progress_anim)
        self.after(0, self.on_ui_reset)
        self.after(0, lambda: self.controller.update_status(
            f"Scan complete \u2014 {self._device_count} device(s) found"
        ))

    def _update_count(self):
        self.count_lbl.configure(text=f"Devices: {self._device_count}")

    # ── Scan profiles ──

    def _load_profiles(self):
        self._profiles = {"Default": {}}
        try:
            if self._profiles_file.exists():
                with open(self._profiles_file, "r") as f:
                    self._profiles.update(json.load(f))
        except Exception:
            pass
        self._profile_names = list(self._profiles.keys())

    def _save_profiles(self):
        try:
            self._profiles_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self._profiles_file, "w") as f:
                json.dump(self._profiles, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save profiles: {e}")

    def _on_profile_selected(self, name):
        profile = self._profiles.get(name)
        if not profile:
            return
        if "subnet" in profile:
            self.subnet_entry.delete(0, "end")
            self.subnet_entry.insert(0, profile["subnet"])
        if "mode" in profile:
            self.scan_mode.set(profile["mode"])
        if "range_from" in profile:
            self.range_from.delete(0, "end")
            self.range_from.insert(0, profile["range_from"])
        if "range_to" in profile:
            self.range_to.delete(0, "end")
            self.range_to.insert(0, profile["range_to"])

    def _on_save_profile(self):
        name = self.profile_var.get().strip()
        if not name or name == "Default":
            prompt = ctk.CTkInputDialog(
                text="Enter a name for this scan profile:",
                title="Save Profile",
            )
            name = prompt.get_input()
            if not name:
                return
        profile = {
            "subnet": self.subnet_entry.get().strip(),
            "mode": self.scan_mode.get(),
            "range_from": self.range_from.get().strip(),
            "range_to": self.range_to.get().strip(),
        }
        self._profiles[name] = profile
        self._save_profiles()
        self._profile_names = list(self._profiles.keys())
        self.profile_menu.configure(values=self._profile_names)
        self.profile_var.set(name)
        self.controller.update_status(f"Profile '{name}' saved")

    def refresh_data(self):
        self.table.refresh_theme()
        trusted_fg = Theme.SUCCESS[1] if Theme.is_dark() else Theme.SUCCESS[0]
        self.table.tag_configure("trusted", foreground=trusted_fg)
        self.table.clear()
        self._all_item_ids.clear()
        self._device_count = 0
        try:
            for d in self.ctlr.get_devices():
                if d.get("status", "") != "Cleared":
                    self._insert_device(d)
            self._update_count()
        except Exception as e:
            logger.error(f"Failed to refresh devices: {e}")
