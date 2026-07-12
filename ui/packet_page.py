"""
Packet Sniffer Page Module.
Live network traffic capture and inspection.
"""
import sys
import customtkinter as ctk

from ui.themes.tokens import Theme
from ui.widgets.controls import (
    page_header, surface_panel, form_label, form_entry,
    option_menu, primary_button, secondary_button, danger_button, warning_button,
)
from ui.widgets.tables import DataTable

from core.logger import logger


class PacketSnifferPage(ctk.CTkFrame):
    """Live packet capture panel."""

    def __init__(self, parent, app_window, ctlr):
        super().__init__(parent, fg_color="transparent")
        self.controller = app_window
        self.ctlr = ctlr
        self.event_bus = ctlr.event_bus

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        header = page_header(
            self, "Packet Capture",
            "Monitor live traffic on a selected network interface",
        )
        header.grid(row=0, column=0, sticky="ew", padx=Theme.PAD_PAGE, pady=(Theme.PAD_PAGE, 8))

        self.control = surface_panel(self)
        self.control.grid(row=1, column=0, sticky="ew", padx=Theme.PAD_PAGE, pady=8)

        # Columns configuration: only column 4 (spacer) has weight=1
        self.control.grid_columnconfigure(4, weight=1)

        self._pkt_buffer = []

        # Row 0
        form_label(self.control, "Interface").grid(row=0, column=0, padx=(Theme.PAD_CARD, 4), pady=Theme.PAD_CARD, sticky="w")
        self.iface_menu = option_menu(self.control, self.ctlr.get_interfaces(), width=100)
        self.iface_menu.grid(row=0, column=1, padx=2, pady=Theme.PAD_CARD, sticky="w")

        form_label(self.control, "Filter IP").grid(row=0, column=2, padx=(8, 4), pady=Theme.PAD_CARD, sticky="w")
        self.ip_filter_var = ctk.StringVar(value="")
        self.ip_filter_var.trace_add("write", lambda *_: self._reapply_filters())
        self.ip_filter_entry = form_entry(self.control, width=90, textvariable=self.ip_filter_var,
                                          placeholder_text="IP filter...")
        self.ip_filter_entry.grid(row=0, column=3, padx=2, pady=Theme.PAD_CARD, sticky="w")

        # Column 4 is empty spacer
        
        form_label(self.control, "Protocols").grid(row=0, column=5, padx=(8, 4), pady=Theme.PAD_CARD, sticky="w")
        self.filter_menu = option_menu(
            self.control,
            ["All", "TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "HTTPS"],
            width=70, command=lambda _: self._reapply_filters(),
        )
        self.filter_menu.grid(row=0, column=6, padx=2, pady=Theme.PAD_CARD, sticky="w")

        self.start_btn = primary_button(self.control, "Capture", self.on_start_capture, width=75)
        self.start_btn.grid(row=0, column=7, padx=2, pady=Theme.PAD_CARD, sticky="e")

        self.pause_btn = warning_button(self.control, "Pause", self.on_pause_capture, width=65, state="disabled")
        self.pause_btn.grid(row=0, column=8, padx=2, pady=Theme.PAD_CARD, sticky="e")

        self.stop_btn = danger_button(self.control, "Stop", self.on_stop_capture, width=60, state="disabled")
        self.stop_btn.grid(row=0, column=9, padx=2, pady=Theme.PAD_CARD, sticky="e")
        self.clean_btn = secondary_button(self.control, "Clean", self.on_clean_table, width=60)
        self.clean_btn.grid(row=0, column=10, padx=(2, Theme.PAD_CARD), pady=Theme.PAD_CARD, sticky="e")

        # Row 1
        form_label(self.control, "Search").grid(row=1, column=0, padx=(Theme.PAD_CARD, 4), pady=(0, Theme.PAD_CARD), sticky="w")
        self.pkt_search_var = ctk.StringVar(value="")
        self.pkt_search_var.trace_add("write", lambda *_: self._reapply_filters())
        self.pkt_search_entry = form_entry(self.control, width=200, textvariable=self.pkt_search_var,
                                           placeholder_text="Search all packet data...")
        self.pkt_search_entry.grid(row=1, column=1, columnspan=3, padx=2, pady=(0, Theme.PAD_CARD), sticky="w")

        table_outer = surface_panel(self)
        table_outer.grid(row=2, column=0, sticky="nsew", padx=Theme.PAD_PAGE, pady=(8, Theme.PAD_PAGE))
        table_outer.grid_columnconfigure(0, weight=1)
        table_outer.grid_rowconfigure(0, weight=1)

        self.table = DataTable(
            table_outer,
            columns=("time", "src", "dst", "proto", "len", "info"),
            headings={
                "time": "Time", "src": "Source", "dst": "Destination",
                "proto": "Protocol", "len": "Size", "info": "Details",
            },
            column_config={
                "time": {"width": 90, "anchor": "center"},
                "src": {"width": 120, "anchor": "center"},
                "dst": {"width": 120, "anchor": "center"},
                "proto": {"width": 80, "anchor": "center"},
                "len": {"width": 60, "anchor": "center"},
                "info": {"width": 300, "anchor": "w"},
            },
            style_name="Packet.Treeview",
        )
        self.table.grid(row=0, column=0, sticky="nsew", padx=4, pady=4)

        proto_colors = {
            "TCP": Theme.PROTO_TCP, "UDP": Theme.PROTO_UDP, "ICMP": Theme.PROTO_ICMP,
            "DNS": Theme.PROTO_DNS, "HTTP": Theme.PROTO_HTTP, "HTTPS": Theme.PROTO_HTTPS,
            "ARP": Theme.PROTO_ARP,
        }
        for proto, color in proto_colors.items():
            fg = color[1] if Theme.is_dark() else color[0]
            self.table.tag_configure(proto, foreground=fg)

        self.event_bus.subscribe("PACKET_CAPTURED", self._on_packet_captured_event)
        self.event_bus.subscribe("SNIFFER_FINISHED", self._on_sniffer_finished_event)
        self.event_bus.subscribe("SNIFFER_ERROR", self._on_sniffer_error_event)
        self.event_bus.subscribe("PACKET_DATA_CLEARED", self._on_packet_data_cleared)

        self.table.tree.bind("<Double-1>", self._on_packet_double_click)

    def destroy(self):
        self.event_bus.unsubscribe("PACKET_CAPTURED", self._on_packet_captured_event)
        self.event_bus.unsubscribe("SNIFFER_FINISHED", self._on_sniffer_finished_event)
        self.event_bus.unsubscribe("SNIFFER_ERROR", self._on_sniffer_error_event)
        self.event_bus.unsubscribe("PACKET_DATA_CLEARED", self._on_packet_data_cleared)
        super().destroy()

    def on_start_capture(self):
        selected_iface = self.iface_menu.get()
        if not selected_iface:
            return

        self._pkt_buffer.clear()
        self.table.clear()
        self.start_btn.configure(state="disabled")
        self.pause_btn.configure(state="normal", text="Pause")
        self.stop_btn.configure(state="normal")
        self.iface_menu.configure(state="disabled")
        self.ctlr.start_packet_capture(selected_iface, 1000)

    def on_stop_capture(self):
        self.ctlr.stop_packet_capture()
        self.on_ui_reset()

    def on_pause_capture(self):
        if self.ctlr.is_capturing_paused():
            self.ctlr.resume_capture()
            self.pause_btn.configure(text="Pause")
        else:
            self.ctlr.pause_capture()
            self.pause_btn.configure(text="Resume")

    def on_ui_reset(self):
        self.start_btn.configure(state="normal")
        self.pause_btn.configure(state="disabled", text="Pause")
        self.stop_btn.configure(state="disabled")
        self.iface_menu.configure(state="normal")

    def on_clean_table(self):
        self._pkt_buffer.clear()
        self.table.clear()
        self.ctlr.clean_packet_data()

    def _on_packet_data_cleared(self, _data=None):
        self._pkt_buffer.clear()
        self.after(10, self.table.clear)

    def _on_packet_double_click(self, event):
        selected = self.table.tree.selection()
        if not selected:
            return
        vals = self.table.item(selected[0], "values")
        self._show_packet_detail(vals)

    def _show_packet_detail(self, vals):
        win = ctk.CTkToplevel(self)
        win.title("Packet Detail")
        win.geometry("560x460")
        win.transient(self)
        win.grab_set()
        win.grid_columnconfigure(0, weight=0, minsize=110)
        win.grid_columnconfigure(1, weight=1)

        proto = vals[3]
        info = vals[5]
        src_port = dst_port = flags = query = None

        if "TCP Port:" in info:
            parts = info.split("|")
            port_part = parts[0].strip()
            if "Port:" in port_part:
                prts = port_part.split("Port:")[1].strip().split(" -> ")
                if len(prts) == 2:
                    src_port = prts[0]
                    dst_port = prts[1]
            if len(parts) > 1 and "Flags:" in parts[1]:
                flags = parts[1].split("Flags:")[1].strip()
        elif "UDP Port:" in info:
            parts = info.split("|")
            port_part = parts[0].strip()
            if "Port:" in port_part:
                prts = port_part.split("Port:")[1].strip().split(" -> ")
                if len(prts) == 2:
                    src_port = prts[0]
                    dst_port = prts[1]
        elif "DNS Query:" in info:
            query = info.replace("DNS Query:", "").strip()
        elif "DNS Response" in info:
            query = info.split("for")[-1].strip() if "for" in info else info

        base_fields = [
            ("Timestamp", vals[0]),
            ("Source", vals[1]),
            ("Destination", vals[2]),
            ("Protocol", proto),
            ("Size", f"{vals[4]} bytes"),
        ]
        if src_port:
            base_fields.append(("Source Port", src_port))
        if dst_port:
            base_fields.append(("Dest Port", dst_port))
        if flags:
            base_fields.append(("TCP Flags", flags))
        if query:
            base_fields.append(("Query", query))

        for i, (label, value) in enumerate(base_fields):
            ctk.CTkLabel(win, text=label + ":", font=Theme.font(11, "bold"),
                         text_color=Theme.TEXT_SECONDARY).grid(
                row=i, column=0, sticky="e", padx=(16, 8), pady=(6, 0))
            ctk.CTkLabel(win, text=str(value), font=Theme.font(11),
                         text_color=Theme.TEXT_PRIMARY,
                         anchor="w", justify="left").grid(
                row=i, column=1, sticky="ew", padx=(0, 16), pady=(6, 0))

        ctk.CTkLabel(win, text="Details:", font=Theme.font(11, "bold"),
                     text_color=Theme.TEXT_SECONDARY).grid(
            row=len(base_fields), column=0, sticky="ne", padx=(16, 8), pady=(10, 0))
        detail_box = ctk.CTkTextbox(win, height=90, wrap="word", fg_color=Theme.BG_INPUT,
                                    font=Theme.font(11))
        detail_box.grid(row=len(base_fields), column=1, sticky="ew", padx=(0, 16), pady=(10, 16))
        detail_box.insert("0.0", str(info))
        detail_box.configure(state="disabled")

    def _on_packet_captured_event(self, packet_data: dict):
        self._pkt_buffer.append(packet_data)
        if len(self._pkt_buffer) > 10000:
            self._pkt_buffer = self._pkt_buffer[-5000:]
        active_filter = self.filter_menu.get()
        if active_filter != "All" and packet_data.get("protocol", "Raw") != active_filter:
            return
        ip_filter = self.ip_filter_var.get().strip()
        if ip_filter:
            src = packet_data.get("source", "")
            dst = packet_data.get("destination", "")
            if ip_filter not in src and ip_filter not in dst:
                return
        search_q = self.pkt_search_var.get().strip().lower()
        if search_q:
            vals = " ".join(str(v) for v in packet_data.values()).lower()
            if search_q not in vals:
                return
        self._insert_packet(packet_data)

    def _insert_packet(self, p: dict):
        item = self.table.insert((
            p["timestamp"], p["source"], p["destination"],
            p["protocol"], p["length"], p["info"],
        ), tags=(p["protocol"],))
        self.table.see(item)

    def _reapply_filters(self):
        self.table.clear()
        active_filter = self.filter_menu.get()
        ip_filter = self.ip_filter_var.get().strip()
        search_q = self.pkt_search_var.get().strip().lower()
        for p in self._pkt_buffer:
            if active_filter != "All" and p.get("protocol", "Raw") != active_filter:
                continue
            if ip_filter:
                src = p.get("source", "")
                dst = p.get("destination", "")
                if ip_filter not in src and ip_filter not in dst:
                    continue
            if search_q:
                vals = " ".join(str(v) for v in p.values()).lower()
                if search_q not in vals:
                    continue
            self._insert_packet(p)

    def _on_sniffer_error_event(self, message):
        logger.error(f"Sniffer error: {message}")
        self.after(10, lambda: self.controller.update_status(f"Sniffer error: {message}"))
        self.after(10, self.on_ui_reset)

    def _on_sniffer_finished_event(self, count):
        self.after(10, self.on_ui_reset)

    def refresh_data(self):
        """Reloads latest captured packets from database."""
        # Refresh interface list in case new interfaces (VPNs, adapters) were added/removed
        try:
            ifaces = self.ctlr.get_interfaces()
            current = self.iface_menu.get()
            self.iface_menu.configure(values=ifaces)
            if current in ifaces:
                self.iface_menu.set(current)
            elif ifaces:
                self.iface_menu.set(ifaces[0])
        except Exception as e:
            logger.error(f"Failed to refresh interface list: {e}")

        self.table.refresh_theme()
        proto_colors = {
            "TCP": Theme.PROTO_TCP, "UDP": Theme.PROTO_UDP, "ICMP": Theme.PROTO_ICMP,
            "DNS": Theme.PROTO_DNS, "HTTP": Theme.PROTO_HTTP, "HTTPS": Theme.PROTO_HTTPS,
            "ARP": Theme.PROTO_ARP, "Ethernet": Theme.PROTO_ETHERNET,
        }
        for proto, color in proto_colors.items():
            fg = color[1] if Theme.is_dark() else color[0]
            self.table.tag_configure(proto, foreground=fg)
        self._pkt_buffer.clear()
        self.table.clear()
        try:
            for p in reversed(self.ctlr.get_packets(limit=200)):
                entry = {
                    "timestamp": p["timestamp"],
                    "source": p["source_ip"],
                    "destination": p["destination_ip"],
                    "protocol": p["protocol"],
                    "length": p["length"],
                    "info": p["information"],
                }
                self._pkt_buffer.append(entry)
            self._reapply_filters()
        except Exception as e:
            logger.error(f"Failed to refresh packets: {e}")
