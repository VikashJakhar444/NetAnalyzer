"""
Dashboard Page Module.
Network overview with metric cards and traffic visualizations.
"""
import sys
import customtkinter as ctk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

from ui.themes.tokens import Theme
from ui.widgets.cards import StatCard
from ui.widgets.controls import page_header, surface_panel

from core.logger import logger


class DashboardPage(ctk.CTkFrame):
    """Main dashboard with summary metrics and charts."""

    def __init__(self, parent, app_window, ctlr):
        super().__init__(parent, fg_color="transparent")
        self.controller = app_window
        self.ctlr = ctlr
        self.event_bus = ctlr.event_bus
        self._annot = None
        self._time_annot = None
        self._pie_cid = None
        self._bar_cid = None
        self._visible = False
        self._debounce_timer = None

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        header = page_header(
            self, "Dashboard",
            "Real-time overview of network activity and security posture",
        )
        header.grid(row=0, column=0, sticky="ew", padx=Theme.PAD_PAGE, pady=(Theme.PAD_PAGE, 8))

        # Metric cards
        cards_frame = ctk.CTkFrame(self, fg_color="transparent")
        cards_frame.grid(row=1, column=0, sticky="ew", padx=Theme.PAD_PAGE, pady=8)
        for col in range(5):
            cards_frame.grid_columnconfigure(col, weight=1)

        self.card_devices = StatCard(cards_frame, "Devices", "0", "Hosts discovered on network")
        self.card_devices.grid(row=0, column=0, padx=(0, 6), sticky="ew")

        self.card_ports = StatCard(cards_frame, "Open Ports", "0", "Exposed TCP services", accent=Theme.INFO)
        self.card_ports.grid(row=0, column=1, padx=6, sticky="ew")

        self.card_packets = StatCard(cards_frame, "Packets", "0", "Frames captured", accent=Theme.PROTO_UDP)
        self.card_packets.grid(row=0, column=2, padx=6, sticky="ew")

        self.card_score = StatCard(cards_frame, "Security Score", "\u2014", "Composite risk rating", accent=Theme.SUCCESS)
        self.card_score.grid(row=0, column=3, padx=6, sticky="ew")

        self.card_vulns = StatCard(cards_frame, "CVEs", "0", "Known vulnerabilities detected", accent=Theme.RISK_HIGH)
        self.card_vulns.grid(row=0, column=4, padx=(6, 0), sticky="ew")

        # Charts
        charts_outer = surface_panel(self)
        charts_outer.grid(row=2, column=0, sticky="nsew", padx=Theme.PAD_PAGE, pady=(8, Theme.PAD_PAGE))
        charts_outer.grid_columnconfigure(0, weight=1)
        charts_outer.grid_columnconfigure(1, weight=1)
        charts_outer.grid_rowconfigure(0, weight=1)

        self.charts_frame = ctk.CTkFrame(charts_outer, fg_color="transparent")
        self.charts_frame.grid(row=0, column=0, columnspan=2, sticky="nsew", padx=8, pady=8)
        self.charts_frame.grid_columnconfigure(0, weight=1)
        self.charts_frame.grid_columnconfigure(1, weight=1)
        self.charts_frame.grid_rowconfigure(0, weight=1)

        self._init_charts()

        self._on_dev_discovered = lambda _: self._trigger_refresh()
        self._on_devs_cleared = lambda _: self._trigger_refresh()
        self._on_port_discovered = lambda _: self._trigger_refresh()
        self._on_pkt_captured = lambda _: self._trigger_refresh()
        self._on_port_cleared = lambda _: self._trigger_refresh()
        self._on_pkt_cleared = lambda _: self._trigger_refresh()
        self._on_theme_changed = lambda _: self._redraw_charts() if self._visible else None

        self.event_bus.subscribe("DEVICE_DISCOVERED", self._on_dev_discovered)
        self.event_bus.subscribe("DEVICES_CLEARED", self._on_devs_cleared)
        self.event_bus.subscribe("PORT_DISCOVERED", self._on_port_discovered)
        self.event_bus.subscribe("PACKET_CAPTURED", self._on_pkt_captured)
        self.event_bus.subscribe("PORT_DATA_CLEARED", self._on_port_cleared)
        self.event_bus.subscribe("PACKET_DATA_CLEARED", self._on_pkt_cleared)
        self.event_bus.subscribe("THEME_CHANGED", self._on_theme_changed)

    def destroy(self):
        if self._debounce_timer:
            try:
                self.after_cancel(self._debounce_timer)
            except Exception:
                pass
            self._debounce_timer = None
        self.event_bus.unsubscribe("DEVICE_DISCOVERED", self._on_dev_discovered)
        self.event_bus.unsubscribe("DEVICES_CLEARED", self._on_devs_cleared)
        self.event_bus.unsubscribe("PORT_DISCOVERED", self._on_port_discovered)
        self.event_bus.unsubscribe("PACKET_CAPTURED", self._on_pkt_captured)
        self.event_bus.unsubscribe("PORT_DATA_CLEARED", self._on_port_cleared)
        self.event_bus.unsubscribe("PACKET_DATA_CLEARED", self._on_pkt_cleared)
        self.event_bus.unsubscribe("THEME_CHANGED", self._on_theme_changed)
        super().destroy()

    def _init_charts(self):
        self.fig_proto = Figure(figsize=(5.0, 3.2), dpi=100, constrained_layout=True)
        self.ax_proto = self.fig_proto.add_subplot(111)
        self.canvas_proto = FigureCanvasTkAgg(self.fig_proto, master=self.charts_frame)
        self.canvas_proto.get_tk_widget().grid(row=0, column=0, padx=8, pady=4, sticky="nsew")

        self.fig_time = Figure(figsize=(5.0, 3.2), dpi=100, constrained_layout=True)
        self.ax_time = self.fig_time.add_subplot(111)
        self.canvas_time = FigureCanvasTkAgg(self.fig_time, master=self.charts_frame)
        self.canvas_time.get_tk_widget().grid(row=0, column=1, padx=8, pady=4, sticky="nsew")

    def notify_hidden(self):
        """Called by app_window when navigating away from dashboard."""
        self._visible = False

    def refresh_dashboard(self):
        """Called by show_frame when navigating to this page."""
        self._visible = True
        # Defer both metrics update and chart rendering to make the tab switch
        # instantaneous and allow the page layout to paint first.
        self.after(100, self._update_metrics)
        self.after(150, self._redraw_charts)

    def _trigger_refresh(self):
        """Called by events — throttle metrics, debounce chart redraw when visible."""
        self._update_metrics()
        if not self._visible:
            return
        if self._debounce_timer:
            try:
                self.after_cancel(self._debounce_timer)
            except Exception:
                pass
        self._debounce_timer = self.after(500, self._redraw_charts)

    def _on_pie_hover(self, event, wedges, labels, sizes):
        shown = False
        for i, w in enumerate(wedges):
            contained, _ = w.contains(event)
            if contained:
                self._annot.xy = (event.xdata, event.ydata)
                total = sum(sizes)
                pct = sizes[i] / total * 100 if total else 0
                self._annot.set_text(f"{labels[i]}: {sizes[i]} ({pct:.1f}%)")
                self._annot.set_visible(True)
                self.fig_proto.canvas.draw_idle()
                shown = True
                break
        if not shown and self._annot.get_visible():
            self._annot.set_visible(False)
            self.fig_proto.canvas.draw_idle()

    def _update_metrics(self):
        """Quick update of card values only - no chart redraw."""
        try:
            metrics = self.ctlr.get_dashboard_metrics()
            score = self.ctlr.get_network_score()
            self.card_devices.set_value(str(metrics["online_devices"]))
            self.card_ports.set_value(str(metrics["total_open_ports"]))
            self.card_packets.set_value(str(metrics["total_packets"]))
            if score is None:
                self.card_score.set_value("\u2014", color=Theme.TEXT_MUTED)
            else:
                score_color = Theme.SUCCESS
                if score < 60:
                    score_color = Theme.DANGER
                elif score < 85:
                    score_color = Theme.WARNING
                self.card_score.set_value(f"{score}/100", color=score_color)
            vuln_stats = self.ctlr.get_all_vulnerability_stats()
            cve_count = vuln_stats.get("total_cves", 0)
            cve_clr = Theme.DANGER if cve_count > 0 else Theme.SUCCESS
            self.card_vulns.set_value(str(cve_count), color=cve_clr)
        except Exception as e:
            logger.debug(f"Dashboard metrics update failed: {e}")

    def _redraw_charts(self):
        """Redraw matplotlib charts (protocol pie + timeline bandwidth)."""
        try:
            colors = Theme.chart_bg()

            # Protocol distribution pie
            self.fig_proto.set_facecolor(colors["fig"])
            self.ax_proto.clear()
            self.ax_proto.set_facecolor(colors["ax"])
            self.ax_proto.set_title("Protocol Distribution", color=colors["text"], fontsize=11, fontweight="600", pad=12)
            proto_data = self.ctlr.get_protocol_distribution()

            if proto_data:
                labels = list(proto_data.keys())
                sizes = list(proto_data.values())
                proto_pie_colors = {
                    "TCP": "#3B82F6", "UDP": "#D97706", "ICMP": "#DC2626",
                    "DNS": "#7C3AED", "HTTP": "#EA580C", "HTTPS": "#059669",
                    "ARP": "#52525B", "Ethernet": "#4B5563",
                }
                pie_colors = [proto_pie_colors.get(l, Theme.CHART_COLORS[i % len(Theme.CHART_COLORS)]) for i, l in enumerate(labels)]
                pie_result = self.ax_proto.pie(
                    sizes, labels=labels, autopct="%1.0f%%",
                    colors=pie_colors,
                    startangle=90, pctdistance=0.75,
                    textprops={"fontsize": 9, "color": colors["text"]},
                    wedgeprops={"linewidth": 1, "edgecolor": colors["ax"]},
                )
                if len(pie_result) == 3:
                    wedges, texts, autotexts = pie_result
                else:
                    wedges, texts = pie_result
                    autotexts = []

                for t in autotexts:
                    t.set_color(colors["text"])
                for w, t in zip(wedges, texts):
                    t.set_color(colors["text"])
                    t.set_fontsize(9)
                self._annot = self.ax_proto.annotate(
                    "", xy=(0, 0), xytext=(10, 10),
                    textcoords="offset points", fontsize=10, zorder=999,
                    color="#18181B" if Theme.is_dark() else "#F4F4F5",
                    bbox=dict(boxstyle="round,pad=0.4",
                              fc="#FFFFFF" if Theme.is_dark() else "#1A1A1D",
                              ec="#2A2A2E" if Theme.is_dark() else "#E4E4E7",
                              alpha=0.9),
                    arrowprops=dict(arrowstyle="-", color=colors["tick"]),
                )
                self._annot.set_clip_on(False)
                self._annot.set_in_layout(False)
                self._annot.set_visible(False)
                if self._pie_cid:
                    self.fig_proto.canvas.mpl_disconnect(self._pie_cid)
                self._pie_cid = self.fig_proto.canvas.mpl_connect(
                    "motion_notify_event",
                    lambda e: self._on_pie_hover(e, wedges, labels, sizes),
                )
            else:
                if self._pie_cid:
                    self.fig_proto.canvas.mpl_disconnect(self._pie_cid)
                    self._pie_cid = None
                self.ax_proto.text(0.5, 0.5, "No packet data", ha="center", va="center",
                                   color=colors["tick"], fontsize=10)
                self.ax_proto.axis("off")

            self.canvas_proto.draw_idle()

            # Traffic timeline with bandwidth overlay
            self.fig_time.set_facecolor(colors["fig"])
            self.ax_time.clear()

            # Remove any stale twin axes (created by previous twinx() calls)
            for ax in list(self.fig_time.axes):
                if ax is not self.ax_time:
                    self.fig_time.delaxes(ax)

            self.ax_time.set_facecolor(colors["ax"])
            self.ax_time.set_title("Traffic Timeline & Bandwidth", color=colors["text"], fontsize=11, fontweight="600", pad=12)
            timeline = self.ctlr.get_traffic_timeline(limit=10)

            if timeline:
                labels = [t["time_bucket"].split(" ")[1] for t in timeline]
                counts = [t["count"] for t in timeline]
                bytes_list = [t.get("bytes", 0) or 0 for t in timeline]
                x = list(range(len(labels)))

                bars = self.ax_time.bar(x, counts, color=Theme.CHART_COLORS[0], width=0.6, alpha=0.85, linewidth=0)
                for bar in bars:
                    bar.set_edgecolor(colors["ax"])
                self.ax_time.set_xlim(-0.5, len(x) - 0.5)
                self.ax_time.set_xticks(x)
                self.ax_time.set_xticklabels(labels)
                self.ax_time.set_ylabel("Packets", color=colors["tick"], fontsize=9)
                self.ax_time.tick_params(axis="x", rotation=35, labelsize=8, colors=colors["tick"])
                self.ax_time.tick_params(axis="y", labelsize=8, colors=colors["tick"])
                self.ax_time.spines["top"].set_visible(False)
                self.ax_time.spines["bottom"].set_color(colors["grid"])
                self.ax_time.spines["left"].set_color(colors["grid"])

                bw_color = Theme.PROTO_UDP[1] if Theme.is_dark() else Theme.PROTO_UDP[0]
                ax_bw = self.ax_time.twinx()
                bw_kbps = [b / 1024.0 for b in bytes_list]
                line = ax_bw.plot(x, bw_kbps, color=bw_color,
                                  marker="o", markersize=4, linewidth=1.5, alpha=0.8, label="KB/s")[0]
                ax_bw.set_ylabel("KB/s", color=bw_color, fontsize=9, fontweight="bold")
                ax_bw.tick_params(axis="y", labelsize=8, colors=bw_color)
                ax_bw.spines["top"].set_visible(False)
                ax_bw.spines["right"].set_color(bw_color)
                ax_bw.spines["bottom"].set_color(colors["grid"])
                ax_bw.set_ylim(bottom=0)
                self.ax_time.set_ylim(bottom=0)

                self.ax_time.grid(axis="y", color=colors["grid"], linestyle="-", alpha=0.3)
                self.ax_time.set_axisbelow(True)
                self._time_annot = self.ax_time.annotate(
                    "", xy=(0, 0), xytext=(10, 10),
                    textcoords="offset points", fontsize=10, zorder=999,
                    color="#18181B" if Theme.is_dark() else "#F4F4F5",
                    bbox=dict(boxstyle="round,pad=0.4",
                              fc="#FFFFFF" if Theme.is_dark() else "#1A1A1D",
                              ec="#2A2A2E" if Theme.is_dark() else "#E4E4E7",
                              alpha=0.9),
                    arrowprops=dict(arrowstyle="-", color=colors["tick"]),
                )
                self._time_annot.set_clip_on(False)
                self._time_annot.set_in_layout(False)
                self._time_annot.set_visible(False)
                if self._bar_cid:
                    self.fig_time.canvas.mpl_disconnect(self._bar_cid)
                self._bar_cid = self.fig_time.canvas.mpl_connect(
                    "motion_notify_event",
                    lambda e: self._on_bar_hover(e, bars, labels, counts, self.ax_time),
                )
            else:
                if self._bar_cid:
                    self.fig_time.canvas.mpl_disconnect(self._bar_cid)
                    self._bar_cid = None
                self.ax_time.text(0.5, 0.55, "No capture data", ha="center", va="center",
                                  color=colors["tick"], fontsize=11, fontweight="600")
                self.ax_time.text(0.5, 0.4, "Start packet capture to see traffic timeline",
                                  ha="center", va="center", color=colors["tick"], fontsize=8)
                self.ax_time.set_xlim(0, 1)
                self.ax_time.set_ylim(0, 1)
                self.ax_time.spines["top"].set_visible(False)
                self.ax_time.spines["right"].set_visible(False)
                self.ax_time.spines["bottom"].set_color(colors["grid"])
                self.ax_time.spines["left"].set_color(colors["grid"])
                self.ax_time.tick_params(axis="both", which="both", length=0, colors=colors["grid"])
                self.ax_time.set_xticklabels([])
                self.ax_time.set_yticklabels([])
                self.ax_time.set_xlabel("")
                self.ax_time.set_ylabel("")

            self.canvas_time.draw_idle()

        except Exception as e:
            logger.debug(f"Dashboard chart refresh failed: {e}")

    def _on_bar_hover(self, event, bars, times, counts, ax):
        shown = False
        for i, bar in enumerate(bars):
            contained, _ = bar.contains(event)
            if contained:
                self._time_annot.xy = (event.xdata, event.ydata)
                self._time_annot.set_text(f"{times[i]}: {counts[i]} packets")
                xlim = ax.get_xlim()
                is_near_right = (event.xdata - xlim[0]) / (xlim[1] - xlim[0]) > 0.6
                if is_near_right:
                    self._time_annot.xytext = (-12, -12)
                    self._time_annot.set_ha("right")
                else:
                    self._time_annot.xytext = (12, -12)
                    self._time_annot.set_ha("left")
                self._time_annot.set_visible(True)
                self.fig_time.canvas.draw_idle()
                shown = True
                break
        if not shown and self._time_annot.get_visible():
            self._time_annot.set_visible(False)
            self.fig_time.canvas.draw_idle()
