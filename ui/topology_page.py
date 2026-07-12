"""
Topology Page Module.
Interactive network device graph with hover tooltips, click-to-detail, and visual filters.
Pure matplotlib (no networkx).
"""
import ipaddress
import math
import random
import customtkinter as ctk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
from matplotlib.lines import Line2D

from ui.themes.tokens import Theme
from ui.widgets.controls import page_header, surface_panel, primary_button, secondary_button, form_label, form_entry
from core.logger import logger


class TopologyPage(ctk.CTkFrame):
    """Interactive network topology with hover tips, click detail, and filters."""

    def __init__(self, parent, app_window, ctlr):
        super().__init__(parent, fg_color="transparent")
        self.controller = app_window
        self.ctlr = ctlr
        self.event_bus = ctlr.event_bus
        self._raw_positions = {}  # unscaled node positions

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        header = page_header(self, "Network Topology",
                             "Interactive map of discovered devices — hover for details, click to inspect")
        header.grid(row=0, column=0, sticky="ew", padx=Theme.PAD_PAGE, pady=(Theme.PAD_PAGE, 8))

        toolbar = surface_panel(self)
        toolbar.grid(row=1, column=0, sticky="ew", padx=Theme.PAD_PAGE, pady=(0, 8))
        toolbar.grid_columnconfigure(8, weight=1)

        form_label(toolbar, "Layout").grid(row=0, column=0, padx=(Theme.PAD_CARD, 4),
                                           pady=Theme.PAD_CARD, sticky="w")
        self.layout_var = ctk.StringVar(value="Force-Directed")
        self.layout_menu = ctk.CTkOptionMenu(toolbar, variable=self.layout_var,
                                             values=["Force-Directed", "Circular", "Hierarchical"],
                                             command=lambda _: self._redraw(),
                                             width=110)
        self.layout_menu.grid(row=0, column=1, padx=2, pady=Theme.PAD_CARD, sticky="w")

        form_label(toolbar, "Filter").grid(row=0, column=2, padx=(8, 4),
                                           pady=Theme.PAD_CARD, sticky="w")
        self.filter_var = ctk.StringVar(value="All")
        self.filter_menu = ctk.CTkOptionMenu(toolbar, variable=self.filter_var,
                                             values=["All", "Low Risk", "Medium Risk",
                                                     "High Risk", "Trusted Only"],
                                             command=lambda _: self._redraw(),
                                             width=100)
        self.filter_menu.grid(row=0, column=3, padx=2, pady=Theme.PAD_CARD, sticky="w")

        form_label(toolbar, "Search").grid(row=0, column=4, padx=(8, 4),
                                           pady=Theme.PAD_CARD, sticky="w")
        self.search_var = ctk.StringVar(value="")
        self.search_var.trace_add("write", lambda *_: self._redraw())
        self.search_entry = form_entry(toolbar, width=130, textvariable=self.search_var)
        self.search_entry.grid(row=0, column=5, padx=2, pady=Theme.PAD_CARD, sticky="w")

        secondary_button(toolbar, "Zoom +", self._zoom_in, width=30).grid(
            row=0, column=6, padx=1, pady=Theme.PAD_CARD, sticky="w")
        secondary_button(toolbar, "Zoom \u2212", self._zoom_out, width=30).grid(
            row=0, column=7, padx=1, pady=Theme.PAD_CARD, sticky="w")
        primary_button(toolbar, "Save Image", self._save_image, width=85).grid(
            row=0, column=9, padx=(2, Theme.PAD_CARD), pady=Theme.PAD_CARD, sticky="e")

        # Split pane: graph (left) + info panel (right)
        main_frame = surface_panel(self)
        main_frame.grid(row=2, column=0, sticky="nsew", padx=Theme.PAD_PAGE, pady=(0, Theme.PAD_PAGE))
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_rowconfigure(0, weight=1)

        self.fig = Figure(figsize=(7, 5), dpi=100, constrained_layout=True)
        self.ax = self.fig.add_subplot(111)
        self.canvas = FigureCanvasTkAgg(self.fig, master=main_frame)
        self.canvas.get_tk_widget().grid(row=0, column=0, sticky="nsew", padx=4, pady=4)

        # Info panel
        info_outer = ctk.CTkFrame(main_frame, fg_color="transparent", width=220)
        info_outer.grid(row=0, column=1, sticky="ns", padx=(0, 4), pady=4)
        info_outer.grid_propagate(False)

        self.info_panel = ctk.CTkScrollableFrame(info_outer, fg_color=Theme.BG_INPUT,
                                                  corner_radius=8)
        self.info_panel.pack(fill="both", expand=True, padx=2, pady=2)
        self._info_label = ctk.CTkLabel(self.info_panel, text="Click a device\nto inspect",
                                        font=Theme.font(10, "bold"),
                                        text_color=Theme.TEXT_MUTED,
                                        justify="center", anchor="center")
        self._info_label.pack(expand=True, fill="both", pady=40)

        # Hover tooltip (matplotlib annotation)
        self._hover_annot = self.ax.annotate("", xy=(0, 0), xytext=(15, 15),
                                             textcoords="offset points", fontsize=8,
                                             color="#18181B", zorder=999,
                                             bbox=dict(boxstyle="round,pad=0.3",
                                                       fc="#FFFFFF", ec="#2A2A2E", alpha=0.9),
                                             arrowprops=dict(arrowstyle="-", color="#666"),
                                             clip_on=False, in_layout=False, visible=False)
        self._topo_label = self.fig.text(0.5, 0.96, "Network Topology",
                                         fontsize=10, fontweight="700",
                                         color="#71717A", ha="center", va="top",
                                         alpha=0.7)
        self._selected_ip = None
        self._current_nodes = []
        self._zoom_factor = 1.0
        self._positions = {}
        self._drag_ip = None
        self._drag_start = None
        self._drag_moved = False
        self._cached_topology = {"nodes": []}
        self._node_artists = {}  # ip -> {glow, node, highlight, label}
        self._edge_artists = []  # [(a_ip, b_ip, line1, line2), ...]

        self._cid_press = self.canvas.mpl_connect("button_press_event", self._on_press)
        self._cid_release = self.canvas.mpl_connect("button_release_event", self._on_release)
        self._cid_motion = self.canvas.mpl_connect("motion_notify_event", self._on_motion)

        self._on_dev_discovered = lambda _: self._redraw()
        self._on_devs_cleared = lambda _: self._redraw()
        self.event_bus.subscribe("DEVICE_DISCOVERED", self._on_dev_discovered)
        self.event_bus.subscribe("DEVICES_CLEARED", self._on_devs_cleared)

        self._redraw()

    def refresh_data(self):
        self._redraw()

    def destroy(self):
        self.event_bus.unsubscribe("DEVICE_DISCOVERED", self._on_dev_discovered)
        self.event_bus.unsubscribe("DEVICES_CLEARED", self._on_devs_cleared)
        for cid in (self._cid_press, self._cid_release, self._cid_motion):
            if cid:
                self.canvas.mpl_disconnect(cid)
        super().destroy()

    def _zoom_in(self):
        self._zoom_factor = min(self._zoom_factor * 1.3, 4.0)
        self._apply_zoom()

    def _zoom_out(self):
        self._zoom_factor = max(self._zoom_factor / 1.3, 0.3)
        self._apply_zoom()

    def _apply_zoom(self):
        if not self._raw_positions:
            return
        self.ax.clear()
        colors = Theme.chart_bg()
        self.fig.set_facecolor(colors["fig"])
        self.ax.set_facecolor(colors["ax"])
        positions = {}
        for ip, (x, y) in self._raw_positions.items():
            positions[ip] = (x * self._zoom_factor, y * self._zoom_factor)
        self._positions = positions
        self._draw_graph(self._current_nodes, positions, colors)
        xvals = [p[0] for p in positions.values()]
        yvals = [p[1] for p in positions.values()]
        xmin, xmax = min(xvals), max(xvals)
        ymin, ymax = min(yvals), max(yvals)
        margin = max((xmax - xmin), (ymax - ymin)) * 0.15 + 0.5
        self.ax.set_xlim(xmin - margin, xmax + margin)
        self.ax.set_ylim(ymin - margin, ymax + margin)
        self.ax.set_aspect("equal")
        self.ax.axis("off")
        self._hover_annot.set_visible(False)
        self.canvas.draw_idle()

    def _save_image(self):
        from tkinter import filedialog
        path = filedialog.asksaveasfilename(
            parent=self, defaultextension=".png",
            filetypes=[("PNG Image", "*.png"), ("All Files", "*.*")],
            title="Save Topology As Image"
        )
        if path:
            self.fig.savefig(path, dpi=150, bbox_inches="tight",
                             facecolor=self.fig.get_facecolor(), edgecolor="none")

    def _redraw(self, _data=None):
        try:
            data = self.ctlr.get_topology_data()
            self._cached_topology = data
            all_nodes = data.get("nodes", [])
            self.ax.clear()
            colors = Theme.chart_bg()
            self.fig.set_facecolor(colors["fig"])
            self.ax.set_facecolor(colors["ax"])

            # Apply filters
            nodes = self._filter_nodes(all_nodes)
            if not nodes:
                self.ax.text(0.5, 0.5, "No devices match filter",
                             ha="center", va="center", color=colors["tick"],
                             fontsize=12, fontweight="600", transform=self.ax.transAxes)
                if all_nodes:
                    self.ax.text(0.5, 0.4, "Try changing filter above",
                                 ha="center", va="center", color=colors["tick"],
                                 fontsize=9, transform=self.ax.transAxes)
                else:
                    self.ax.text(0.5, 0.4, "Run a network scan first",
                                 ha="center", va="center", color=colors["tick"],
                                 fontsize=9, transform=self.ax.transAxes)
                self.ax.set_xlim(0, 1)
                self.ax.set_ylim(0, 1)
                self.ax.axis("off")
                self.canvas.draw_idle()
                self._clear_info()
                return

            layout = self.layout_var.get()
            self._raw_positions = self._compute_layout(nodes, layout)
            self._current_nodes = nodes
            self._apply_zoom()
        except Exception as e:
            logger.error(f"Topology render failed: {e}")

    def _filter_nodes(self, nodes):
        f = self.filter_var.get()
        q = self.search_var.get().strip().lower()

        def matches(nd):
            if f == "Trusted Only" and not nd.get("trusted"):
                return False
            if f == "Low Risk":
                if nd.get("trusted"):
                    return True
                risk = nd.get("risk_score", 0)
                if risk >= 1:
                    return False
            elif f == "Medium Risk":
                if nd.get("trusted"):
                    return False
                risk = nd.get("risk_score", 0)
                if risk < 1 or risk >= 2:
                    return False
            elif f == "High Risk":
                if nd.get("trusted"):
                    return False
                if nd.get("risk_score", 0) < 2:
                    return False
            if q:
                ip = nd.get("ip", "").lower()
                hn = nd.get("hostname", "").lower()
                if q not in ip and q not in hn:
                    return False
            return True

        return [nd for nd in nodes if matches(nd)]

    def _compute_layout(self, nodes, layout_type):
        n = len(nodes)
        if n == 1:
            return {nodes[0]["ip"]: (0.0, 0.0)}

        if layout_type == "Circular":
            angles = [2 * math.pi * i / n for i in range(n)]
            return {nodes[i]["ip"]: (math.cos(angles[i]), math.sin(angles[i]))
                    for i in range(n)}

        if layout_type == "Hierarchical":
            # Group by subnet prefix, then by risk within each subnet
            subnets = {}
            for nd in nodes:
                ip = nd["ip"]
                subnet = self._subnet_prefix(ip)
                subnets.setdefault(subnet, []).append(nd)
            sorted_subnets = sorted(subnets.items(),
                                    key=lambda x: x[0])  # sort subnet groups
            positions = {}
            spacing_x = 1.5
            spacing_y = 1.2
            for col, (subnet, group) in enumerate(sorted_subnets):
                group.sort(key=lambda nd: (-nd.get("risk_score", 0), nd["ip"]))
                for row, nd in enumerate(group):
                    x = (col - (len(sorted_subnets) - 1) / 2) * spacing_x
                    y = (len(group) - 1) / 2 * spacing_y - row * spacing_y
                    positions[nd["ip"]] = (x, y)
            return positions

        # Force-directed with Fruchterman-Reingold style
        pos = {nd["ip"]: (random.uniform(-0.5, 0.5), random.uniform(-0.5, 0.5))
               for nd in nodes}
        conn = self._infer_connections(nodes)
        k = 1.5 / math.sqrt(n + 1)  # optimal distance
        temp = 0.5
        for iteration in range(150):
            forces = {ip: [0.0, 0.0] for ip in pos}
            items = list(pos.items())
            # Repulsion: all pairs
            for i in range(len(items)):
                for j in range(i + 1, len(items)):
                    ip1, (x1, y1) = items[i]
                    ip2, (x2, y2) = items[j]
                    dx = x1 - x2
                    dy = y1 - y2
                    dist = math.hypot(dx, dy) + 0.01
                    f = k * k / (dist * dist)
                    forces[ip1][0] += f * dx
                    forces[ip1][1] += f * dy
                    forces[ip2][0] -= f * dx
                    forces[ip2][1] -= f * dy
            # Attraction along edges
            for a, b in conn:
                if a in pos and b in pos:
                    x1, y1 = pos[a]
                    x2, y2 = pos[b]
                    dx = x2 - x1
                    dy = y2 - y1
                    dist = math.hypot(dx, dy) + 0.01
                    f = dist * dist / k
                    forces[a][0] += f * dx / dist
                    forces[a][1] += f * dy / dist
                    forces[b][0] -= f * dx / dist
                    forces[b][1] -= f * dy / dist
            # Apply forces with cooling
            for ip in pos:
                fx, fy = forces[ip]
                m = math.hypot(fx, fy) + 0.01
                if m > temp:
                    fx = fx / m * temp
                    fy = fy / m * temp
                pos[ip] = (pos[ip][0] + fx, pos[ip][1] + fy)
            temp *= 0.95
        return pos

    @staticmethod
    def _subnet_prefix(ip: str) -> str:
        try:
            addr = ipaddress.ip_address(ip)
            if addr.version == 6:
                # Use first 4 hextets (64-bit prefix) for IPv6
                return ":".join(addr.exploded.split(":")[:4])
            else:
                return ".".join(ip.split(".")[:3])
        except Exception:
            return ip

    def _infer_connections(self, nodes):
        conn = set()
        ips = [nd["ip"] for nd in nodes]
        for i in range(len(ips)):
            for j in range(i + 1, len(ips)):
                if self._subnet_prefix(ips[i]) == self._subnet_prefix(ips[j]):
                    conn.add((ips[i], ips[j]))
        return list(conn)

    def _detect_topology(self, nodes, connections):
        n = len(nodes)
        if n <= 1:
            return "Single"
        if n == 2:
            return "Point-to-Point"
        # Build adjacency
        adj = {nd["ip"]: set() for nd in nodes}
        for a, b in connections:
            adj[a].add(b)
            adj[b].add(a)
        degrees = [len(adj[ip]) for ip in adj]
        # Star: one central node connected to almost all others
        max_deg = max(degrees)
        if max_deg >= n - 2:
            return "Star"
        # Ring: each node has degree 2
        if all(d == 2 for d in degrees):
            return "Ring"
        # Bus: most nodes have degree 2, ends have degree 1
        ones = sum(1 for d in degrees if d == 1)
        twos = sum(1 for d in degrees if d == 2)
        if ones == 2 and twos == n - 2 and n > 2:
            return "Bus"
        # Mesh: dense connections
        total_possible = n * (n - 1) / 2
        actual = len(connections)
        if actual / total_possible > 0.5:
            return "Mesh"
        # Tree: hierarchical by subnet
        subnets = {}
        for nd in nodes:
            subnet = self._subnet_prefix(nd["ip"])
            subnets.setdefault(subnet, 0)
            subnets[subnet] += 1
        if len(subnets) > 1 and all(v > 1 for v in subnets.values()):
            return "Tree"
        if twos > 0 and ones > 0:
            return "Tree"
        return "Hybrid"

    def _draw_graph(self, nodes, positions, colors):
        conn = self._infer_connections(nodes)
        is_dark = Theme.is_dark()

        # Edges with glow effect
        self._edge_artists = []
        for a, b in conn:
            if a in positions and b in positions:
                x1, y1 = positions[a]
                x2, y2 = positions[b]
                line1 = self.ax.plot([x1, x2], [y1, y2], color=colors["grid"],
                                     linewidth=0.8, alpha=0.3, zorder=1)[0]
                line2 = self.ax.plot([x1, x2], [y1, y2], color=colors["grid"],
                                     linewidth=2.5, alpha=0.08, zorder=0)[0]
                self._edge_artists.append((a, b, line1, line2))

        # Nodes
        self._node_artists = {}
        for nd in nodes:
            ip = nd["ip"]
            if ip not in positions:
                continue
            x, y = positions[ip]
            risk = nd.get("risk_score", 0)
            trusted = nd.get("trusted", 0)
            port_count = nd.get("port_count", 0)
            size = 250 + port_count * 30

            if trusted:
                node_color = "#16A34A"
                glow_color = "#16A34A33"
            elif risk >= 2:
                node_color = "#DC2626"
                glow_color = "#DC262633"
            elif risk >= 1:
                node_color = "#EA580C"
                glow_color = "#EA580C33"
            else:
                node_color = "#3B82F6"
                glow_color = "#3B82F633"

            artists = {}
            # Glow circle behind node
            artists["glow"] = self.ax.scatter(x, y, s=size * 2.5, c=glow_color,
                                              edgecolors="none", zorder=1, alpha=0.5,
                                              clip_on=False)
            # Node
            artists["node"] = self.ax.scatter(x, y, s=size, c=node_color,
                                              edgecolors=colors["fig"], linewidth=2.5,
                                              zorder=3, alpha=0.95, clip_on=False)
            # Inner highlight
            artists["highlight"] = self.ax.scatter(x, y, s=size * 0.25, c="white",
                                                    edgecolors="none", zorder=4, alpha=0.15,
                                                    clip_on=False)
            label = nd.get("hostname") or ip
            artists["label"] = self.ax.annotate(label, (x, y), textcoords="offset points",
                                                xytext=(0, 12), ha="center", va="bottom",
                                                fontsize=7, color=colors["text"], zorder=5,
                                                clip_on=False)
            self._node_artists[ip] = artists

        topo_name = self._detect_topology(nodes, conn)
        self._topo_label.set_text(f"Network Topology \u2014 {topo_name}")

        # Legend
        legend_elements = [
            Line2D([0], [0], marker="o", color="w", markerfacecolor="#3B82F6", markersize=8, label="Low Risk"),
            Line2D([0], [0], marker="o", color="w", markerfacecolor="#EA580C", markersize=8, label="Medium Risk"),
            Line2D([0], [0], marker="o", color="w", markerfacecolor="#DC2626", markersize=8, label="High Risk"),
            Line2D([0], [0], marker="o", color="w", markerfacecolor="#16A34A", markersize=8, label="Trusted"),
        ]
        legend = self.ax.legend(handles=legend_elements, loc="lower left",
                                fontsize=7, framealpha=0.85,
                                facecolor=colors["ax"], edgecolor=colors["grid"],
                                labelcolor=colors["text"])
        legend.get_frame().set_linewidth(0.5)

    def _find_node_at(self, x, y):
        if not self._positions:
            return None
        best = None
        best_dist = float("inf")
        for ip, (nx, ny) in self._positions.items():
            d = math.hypot(x - nx, y - ny)
            if d < best_dist:
                best_dist = d
                best = ip
        if best_dist < 0.3 * self._zoom_factor:
            return best
        return None

    def _on_motion(self, event):
        if event.inaxes != self.ax or not self._positions:
            self._hover_annot.set_visible(False)
            self.canvas.draw_idle()
            return
        if self._drag_ip:
            dx = event.xdata - self._drag_start[0]
            dy = event.ydata - self._drag_start[1]
            if not self._drag_moved:
                if abs(dx) < 0.1 and abs(dy) < 0.1:
                    return
                self._drag_moved = True
            x, y = self._positions[self._drag_ip]
            self._positions[self._drag_ip] = (x + dx, y + dy)
            self._raw_positions[self._drag_ip] = (
                self._raw_positions[self._drag_ip][0] + dx / self._zoom_factor,
                self._raw_positions[self._drag_ip][1] + dy / self._zoom_factor
            )
            self._drag_start = (event.xdata, event.ydata)
            # Move dragged node's artists + connected edges — no full redraw
            if self._drag_ip in self._node_artists:
                arts = self._node_artists[self._drag_ip]
                nx, ny = self._positions[self._drag_ip]
                for key in ("glow", "node", "highlight"):
                    if key in arts:
                        arts[key].set_offsets([[nx, ny]])
                if "label" in arts:
                    arts["label"].xy = (nx, ny)
            # Update edges connected to the dragged node
            for a, b, line1, line2 in self._edge_artists:
                if a == self._drag_ip and b in self._positions:
                    ex, ey = self._positions[b]
                    line1.set_data([nx, ex], [ny, ey])
                    line2.set_data([nx, ex], [ny, ey])
                elif b == self._drag_ip and a in self._positions:
                    ex, ey = self._positions[a]
                    line1.set_data([ex, nx], [ey, ny])
                    line2.set_data([ex, nx], [ey, ny])
            self.canvas.draw_idle()
            return
        ip = self._find_node_at(event.xdata, event.ydata)
        if ip:
            data = self._cached_topology
            node = next((nd for nd in data["nodes"] if nd["ip"] == ip), None)
            if node:
                hostname = node.get("hostname") or "\u2014"
                vendor = node.get("vendor") or "\u2014"
                mac = node.get("mac") or "\u2014"
                ports = node.get("port_count", 0)
                risk = node.get("risk_score", 0)
                trusted = node.get("trusted", 0)
                status = node.get("status", "Offline")
                risk_label = "High" if risk >= 2 else ("Medium" if risk >= 1 else "Low")
                text = (f"{ip}\n{hostname}\n{vendor} | {ports} ports\n"
                        f"{'Trusted' if trusted else risk_label} | {status}")
                self._hover_annot.xy = (event.xdata, event.ydata)
                self._hover_annot.set_text(text)
                self._hover_annot.set_visible(True)
                self.canvas.draw_idle()
                return
        if self._hover_annot.get_visible():
            self._hover_annot.set_visible(False)
            self.canvas.draw_idle()

    def _on_press(self, event):
        if event.inaxes != self.ax or not self._positions:
            return
        ip = self._find_node_at(event.xdata, event.ydata)
        if not ip:
            return
        self._drag_ip = ip
        self._drag_start = (event.xdata, event.ydata)
        self._drag_moved = False

    def _on_release(self, event):
        if self._drag_ip:
            if not self._drag_moved:
                self._show_device_info(self._drag_ip)
            self._drag_ip = None
            self._drag_start = None
            self._drag_moved = False

    def _show_device_info(self, ip):
        data = self.ctlr.get_topology_data()
        node = next((nd for nd in data["nodes"] if nd["ip"] == ip), None)
        if not node:
            return
        self._update_info_panel(node)

    def _update_info_panel(self, node):
        for w in self.info_panel.winfo_children():
            w.destroy()

        ip = node.get("ip", "")
        hostname = node.get("hostname") or "\u2014"
        vendor = node.get("vendor") or "\u2014"
        mac = node.get("mac") or "\u2014"
        status = node.get("status", "Offline")
        ports = node.get("port_count", 0)
        risk = node.get("risk_score", 0)
        trusted = node.get("trusted", 0)
        risk_label = "High" if risk >= 2 else ("Medium" if risk >= 1 else "Low")

        ctk.CTkLabel(self.info_panel, text=ip, font=Theme.font(13, "bold"),
                     text_color=Theme.TEXT_PRIMARY, anchor="w").pack(
            fill="x", padx=10, pady=(10, 2), anchor="w")
        ctk.CTkLabel(self.info_panel, text=hostname, font=Theme.font(10),
                     text_color=Theme.TEXT_SECONDARY, anchor="w").pack(
            fill="x", padx=10, pady=(0, 6), anchor="w")

        separator(self.info_panel)

        for label, value in [
            ("Vendor", vendor), ("MAC", mac),
            ("Status", status), ("Ports", str(ports)),
            ("Risk", risk_label), ("Trusted", "Yes" if trusted else "No"),
        ]:
            row = ctk.CTkFrame(self.info_panel, fg_color="transparent")
            row.pack(fill="x", padx=10, pady=1)
            ctk.CTkLabel(row, text=label+":", font=Theme.font(9, "bold"),
                         text_color=Theme.TEXT_MUTED).pack(side="left")
            clr = Theme.DANGER if risk >= 2 else (Theme.WARNING if risk >= 1 else Theme.TEXT_PRIMARY)
            ctk.CTkLabel(row, text=value, font=Theme.font(9),
                         text_color=clr).pack(side="right")

        separator(self.info_panel)

        # Action buttons
        def _open_scanner():
            self.controller.show_frame("NetworkScannerPage")

        def _open_port():
            self.controller.show_frame("PortScannerPage")

        primary_button(self.info_panel, "Scan Ports", _open_port, width=180).pack(
            padx=10, pady=(6, 3))
        secondary_button(self.info_panel, "Device Scanner", _open_scanner, width=180).pack(
            padx=10, pady=(0, 10))

    def _clear_info(self):
        for w in self.info_panel.winfo_children():
            w.destroy()
        self._info_label = ctk.CTkLabel(self.info_panel, text="No device selected",
                                        font=Theme.font(10, "bold"),
                                        text_color=Theme.TEXT_MUTED,
                                        justify="center", anchor="center")
        self._info_label.pack(expand=True, fill="both", pady=40)


def separator(parent):
    s = ctk.CTkFrame(parent, height=1, fg_color=Theme.BORDER)
    s.pack(fill="x", padx=10, pady=6)
