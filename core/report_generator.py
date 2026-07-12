"""
Report Generator Module.
Generates CSV spreadsheets, JSON dumps, and professional PDF reports using ReportLab.
"""
import csv
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

# Project root for relative paths
BASE_DIR = Path(__file__).resolve().parent.parent

# Try imports
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, KeepTogether, HRFlowable,
    )
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER, TA_RIGHT, TA_LEFT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

try:
    from core.constants import REPORTS_DIR, EXPORTS_DIR
    from core.logger import logger
    from core.database import DatabaseManager
    from core.statistics_engine import StatisticsEngine
    from core.risk_engine import RiskEngine
    from core.vuln_checker import VulnerabilityChecker
except ImportError:
    BASE_DIR = Path(__file__).resolve().parent.parent
    REPORTS_DIR = BASE_DIR / "reports"
    EXPORTS_DIR = BASE_DIR / "exports"
    from core.compat import DummyLogger
    logger = DummyLogger()
    REPORTLAB_AVAILABLE = False


# ─── Dark Aesthetic Color Palette ─────────────────────────────────────
# Near-black base + sage/olive accents — no pure colors anywhere
_C = {
    "bg":          '#121214',   # near-black
    "surface":     '#1a1c1e',   # dark card/table body
    "surface_alt": '#222426',   # alternating row
    "border":      '#2e3234',   # grid lines, subtle borders
    "text":        '#e4e6e8',   # warm off-white text
    "text_dim":    '#8a9090',   # secondary/muted text
    "text_faint":  '#5c6666',   # footer/tiny labels
    "accent":      '#a3b18a',   # sage-400 (muted olive accent)
    "accent_dim":  '#8a9a6e',   # sage-500 (deeper olive)
    "accent_deep": '#556b2f',   # dark olive green (table headers)
    "red":         '#e07070',   # muted coral
    "red_bg":      '#1e1616',   # dark red surface
    "amber":       '#d4a84b',   # muted warm gold
    "amber_bg":    '#1e1c14',   # dark amber surface
    "green":       '#7bc8a4',   # soft sage-mint
    "green_bg":    '#161e1a',   # dark green surface
    "white":       '#f0f2f0',   # natural off-white
}


def _hex(name):
    return colors.HexColor(_C[name])


def _draw_dark_bg(canvas, doc):
    """Draw dark background on every page."""
    canvas.saveState()
    w, h = doc.pagesize
    canvas.setFillColor(_hex('bg'))
    canvas.rect(0, 0, w, h, stroke=0, fill=1)
    canvas.restoreState()


def _page_first(canvas, doc):
    """First page: dark bg only."""
    _draw_dark_bg(canvas, doc)


def _page_later(canvas, doc):
    """Pages 2+: dark bg + header/footer."""
    _draw_dark_bg(canvas, doc)
    canvas.saveState()
    w = doc.pagesize[0]
    # header
    canvas.setStrokeColor(_hex('border'))
    canvas.setLineWidth(0.5)
    canvas.line(50, 752, w - 50, 752)
    canvas.setFont('Helvetica-Bold', 7)
    canvas.setFillColor(_hex('accent'))
    canvas.drawString(50, 756, "NETANALYZER — NETWORK SECURITY REPORT")
    canvas.setFont('Helvetica', 7)
    canvas.setFillColor(_hex('text_dim'))
    canvas.drawRightString(w - 50, 756, datetime.now().strftime('%d %b %Y'))
    # footer
    canvas.line(50, 42, w - 50, 42)
    canvas.setFont('Helvetica', 7)
    canvas.setFillColor(_hex('text_faint'))
    canvas.drawString(50, 32, "CONFIDENTIAL")
    canvas.drawRightString(w - 50, 32, f"Page {doc.page}")
    canvas.restoreState()


class ReportGenerator:
    """
    Compiles database scanning data into professional downloadable files.
    """

    def __init__(self):
        self.db = DatabaseManager()
        self.stats = StatisticsEngine()
        self.risk = RiskEngine()
        self.vuln_checker = VulnerabilityChecker()

    def _get_reports_dir(self) -> Path:
        """Resolves output directory dynamically from configuration preferences."""
        try:
            from config.config import ConfigurationManager
            config_path = ConfigurationManager().get("report_path")
            if config_path:
                p = Path(config_path)
                os.makedirs(p, exist_ok=True)
                return p
        except Exception:
            pass
        fallback_path = BASE_DIR / "reports"
        os.makedirs(fallback_path, exist_ok=True)
        return fallback_path

    # ── Data collection (latest scan only, no cleared) ──────────────────

    def _active_devices(self):
        return self.db.execute_read(
            "SELECT * FROM devices WHERE status != 'Cleared' ORDER BY ip_address")

    def _active_open_ports(self):
        return self.db.execute_read("""
            SELECT d.ip_address, ps.port, ps.protocol, ps.service, ps.state, ps.risk, ps.banner
            FROM port_scans ps
            JOIN devices d ON ps.device_id = d.device_id
            WHERE ps.state IN ('Open','Open|Filtered') AND d.status != 'Cleared'
            ORDER BY d.ip_address, ps.port
        """)

    def _device_ports(self, device_id):
        return self.db.execute_read("""
            SELECT port, protocol, service, risk, banner FROM port_scans
            WHERE device_id = ? AND state IN ('Open','Open|Filtered')
            ORDER BY port
        """, (device_id,))

    def _collect_vulnerabilities(self) -> Dict[str, Any]:
        devices = self._active_devices()
        all_device_ports = {}
        for d in devices:
            ports = self._device_ports(d["device_id"])
            if ports:
                all_device_ports[d["ip_address"]] = ports
        stats = self.vuln_checker.get_statistics(all_device_ports)
        details = []
        for ip, ports in all_device_ports.items():
            result = self.vuln_checker.check_device_ports(ports)
            if result["entries"]:
                details.append({"device_ip": ip, "cves": result["entries"]})
        return {"statistics": stats, "details": details}

    # ── PDF style helpers ─────────────────────────────────────────────

    def _build_styles(self):
        base = getSampleStyleSheet()
        s = {}
        s['h1'] = ParagraphStyle('H1', parent=base['Heading1'],
            fontSize=13, leading=16, textColor=_hex('accent'),
            spaceBefore=16, spaceAfter=6, keepWithNext=True)
        s['h2'] = ParagraphStyle('H2', parent=base['Heading2'],
            fontSize=11, leading=14, textColor=_hex('accent_dim'),
            spaceBefore=10, spaceAfter=4, keepWithNext=True)
        s['body'] = ParagraphStyle('Body', parent=base['BodyText'],
            fontSize=9, leading=13, textColor=_hex('text'))
        s['small'] = ParagraphStyle('Small', parent=s['body'],
            fontSize=7.5, leading=10, textColor=_hex('text_faint'))
        s['th'] = ParagraphStyle('TH', parent=s['body'],
            fontSize=8.5, leading=11, fontName='Helvetica-Bold',
            textColor=_hex('white'))
        s['td'] = ParagraphStyle('TD', parent=s['body'],
            fontSize=8, leading=11, textColor=_hex('text'))
        s['td_bold'] = ParagraphStyle('TDB', parent=s['td'],
            fontName='Helvetica-Bold')
        self._s = s

    def _P(self, text, style_key='body'):
        return Paragraph(str(text) if text else "\u2014", self._s[style_key])

    def _TH(self, text):
        return Paragraph(text, self._s['th'])

    def _TD(self, text, bold=False):
        t = str(text) if text is not None and text != "" else "\u2014"
        return Paragraph(t, self._s['td_bold'] if bold else self._s['td'])

    def _risk_tag(self, risk):
        r = risk or "Low"
        c = _C['green'] if r == 'Low' else (_C['amber'] if r == 'Medium' else _C['red'])
        return Paragraph(f"<font color='{c}'><b>{r}</b></font>", self._s['td'])

    def _table(self, rows, widths):
        """Build a dark-themed styled table."""
        t = Table(rows, colWidths=widths, repeatRows=1, splitInRow=1)
        t.setStyle(TableStyle([
            ('BACKGROUND',    (0, 0), (-1, 0), _hex('accent_deep')),
            ('TEXTCOLOR',     (0, 0), (-1, 0), _hex('white')),
            ('GRID',          (0, 0), (-1, -1), 0.4, _hex('border')),
            ('ROWBACKGROUNDS',(0, 1), (-1, -1), [_hex('surface'), _hex('surface_alt')]),
            ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING',    (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('LEFTPADDING',   (0, 0), (-1, -1), 5),
            ('RIGHTPADDING',  (0, 0), (-1, -1), 5),
        ]))
        return t

    def _hr(self):
        return HRFlowable(width="100%", thickness=0.6, color=_hex('border'),
                          spaceBefore=6, spaceAfter=6)

    def _score_color(self, score):
        if score >= 85: return _C['green'], 'LOW RISK'
        if score >= 60: return _C['amber'], 'MEDIUM RISK'
        return _C['red'], 'HIGH RISK'

    # ── PDF sections ─────────────────────────────────────────────────

    def _sec_header(self, story, score, metrics, vs, devices):
        """Compact top header with branding + date."""
        hdr = Table([
            [Paragraph("<b>NETANALYZER</b>", ParagraphStyle('Brand',
                fontSize=16, leading=18, textColor=_hex('accent'),
                fontName='Helvetica-Bold')),
             Paragraph(f"<b>Network Security Report</b><br/>"
                       f"<font size='8' color='{_C['text_dim']}'>"
                       f"{datetime.now().strftime('%d %b %Y, %H:%M')}</font>",
                       ParagraphStyle('HdrR', fontSize=10, leading=13,
                                      textColor=_hex('text'), alignment=TA_RIGHT))]
        ], colWidths=[250, 252])
        hdr.setStyle(TableStyle([
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('LINEBELOW', (0,0), (-1,-1), 1.5, _hex('accent')),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ]))
        story.append(hdr)
        story.append(Spacer(1, 14))

        # KPI row — 4 metric cards
        sc, sl = self._score_color(score)
        cve_count = vs.get('total_cves', 0)

        def _kpi(label, value, color=_C['text'], bg=_C['surface'], border=_C['border']):
            inner = [
                [Paragraph(f"<font size='7' color='{_C['text_dim']}'><b>{label}</b></font>",
                           ParagraphStyle('KL', fontSize=7, leading=9, alignment=TA_CENTER))],
                [Paragraph(f"<b>{value}</b>",
                           ParagraphStyle('KV', fontSize=15, leading=18,
                                          textColor=colors.HexColor(color),
                                          alignment=TA_CENTER, fontName='Helvetica-Bold'))],
            ]
            t = Table(inner, colWidths=[115])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), colors.HexColor(bg)),
                ('BOX', (0,0), (-1,-1), 0.8, colors.HexColor(border)),
                ('TOPPADDING', (0,0), (-1,-1), 6),
                ('BOTTOMPADDING', (0,0), (-1,-1), 6),
                ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ]))
            return t

        k1 = _kpi("SECURITY SCORE", f"{score}/100", sc, _C['surface'], _C['accent_dim'])
        k2 = _kpi("HOSTS", f"{metrics.get('online_devices',0)}/{metrics.get('total_devices',0)}")
        k3 = _kpi("OPEN PORTS", str(metrics.get('total_open_ports', 0)))
        cve_bg = _C['red_bg'] if cve_count else _C['green_bg']
        cve_bd = _C['red'] if cve_count else _C['green']
        k4 = _kpi("CVE MATCHES", str(cve_count),
                   _C['red'] if cve_count else _C['green'], cve_bg, cve_bd)

        row = Table([[k1, k2, k3, k4]], colWidths=[125, 125, 125, 125])
        row.setStyle(TableStyle([
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('LEFTPADDING', (0,0), (-1,-1), 2),
            ('RIGHTPADDING', (0,0), (-1,-1), 2),
        ]))
        story.append(row)
        story.append(Spacer(1, 10))

        # Port risk distribution bar (fills page 1)
        open_ports = self._active_open_ports()
        high_ct = sum(1 for p in open_ports if p.get('risk') == 'High')
        med_ct = sum(1 for p in open_ports if p.get('risk') == 'Medium')
        low_ct = sum(1 for p in open_ports if p.get('risk') == 'Low')
        if open_ports:
            dist_data = [
                [Paragraph(f"<font color='{_C['red']}'><b>\u25cf</b></font> High Risk: <b>{high_ct}</b>", self._s['td']),
                 Paragraph(f"<font color='{_C['amber']}'><b>\u25cf</b></font> Medium Risk: <b>{med_ct}</b>", self._s['td']),
                 Paragraph(f"<font color='{_C['green']}'><b>\u25cf</b></font> Low Risk: <b>{low_ct}</b>", self._s['td']),
                 Paragraph(f"Total: <b>{len(open_ports)}</b> open ports across <b>{len(devices)}</b> host(s)", self._s['td'])]
            ]
            dist_t = Table(dist_data, colWidths=[120, 130, 120, 130])
            dist_t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), _hex('surface')),
                ('BOX', (0,0), (-1,-1), 0.6, _hex('accent_deep')),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('TOPPADDING', (0,0), (-1,-1), 5),
                ('BOTTOMPADDING', (0,0), (-1,-1), 5),
                ('LEFTPADDING', (0,0), (-1,-1), 8),
            ]))
            story.append(dist_t)
            story.append(Spacer(1, 10))

    def _sec_devices(self, story, devices):
        """Section 1: Device inventory table."""
        story.append(self._P("<b>1 &nbsp; DISCOVERED DEVICES</b>", 'h1'))
        if not devices:
            story.append(self._P("No active hosts found in the current scan session."))
            story.append(self._hr())
            return

        rows = [[self._TH("IP Address"), self._TH("MAC"), self._TH("Hostname"),
                 self._TH("Vendor"), self._TH("RTT (ms)"), self._TH("Status")]]
        for d in devices:
            rtt = f"{d['response_time']*1000:.1f}" if d.get('response_time') else "\u2014"
            rows.append([
                self._TD(d['ip_address'], bold=True),
                self._TD(d.get('mac_address')),
                self._TD(d.get('hostname')),
                self._TD(d.get('vendor')),
                self._TD(rtt),
                self._TD(d.get('status')),
            ])
        story.append(self._table(rows, [82, 100, 90, 100, 55, 55]))
        story.append(Spacer(1, 4))
        story.append(self._hr())

    def _sec_ports(self, story, devices):
        """Section 2: Per-device open ports — one small table per host, avoids the
        giant-single-cell overflow crash."""
        story.append(self._P("<b>2 &nbsp; OPEN PORTS &amp; SERVICES</b>", 'h1'))
        any_ports = False
        for d in devices:
            ports = self._device_ports(d['device_id'])
            if not ports:
                continue
            any_ports = True
            label = d.get('hostname') or d['ip_address']
            story.append(self._P(f"<b>{d['ip_address']}</b> — {label} "
                                 f"({len(ports)} open)", 'h2'))
            rows = [[self._TH("Port"), self._TH("Proto"), self._TH("Service"),
                     self._TH("Banner"), self._TH("Risk")]]
            for p in ports:
                rows.append([
                    self._TD(str(p['port']), bold=True),
                    self._TD(p['protocol']),
                    self._TD(p.get('service')),
                    self._TD((p.get('banner') or '')[:60]),
                    self._risk_tag(p.get('risk')),
                ])
            story.append(self._table(rows, [50, 45, 110, 195, 55]))
            story.append(Spacer(1, 6))

        if not any_ports:
            story.append(self._P("No open ports detected on any host."))
        story.append(self._hr())

    def _sec_risk(self, story, recs):
        """Section 3: Hardening recommendations (only High & Medium)."""
        # Filter to only meaningful recs
        important = [r for r in recs if r.get('risk') in ('High', 'Medium')]
        story.append(self._P("<b>3 &nbsp; SECURITY RECOMMENDATIONS</b>", 'h1'))
        if not important:
            story.append(self._P("No high or medium risk items. Network posture is within "
                                 "acceptable safety thresholds."))
            story.append(self._hr())
            return

        rows = [[self._TH("Risk"), self._TH("Host"), self._TH("Port"),
                 self._TH("Service"), self._TH("Action Required")]]
        for r in important:
            rows.append([
                self._risk_tag(r.get('risk')),
                self._TD(r.get('target')),
                self._TD(str(r.get('port', ''))),
                self._TD(r.get('service')),
                self._TD(r.get('description')),
            ])
        story.append(self._table(rows, [45, 110, 42, 65, 240]))
        story.append(Spacer(1, 6))
        story.append(self._hr())

    def _sec_cves(self, story, vuln_data):
        """Section 4: CVE vulnerability details."""
        stats = vuln_data.get('statistics', {})
        if stats.get('total_cves', 0) == 0:
            return
        story.append(self._P("<b>4 &nbsp; VULNERABILITY ASSESSMENT (CVE)</b>", 'h1'))
        # Summary bar
        story.append(self._P(
            f"Matched <b>{stats['total_cves']}</b> CVEs — "
            f"<font color='{_C['red']}'><b>{stats['critical']}</b> Critical</font>, "
            f"<font color='{_C['amber']}'><b>{stats['high']}</b> High</font>, "
            f"<font color='{_C['amber']}'><b>{stats['medium']}</b> Medium</font> "
            f"across <b>{stats.get('vulnerable_devices', 0)}</b> host(s)."))
        story.append(Spacer(1, 8))

        rows = [[self._TH("Host"), self._TH("CVE ID"), self._TH("Port"),
                 self._TH("Severity"), self._TH("Description"), self._TH("Fix")]]
        for detail in vuln_data.get('details', []):
            ip = detail.get('device_ip', '')
            for cve in detail.get('cves', []):
                sev = cve.get('severity', 'Medium')
                sc = _C['red'] if sev == 'Critical' else (_C['amber'] if sev == 'High' else _C['amber'])
                rows.append([
                    self._TD(ip),
                    self._TD(cve.get('cve', ''), bold=True),
                    self._TD(str(cve.get('port', ''))),
                    Paragraph(f"<font color='{sc}'><b>{sev}</b></font>", self._s['td']),
                    self._TD((cve.get('description') or '')[:120]),
                    self._TD((cve.get('solution') or '')[:90]),
                ])
        story.append(self._table(rows, [68, 78, 35, 52, 145, 120]))
        story.append(Spacer(1, 6))
        story.append(self._hr())

    def _sec_footer(self, story):
        """Final footer note."""
        story.append(Spacer(1, 8))
        story.append(self._P(
            f"<b>Scan Engine:</b> ARP + ICMP host discovery, TCP/UDP connect scans, "
            f"CVE signature matching &nbsp;|&nbsp; "
            f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 'small'))
        story.append(self._P("NetworkAnalyzer v1.0 — Confidential", 'small'))

    # ── Generate PDF ─────────────────────────────────────────────────

    def generate_pdf(self, filename: str = "network_scan_report.pdf") -> str:
        if not REPORTLAB_AVAILABLE:
            logger.error("ReportLab not available.")
            return ""
        output_path = self._get_reports_dir() / filename
        try:
            doc = SimpleDocTemplate(str(output_path), pagesize=letter,
                                    leftMargin=50, rightMargin=50,
                                    topMargin=50, bottomMargin=50)
            self._build_styles()
            story = []

            # Collect data once
            metrics = self.stats.get_dashboard_metrics()
            score = self.risk.calculate_network_score() or 0
            devices = self._active_devices()
            recs = self.risk.generate_recommendations()
            vuln_data = self._collect_vulnerabilities()
            vs = vuln_data.get('statistics', {})

            # Build sections — order maximizes page 1 density
            self._sec_header(story, score, metrics, vs, devices)
            self._sec_devices(story, devices)
            self._sec_risk(story, recs)    # compact table, fills page 1
            self._sec_ports(story, devices) # per-device detail, flows to page 2+
            self._sec_cves(story, vuln_data)
            self._sec_footer(story)

            doc.build(story, onFirstPage=_page_first, onLaterPages=_page_later)
            logger.info(f"PDF report generated: {filename}")
            self.db.save_report(filename, "PDF", score, filename)
            return str(output_path)
        except Exception as e:
            logger.error(f"Failed to generate PDF report: {e}")
            return ""

    # ── JSON ──────────────────────────────────────────────────────────

    def generate_json(self, filename: str = "network_scan_report.json") -> str:
        output_path = self._get_reports_dir() / filename
        try:
            vuln_data = self._collect_vulnerabilities()
            data = {
                "report_metadata": {
                    "title": "Network Security Audit Report",
                    "generated": datetime.now().isoformat(),
                    "generator": "NetworkAnalyzer v1.0",
                },
                "metrics": self.stats.get_dashboard_metrics(),
                "network_score": self.risk.calculate_network_score() or 0,
                "devices": self._active_devices(),
                "port_scans": self.db.execute_read("""
                    SELECT ps.* FROM port_scans ps
                    JOIN devices d ON ps.device_id = d.device_id
                    WHERE d.status != 'Cleared'
                """),
                "packets_summary": self.stats.get_protocol_distribution(),
                "recommendations": self.risk.generate_recommendations(),
                "vulnerabilities": vuln_data,
            }
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, default=str)
            logger.info(f"JSON report generated: {filename}")
            score = self.risk.calculate_network_score() or 0
            self.db.save_report(filename, "JSON", score, filename)
            return str(output_path)
        except Exception as e:
            logger.error(f"Failed to generate JSON report: {e}")
            return ""

    # ── CSV ────────────────────────────────────────────────────────────

    def generate_csv(self, filename: str = "network_scan_report.csv") -> str:
        output_path = self._get_reports_dir() / filename
        try:
            query = """
                SELECT d.ip_address, d.mac_address, d.hostname, d.vendor, d.status,
                       ps.port, ps.protocol, ps.service, ps.risk
                FROM devices d
                LEFT JOIN port_scans ps ON d.device_id = ps.device_id
                    AND ps.state IN ('Open', 'Open|Filtered')
                WHERE d.status != 'Cleared'
                ORDER BY d.ip_address ASC, ps.port ASC
            """
            rows = self.db.execute_read(query)
            with open(output_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "IP Address", "MAC Address", "Hostname", "Vendor", "Status",
                    "Open Port", "Protocol", "Service", "Risk Rating"
                ])
                for row in rows:
                    writer.writerow([
                        row["ip_address"], row["mac_address"] or "",
                        row["hostname"] or "", row["vendor"] or "",
                        row["status"], row["port"] or "N/A",
                        row["protocol"] or "N/A", row["service"] or "N/A",
                        row["risk"] or "N/A",
                    ])
            logger.info(f"CSV report generated: {filename}")
            score = self.risk.calculate_network_score() or 0
            self.db.save_report(filename, "CSV", score, filename)
            return str(output_path)
        except Exception as e:
            logger.error(f"Failed to generate CSV report: {e}")
            return ""
