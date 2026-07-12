"""
Centralized design tokens for a modern, premium interface.
Every color and spacing value has a semantic role — no decorative noise.
"""
import customtkinter as ctk


class Theme:
    """Semantic color and typography tokens. Light tuple first, dark second."""

    # ── Surfaces ──────────────────────────────────────────────
    BG_APP = ("#F8F8F8", "#0C0C0E")
    BG_SIDEBAR = ("#FFFFFF", "#111113")
    BG_HEADER = ("#FFFFFF", "#141416")
    BG_SURFACE = ("#FFFFFF", "#1A1A1D")
    BG_SURFACE_ALT = ("#F4F4F5", "#222225")
    BG_INPUT = ("#F4F4F5", "#1E1E21")
    BG_STATUS = ("#F4F4F5", "#0C0C0E")

    # ── Borders ───────────────────────────────────────────────
    BORDER = ("#E4E4E7", "#2A2A2E")
    BORDER_SUBTLE = ("#F0F0F2", "#1E1E21")
    BORDER_FOCUS = ("#2563EB", "#60A5FA")

    # ── Text ──────────────────────────────────────────────────
    TEXT_PRIMARY = ("#18181B", "#F4F4F5")
    TEXT_SECONDARY = ("#52525B", "#A1A1AA")
    TEXT_MUTED = ("#A1A1AA", "#71717A")
    TEXT_INVERSE = ("#FFFFFF", "#FFFFFF")

    # ── Accent (primary actions, active nav) ──────────────────
    ACCENT = ("#2563EB", "#60A5FA")
    ACCENT_HOVER = ("#1D4ED8", "#3B82F6")
    ACCENT_SUBTLE = ("#EFF6FF", "#1E3A5F")
    ACCENT_MUTED = ("#BFDBFE", "#1E40AF")

    # ── Semantic (meaningful status only) ───────────────────
    SUCCESS = ("#16A34A", "#4ADE80")
    SUCCESS_SUBTLE = ("#F0FDF4", "#052E16")
    WARNING = ("#CA8A04", "#FACC15")
    WARNING_SUBTLE = ("#FEFCE8", "#422006")
    DANGER = ("#DC2626", "#F87171")
    DANGER_SUBTLE = ("#FEF2F2", "#450A0A")
    INFO = ("#2563EB", "#60A5FA")

    # ── Data visualization ────────────────────────────────────
    CHART_COLORS = ["#3B82F6", "#F59E0B", "#EF4444", "#10B981", "#8B5CF6", "#F97316", "#EC4899"]

    # ── Risk severity (port scanner) ──────────────────────────
    RISK_HIGH = ("#DC2626", "#F87171")
    RISK_MEDIUM = ("#CA8A04", "#FACC15")
    RISK_LOW = ("#16A34A", "#4ADE80")
    RISK_NONE = ("#52525B", "#A1A1AA")

    # ── Protocol colors (packet sniffer — distinct but restrained) ──
    PROTO_TCP = ("#3B82F6", "#60A5FA")
    PROTO_UDP = ("#F59E0B", "#FBBF24")
    PROTO_ICMP = ("#EF4444", "#F87171")
    PROTO_DNS = ("#8B5CF6", "#A78BFA")
    PROTO_HTTP = ("#F97316", "#FB923C")
    PROTO_HTTPS = ("#059669", "#34D399")
    PROTO_ARP = ("#6B7280", "#9CA3AF")
    PROTO_ETHERNET = ("#4B5563", "#6B7280")

    # ── Spacing & sizing ──────────────────────────────────────
    RADIUS_SM = 6
    RADIUS_MD = 8
    RADIUS_LG = 12

    SIDEBAR_WIDTH = 240
    HEADER_HEIGHT = 80
    STATUS_HEIGHT = 28

    PAD_PAGE = 24
    PAD_CARD = 16
    PAD_SECTION = 12

    # ── Typography ────────────────────────────────────────────
    FONT_FAMILY = "Segoe UI"

    @staticmethod
    def font(size: int, weight: str = "normal") -> ctk.CTkFont:
        return ctk.CTkFont(family=Theme.FONT_FAMILY, size=size, weight=weight)

    @staticmethod
    def is_dark() -> bool:
        return ctk.get_appearance_mode() == "Dark"

    @staticmethod
    def chart_bg() -> dict:
        """Matplotlib theme colors matching current mode."""
        if Theme.is_dark():
            return {
                "fig": "#0C0C0E",
                "ax": "#1A1A1D",
                "text": "#F4F4F5",
                "grid": "#2A2A2E",
                "tick": "#71717A",
            }
        return {
            "fig": "#F8F8F8",
            "ax": "#FFFFFF",
            "text": "#18181B",
            "grid": "#E4E4E7",
            "tick": "#52525B",
        }


def get_theme() -> Theme:
    return Theme()
