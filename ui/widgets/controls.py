"""
Shared page-level components: headers, panels, buttons.
"""
import customtkinter as ctk
from ui.themes.tokens import Theme


def page_header(parent, title: str, subtitle: str = "") -> ctk.CTkFrame:
    """Page title block with optional descriptive subtitle."""
    frame = ctk.CTkFrame(parent, fg_color="transparent")
    frame.grid_columnconfigure(0, weight=1)

    ctk.CTkLabel(
        frame, text=title,
        font=Theme.font(20, "bold"),
        text_color=Theme.TEXT_PRIMARY,
        anchor="w",
    ).grid(row=0, column=0, sticky="w")

    if subtitle:
        ctk.CTkLabel(
            frame, text=subtitle,
            font=Theme.font(12),
            text_color=Theme.TEXT_MUTED,
            anchor="w",
        ).grid(row=1, column=0, sticky="w", pady=(2, 0))

    return frame


def surface_panel(parent, **kwargs) -> ctk.CTkFrame:
    """Elevated card/panel with consistent border and radius."""
    defaults = dict(
        fg_color=Theme.BG_SURFACE,
        border_width=1,
        border_color=Theme.BORDER,
        corner_radius=Theme.RADIUS_LG,
    )
    defaults.update(kwargs)
    return ctk.CTkFrame(parent, **defaults)


def primary_button(parent, text: str, command=None, width: int = 120, **kwargs) -> ctk.CTkButton:
    return ctk.CTkButton(
        parent, text=text, command=command, width=width,
        height=36, corner_radius=Theme.RADIUS_SM,
        fg_color=Theme.ACCENT, hover_color=Theme.ACCENT_HOVER,
        text_color=Theme.TEXT_INVERSE,
        font=Theme.font(12, "bold"),
        **kwargs,
    )


def secondary_button(parent, text: str, command=None, width: int = 120, **kwargs) -> ctk.CTkButton:
    return ctk.CTkButton(
        parent, text=text, command=command, width=width,
        height=36, corner_radius=Theme.RADIUS_SM,
        fg_color=Theme.BG_SURFACE_ALT, hover_color=Theme.BORDER,
        text_color=Theme.TEXT_SECONDARY,
        border_width=1, border_color=Theme.BORDER,
        font=Theme.font(12),
        **kwargs,
    )


def danger_button(parent, text: str, command=None, width: int = 100, **kwargs) -> ctk.CTkButton:
    return ctk.CTkButton(
        parent, text=text, command=command, width=width,
        height=36, corner_radius=Theme.RADIUS_SM,
        fg_color=Theme.DANGER, hover_color=("#B91C1C", "#EF4444"),
        text_color=Theme.TEXT_INVERSE,
        font=Theme.font(12, "bold"),
        **kwargs,
    )


def success_button(parent, text: str, command=None, width: int = 140, **kwargs) -> ctk.CTkButton:
    return ctk.CTkButton(
        parent, text=text, command=command, width=width,
        height=36, corner_radius=Theme.RADIUS_SM,
        fg_color=Theme.SUCCESS, hover_color=("#15803D", "#22C55E"),
        text_color=Theme.TEXT_INVERSE,
        font=Theme.font(12, "bold"),
        **kwargs,
    )


def warning_button(parent, text: str, command=None, width: int = 90, **kwargs) -> ctk.CTkButton:
    return ctk.CTkButton(
        parent, text=text, command=command, width=width,
        height=36, corner_radius=Theme.RADIUS_SM,
        fg_color=Theme.WARNING, hover_color=("#A16207", "#EAB308"),
        text_color=("#FFFFFF", "#18181B"),
        font=Theme.font(12, "bold"),
        **kwargs,
    )


def form_label(parent, text: str, **kwargs) -> ctk.CTkLabel:
    return ctk.CTkLabel(
        parent, text=text,
        font=Theme.font(12, "bold"),
        text_color=Theme.TEXT_SECONDARY,
        **kwargs,
    )


def form_entry(parent, width: int = 200, **kwargs) -> ctk.CTkEntry:
    return ctk.CTkEntry(
        parent, width=width, height=36,
        corner_radius=Theme.RADIUS_SM,
        border_color=Theme.BORDER,
        fg_color=Theme.BG_INPUT,
        text_color=Theme.TEXT_PRIMARY,
        font=Theme.font(12),
        **kwargs,
    )


def option_menu(parent, values: list, width: int = 140, **kwargs) -> ctk.CTkOptionMenu:
    return ctk.CTkOptionMenu(
        parent, values=values, width=width, height=36,
        corner_radius=Theme.RADIUS_SM,
        fg_color=Theme.BG_INPUT,
        button_color=Theme.BG_SURFACE_ALT,
        button_hover_color=Theme.BORDER,
        dropdown_fg_color=Theme.BG_SURFACE,
        dropdown_hover_color=Theme.BG_SURFACE_ALT,
        text_color=Theme.TEXT_PRIMARY,
        font=Theme.font(12),
        **kwargs,
    )


def combo_box(parent, values: list, width: int = 200, **kwargs) -> ctk.CTkComboBox:
    return ctk.CTkComboBox(
        parent, values=values, width=width, height=36,
        corner_radius=Theme.RADIUS_SM,
        fg_color=Theme.BG_INPUT,
        border_color=Theme.BORDER,
        button_color=Theme.BG_SURFACE_ALT,
        button_hover_color=Theme.BORDER,
        dropdown_fg_color=Theme.BG_SURFACE,
        dropdown_hover_color=Theme.BG_SURFACE_ALT,
        text_color=Theme.TEXT_PRIMARY,
        font=Theme.font(12),
        **kwargs,
    )


def section_label(parent, text: str) -> ctk.CTkLabel:
    """Uppercase section divider label for sidebar grouping."""
    return ctk.CTkLabel(
        parent, text=text.upper(),
        font=Theme.font(9, "bold"),
        text_color=Theme.TEXT_MUTED,
        anchor="w",
    )


def status_badge(parent, text: str, variant: str = "success") -> ctk.CTkFrame:
    """Compact status indicator pill."""
    colors = {
        "success": (Theme.SUCCESS_SUBTLE, Theme.SUCCESS),
        "warning": (Theme.WARNING_SUBTLE, Theme.WARNING),
        "danger": (Theme.DANGER_SUBTLE, Theme.DANGER),
        "info": (Theme.ACCENT_SUBTLE, Theme.ACCENT),
    }
    bg, fg = colors.get(variant, colors["info"])

    frame = ctk.CTkFrame(parent, fg_color=bg, corner_radius=Theme.RADIUS_SM)

    dot = ctk.CTkFrame(frame, width=6, height=6, corner_radius=3, fg_color=fg)
    dot.pack(side=ctk.LEFT, padx=(8, 4))

    ctk.CTkLabel(
        frame, text=text,
        font=Theme.font(11, "bold"),
        text_color=fg,
    ).pack(side=ctk.LEFT, padx=(0, 8))

    return frame
