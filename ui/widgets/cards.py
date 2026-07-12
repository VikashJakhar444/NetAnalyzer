"""
Metric stat cards for the dashboard.
"""
import customtkinter as ctk
from ui.themes.tokens import Theme


class StatCard(ctk.CTkFrame):
    """Displays a single metric with label, value, and context."""

    def __init__(self, parent, title: str, value: str, context: str, accent: str = None):
        super().__init__(
            parent,
            fg_color=Theme.BG_SURFACE,
            border_width=1,
            border_color=Theme.BORDER,
            corner_radius=Theme.RADIUS_LG,
            height=120,
        )
        self.grid_propagate(False)
        self.grid_columnconfigure(0, weight=1)

        self._accent = accent or Theme.ACCENT

        # Accent strip — visual anchor, not decoration
        self._strip = ctk.CTkFrame(self, width=3, corner_radius=0, fg_color=self._accent)
        self._strip.place(relx=0, rely=0, relheight=1, anchor="nw")

        ctk.CTkLabel(
            self, text=title,
            font=Theme.font(11),
            text_color=Theme.TEXT_MUTED,
            anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=(Theme.PAD_CARD, 8), pady=(Theme.PAD_CARD, 0))

        self.val_lbl = ctk.CTkLabel(
            self, text=value,
            font=Theme.font(28, "bold"),
            text_color=self._accent,
            anchor="w",
        )
        self.val_lbl.grid(row=1, column=0, sticky="w", padx=(Theme.PAD_CARD, 8), pady=(0, 0))

        ctk.CTkLabel(
            self, text=context,
            font=Theme.font(10),
            text_color=Theme.TEXT_MUTED,
            anchor="w",
        ).grid(row=2, column=0, sticky="w", padx=(Theme.PAD_CARD, 8), pady=(2, Theme.PAD_CARD))

    def set_value(self, value: str, color=None):
        self.val_lbl.configure(text=value)
        if color:
            self.val_lbl.configure(text_color=color)
            self._strip.configure(fg_color=color)
