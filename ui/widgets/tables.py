"""
Themed data table wrapper around ttk.Treeview.
"""
from tkinter import ttk
import customtkinter as ctk
from ui.themes.tokens import Theme


class DataTable:
    """Consistent table styling with theme-aware refresh."""

    def __init__(self, parent, columns: list, headings: dict, column_config: dict = None, style_name: str = "NetAnalyzer.Treeview"):
        self.parent = parent
        self.style_name = style_name
        self.columns = columns

        self.frame = ctk.CTkFrame(parent, fg_color="transparent")
        self.frame.grid_columnconfigure(0, weight=1)
        self.frame.grid_rowconfigure(0, weight=1)

        self._apply_style()

        self.tree = ttk.Treeview(self.frame, columns=columns, show="headings", style=self.style_name)
        self.tree.grid(row=0, column=0, sticky="nsew")

        for col in columns:
            self.tree.heading(col, text=headings.get(col, col))
            cfg = (column_config or {}).get(col, {})
            self.tree.column(col, width=cfg.get("width", 100), anchor=cfg.get("anchor", "w"))

        scrollbar = ttk.Scrollbar(self.frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.grid(row=0, column=1, sticky="ns")

    def _apply_style(self):
        style = ttk.Style()
        style.theme_use("clam")

        if Theme.is_dark():
            bg, fg, field = "#1A1A1D", "#F4F4F5", "#141416"
            header_bg, header_fg = "#222225", "#A1A1AA"
            select_bg = "#4F46E5"
        else:
            bg, fg, field = "#FFFFFF", "#18181B", "#FFFFFF"
            header_bg, header_fg = "#F4F4F5", "#52525B"
            select_bg = "#4F46E5"

        style.configure(
            self.style_name,
            background=bg,
            foreground=fg,
            fieldbackground=field,
            rowheight=32,
            borderwidth=0,
            font=(Theme.FONT_FAMILY, 11),
        )
        style.map(self.style_name, background=[("selected", select_bg)])

        heading_style = f"{self.style_name}.Heading"
        style.configure(
            heading_style,
            background=header_bg,
            foreground=header_fg,
            relief="flat",
            font=(Theme.FONT_FAMILY, 10, "bold"),
            padding=(8, 6),
        )
        style.map(heading_style, background=[("active", header_bg)])

    def refresh_theme(self):
        self._apply_style()

    def clear(self):
        for row in self.tree.get_children():
            self.tree.delete(row)

    def insert(self, values: tuple, tags: tuple = ()):
        return self.tree.insert("", "end", values=values, tags=tags)

    def see(self, item):
        self.tree.see(item)

    def tag_configure(self, tag: str, **kwargs):
        self.tree.tag_configure(tag, **kwargs)

    def get_children(self):
        return self.tree.get_children()

    def item(self, item_id, option=None):
        if option:
            return self.tree.item(item_id, option)
        return self.tree.item(item_id)

    def detach(self, item_id):
        self.tree.detach(item_id)

    def reattach(self, item_id, parent, index):
        self.tree.reattach(item_id, parent, index)

    def grid(self, **kwargs):
        self.frame.grid(**kwargs)
