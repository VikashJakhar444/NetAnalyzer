"""
Compatibility module with shared fallback implementations.
Centralises DummyLogger to avoid 20+ copies across the codebase.
"""
import sys


class DummyLogger:
    def info(self, msg): print(f"INFO: {msg}")
    def error(self, msg): print(f"ERROR: {msg}", file=sys.stderr)
    def warning(self, msg): print(f"WARNING: {msg}")
    def debug(self, msg): print(f"DEBUG: {msg}")
