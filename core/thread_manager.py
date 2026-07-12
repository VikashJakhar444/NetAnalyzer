"""
Thread Manager Module.
Launches, tracks, and stops background worker threads to keep the UI responsive.
"""
import sys
import threading
from typing import Callable, Dict, Optional, Any

# Setup import compatibility for testing and main execution
from core.logger import logger


class ThreadManager:
    """
    Spins up background workers, tracks active thread states, and manages thread shutdowns.
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(ThreadManager, cls).__new__(cls, *args, **kwargs)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self.workers: Dict[str, threading.Thread] = {}
        self.stop_flags: Dict[str, threading.Event] = {}
        self.lock = threading.Lock()
        self._initialized = True
        logger.info("ThreadManager initialized.")

    def start_worker(self, name: str, target: Callable[..., Any], args: tuple = (), kwargs: Optional[dict] = None) -> bool:
        """
        Launches a worker thread if another thread with the same name is not already active.
        Provides a stop flag (threading.Event) that the target function can monitor.
        """
        if kwargs is None:
            kwargs = {}

        with self.lock:
            if self.is_alive(name):
                logger.warning(f"Worker thread '{name}' is already running. Cannot start duplicate.")
                return False

            # Create an event flag for thread control
            stop_event = threading.Event()
            self.stop_flags[name] = stop_event
            
            # Inject stop flag event parameter if required by target
            kwargs["stop_event"] = stop_event

            # Create thread wrapper
            thread = threading.Thread(
                target=self._run_wrapper,
                args=(name, target, args, kwargs),
                name=name,
                daemon=True  # Daemonized so threads close when main application exits
            )
            self.workers[name] = thread
            thread.start()
            logger.info(f"Started background worker thread: '{name}'")
            return True

    def _run_wrapper(self, name: str, target: Callable[..., Any], args: tuple, kwargs: dict):
        """Wrapper around target function to cleanup references when execution completes."""
        try:
            target(*args, **kwargs)
        except Exception as e:
            logger.error(f"Unhandled exception in background worker '{name}': {e}")
        finally:
            self.cleanup_worker(name)

    def stop_worker(self, name: str, timeout: float = 2.0) -> bool:
        """
        Signals a thread worker to stop by setting its stop flag Event and waits for termination.
        """
        stop_event = None
        thread = None

        with self.lock:
            if not self.is_alive(name):
                return True
            stop_event = self.stop_flags.get(name)
            thread = self.workers.get(name)

        if stop_event:
            logger.info(f"Signaling stop event for worker: '{name}'")
            stop_event.set()

        if thread:
            thread.join(timeout=timeout)
            if thread.is_alive():
                logger.warning(f"Worker thread '{name}' failed to terminate within {timeout} seconds.")
                return False
            else:
                logger.info(f"Worker thread '{name}' stopped successfully.")
                self.cleanup_worker(name)
                return True
        return True

    def cleanup_worker(self, name: str):
        """Removes thread and stop event records from active dictionary tables."""
        with self.lock:
            if name in self.workers:
                del self.workers[name]
            if name in self.stop_flags:
                del self.stop_flags[name]
            logger.debug(f"Cleaned up worker thread registers for '{name}'")

    def is_alive(self, name: str) -> bool:
        """Checks if a worker thread is registered and running."""
        thread = self.workers.get(name)
        return thread is not None and thread.is_alive()

    def get_stop_event(self, name: str) -> Optional[threading.Event]:
        """Gets the stop event instance for a specific thread name."""
        with self.lock:
            return self.stop_flags.get(name)
