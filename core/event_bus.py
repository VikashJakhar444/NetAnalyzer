"""
Event Bus Module.
Decouples core business modules from the presentation layer using a pub-sub model.
"""
import sys
import threading
from typing import Callable, Dict, List, Any

# Setup import compatibility for testing and main execution
from core.logger import logger


class EventBus:
    """
    Thread-safe event publish-subscribe dispatcher.
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(EventBus, cls).__new__(cls, *args, **kwargs)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self.subscribers: Dict[str, List[Callable[..., Any]]] = {}
        self.bus_lock = threading.Lock()
        self._initialized = True
        logger.info("EventBus initialized.")

    def subscribe(self, topic: str, callback: Callable[..., Any]):
        """
        Registers a callback subscriber for a specific event topic.
        """
        with self.bus_lock:
            if topic not in self.subscribers:
                self.subscribers[topic] = []
            if callback not in self.subscribers[topic]:
                self.subscribers[topic].append(callback)
                logger.debug(f"Subscriber registered for event topic '{topic}'.")

    def unsubscribe(self, topic: str, callback: Callable[..., Any]):
        """
        Removes a callback registration from an event topic.
        """
        with self.bus_lock:
            if topic in self.subscribers and callback in self.subscribers[topic]:
                self.subscribers[topic].remove(callback)
                logger.debug(f"Subscriber unsubscribed from event topic '{topic}'.")

    def publish(self, topic: str, *args, **kwargs):
        """
        Publishes an event to all subscribers listening to the topic.
        Runs callbacks on the calling thread context.
        """
        targets = []
        with self.bus_lock:
            if topic in self.subscribers:
                # Copy list to prevent issues if a callback alters subscription table
                targets = list(self.subscribers[topic])

        if not targets:
            return

        for callback in targets:
            try:
                callback(*args, **kwargs)
            except Exception as e:
                logger.error(f"Error executing callback for event topic '{topic}': {e}")
