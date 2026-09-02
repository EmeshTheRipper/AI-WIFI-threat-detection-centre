import logging
from collections.abc import Callable
from threading import Event, Thread

from scapy.all import sniff as scapy_sniff

logger = logging.getLogger(__name__)


class PacketSniffer:
    """Live network packet capture using scapy."""

    def __init__(self, interface: str | None = None, packet_count: int = 0):
        self.interface = interface
        self.packet_count = packet_count
        self._stop_event = Event()
        self._thread: Thread | None = None
        self._callback: Callable | None = None

    def _process_packet(self, packet):
        if self._callback:
            try:
                self._callback(packet)
            except Exception:
                logger.exception("Error processing packet")

    def start(self, callback: Callable, count: int = 0) -> Thread:
        """Start capturing packets in a background thread.

        Args:
            callback: Function called with each captured packet.
            count: Number of packets to capture (0 = unlimited).
        """
        self._callback = callback
        self._stop_event.clear()
        pkt_count = count or self.packet_count

        def _sniff_loop():
            logger.info(
                "Sniffer started on %s",
                self.interface or "default interface",
            )
            scapy_sniff(
                iface=self.interface,
                count=pkt_count,
                prn=self._process_packet,
                stop_filter=lambda _: self._stop_event.is_set(),
            )
            logger.info("Sniffer stopped")

        self._thread = Thread(target=_sniff_loop, daemon=True)
        self._thread.start()
        return self._thread

    def stop(self):
        """Signal the sniffer to stop."""
        self._stop_event.set()

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()
