"""PCAP file reading with in-memory and streaming access."""

import logging
from collections.abc import Iterator
from pathlib import Path

from scapy.packet import Packet
from scapy.utils import PcapReader as ScapyPcapReader, rdpcap

logger = logging.getLogger(__name__)


class PcapReader:
    """Read and iterate over packets from PCAP / PCAPng files."""

    def __init__(self, filepath: str | Path):
        self.filepath = Path(filepath)
        if not self.filepath.exists():
            raise FileNotFoundError(f"PCAP file not found: {self.filepath}")

    def read_all(self) -> list[Packet]:
        """Read all packets into memory and return them as a list."""
        logger.info("Reading all packets from %s", self.filepath)
        packets = rdpcap(str(self.filepath))
        logger.info("Read %d packets", len(packets))
        return list(packets)

    def read_stream(self, count: int = 0) -> Iterator[Packet]:
        """Yield packets one at a time without loading all into memory.

        Args:
            count: Maximum number of packets to yield (0 = all).
        """
        logger.info("Streaming packets from %s", self.filepath)
        with ScapyPcapReader(str(self.filepath)) as reader:
            for i, packet in enumerate(reader):
                if count and i >= count:
                    break
                yield packet

    @staticmethod
    def get_pcap_files(directory: str | Path) -> list[Path]:
        """Find all ``.pcap`` / ``.pcapng`` files in a directory."""
        directory = Path(directory)
        extensions = {".pcap", ".pcapng"}
        return [
            f
            for f in directory.iterdir()
            if f.is_file() and f.suffix.lower() in extensions
        ]