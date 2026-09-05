import logging
from pathlib import Path

from scapy.all import PcapReader as ScapyPcapReader, rdpcap

logger = logging.getLogger(__name__)


class PcapReader:
    """Read and iterate over packets from PCAP files."""

    def __init__(self, filepath: str | Path):
        self.filepath = Path(filepath)
        if not self.filepath.exists():
            raise FileNotFoundError(f"PCAP file not found: {self.filepath}")

    def read_all(self) -> list:
        """Read all packets into memory and return as a list."""
        logger.info("Reading all packets from %s", self.filepath)
        packets = rdpcap(str(self.filepath))
        logger.info("Read %d packets", len(packets))
        return packets

    def read_stream(self, count: int = 0):
        """Yield packets one at a time without loading all into memory.

        Args:
            count: Maximum packets to read (0 = all).
        """
        logger.info("Streaming packets from %s", self.filepath)
        with ScapyPcapReader(str(self.filepath)) as reader:
            for i, packet in enumerate(reader):
                if count and i >= count:
                    break
                yield packet

    @staticmethod
    def get_pcap_files(directory: str | Path) -> list[Path]:
        """Find all .pcap / .pcapng files in a directory."""
        directory = Path(directory)
        extensions = {".pcap", ".pcapng"}
        return [
            f
            for f in directory.iterdir()
            if f.suffix.lower() in extensions
        ]
