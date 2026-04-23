"""
Suppress scapy's "No libpcap provider available" warning.

IMPORTANT: Do NOT pre-import scapy here. Pre-importing locks scapy's
internal provider detection to "no provider" at startup, permanently
breaking the sniffer even when Npcap is installed. Instead, we only
set log levels — the warning fires once on first real import, silently.
"""
import sys
import io
import logging
import warnings

# Kill all scapy loggers before the package loads
for _n in ("scapy.runtime", "scapy.loading", "scapy.main",
           "scapy.arch", "scapy"):
    logging.getLogger(_n).setLevel(logging.CRITICAL)

warnings.filterwarnings("ignore")


class _ScapyStderrFilter(io.TextIOWrapper):
    """
    Drop any stderr line that originates from scapy's libpcap check.
    Pass everything else through to the real stderr.
    """
    _NOISE = (
        "no libpcap provider",
        "pcap won't be used",
        "winpcap",
        "WARNING: No",
    )

    def __init__(self, real_stderr):
        self._real = real_stderr

    def write(self, s: str) -> int:
        sl = s.lower()
        if any(k in sl for k in self._NOISE):
            return len(s)
        return self._real.write(s)

    def flush(self):
        self._real.flush()

    def __getattr__(self, item):
        return getattr(self._real, item)


sys.stderr = _ScapyStderrFilter(sys.stderr)
