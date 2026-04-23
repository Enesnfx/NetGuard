import _silence  # noqa — must be first, suppresses scapy libpcap warning
import os
import subprocess
import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Optional

_NPCAP_DLLS = [
    r"C:\Windows\System32\Npcap\wpcap.dll",
    r"C:\Windows\System32\wpcap.dll",
]

_NPCAP_ABSENT_ERRORS = (
    "winpcap is not installed",
    "not available at layer 2",
    "libpcap",
    "no match",
    "sniffing",
)


def _npcap_dll_present() -> bool:
    return any(os.path.exists(p) for p in _NPCAP_DLLS)


def _try_start_npcap_service():
    """Attempt to start the npcap driver service (no-op if already running)."""
    try:
        subprocess.run(
            ["sc", "start", "npcap"],
            capture_output=True, timeout=8,
        )
    except Exception:
        pass


def _reload_scapy_provider():
    """
    After Npcap is installed + service started, force scapy to re-detect
    the provider by resetting its L2 socket conf.
    """
    try:
        from scapy.all import conf
        from scapy.arch.windows import get_windows_if_list  # noqa
        # Reload the pcap layer so scapy picks up the newly active driver
        import importlib
        import scapy.arch.windows.native
        importlib.reload(scapy.arch.windows.native)
        conf.use_pcap = True
    except Exception:
        pass


@dataclass
class SnifferAlert:
    timestamp: str
    alert_type: str
    description: str
    src_ip: str = ""
    src_mac: str = ""
    severity: str = "WARNING"


class NetworkSniffer:
    def __init__(self, alert_callback: Optional[Callable] = None):
        self.alert_callback = alert_callback
        self.alerts: list = []
        self.running = False
        self.active  = False
        self._thread: Optional[threading.Thread] = None
        self._ip_mac_table: dict = {}
        self._gateway_ip: Optional[str] = None

    def set_gateway(self, ip: str):
        self._gateway_ip = ip

    def _emit(self, alert: SnifferAlert):
        self.alerts.append(alert)
        if self.alert_callback:
            self.alert_callback(alert)

    def _handle_packet(self, pkt):
        try:
            from scapy.all import ARP, DHCP, Ether, IP

            if pkt.haslayer(ARP) and pkt[ARP].op == 2:
                ip  = pkt[ARP].psrc
                mac = pkt[ARP].hwsrc.upper()
                seen = self._ip_mac_table.setdefault(ip, set())
                seen.add(mac)
                if len(seen) > 1:
                    self._emit(SnifferAlert(
                        timestamp=datetime.now().strftime("%H:%M:%S"),
                        alert_type="ARP_SPOOF",
                        description=(
                            f"IP {ip} claimed by {len(seen)} MACs: "
                            f"{', '.join(seen)}"
                        ),
                        src_ip=ip, src_mac=mac, severity="DANGER",
                    ))

            if pkt.haslayer(DHCP) and pkt.haslayer(IP):
                opts = {k: v for k, v in pkt[DHCP].options if isinstance(k, str)}
                if opts.get("message-type") == 2:
                    server_ip = pkt[IP].src
                    gw        = self._gateway_ip or ""
                    if gw and server_ip != gw:
                        src_mac = (
                            pkt[Ether].src.upper() if pkt.haslayer(Ether) else ""
                        )
                        self._emit(SnifferAlert(
                            timestamp=datetime.now().strftime("%H:%M:%S"),
                            alert_type="ROGUE_DHCP",
                            description=(
                                f"DHCP OFFER from {server_ip} "
                                f"(expected gateway {gw})"
                            ),
                            src_ip=server_ip, src_mac=src_mac, severity="DANGER",
                        ))
        except Exception:
            pass

    def start(self):
        if self.running:
            return
        # If Npcap DLL is present but scapy didn't detect it (fresh install),
        # try to kick the service and reload scapy's provider detection.
        if _npcap_dll_present():
            _try_start_npcap_service()
            _reload_scapy_provider()

        self.running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False

    def _loop(self):
        try:
            from scapy.all import sniff
            self.active = True
            sniff(
                prn=self._handle_packet,
                filter="arp or (udp and port 67)",
                stop_filter=lambda _: not self.running,
                store=0,
            )
        except Exception as e:
            err_lower = str(e).lower()
            if any(k in err_lower for k in _NPCAP_ABSENT_ERRORS):
                if _npcap_dll_present():
                    # DLL exists but driver not active yet — needs reboot
                    msg = (
                        "Npcap is installed but the driver needs a Windows reboot "
                        "to activate. Reboot and relaunch NetGuard."
                    )
                    severity = "WARNING"
                else:
                    msg = (
                        "Live sniffing inactive — Npcap not installed. "
                        "Run main.py to trigger auto-install."
                    )
                    severity = "INFO"

                self._emit(SnifferAlert(
                    timestamp=datetime.now().strftime("%H:%M:%S"),
                    alert_type="SNIFFER_INACTIVE",
                    description=msg,
                    severity=severity,
                ))
            else:
                self._emit(SnifferAlert(
                    timestamp=datetime.now().strftime("%H:%M:%S"),
                    alert_type="SNIFFER_ERROR",
                    description=str(e),
                    severity="WARNING",
                ))
        finally:
            self.active = False

    def get_alerts(self) -> list:
        return list(self.alerts)

    def clear_alerts(self):
        self.alerts.clear()
