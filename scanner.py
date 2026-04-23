import _silence  # noqa â€” suppress scapy warning before any scapy import
import subprocess
import socket
import re
import time
import concurrent.futures
from threading import Lock
from dataclasses import dataclass, field
from typing import Optional, List, Callable

CAMERA_VENDORS = {
    "hikvision", "dahua", "axis", "hanwha", "reolink",
    "amcrest", "uniview", "vivotek", "foscam", "wyze",
    "arlo", "ring", "nest", "lorex", "swann", "tiandy",
    "pelco", "bosch security", "avigilon", "genetec",
    "cp plus", "tplink", "tp-link tapo",
}

ROUTER_VENDORS = {
    "cisco", "netgear", "tp-link", "ubiquiti", "mikrotik",
    "linksys", "asus", "zyxel", "draytek", "edgerouter", "tenda",
}

NAS_VENDORS    = {"synology", "qnap", "buffalo", "western digital", "wd"}

MOBILE_VENDORS = {
    "apple", "samsung", "xiaomi", "huawei", "oneplus",
    "oppo", "vivo", "realme", "google", "motorola",
}

PC_VENDORS = {
    "intel", "dell", "hp", "hewlett", "lenovo", "acer",
    "msi", "gigabyte", "asus", "razer", "microsoft surface",
}

CAMERA_PORTS  = {554, 8554}
RTSP_PORTS    = {554, 8554}
SERVER_PORTS  = {21, 22, 25, 53, 3306, 5432, 6379, 27017}

# Extended port list â€” includes Hikvision (8000), Dahua (37777), generic IoT
SCAN_PORTS = "21,22,23,25,53,80,443,554,1080,3389,5000,5001,8000,8080,8443,8554,34567,37777,49152"

_PORT_LABELS = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet (legacy/IoT)",
    25:    "SMTP mail server",
    53:    "DNS server",
    80:    "HTTP web UI",
    443:   "HTTPS",
    554:   "RTSP video stream",
    1080:  "SOCKS proxy",
    3389:  "RDP remote desktop",
    5000:  "UPnP / app port",
    5001:  "App server",
    8000:  "Hikvision SDK / HTTP",
    8080:  "HTTP alt / camera UI",
    8443:  "HTTPS alt",
    8554:  "RTSP alt stream",
    34567: "Dahua / generic DVR",
    37777: "Dahua TCP",
    49152: "UPnP / camera",
}

# HTTP response signatures that indicate a camera web UI
_CAMERA_HTTP_SIGS = (
    "hikvision", "dahua", "reolink", "axis", "foscam", "amcrest",
    "ipcam", "webcam", "netcam", "dvr", "nvr", "onvif",
    "surveillance", "cgi-bin/snapshot", "videostream.cgi",
    "mjpg/video.mjpg", "snap.jpg",
)


@dataclass
class Device:
    ip: str
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    open_ports: List[int] = field(default_factory=list)
    rtsp_status: bool = False
    is_camera: bool = False
    device_category: str = "unknown"
    risk_level: str = "UNKNOWN"
    risk_score: int = 0
    rep_score: int = 0
    risk_reasons: List[str] = field(default_factory=list)
    is_whitelisted: bool = False


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ network helpers

def get_local_network() -> tuple:
    """Returns (network_cidr, local_ip). Tries multiple routes for robustness."""
    for target in ("8.8.8.8", "1.1.1.1", "192.168.1.1"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)
            s.connect((target, 80))
            local_ip = s.getsockname()[0]
            s.close()
            if not local_ip.startswith("127."):
                prefix = local_ip.rsplit(".", 1)[0]
                return f"{prefix}.0/24", local_ip
        except Exception:
            pass
    return "192.168.1.0/24", "192.168.1.1"


def get_gateway_ip(local_ip: str) -> str:
    """Detect actual gateway from routing table; fall back to .1."""
    try:
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command",
             "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
             "Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty NextHop"],
            text=True, timeout=5,
        ).strip()
        if out and re.match(r"\d+\.\d+\.\d+\.\d+", out):
            return out
    except Exception:
        pass
    # Fallback: same subnet .1
    return local_ip.rsplit(".", 1)[0] + ".1"


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ discovery

def _ping_sweep(network: str):
    """Ping all 254 hosts to populate ARP cache. Fast: 64 threads, 500ms each."""
    prefix = network.rsplit(".", 1)[0]
    hosts  = [f"{prefix}.{i}" for i in range(1, 255)]

    def ping(ip: str):
        try:
            subprocess.run(["ping", "-n", "1", "-w", "500", ip],
                           capture_output=True, timeout=2)
        except Exception:
            pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
        list(ex.map(ping, hosts))


def _parse_arp_table() -> List[dict]:
    """Read Windows ARP cache â€” captures both dynamic and static entries."""
    try:
        out = subprocess.check_output(["arp", "-a"], text=True, timeout=10)
        found = []
        for line in out.splitlines():
            # Accept dynamic AND static (cameras often use static ARP)
            m = re.match(
                r"\s+([\d.]+)\s+([0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2}"
                r"[-:][0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2})\s+(dynamic|static)",
                line, re.IGNORECASE,
            )
            if m:
                ip  = m.group(1)
                mac = m.group(2).replace("-", ":").upper()
                # Skip multicast/broadcast MACs
                if not mac.startswith(("01:", "FF:", "33:")):
                    found.append({"ip": ip, "mac": mac})
        return found
    except Exception:
        return []


def _scapy_arp(network: str) -> List[dict]:
    """Scapy ARP broadcast â€” requires Npcap. Retry=2, timeout=6s."""
    try:
        from scapy.all import ARP, Ether, srp
        result = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network),
            timeout=6, verbose=0, retry=2,
        )[0]
        return [{"ip": r.psrc, "mac": r.hwsrc.upper()} for _, r in result]
    except Exception:
        return []


def _ws_discovery() -> List[str]:
    """
    ONVIF WS-Discovery multicast probe â€” finds IP cameras that ignore ARP.
    Returns list of IPs that responded.
    """
    PROBE = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
        '<Header>'
        '<wsa:MessageID xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">'
        'uuid:netguard-probe-1</wsa:MessageID>'
        '<wsa:To xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">'
        'urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>'
        '<wsa:Action xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">'
        'http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>'
        '</Header>'
        '<Body><dn:Probe><dn:Types>dn:NetworkVideoTransmitter'
        '</dn:Types></dn:Probe></Body></Envelope>'
    ).encode()

    found = set()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(3)
        sock.sendto(PROBE, ("239.255.255.250", 3702))
        while True:
            try:
                _, addr = sock.recvfrom(4096)
                found.add(addr[0])
            except socket.timeout:
                break
    except Exception:
        pass
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return list(found)


def _ssdp_discovery() -> List[str]:
    """SSDP M-SEARCH â€” finds UPnP devices (cameras, NAS, smart devices)."""
    MSEARCH = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 3\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode()

    found = set()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(3)
        sock.sendto(MSEARCH, ("239.255.255.250", 1900))
        while True:
            try:
                _, addr = sock.recvfrom(4096)
                found.add(addr[0])
            except socket.timeout:
                break
    except Exception:
        pass
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return list(found)


def arp_scan(network: str) -> List[dict]:
    """
    Aggressive hybrid scan:
    1. Ping sweep all 254 hosts to wake sleeping devices + populate ARP cache
    2. Scapy ARP broadcast (if Npcap available)
    3. Parse Windows ARP table (dynamic + static)
    4. ONVIF WS-Discovery multicast
    5. SSDP multicast
    Merge all, deduplicate by IP.
    """
    merged: dict = {}  # ip â†’ entry

    # Step 1: ping sweep first â€” wakes devices, populates ARP cache
    _ping_sweep(network)

    # Step 2: Scapy ARP
    for e in _scapy_arp(network):
        merged[e["ip"]] = e

    # Step 3: ARP table (after ping sweep it's freshly populated)
    for e in _parse_arp_table():
        if e["ip"] not in merged:
            merged[e["ip"]] = e

    # Step 4 + 5: Multicast probes â€” add IPs we haven't seen yet
    extra_ips: set = set()
    for ip in _ws_discovery() + _ssdp_discovery():
        if ip not in merged:
            extra_ips.add(ip)

    # For multicast-discovered IPs without MAC: ping once, then arp lookup
    for ip in extra_ips:
        try:
            subprocess.run(["ping", "-n", "1", "-w", "500", ip],
                           capture_output=True, timeout=2)
        except Exception:
            pass

    # Re-read ARP table to pick up newly pinged devices
    for e in _parse_arp_table():
        if e["ip"] not in merged:
            merged[e["ip"]] = e

    # Filter to subnet only
    prefix = network.rsplit(".", 1)[0]
    return [v for v in merged.values() if v["ip"].startswith(prefix + ".")]


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ vendor lookup

_mac_lookup      = None
_mac_lookup_lock = Lock()


def _get_mac_lookup():
    global _mac_lookup
    with _mac_lookup_lock:
        if _mac_lookup is None:
            from mac_vendor_lookup import MacLookup
            _mac_lookup = MacLookup()
    return _mac_lookup


def ensure_vendor_db():
    import os as _os
    marker = _os.path.join(_os.path.dirname(__file__), ".vendor_db_ready")
    if _os.path.exists(marker):
        return
    try:
        from mac_vendor_lookup import MacLookup
        MacLookup().update_vendors()
        open(marker, "w").close()
    except Exception:
        pass


def lookup_vendor(mac: str) -> str:
    if not mac or mac == "00:00:00:00:00:00":
        return "Unknown"
    try:
        return _get_mac_lookup().lookup(mac)
    except Exception:
        return _oui_fallback(mac.replace(":", "").replace("-", "")[:6].upper())


def _oui_fallback(oui: str) -> str:
    KNOWN = {
        "C05B67": "Hikvision", "44191F": "Hikvision", "BC0F18": "Hikvision",
        "E0501E": "Dahua",     "4CB477": "Dahua",
        "ACCC8E": "Axis",      "00408C": "Axis",
        "EC71DB": "Reolink",
    }
    return KNOWN.get(oui, "Unknown")


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ probes

def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip


def probe_rtsp(ip: str, port: int, timeout: float = 2.0) -> bool:
    """
    RTSP OPTIONS probe â€” confirms live camera stream.
    Tries root path first; if server responds but returns 401/404,
    it's still a real RTSP server (auth required = camera exists).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            s.send(
                f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\n"
                f"CSeq: 1\r\n"
                f"User-Agent: NetGuard/1.0\r\n\r\n"
                .encode()
            )
            resp = s.recv(1024).decode("utf-8", errors="ignore")
            # Any RTSP response (200 OK, 401 Auth, 404 Not Found) = real RTSP server
            return ("RTSP/1.0" in resp or "200" in resp
                    or "401" in resp or "403" in resp)
    except Exception:
        return False


def probe_http_camera(ip: str, port: int, timeout: float = 2.0) -> bool:
    """GET / on HTTP port â€” detects camera web UIs by response content."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            s.send(
                f"GET / HTTP/1.0\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
                .encode()
            )
            resp = s.recv(2048).decode("utf-8", errors="ignore").lower()
            return any(sig in resp for sig in _CAMERA_HTTP_SIGS)
    except Exception:
        return False


def nmap_scan(ip: str) -> List[int]:
    try:
        result = subprocess.run(
            ["nmap", "-T4", "--open", "-p", SCAN_PORTS,
             "--host-timeout", "5s", ip],
            capture_output=True, text=True, timeout=20,
        )
        return [
            int(m.group(1))
            for line in result.stdout.split("\n")
            if (m := re.match(r"(\d+)/tcp\s+open", line))
        ]
    except Exception:
        return []


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ classification

def classify_device(device: "Device") -> str:
    vl    = device.vendor.lower()
    ports = set(device.open_ports)

    if device.is_camera:
        return "IP camera"
    if any(v in vl for v in CAMERA_VENDORS):
        return "IP camera"
    if any(v in vl for v in ROUTER_VENDORS):
        return "router / access point"
    if any(v in vl for v in NAS_VENDORS):
        return "NAS / storage device"
    if any(v in vl for v in MOBILE_VENDORS):
        return "mobile device"
    if 3389 in ports:
        return "Windows PC / server"
    if any(v in vl for v in PC_VENDORS):
        return "PC / laptop"
    if SERVER_PORTS & ports:
        return "server"
    if 80 in ports or 443 in ports or 8080 in ports:
        return "device with web UI"
    return "unknown device"


def calculate_risk(device: "Device", gateway_ip: str) -> tuple:
    """Returns (risk_level, risk_score, reasons)."""
    if device.ip == gateway_ip or device.is_whitelisted:
        return "SAFE", 0, []

    score   = 0
    reasons: List[str] = []
    vl      = device.vendor.lower()
    ports   = set(device.open_ports)

    vendor_is_camera = any(v in vl for v in CAMERA_VENDORS)
    rtsp_port_open   = bool(RTSP_PORTS & ports)
    rtsp_confirmed   = device.rtsp_status

    # Camera-specific ports (Hikvision/Dahua)
    cam_specific_ports = {8000, 37777, 34567} & ports

    if rtsp_confirmed:
        score += 75
        reasons.append("RTSP stream confirmed â€” active surveillance camera")
    elif rtsp_port_open:
        score += 55
        for p in sorted(RTSP_PORTS & ports):
            reasons.append(f"Port {p} open â€” {_PORT_LABELS[p]}")
    elif vendor_is_camera:
        score += 50
        reasons.append(f"Known camera vendor: {device.vendor}")

    if cam_specific_ports:
        score += 30
        for p in sorted(cam_specific_ports):
            reasons.append(f"Port {p} â€” {_PORT_LABELS.get(p, 'camera/DVR port')}")

    if vendor_is_camera and (rtsp_port_open or cam_specific_ports):
        score += 10
        if "Known camera vendor" not in " ".join(reasons):
            reasons.append(f"Vendor: {device.vendor}")

    # Any detected camera is always at least DANGER — surveillance device
    if device.is_camera and score < 65:
        deficit = 65 - score
        score   = 65
        if not any("camera" in r.lower() or "surveillance" in r.lower() for r in reasons):
            reasons.append("IP camera on network — surveillance device")
        if not reasons or reasons[0].startswith("Likely:"):
            pass  # category prefix already set below
        # bump reason for unknown cam vendor (unrecognised OUI = higher risk)
        if device.vendor.lower() in ("unknown", "") and deficit > 0:
            reasons.append("Hardware vendor unrecognised — possible undisclosed brand")

    if device.vendor.lower() in ("unknown", ""):
        if score > 0:
            score += 15
            reasons.append("Hardware vendor unrecognised")

    if 23 in ports:
        score += 25
        reasons.append("Telnet open â€” legacy or unpatched IoT device")
    if 1080 in ports:
        score += 20
        reasons.append("SOCKS proxy port open")
    if 3389 in ports:
        score += 10
        reasons.append("RDP exposed â€” remote desktop accessible")

    non_std_web = {8080, 8443} & ports
    if non_std_web and not vendor_is_camera:
        score += 10
        reasons.append(f"Non-standard web UI port: {', '.join(map(str, non_std_web))}")

    if device.rep_score > 50:
        score += 40
        reasons.append(f"AbuseIPDB score {device.rep_score}/100 â€” flagged malicious")
    elif device.rep_score > 20:
        score += 20
        reasons.append(f"AbuseIPDB score {device.rep_score}/100 â€” abuse reports on record")

    category = classify_device(device)
    if reasons:
        reasons.insert(0, f"Likely: {category}")

    if score >= 60:
        return "DANGER", score, reasons
    if score >= 30:
        return "SUSPICIOUS", score, reasons
    return "SAFE", score, reasons


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ per-device scan

def _scan_device(entry: dict, gateway_ip: str) -> Device:
    """Full scan of one device â€” runs in parallel worker thread."""
    d            = Device(ip=entry["ip"], mac=entry.get("mac", ""))
    d.hostname   = resolve_hostname(d.ip)
    d.vendor     = lookup_vendor(d.mac)
    d.open_ports = nmap_scan(d.ip)

    # RTSP live probe
    for port in RTSP_PORTS:
        if port in d.open_ports:
            if probe_rtsp(d.ip, port):
                d.rtsp_status = True
                break

    # HTTP camera detection on web ports
    http_camera = False
    if not d.rtsp_status:
        for port in (80, 8080, 8000, 8443):
            if port in d.open_ports:
                if probe_http_camera(d.ip, port):
                    http_camera = True
                    break

    d.is_camera = (
        d.rtsp_status
        or http_camera
        or any(v in d.vendor.lower() for v in CAMERA_VENDORS)
        or bool({8000, 37777, 34567} & set(d.open_ports))
    )

    d.device_category                          = classify_device(d)
    d.risk_level, d.risk_score, d.risk_reasons = calculate_risk(d, gateway_ip)
    return d


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ main entry point

def scan_network(progress_callback: Optional[Callable] = None) -> List[Device]:
    t0 = time.time()

    network, local_ip = get_local_network()
    gateway_ip = get_gateway_ip(local_ip)

    if progress_callback:
        progress_callback("Updating vendor databaseâ€¦", 0)
    ensure_vendor_db()

    if progress_callback:
        progress_callback("Phase 1/3 â€” Pinging subnet, ARP sweep, ONVIF/SSDPâ€¦", 2)

    raw = arp_scan(network)

    if not raw:
        if progress_callback:
            progress_callback("No hosts found. Check network connection.", 100)
        return []

    if progress_callback:
        progress_callback(
            f"Phase 2/3 â€” Port scanning {len(raw)} host(s) (gateway: {gateway_ip})â€¦",
            10,
        )

    completed  = [0]
    prog_lock  = Lock()
    workers    = min(len(raw), 16)

    def scan_one(entry: dict) -> Device:
        d = _scan_device(entry, gateway_ip)
        with prog_lock:
            completed[0] += 1
            pct = 10 + int(completed[0] / len(raw) * 85)
        if progress_callback:
            progress_callback(
                f"Scanned {entry['ip']}  ({completed[0]}/{len(raw)})", pct
            )
        return d

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        devices = list(ex.map(scan_one, raw))

    elapsed = int(time.time() - t0)
    cameras = sum(1 for d in devices if d.is_camera)
    danger  = sum(1 for d in devices if d.risk_level == "DANGER")

    if progress_callback:
        summary = f"Phase 3/3 â€” Done in {elapsed}s Â· {len(devices)} devices"
        if cameras:
            summary += f" Â· {cameras} camera(s)"
        if danger:
            summary += f" Â· {danger} DANGER"
        progress_callback(summary, 100)

    return devices
