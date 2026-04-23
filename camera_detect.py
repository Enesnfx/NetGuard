import socket

CAMERA_VENDORS = {
    "hikvision", "dahua", "axis", "hanwha", "reolink",
    "amcrest", "uniview", "vivotek", "foscam", "wyze",
    "arlo", "ring", "nest", "lorex", "swann", "tiandy",
}

RTSP_PORTS = [554, 8554]
WEB_PORTS = [80, 8080, 8443, 443]


def probe_rtsp(ip: str, port: int = 554, timeout: float = 2.0) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            s.send(f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode())
            resp = s.recv(512).decode("utf-8", errors="ignore")
            return "RTSP" in resp or "200" in resp
    except Exception:
        return False


def classify_device(ip: str, vendor: str, open_ports: list) -> dict:
    result = {
        "is_camera": False,
        "rtsp_active": False,
        "rtsp_port": None,
        "web_ui_port": None,
        "vendor_match": False,
        "confidence": 0,
    }

    vendor_lower = vendor.lower()
    if any(v in vendor_lower for v in CAMERA_VENDORS):
        result["vendor_match"] = True
        result["confidence"] += 40

    for port in RTSP_PORTS:
        if port in open_ports:
            if probe_rtsp(ip, port):
                result["rtsp_active"] = True
                result["rtsp_port"] = port
                result["confidence"] += 40
            else:
                result["confidence"] += 15
            break

    for port in WEB_PORTS:
        if port in open_ports:
            result["web_ui_port"] = port
            result["confidence"] += 10
            break

    result["is_camera"] = result["confidence"] >= 40
    return result
