import threading


def _toast(title: str, msg: str, duration: int = 5):
    def _send():
        try:
            from win10toast import ToastNotifier
            ToastNotifier().show_toast(title, msg, duration=duration, threaded=True)
        except Exception:
            try:
                from plyer import notification
                notification.notify(title=title, message=msg, timeout=duration)
            except Exception:
                pass

    threading.Thread(target=_send, daemon=True).start()


def alert_arp_spoof(ip: str, macs: list):
    _toast("NetGuard — ARP Spoof!", f"IP {ip} claimed by {len(macs)} MACs. Possible MITM.", 8)


def alert_rogue_dhcp(server_ip: str):
    _toast("NetGuard — Rogue DHCP!", f"Unauthorized DHCP server: {server_ip}", 8)


def alert_new_device(ip: str, vendor: str):
    _toast("NetGuard — New Device", f"{ip} ({vendor})", 5)


def alert_danger_device(ip: str, hostname: str):
    _toast("NetGuard — Danger Device!", f"High-risk: {hostname} ({ip})", 8)
