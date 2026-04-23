import customtkinter as ctk
import tkinter as tk
from typing import List, Callable

RISK_COLORS = {
    "SAFE":       "#00ff88",
    "SUSPICIOUS": "#ffaa00",
    "DANGER":     "#ff4444",
    "UNKNOWN":    "#888888",
}

DEVICE_ICONS = {
    "camera":  "CAM",
    "phone":   "MOB",
    "router":  "RTR",
    "server":  "SRV",
    "pc":      " PC",
    "unknown": "  ?",
}

_PHONE_VENDORS  = {"apple", "samsung", "xiaomi", "huawei", "oneplus", "oppo", "google"}
_ROUTER_VENDORS = {"cisco", "netgear", "tp-link", "asus", "linksys", "ubiquiti", "mikrotik"}
_SERVER_VENDORS = {"synology", "qnap", "buffalo", "supermicro"}
_PC_VENDORS     = {"intel", "dell", "hp", "lenovo", "acer", "msi", "gigabyte"}


def _device_type(device) -> str:
    if device.is_camera:
        return "camera"
    vl = device.vendor.lower()
    ports = set(device.open_ports)
    if 3389 in ports:
        return "pc"
    if any(v in vl for v in _SERVER_VENDORS) or (22 in ports and 80 not in ports):
        return "server"
    if any(v in vl for v in _PHONE_VENDORS):
        return "phone"
    if any(v in vl for v in _ROUTER_VENDORS):
        return "router"
    if any(v in vl for v in _PC_VENDORS):
        return "pc"
    return "unknown"


class HealthRing(tk.Canvas):
    def __init__(self, parent, size: int = 180, **kw):
        super().__init__(parent, width=size, height=size,
                         bg="#0d1117", highlightthickness=0, **kw)
        self._size = size
        self._draw(0)

    def set_score(self, score: int):
        self._draw(score)

    def _draw(self, score: int):
        self.delete("all")
        s, pad = self._size, 14
        color = "#00ff88" if score >= 70 else "#ffaa00" if score >= 40 else "#ff4444"

        self.create_arc(pad, pad, s - pad, s - pad,
                        start=0, extent=359.9,
                        outline="#1f2937", width=16, style="arc")
        if score > 0:
            self.create_arc(pad, pad, s - pad, s - pad,
                            start=90, extent=-(score / 100 * 360),
                            outline=color, width=16, style="arc")

        cx = s // 2
        self.create_text(cx, cx - 10, text=str(score),
                         fill=color, font=("Helvetica", 30, "bold"))
        self.create_text(cx, cx + 14, text="/100",
                         fill="#555555", font=("Helvetica", 12))
        self.create_text(cx, cx + 34, text="Network Health",
                         fill="#666666", font=("Helvetica", 9))


class DeviceCard(ctk.CTkFrame):
    def __init__(self, parent, device, whitelist_cb: Callable, **kw):
        super().__init__(parent, fg_color="#161b22", corner_radius=10, **kw)
        self._device = device
        self._whitelist_cb = whitelist_cb
        self._build()

    def _build(self):
        d = self._device
        risk_color = RISK_COLORS.get(d.risk_level, "#888888")
        icon = DEVICE_ICONS.get(_device_type(d), "  ?")

        # ── Row 0: icon | name/ip | risk badge ──────────────────
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 4))
        top.columnconfigure(1, weight=1)

        icon_pill = ctk.CTkFrame(top, fg_color="#0d1117", corner_radius=6,
                                  width=46, height=46)
        icon_pill.grid(row=0, column=0, rowspan=2, padx=(0, 8), sticky="ns")
        icon_pill.grid_propagate(False)
        ctk.CTkLabel(icon_pill, text=icon,
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color="#00d4ff").place(relx=0.5, rely=0.5, anchor="center")

        host = d.hostname if d.hostname != d.ip else d.ip
        ctk.CTkLabel(top, text=host[:26],
                     font=ctk.CTkFont(size=12, weight="bold"),
                     anchor="w").grid(row=0, column=1, sticky="w")

        ctk.CTkLabel(top, text=f"{d.ip}  ·  {d.vendor or 'Unknown'}",
                     font=ctk.CTkFont(size=10), text_color="#888888",
                     anchor="w").grid(row=1, column=1, sticky="w")

        ctk.CTkLabel(top, text=d.risk_level,
                     font=ctk.CTkFont(size=9, weight="bold"),
                     text_color=risk_color,
                     fg_color="#0d1117", corner_radius=4,
                     width=74, height=20).grid(row=0, column=2, rowspan=2,
                                               padx=(6, 0), sticky="e")

        # ── Row 1: risk reasons ──────────────────────────────────
        if d.risk_reasons:
            reasons_text = "  ·  ".join(d.risk_reasons[:3])
            if len(d.risk_reasons) > 3:
                reasons_text += f"  +{len(d.risk_reasons) - 3} more"

            reason_frame = ctk.CTkFrame(self, fg_color="#0d1117", corner_radius=6)
            reason_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 4))

            ctk.CTkLabel(
                reason_frame,
                text=reasons_text,
                font=ctk.CTkFont(size=9),
                text_color=risk_color,
                anchor="w",
                wraplength=320,
                justify="left",
            ).pack(fill="x", padx=8, pady=4)

        # ── Divider ──────────────────────────────────────────────
        ctk.CTkFrame(self, height=1, fg_color="#2d333b").grid(
            row=2, column=0, sticky="ew", padx=6)

        # ── Row 3: MAC / ports / whitelist ───────────────────────
        bot = ctk.CTkFrame(self, fg_color="transparent")
        bot.grid(row=3, column=0, sticky="ew", padx=10, pady=(5, 8))
        bot.columnconfigure(0, weight=1)

        port_str = ", ".join(map(str, d.open_ports[:5])) or "None"
        if len(d.open_ports) > 5:
            port_str += "…"
        ctk.CTkLabel(bot,
                     text=f"MAC: {d.mac}   Ports: {port_str}",
                     font=ctk.CTkFont(size=9), text_color="#555555",
                     anchor="w").grid(row=0, column=0, sticky="w")

        wl_text  = "✓ Listed" if d.is_whitelisted else "+ Whitelist"
        wl_color = "#00ff88"  if d.is_whitelisted else "#00d4ff"
        ctk.CTkButton(
            bot, text=wl_text, width=82, height=22,
            font=ctk.CTkFont(size=9),
            fg_color="transparent", border_width=1,
            border_color=wl_color, text_color=wl_color,
            hover_color="#1f2937",
            command=lambda: self._whitelist_cb(d.mac, d.hostname, d.ip),
        ).grid(row=0, column=1, sticky="e")

        self.columnconfigure(0, weight=1)


class GeneralTab(ctk.CTkFrame):
    def __init__(self, parent, scan_callback: Callable,
                 whitelist_callback: Callable, schedule_callback: Callable, **kw):
        super().__init__(parent, fg_color="#0d1117", **kw)
        self._scan_cb   = scan_callback
        self._wl_cb     = whitelist_callback
        self._sched_cb  = schedule_callback
        self._devices   = []
        self._filter    = "ALL"
        self._build()

    # ─────────────────────────────────────────────────── build
    def _build(self):
        sidebar = ctk.CTkFrame(self, fg_color="#0d1117", width=224)
        sidebar.pack(side="left", fill="y", padx=(8, 4), pady=8)
        sidebar.pack_propagate(False)

        ctk.CTkLabel(sidebar, text="Network Health",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#cccccc").pack(pady=(8, 4))

        ring_wrap = ctk.CTkFrame(sidebar, fg_color="#161b22", corner_radius=12)
        ring_wrap.pack(padx=8, pady=4)
        self._ring = HealthRing(ring_wrap, size=178)
        self._ring.pack(padx=12, pady=12)

        stats_frame = ctk.CTkFrame(sidebar, fg_color="#161b22", corner_radius=8)
        stats_frame.pack(fill="x", padx=8, pady=6)
        self._stats: dict = {}
        for key, label, clr in [
            ("total",      "Total Devices", "#cccccc"),
            ("cameras",    "IP Cameras",    "#00d4ff"),
            ("suspicious", "Suspicious",    "#ffaa00"),
            ("danger",     "Danger",        "#ff4444"),
        ]:
            row = ctk.CTkFrame(stats_frame, fg_color="transparent")
            row.pack(fill="x", padx=10, pady=3)
            ctk.CTkLabel(row, text=label, font=ctk.CTkFont(size=11),
                         text_color="#888888", anchor="w").pack(side="left")
            lbl = ctk.CTkLabel(row, text="0",
                               font=ctk.CTkFont(size=11, weight="bold"),
                               text_color=clr, anchor="e")
            lbl.pack(side="right")
            self._stats[key] = lbl

        self._scan_btn = ctk.CTkButton(
            sidebar, text="Scan Now", height=40,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color="#00d4ff", hover_color="#00b8d9", text_color="#000000",
            command=self._scan_cb,
        )
        self._scan_btn.pack(fill="x", padx=8, pady=(14, 4))

        sched = ctk.CTkFrame(sidebar, fg_color="#161b22", corner_radius=8)
        sched.pack(fill="x", padx=8, pady=4)
        srow = ctk.CTkFrame(sched, fg_color="transparent")
        srow.pack(fill="x", padx=8, pady=(8, 4))
        ctk.CTkLabel(srow, text="Auto-Scan",
                     font=ctk.CTkFont(size=12)).pack(side="left")
        self._sched_sw = ctk.CTkSwitch(
            srow, text="", width=46,
            button_color="#00d4ff", button_hover_color="#00b8d9",
            progress_color="#00d4ff",
            command=self._toggle_schedule,
        )
        self._sched_sw.pack(side="right")

        irow = ctk.CTkFrame(sched, fg_color="transparent")
        irow.pack(fill="x", padx=8, pady=(0, 8))
        ctk.CTkLabel(irow, text="Interval (min)",
                     font=ctk.CTkFont(size=10),
                     text_color="#888888").pack(side="left")
        self._interval_var = ctk.StringVar(value="30")
        ctk.CTkOptionMenu(
            irow, values=["5", "15", "30", "60"],
            variable=self._interval_var,
            width=68, height=24, fg_color="#0d1117", button_color="#2d333b",
            font=ctk.CTkFont(size=10),
        ).pack(side="right")

        right = ctk.CTkFrame(self, fg_color="#0d1117")
        right.pack(side="right", fill="both", expand=True, padx=(4, 8), pady=8)

        hdr = ctk.CTkFrame(right, fg_color="transparent")
        hdr.pack(fill="x", pady=(0, 6))
        ctk.CTkLabel(hdr, text="Devices",
                     font=ctk.CTkFont(size=15, weight="bold")).pack(side="left")
        self._count_lbl = ctk.CTkLabel(hdr, text="",
                                        font=ctk.CTkFont(size=11),
                                        text_color="#888888")
        self._count_lbl.pack(side="left", padx=8)

        filt_row = ctk.CTkFrame(hdr, fg_color="transparent")
        filt_row.pack(side="right")
        for f in ("ALL", "DANGER", "SUSPICIOUS", "CAMERAS"):
            ctk.CTkButton(
                filt_row, text=f, width=86, height=26,
                font=ctk.CTkFont(size=10),
                fg_color="transparent", border_width=1,
                border_color="#2d333b", hover_color="#1f2937",
                command=lambda v=f: self._set_filter(v),
            ).pack(side="left", padx=2)

        self._scroll = ctk.CTkScrollableFrame(
            right, fg_color="#0d1117", scrollbar_button_color="#2d333b")
        self._scroll.pack(fill="both", expand=True)
        for c in range(3):
            self._scroll.grid_columnconfigure(c, weight=1)

        self._show_empty()

    # ─────────────────────────────────────────────────── helpers
    def _show_empty(self):
        for w in self._scroll.winfo_children():
            w.destroy()
        ctk.CTkLabel(self._scroll,
                     text="No devices found.\nClick 'Scan Now' to discover network.",
                     font=ctk.CTkFont(size=12), text_color="#444444").grid(
            row=0, column=0, columnspan=3, pady=60)

    def _set_filter(self, f: str):
        self._filter = f
        self._render_cards()

    def _render_cards(self):
        for w in self._scroll.winfo_children():
            w.destroy()
        if not self._devices:
            self._show_empty()
            return

        shown = self._devices
        if self._filter == "DANGER":
            shown = [d for d in shown if d.risk_level == "DANGER"]
        elif self._filter == "SUSPICIOUS":
            shown = [d for d in shown if d.risk_level == "SUSPICIOUS"]
        elif self._filter == "CAMERAS":
            shown = [d for d in shown if d.is_camera]

        if not shown:
            ctk.CTkLabel(self._scroll,
                         text=f"No {self._filter.lower()} devices.",
                         font=ctk.CTkFont(size=12),
                         text_color="#444444").grid(
                row=0, column=0, columnspan=3, pady=60)
            return

        for i, dev in enumerate(shown):
            card = DeviceCard(self._scroll, dev, whitelist_cb=self._wl_cb)
            row, col = divmod(i, 3)
            card.grid(row=row, column=col, padx=5, pady=5, sticky="nsew")

    def _toggle_schedule(self):
        self._sched_cb(bool(self._sched_sw.get()), int(self._interval_var.get()))

    # ─────────────────────────────────────────────────── public
    def update_devices(self, devices):
        self._devices = devices
        total   = len(devices)
        cameras = sum(1 for d in devices if d.is_camera)
        susp    = sum(1 for d in devices if d.risk_level == "SUSPICIOUS")
        danger  = sum(1 for d in devices if d.risk_level == "DANGER")

        self._stats["total"].configure(text=str(total))
        self._stats["cameras"].configure(
            text=str(cameras), text_color="#00d4ff" if cameras else "#555555")
        self._stats["suspicious"].configure(
            text=str(susp), text_color="#ffaa00" if susp else "#555555")
        self._stats["danger"].configure(
            text=str(danger), text_color="#ff4444" if danger else "#555555")

        score = max(0, min(100, 100 - danger * 25 - susp * 10))
        self._ring.set_score(score)
        self._count_lbl.configure(text=f"({total} found)")
        self._render_cards()

    def set_scanning(self, scanning: bool):
        if scanning:
            self._scan_btn.configure(text="Scanning…", state="disabled",
                                     fg_color="#1f2937", text_color="#888888")
        else:
            self._scan_btn.configure(text="Scan Now", state="normal",
                                     fg_color="#00d4ff", text_color="#000000")
