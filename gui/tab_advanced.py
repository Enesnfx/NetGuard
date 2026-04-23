import customtkinter as ctk
import tkinter as tk
from tkinter import ttk
from typing import Callable, List
from datetime import datetime


class AdvancedTab(ctk.CTkFrame):
    def __init__(self, parent, export_csv_callback: Callable,
                 export_pdf_callback: Callable, **kw):
        super().__init__(parent, fg_color="#0d1117", **kw)
        self._csv_cb = export_csv_callback
        self._pdf_cb = export_pdf_callback
        self._devices = []
        self._alerts = []
        self._build()

    # ------------------------------------------------------------------ build
    def _build(self):
        # Toolbar
        bar = ctk.CTkFrame(self, fg_color="#161b22", height=48, corner_radius=8)
        bar.pack(fill="x", padx=8, pady=(8, 4))
        bar.pack_propagate(False)

        ctk.CTkLabel(bar, text="Advanced",
                     font=ctk.CTkFont(size=14, weight="bold")).pack(
            side="left", padx=14, pady=12)

        for text, color, cb in [
            ("Export PDF", "#00d4ff", self._pdf_cb),
            ("Export CSV", "#00ff88", self._csv_cb),
        ]:
            ctk.CTkButton(
                bar, text=text, width=100, height=30,
                font=ctk.CTkFont(size=10),
                fg_color="transparent", border_width=1,
                border_color=color, text_color=color,
                hover_color="#1f2937",
                command=cb,
            ).pack(side="right", padx=5, pady=9)

        # Paned (table top, log bottom)
        pane = tk.PanedWindow(self, orient="vertical",
                              bg="#0d1117", sashwidth=6,
                              sashrelief="flat", sashpad=2)
        pane.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        table_wrap = ctk.CTkFrame(pane, fg_color="#161b22", corner_radius=8)
        pane.add(table_wrap, height=330, minsize=160)
        self._build_table(table_wrap)

        log_wrap = ctk.CTkFrame(pane, fg_color="#161b22", corner_radius=8)
        pane.add(log_wrap, minsize=120)
        self._build_log(log_wrap)

    # ------------------------------------------------------------ device table
    def _build_table(self, parent):
        hdr = ctk.CTkFrame(parent, fg_color="transparent")
        hdr.pack(fill="x", padx=10, pady=(8, 5))

        ctk.CTkLabel(hdr, text="Device Details",
                     font=ctk.CTkFont(size=13, weight="bold")).pack(side="left")
        self._tbl_count = ctk.CTkLabel(hdr, text="",
                                        font=ctk.CTkFont(size=11),
                                        text_color="#888888")
        self._tbl_count.pack(side="left", padx=8)

        cols = ("IP", "MAC", "Hostname", "Vendor", "Ports",
                "RTSP", "Risk", "Rep", "WL")
        widths = (120, 140, 160, 150, 130, 50, 90, 55, 40)

        wrap = tk.Frame(parent, bg="#161b22")
        wrap.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        style = ttk.Style()
        style.theme_use("default")
        style.configure("NG.Treeview",
                        background="#0d1117", foreground="#cccccc",
                        fieldbackground="#0d1117", rowheight=26,
                        borderwidth=0, font=("Consolas", 10))
        style.configure("NG.Treeview.Heading",
                        background="#161b22", foreground="#777777",
                        relief="flat", font=("Helvetica", 10, "bold"))
        style.map("NG.Treeview",
                  background=[("selected", "#1f2937")],
                  foreground=[("selected", "#00d4ff")])

        self._tree = ttk.Treeview(wrap, columns=cols, show="headings",
                                   style="NG.Treeview")
        for col, w in zip(cols, widths):
            self._tree.heading(col, text=col)
            self._tree.column(col, width=w, minwidth=40)

        vsb = ttk.Scrollbar(wrap, orient="vertical", command=self._tree.yview)
        hsb = ttk.Scrollbar(wrap, orient="horizontal", command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        wrap.grid_rowconfigure(0, weight=1)
        wrap.grid_columnconfigure(0, weight=1)

        self._tree.tag_configure("DANGER",     foreground="#ff4444")
        self._tree.tag_configure("SUSPICIOUS", foreground="#ffaa00")
        self._tree.tag_configure("SAFE",       foreground="#00ff88")

    # -------------------------------------------------------------- sniffer log
    def _build_log(self, parent):
        hdr = ctk.CTkFrame(parent, fg_color="transparent")
        hdr.pack(fill="x", padx=10, pady=(8, 4))

        ctk.CTkLabel(hdr, text="Live Sniffer Log",
                     font=ctk.CTkFont(size=13, weight="bold")).pack(side="left")
        ctk.CTkButton(
            hdr, text="Clear", width=55, height=22,
            font=ctk.CTkFont(size=10),
            fg_color="transparent", border_width=1,
            border_color="#444444", text_color="#888888",
            hover_color="#1f2937",
            command=self._clear_log,
        ).pack(side="right", padx=4)

        log_wrap = tk.Frame(parent, bg="#161b22")
        log_wrap.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self._log = tk.Text(
            log_wrap, bg="#0d1117", fg="#cccccc",
            font=("Consolas", 10), bd=0,
            state="disabled", wrap="word",
        )
        vsb = ttk.Scrollbar(log_wrap, orient="vertical", command=self._log.yview)
        self._log.configure(yscrollcommand=vsb.set)
        self._log.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self._log.tag_configure("ts",      foreground="#444444")
        self._log.tag_configure("type",    foreground="#00d4ff",
                                font=("Consolas", 10, "bold"))
        self._log.tag_configure("DANGER",  foreground="#ff4444")
        self._log.tag_configure("WARNING", foreground="#ffaa00")
        self._log.tag_configure("INFO",    foreground="#888888")

        self._log_line("INFO", "SYSTEM",
                       "NetGuard sniffer active — monitoring ARP & DHCP.")

    # ----------------------------------------------------------------- helpers
    def _log_line(self, severity: str, atype: str, desc: str):
        self._log.configure(state="normal")
        ts = datetime.now().strftime("%H:%M:%S")
        self._log.insert("end", f"[{ts}] ", "ts")
        self._log.insert("end", f"[{atype}] ", "type")
        self._log.insert("end", f"{desc}\n", severity)
        self._log.see("end")
        self._log.configure(state="disabled")

    def _clear_log(self):
        self._log.configure(state="normal")
        self._log.delete("1.0", "end")
        self._log.configure(state="disabled")
        self._log_line("INFO", "SYSTEM", "Log cleared.")

    # ------------------------------------------------------------------ public
    def add_sniffer_alert(self, alert):
        self._alerts.append(alert)
        self._log_line(alert.severity, alert.alert_type, alert.description)

    def update_devices(self, devices):
        self._devices = devices
        for item in self._tree.get_children():
            self._tree.delete(item)
        for d in devices:
            ports = ", ".join(map(str, d.open_ports[:5]))
            if len(d.open_ports) > 5:
                ports += "…"
            self._tree.insert("", "end", tags=(d.risk_level,), values=(
                d.ip, d.mac, d.hostname,
                d.vendor or "Unknown",
                ports or "None",
                "Yes" if d.rtsp_status else "No",
                d.risk_level,
                d.rep_score,
                "Y" if d.is_whitelisted else "N",
            ))
        self._tbl_count.configure(text=f"({len(devices)} devices)")
