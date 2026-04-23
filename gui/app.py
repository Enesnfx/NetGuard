import sys
import os
import threading
from datetime import datetime
from typing import List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import _silence  # noqa — suppress scapy warning before any scapy import

import customtkinter as ctk
import scanner
import whitelist
import alerts
import config
import ip_reputation
import exporter
from sniffer import NetworkSniffer, SnifferAlert
from scheduler import ScanScheduler
from gui.tab_general import GeneralTab
from gui.tab_advanced import AdvancedTab

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class NetGuardApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("NetGuard — Network Security Monitor")
        self.geometry("1260x760")
        self.minsize(960, 620)

        self._devices: List[scanner.Device] = []
        self._scanning = False

        api_key = config.get("abuseipdb_api_key")
        if api_key:
            ip_reputation.set_api_key(api_key)

        self._sniffer   = NetworkSniffer(alert_callback=self._on_sniffer_alert)
        self._scheduler = ScanScheduler(scan_fn=self._bg_scan)

        self._build_ui()
        self._sniffer.start()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        if config.get("auto_scan_on_start"):
            self.after(500, self.start_scan)

    # ──────────────────────────────────────────────── UI build
    def _build_ui(self):
        hbar = ctk.CTkFrame(self, height=56, fg_color="#0d1117", corner_radius=0)
        hbar.pack(fill="x", side="top")
        hbar.pack_propagate(False)

        ctk.CTkLabel(hbar, text="NetGuard",
                     font=ctk.CTkFont(size=22, weight="bold"),
                     text_color="#00d4ff").pack(side="left", padx=18, pady=14)

        self._status_lbl = ctk.CTkLabel(
            hbar, text="Ready", font=ctk.CTkFont(size=12), text_color="#555555")
        self._status_lbl.pack(side="left", padx=6)

        self._last_scan_lbl = ctk.CTkLabel(
            hbar, text="", font=ctk.CTkFont(size=10), text_color="#444444")
        self._last_scan_lbl.pack(side="right", padx=18)

        # AbuseIPDB key
        api_frame = ctk.CTkFrame(hbar, fg_color="transparent")
        api_frame.pack(side="right", padx=6)
        ctk.CTkLabel(api_frame, text="AbuseIPDB Key:",
                     font=ctk.CTkFont(size=10),
                     text_color="#555555").pack(side="left", padx=4)
        self._api_entry = ctk.CTkEntry(
            api_frame, width=180, height=28, font=ctk.CTkFont(size=10),
            placeholder_text="optional API key", show="*")
        self._api_entry.pack(side="left")
        saved = config.get("abuseipdb_api_key")
        if saved:
            self._api_entry.insert(0, saved)
        ctk.CTkButton(api_frame, text="Save", width=46, height=28,
                      font=ctk.CTkFont(size=10),
                      fg_color="#1f2937", hover_color="#2d333b",
                      command=self._save_api_key).pack(side="left", padx=4)

        # Tabs
        self._tabs = ctk.CTkTabview(
            self, fg_color="#0d1117",
            segmented_button_fg_color="#161b22",
            segmented_button_selected_color="#00d4ff",
            segmented_button_selected_hover_color="#00b8d9",
            segmented_button_unselected_color="#161b22",
            segmented_button_unselected_hover_color="#1f2937",
        )
        self._tabs.pack(fill="both", expand=True, padx=8, pady=(4, 8))
        self._tabs.add("General")
        self._tabs.add("Advanced")

        self._general = GeneralTab(
            self._tabs.tab("General"),
            scan_callback=self.start_scan,
            whitelist_callback=self._toggle_whitelist,
            schedule_callback=self._toggle_schedule,
        )
        self._general.pack(fill="both", expand=True)

        self._advanced = AdvancedTab(
            self._tabs.tab("Advanced"),
            export_csv_callback=self._export_csv,
            export_pdf_callback=self._export_pdf,
        )
        self._advanced.pack(fill="both", expand=True)

    # ──────────────────────────────────────────────── scan
    def start_scan(self):
        if self._scanning:
            return
        self._scanning = True
        self._set_status("Scanning network…", "#00d4ff")
        self._general.set_scanning(True)
        threading.Thread(target=self._scan_thread, daemon=True).start()

    def _scan_thread(self):
        def prog(msg, _pct):
            self.after(0, lambda m=msg: self._set_status(m, "#00d4ff"))

        try:
            devices = scanner.scan_network(progress_callback=prog)

            # IP reputation enrichment
            for d in devices:
                if not ip_reputation._is_private(d.ip):
                    rep = ip_reputation.check_ip(d.ip)
                    d.rep_score = rep.get("abuse_score", 0)

            # Whitelist flags
            for d in devices:
                d.is_whitelisted = whitelist.is_whitelisted(d.mac)

            # Re-score with rep included (calculate_risk now returns 3 values)
            _, local_ip = scanner.get_local_network()
            gateway = local_ip.rsplit(".", 1)[0] + ".1"
            for d in devices:
                d.risk_level, d.risk_score, d.risk_reasons = \
                    scanner.calculate_risk(d, gateway)

            self._devices = devices
            ts = datetime.now().strftime("%H:%M:%S")
            self.after(0, lambda: self._update_ui(devices, ts))

            for d in devices:
                if d.risk_level == "DANGER":
                    alerts.alert_danger_device(d.ip, d.hostname)

        except Exception as e:
            self.after(0, lambda: self._set_status(f"Scan error: {e}", "#ff4444"))
        finally:
            self._scanning = False
            self.after(0, lambda: self._general.set_scanning(False))

    def _bg_scan(self):
        self.after(0, self.start_scan)

    def _update_ui(self, devices, ts: str):
        count  = len(devices)
        danger = sum(1 for d in devices if d.risk_level == "DANGER")
        self._set_status(
            f"Found {count} device{'s' if count != 1 else ''}",
            "#ff4444" if danger else "#00ff88",
        )
        self._last_scan_lbl.configure(text=f"Last scan: {ts}")
        self._general.update_devices(devices)
        self._advanced.update_devices(devices)

    # ──────────────────────────────────────────────── whitelist
    def _toggle_whitelist(self, mac: str, label: str = "", ip: str = ""):
        if whitelist.is_whitelisted(mac):
            whitelist.remove(mac)
        else:
            whitelist.add(mac, label, ip)
        for d in self._devices:
            d.is_whitelisted = whitelist.is_whitelisted(d.mac)
        self._general.update_devices(self._devices)
        self._advanced.update_devices(self._devices)

    # ──────────────────────────────────────────────── schedule
    def _toggle_schedule(self, enabled: bool, interval_minutes: int = 30):
        if enabled:
            self._scheduler.start(interval_minutes)
        else:
            self._scheduler.stop()

    # ──────────────────────────────────────────────── sniffer
    def _on_sniffer_alert(self, alert: SnifferAlert):
        self.after(0, lambda: self._advanced.add_sniffer_alert(alert))
        if alert.severity == "DANGER":
            if alert.alert_type == "ARP_SPOOF":
                alerts.alert_arp_spoof(alert.src_ip, [alert.src_mac])
            elif alert.alert_type == "ROGUE_DHCP":
                alerts.alert_rogue_dhcp(alert.src_ip)

    # ──────────────────────────────────────────────── export
    def _export_csv(self):
        if not self._devices:
            self._set_status("No devices to export — run a scan first.", "#ffaa00")
            return
        try:
            from tkinter import filedialog
            path = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
                initialfile=f"netguard_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                title="Save CSV Report",
            )
            if not path:
                return
            exporter.export_csv(self._devices, filepath=path)
            self._set_status(f"CSV saved: {os.path.basename(path)}", "#00ff88")
            os.startfile(path)
        except Exception as e:
            self._set_status(f"CSV error: {e}", "#ff4444")

    def _export_pdf(self):
        if not self._devices:
            self._set_status("No devices to export — run a scan first.", "#ffaa00")
            return
        try:
            from tkinter import filedialog
            path = filedialog.asksaveasfilename(
                defaultextension=".pdf",
                filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")],
                initialfile=f"netguard_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                title="Save PDF Report",
            )
            if not path:
                return
            exporter.export_pdf(self._devices, self._sniffer.get_alerts(),
                                 filepath=path)
            self._set_status(f"PDF saved: {os.path.basename(path)}", "#00ff88")
            os.startfile(path)
        except Exception as e:
            self._set_status(f"PDF error: {e}", "#ff4444")

    # ──────────────────────────────────────────────── misc
    def _save_api_key(self):
        key = self._api_entry.get().strip()
        config.set_value("abuseipdb_api_key", key)
        ip_reputation.set_api_key(key)
        self._set_status("API key saved.", "#00ff88")

    def _set_status(self, text: str, color: str = "#888888"):
        self._status_lbl.configure(text=text, text_color=color)

    def _on_close(self):
        self._sniffer.stop()
        self._scheduler.shutdown()
        self.destroy()
