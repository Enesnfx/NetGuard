"""NetGuard — entry point.
Run: python main.py

First-run behaviour:
  1. Auto-installs missing pip packages.
  2. Downloads + silently installs Npcap (UAC) if absent.
  3. Downloads + silently installs Nmap (UAC) if absent.
  4. Asks for AbuseIPDB API key once; saves to config.json forever.
  5. Launches main GUI.
"""
import _silence  # noqa — MUST be first: suppresses scapy libpcap warning

import sys
import os
import subprocess
import threading
import importlib
import shutil
import tempfile
import urllib.request

# ── dependency versions ────────────────────────────────────────────────────
NPCAP_VERSION = "1.80"
NPCAP_URL     = f"https://npcap.com/dist/npcap-{NPCAP_VERSION}.exe"
NMAP_VERSION  = "7.95"
NMAP_URL      = f"https://nmap.org/dist/nmap-{NMAP_VERSION}-setup.exe"

REQUIRED_PACKAGES = [
    ("customtkinter",   "customtkinter"),
    ("scapy",           "scapy"),
    ("requests",        "requests"),
    ("reportlab",       "reportlab"),
    ("win10toast",      "win10toast"),
    ("apscheduler",     "apscheduler"),
    ("mac_vendor_lookup", "mac-vendor-lookup"),
]


# ── detection ──────────────────────────────────────────────────────────────
def check_package(import_name: str) -> bool:
    try:
        importlib.import_module(import_name)
        return True
    except ImportError:
        return False


def check_nmap() -> bool:
    return shutil.which("nmap") is not None


def check_npcap() -> bool:
    return any(os.path.exists(p) for p in [
        r"C:\Windows\System32\Npcap\wpcap.dll",
        r"C:\Windows\System32\wpcap.dll",
    ])


def get_missing_packages():
    return [(imp, pip) for imp, pip in REQUIRED_PACKAGES if not check_package(imp)]


def has_api_key() -> bool:
    try:
        import config
        return bool(config.get("abuseipdb_api_key"))
    except Exception:
        return False


# ── auto-install helpers ───────────────────────────────────────────────────
def _download(url: str, dest: str, log_fn, label: str):
    log_fn(f"Downloading {label}…")
    last = [0]

    def _hook(block, block_size, total):
        if total > 0:
            pct = min(100, block * block_size * 100 // total)
            if pct - last[0] >= 10:
                log_fn(f"  {label}: {pct}%")
                last[0] = pct

    urllib.request.urlretrieve(url, dest, reporthook=_hook)
    log_fn(f"  {label}: download complete.")


def _run_elevated(exe: str, args: str, log_fn, timeout: int = 180) -> bool:
    cmd = (
        f'Start-Process "{exe}" -ArgumentList "{args}" '
        f'-Verb RunAs -Wait -WindowStyle Hidden'
    )
    log_fn("  UAC prompt will appear — approve to continue.")
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", cmd],
            timeout=timeout, capture_output=True,
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        log_fn("  Timed out waiting for installer.")
        return False
    except Exception as e:
        log_fn(f"  Elevation error: {e}")
        return False


def install_npcap(log_fn) -> bool:
    dest = os.path.join(tempfile.gettempdir(), "npcap_installer.exe")
    try:
        _download(NPCAP_URL, dest, log_fn, f"Npcap {NPCAP_VERSION}")
    except Exception as e:
        log_fn(f"  Npcap download failed: {e}")
        return False
    ok = _run_elevated(dest, "/S /winpcap_mode=yes /loopback_support=yes", log_fn)
    log_fn("  Npcap installed." if ok else "  Npcap install may have failed — check manually.")
    return ok


def install_nmap(log_fn) -> bool:
    dest = os.path.join(tempfile.gettempdir(), "nmap_installer.exe")
    try:
        _download(NMAP_URL, dest, log_fn, f"Nmap {NMAP_VERSION} (~30 MB)")
    except Exception as e:
        log_fn(f"  Nmap download failed: {e}")
        return False
    ok = _run_elevated(dest, "/S", log_fn, timeout=300)
    log_fn("  Nmap installed." if ok else "  Nmap install may have failed — check manually.")
    return ok


# ── installer GUI ──────────────────────────────────────────────────────────
def show_installer(missing_packages, needs_npcap: bool,
                   needs_nmap: bool, needs_api_key: bool):
    import tkinter as tk
    from tkinter import ttk

    root = tk.Tk()
    root.title("NetGuard — First-Run Setup")
    root.geometry("560x480")
    root.configure(bg="#0d1117")
    root.resizable(False, False)
    root.eval("tk::PlaceWindow . center")

    tk.Label(root, text="NetGuard", font=("Helvetica", 26, "bold"),
             bg="#0d1117", fg="#00d4ff").pack(pady=(18, 2))
    tk.Label(root, text="First-run setup", font=("Helvetica", 11),
             bg="#0d1117", fg="#888888").pack()

    status_var = tk.StringVar(value="Starting…")
    tk.Label(root, textvariable=status_var, font=("Helvetica", 11),
             bg="#0d1117", fg="#ffffff").pack(pady=(10, 4))

    style = ttk.Style()
    style.theme_use("default")
    style.configure("NG.Horizontal.TProgressbar",
                    background="#00d4ff", troughcolor="#161b22",
                    borderwidth=0, lightcolor="#00d4ff", darkcolor="#00d4ff")
    progress_var = tk.DoubleVar(value=0)
    ttk.Progressbar(root, variable=progress_var, maximum=100,
                    style="NG.Horizontal.TProgressbar",
                    length=480, mode="determinate").pack(pady=5)

    log_outer = tk.Frame(root, bg="#161b22", bd=1, relief="solid")
    log_outer.pack(pady=5, padx=30, fill="both", expand=True)
    log_text = tk.Text(log_outer, bg="#0d1117", fg="#00ff88",
                       font=("Consolas", 9), bd=0, state="disabled")
    sb = tk.Scrollbar(log_outer, command=log_text.yview)
    log_text.configure(yscrollcommand=sb.set)
    sb.pack(side="right", fill="y")
    log_text.pack(padx=4, pady=4, fill="both", expand=True)

    # API key entry shown only when needed
    api_frame = tk.Frame(root, bg="#0d1117")
    api_var   = tk.StringVar()
    if needs_api_key:
        api_frame.pack(pady=(6, 0), padx=30, fill="x")
        tk.Label(api_frame, text="AbuseIPDB API Key (free at abuseipdb.com):",
                 font=("Helvetica", 10), bg="#0d1117", fg="#888888").pack(anchor="w")
        entry_row = tk.Frame(api_frame, bg="#0d1117")
        entry_row.pack(fill="x")
        api_entry = tk.Entry(entry_row, textvariable=api_var, show="*",
                             font=("Consolas", 10), bg="#161b22",
                             fg="#00d4ff", insertbackground="#00d4ff",
                             relief="flat", bd=4)
        api_entry.pack(side="left", fill="x", expand=True)
        tk.Label(entry_row, text="(optional — skip to continue)",
                 font=("Helvetica", 9), bg="#0d1117", fg="#444444").pack(side="left", padx=6)

    proceed_event = threading.Event()

    continue_btn = tk.Button(
        root, text="Continue →",
        font=("Helvetica", 11, "bold"),
        bg="#00d4ff", fg="#000000",
        activebackground="#00b8d9", relief="flat", padx=20, pady=6,
        command=proceed_event.set,
    )
    if needs_api_key:
        continue_btn.pack(pady=(6, 12))

    def log(msg: str):
        log_text.configure(state="normal")
        log_text.insert("end", f"> {msg}\n")
        log_text.see("end")
        log_text.configure(state="disabled")
        root.update_idletasks()

    def run():
        steps = len(missing_packages) + needs_npcap + needs_nmap + 1
        done  = [0]

        def advance(label: str):
            done[0] += 1
            progress_var.set(done[0] / steps * (85 if needs_api_key else 95))
            status_var.set(label)
            root.update_idletasks()

        # pip packages
        if missing_packages:
            log(f"Installing {len(missing_packages)} Python package(s)…")
            for imp_name, pip_name in missing_packages:
                advance(f"pip install {pip_name}…")
                log(f"  pip install {pip_name}")
                try:
                    subprocess.check_call(
                        [sys.executable, "-m", "pip", "install",
                         pip_name, "--quiet"],
                        stderr=subprocess.DEVNULL,
                    )
                    log(f"  OK: {pip_name}")
                except Exception as e:
                    log(f"  FAIL: {pip_name} — {e}")
        else:
            log("Python packages: all present.")

        # Npcap
        if needs_npcap:
            advance("Installing Npcap…")
            log("─── Npcap (packet capture driver) ───")
            install_npcap(log)

        # Nmap
        if needs_nmap:
            advance("Installing Nmap…")
            log("─── Nmap (port scanner) ───")
            install_nmap(log)

        # MAC vendor database
        advance("Downloading MAC vendor database…")
        log("─── MAC vendor database ───")
        try:
            import sys as _sys
            _sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            from scanner import ensure_vendor_db
            ensure_vendor_db()
            log("  Vendor database ready.")
        except Exception as e:
            log(f"  Vendor DB update failed (offline?): {e}")

        # API key
        if needs_api_key:
            status_var.set("Enter AbuseIPDB API key…")
            log("─── AbuseIPDB API key ───")
            log("Enter your key above (or leave blank) then click Continue.")
            proceed_event.wait()

            key = api_var.get().strip()
            if key:
                try:
                    import config
                    config.set_value("abuseipdb_api_key", key)
                    log("  API key saved to config.json.")
                except Exception as e:
                    log(f"  Could not save key: {e}")
            else:
                log("  Skipped — IP reputation checks disabled.")

        progress_var.set(100)
        status_var.set("Launching NetGuard…")
        log("Setup complete.")
        root.after(1000, lambda: [root.destroy(), launch_app()])

    threading.Thread(target=run, daemon=True).start()
    root.mainloop()


# ── launch ─────────────────────────────────────────────────────────────────
def launch_app():
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    # Reload ip_reputation so it picks up newly saved API key
    import importlib
    import ip_reputation
    importlib.reload(ip_reputation)
    import config
    key = config.get("abuseipdb_api_key")
    if key:
        ip_reputation.set_api_key(key)

    from gui.app import NetGuardApp
    NetGuardApp().mainloop()


def main():
    missing      = get_missing_packages()
    needs_npcap  = not check_npcap()
    needs_nmap   = not check_nmap()
    needs_api    = not has_api_key()

    if missing or needs_npcap or needs_nmap or needs_api:
        show_installer(missing, needs_npcap, needs_nmap, needs_api)
    else:
        launch_app()


if __name__ == "__main__":
    main()
