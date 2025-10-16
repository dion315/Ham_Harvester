#!/usr/bin/env python3
"""
Ham Harvester (QRZ-only mode while FCC ULS is offline)

What this build does:
- Prompt-first QRZ login/API key (required to proceed)
- Mode: Callsign(s) only (paste or CSV) -> Lookup via QRZ XML API
- CSV export fields: callsign, name, addr1, addr2, city, state, county (best-effort), zip, grid, email, lat, lon, address
- Map export: KML, HTML (Leaflet or Google if API key provided)
- Verbose logging, progress/ETA, Stop button
- County/State UI present but disabled with explanatory text (no QRZ XML bulk-by-county)

Why no County/State harvesting now?
- QRZ XML API spec exposes Session, Callsign and DXCC nodes (no bulk / county listing).
  See: https://www.qrz.com/docs/xml/current_spec.html
"""

import sys
import subprocess
import importlib
import threading
import queue
import time
import csv
import json
import requests
import xml.etree.ElementTree as ET
from datetime import datetime
import re
import webbrowser

# ---------- tk check first (system-provided) ----------
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext
except Exception:
    print("[ERROR] tkinter is not available.\n"
          "Debian/Ubuntu: sudo apt-get install python3-tk\n"
          "Fedora: sudo dnf install python3-tkinter\n"
          "Windows/macOS: install Python from python.org (includes tkinter).")
    sys.exit(1)

# ---------- deps (pip-installable) ----------
def ensure_deps(verbose=False):
    req = ["requests", "simplekml", "geopy", "beautifulsoup4"]
    missing = []
    for m in req:
        try:
            importlib.import_module(m)
            if verbose:
                print(f"[OK] {m} importable")
        except ImportError:
            missing.append(m)
    if not missing:
        if verbose:
            print("[INFO] All dependencies satisfied")
        return
    print(f"[INFO] Missing packages: {missing}")
    print("[INFO] Attempting to install missing packages into the current environment...")
    for m in missing:
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", m])
            print(f"[INSTALLED] {m}")
        except Exception as e:
            print(f"[ERROR] Could not install {m}: {e}")
            print("Install dependencies manually in your virtualenv and re-run.")
            sys.exit(1)

ensure_deps(verbose=True)

# ---------- now safe to import external packages ----------
from geopy.geocoders import Nominatim as GeoNominatim  # optional; we also have manual OSM call
import simplekml
from bs4 import BeautifulSoup  # (not used for QRZ; left in for future FCC HTML parsing if re-enabled)

# ---------- Globals / HTTP ----------
QRZ_XML_BASE = "https://xmldata.qrz.com/xml/current/"
USER_AGENT = "HamHarvester/1.0 (+https://example.invalid)"
HTTP = requests.Session()
HTTP.headers.update({"User-Agent": USER_AGENT})

# ---------- Helpers ----------
def now_ts():
    return time.time()

def nice_elapsed(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h}h {m}m {s}s"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"

CALL_RE = re.compile(r"^[A-Z0-9/]{3,}$", re.I)

# ---------- XML helpers ----------
def find_first(elem, *tag_names):
    if elem is None:
        return None
    want = {t.lower() for t in tag_names}
    for node in elem.iter():
        local = node.tag.split('}', 1)[-1].lower()
        if local in want:
            return node
    return None

def find_text(elem, *tag_names):
    if elem is None:
        return ""
    node = find_first(elem, *tag_names)
    if node is not None and node.text:
        return node.text.strip()
    return ""

# ---------- QRZ XML API ----------
def qrz_login(username, password, verbose=False):
    if verbose:
        print("[qrz_login] attempting login")
    def parse_session_key(xml_text):
        root = ET.fromstring(xml_text)
        ses = find_first(root, "Session")
        key = find_text(ses, "Key") if ses is not None else ""
        if not key and ses is not None and ses.text:
            key = ses.text.strip()
        return key

    # try POST xml
    try:
        xml_payload = (
            f"<QRZDatabase><USERNAME>{username}</USERNAME><PASSWORD>{password}</PASSWORD>"
            "<OPTIONS><keeplogin>1</keeplogin></OPTIONS></QRZDatabase>"
        )
        resp = HTTP.post(
            QRZ_XML_BASE,
            data=xml_payload,
            headers={"Content-Type": "application/xml", "User-Agent": USER_AGENT},
            timeout=20,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"QRZ login HTTP {resp.status_code}")
        key = parse_session_key(resp.text)
        if key:
            if verbose:
                print("[qrz_login] obtained session key")
            return key
    except Exception as e:
        if verbose:
            print("[qrz_login] xml-post failed:", e)

    # fallback GET
    try:
        resp2 = HTTP.get(
            QRZ_XML_BASE,
            params={"username": username, "password": password},
            headers={"User-Agent": USER_AGENT},
            timeout=20,
        )
        if resp2.status_code != 200:
            raise RuntimeError(f"QRZ login HTTP {resp2.status_code}")
        key = parse_session_key(resp2.text)
        if key:
            return key
    except Exception as e:
        if verbose:
            print("[qrz_login] GET fallback failed:", e)

    raise RuntimeError("QRZ login failed. Subscription with XML privileges required.")

def qrz_lookup_call(session_key, callsign, verbose=False):
    # returns dict or None
    resp = HTTP.get(QRZ_XML_BASE, params={"s": session_key, "callsign": callsign}, timeout=20)
    if resp.status_code != 200:
        raise RuntimeError(f"QRZ lookup HTTP {resp.status_code}")
    root = ET.fromstring(resp.text)
    call = find_first(root, "call", "Callsign")
    if call is None:
        # If Session error present, surface it
        ses = find_first(root, "Session")
        err = find_text(ses, "Error") if ses is not None else ""
        if err:
            raise RuntimeError(f"QRZ error: {err}")
        return None

    def gt(tag): return find_text(call, tag)

    data = {
        "callsign": gt("call") or callsign,
        "fname": gt("fname") or gt("name"),
        "addr1": gt("addr1"),
        "addr2": gt("addr2"),
        "city": gt("addr2") if (gt("city") == "" and gt("addr2")) else gt("city"),  # some records use addr2=city
        "state": gt("state"),
        "zipcode": gt("zip") or gt("zipcode") or gt("postcode"),
        "country": gt("country"),
        "grid": gt("grid"),
        "email": gt("email"),
        "county": gt("county"),  # not always present
    }
    parts = [data.get("addr1"), data.get("addr2"), data.get("city"), data.get("state"),
             data.get("zipcode"), data.get("country")]
    data["address"] = ", ".join([p for p in parts if p])
    return data

# ---------- Geocoding ----------
def geocode_nominatim(address, email="you@example.com", pause=1.0, verbose=False):
    url = "https://nominatim.openstreetmap.org/search"
    headers = {"User-Agent": f"{USER_AGENT} ({email})"}
    params = {"q": address, "format": "json", "limit": 1, "email": email}
    for attempt in range(3):
        if verbose:
            print(f"[geocode_nominatim] {address} (try {attempt+1})")
        r = HTTP.get(url, params=params, headers=headers, timeout=20)
        if r.status_code == 200:
            arr = r.json()
            if arr:
                lat = float(arr[0]["lat"]); lon = float(arr[0]["lon"])
                time.sleep(pause)
                return lat, lon
            time.sleep(pause)
            return None
        if r.status_code in (429, 503):
            time.sleep(pause * (2 ** attempt))
            continue
        raise RuntimeError(f"Nominatim HTTP {r.status_code}")
    return None

def geocode_google(address, api_key, verbose=False):
    url = "https://maps.googleapis.com/maps/api/geocode/json"
    params = {"address": address, "key": api_key}
    if verbose:
        print(f"[geocode_google] {address}")
    r = HTTP.get(url, params=params, timeout=20)
    if r.status_code != 200:
        raise RuntimeError(f"Google geocode HTTP {r.status_code}")
    j = r.json()
    if j.get("status") != "OK":
        return None, j.get("status", "UNKNOWN")
    loc = j["results"][0]["geometry"]["location"]
    return (loc["lat"], loc["lng"]), "OK"

# ---------- Worker (QRZ-only) ----------
class LookupWorker(threading.Thread):
    def __init__(self, callsigns, session_key, geocode_mode, google_key,
                 nominatim_email, out_q, verbose=False):
        super().__init__(daemon=True)
        self.callsigns = callsigns
        self.session_key = session_key
        self.geocode_mode = geocode_mode
        self.google_key = google_key
        self.nominatim_email = nominatim_email or "you@example.com"
        self.out_q = out_q
        self.verbose = verbose
        self.stop_event = threading.Event()

    def stop(self):
        self.stop_event.set()

    def run(self):
        start = now_ts()
        total = len(self.callsigns)
        processed = 0
        recs = []
        for cs in self.callsigns:
            if self.stop_event.is_set():
                break
            try:
                cu = cs.strip().upper()
                if not CALL_RE.match(cu):
                    self.out_q.put(("log", f"Skipping invalid callsign: {cu}"))
                else:
                    info = qrz_lookup_call(self.session_key, cu, verbose=self.verbose) or {"callsign": cu}
                    # Geocode
                    lat = lon = None
                    addr = info.get("address", "")
                    if addr:
                        try:
                            if self.geocode_mode == "google" and self.google_key:
                                loc, status = geocode_google(addr, self.google_key, verbose=self.verbose)
                                if loc:
                                    lat, lon = loc
                                else:
                                    self.out_q.put(("log", f"Google geocode status for {cu}: {status}"))
                            else:
                                loc = geocode_nominatim(addr, email=self.nominatim_email, verbose=self.verbose)
                                if loc:
                                    lat, lon = loc
                            if loc:
                                info["lat"] = lat; info["lon"] = lon
                            else:
                                info["lat"] = info["lon"] = ""
                        except Exception as ge:
                            info["lat"] = info["lon"] = ""
                            self.out_q.put(("log", f"Geocode error for {cu}: {ge}"))
                    else:
                        info["lat"] = info["lon"] = ""
                    recs.append(info)
            except Exception as e:
                self.out_q.put(("log", f"Error processing {cs}: {e}"))

            processed += 1
            elapsed = now_ts() - start
            avg = elapsed / processed if processed else 0.001
            remaining = max(0, total - processed)
            eta = remaining * avg
            self.out_q.put(("progress", {"processed": processed, "total": total,
                                         "elapsed": elapsed, "eta": eta, "last": cs}))
        self.out_q.put(("finished", recs))

# ---------- GUI ----------
class App:
    def __init__(self, root):
        self.root = root
        root.title("Ham Harvester — QRZ XML Mode")
        root.rowconfigure(2, weight=1)
        root.columnconfigure(0, weight=1)

        self.session_key = None
        self.cached_user = ""
        self.cached_pass = ""

        main = ttk.Frame(root, padding=8)
        main.grid(row=0, column=0, sticky="nsew")
        main.columnconfigure(1, weight=1)

        # Top: login first
        ttk.Label(main, text="QRZ XML API Session Key:").grid(row=0, column=0, sticky="w")
        self.api_key_var = tk.StringVar()
        ttk.Entry(main, textvariable=self.api_key_var, width=50).grid(row=0, column=1, sticky="we", padx=4)
        ttk.Button(main, text="Use Key", command=self.use_key).grid(row=0, column=2, padx=2)

        ttk.Label(main, text="— OR —").grid(row=1, column=0, sticky="w")
        ttk.Label(main, text="QRZ Username:").grid(row=2, column=0, sticky="w")
        self.user_var = tk.StringVar()
        ttk.Entry(main, textvariable=self.user_var, width=24).grid(row=2, column=1, sticky="w")
        ttk.Label(main, text="QRZ Password:").grid(row=3, column=0, sticky="w")
        self.pass_var = tk.StringVar()
        ttk.Entry(main, textvariable=self.pass_var, show="*").grid(row=3, column=1, sticky="w")
        ttk.Button(main, text="Login", command=self.login_action).grid(row=2, column=2, rowspan=2, padx=2)

        ttk.Separator(main).grid(row=4, column=0, columnspan=3, sticky="ew", pady=6)

        # Mode: Callsigns (active; county mode disabled)
        modefrm = ttk.Frame(main)
        modefrm.grid(row=5, column=0, columnspan=3, sticky="we")
        ttk.Label(modefrm, text="Mode: Callsigns via QRZ XML (County/State bulk is disabled in QRZ-only mode)").grid(row=0, column=0, sticky="w")

        # Callsign inputs
        inpf = ttk.LabelFrame(main, text="Input Callsigns")
        inpf.grid(row=6, column=0, columnspan=3, sticky="we", pady=4)
        inpf.columnconfigure(1, weight=1)
        ttk.Label(inpf, text="CSV file (first column or header 'callsign'):").grid(row=0, column=0, sticky="w")
        self.csv_path = tk.StringVar()
        ttk.Entry(inpf, textvariable=self.csv_path).grid(row=0, column=1, sticky="we", padx=4)
        ttk.Button(inpf, text="Browse", command=self.browse_csv).grid(row=0, column=2, padx=2)

        ttk.Label(inpf, text="Or paste callsigns (comma/newline separated):").grid(row=1, column=0, sticky="nw")
        self.calls_text = scrolledtext.ScrolledText(inpf, width=60, height=4)
        self.calls_text.grid(row=1, column=1, columnspan=2, sticky="we")

        # Geocoding options
        geof = ttk.LabelFrame(main, text="Geocoding")
        geof.grid(row=7, column=0, columnspan=3, sticky="we", pady=4)
        self.gc_mode = tk.StringVar(value="nominatim")
        ttk.Radiobutton(geof, text="OpenStreetMap (no key)", variable=self.gc_mode, value="nominatim").grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(geof, text="Google (requires key)", variable=self.gc_mode, value="google").grid(row=0, column=1, sticky="w")
        ttk.Label(geof, text="Google API key:").grid(row=0, column=2, sticky="e")
        self.google_var = tk.StringVar()
        ttk.Entry(geof, textvariable=self.google_var, width=40).grid(row=0, column=3, sticky="we", padx=4)
        ttk.Label(geof, text="Nominatim contact email:").grid(row=1, column=2, sticky="e")
        self.email_var = tk.StringVar(value="you@example.com")
        ttk.Entry(geof, textvariable=self.email_var, width=40).grid(row=1, column=3, sticky="we", padx=4)

        # Controls / progress
        ctl = ttk.Frame(main)
        ctl.grid(row=8, column=0, columnspan=3, sticky="we", pady=6)
        self.verbose = tk.BooleanVar(value=True)
        ttk.Checkbutton(ctl, text="Verbose", variable=self.verbose).grid(row=0, column=0, sticky="w")
        ttk.Button(ctl, text="Run", command=self.run_action).grid(row=0, column=1, padx=4)
        ttk.Button(ctl, text="Stop", command=self.stop).grid(row=0, column=2, padx=2)
        ttk.Button(ctl, text="Export CSV", command=self.export_csv).grid(row=0, column=3, padx=2)
        ttk.Button(ctl, text="Export KML", command=self.export_kml).grid(row=0, column=4, padx=2)
        ttk.Button(ctl, text="Export HTML Map", command=self.export_html).grid(row=0, column=5, padx=2)

        self.progress = ttk.Progressbar(main, orient="horizontal", length=420, mode="determinate")
        self.progress.grid(row=9, column=0, columnspan=2, sticky="w")
        self.status_var = tk.StringVar(value="Idle")
        ttk.Label(main, textvariable=self.status_var).grid(row=9, column=2, sticky="w")

        # Log
        ttk.Label(root, text="Log / Output:").grid(row=1, column=0, sticky="w")
        self.log_text = scrolledtext.ScrolledText(root, width=100, height=14)
        self.log_text.grid(row=2, column=0, sticky="nsew")

        # County/State panel (disabled; explanatory)
        cframe = ttk.LabelFrame(root, text="County/State (disabled in QRZ-only mode)")
        cframe.grid(row=3, column=0, sticky="we", padx=8, pady=4)
        ttk.Label(cframe, text="Bulk listing by county/state requires FCC ULS or QRZ web UI (not available via QRZ XML API).").grid(row=0, column=0, sticky="w")
        ttk.Button(cframe, text="Open QRZ Advanced Search (browser)", command=self.open_qrz_search).grid(row=0, column=1, padx=6)

        # runtime
        self.queue = queue.Queue()
        self.records = []
        self.worker = None

        # Prompt for login/key immediately
        self.prompt_login()

        # poll queue
        self.root.after(200, self.poll_queue)

    # ----- Login flow -----
    def prompt_login(self):
        # Auto-open a dialog-like guidance by focusing the key/username field
        self.log("[info] Please login to QRZ (API key preferred) to enable lookups.")
        self.api_key_var.set(self.api_key_var.get())
        # If you enter creds and click Login/Use Key we’ll proceed

    def use_key(self):
        key = (self.api_key_var.get() or "").strip()
        if not key:
            messagebox.showinfo("QRZ API key", "Please paste a QRZ XML session key.")
            return
        self.session_key = key
        masked = key[:4] + "..." + key[-4:] if len(key) >= 8 else "****"
        self.log(f"[info] Using provided QRZ session key ({masked})")

    def login_action(self):
        u = (self.user_var.get() or "").strip()
        p = self.pass_var.get() or ""
        if not (u and p):
            messagebox.showinfo("QRZ Login", "Enter username and password or supply an API key.")
            return
        self.cached_user, self.cached_pass = u, p
        self.log(f"[info] Logging in to QRZ as {u} ...")

        def do_login():
            try:
                sk = qrz_login(u, p, verbose=self.verbose.get())
                self.session_key = sk
                self.log("[info] QRZ session key obtained.")
            except Exception as e:
                self.log(f"[error] QRZ login failed: {e}")

        threading.Thread(target=do_login, daemon=True).start()

    # ----- Input / run -----
    def browse_csv(self):
        p = filedialog.askopenfilename(filetypes=[("CSV", "*.csv"), ("All files", "*.*")])
        if p:
            self.csv_path.set(p)

    def gather_callsigns(self):
        out = []
        # CSV
        p = (self.csv_path.get() or "").strip()
        if p:
            try:
                with open(p, newline="", encoding="utf-8") as fh:
                    rdr = csv.reader(fh)
                    header = next(rdr, None)
                    idx = 0
                    if header and any(h.lower() == "callsign" for h in header):
                        idx = [i for i, h in enumerate(header) if h.lower() == "callsign"][0]
                    else:
                        # If first row is not header "callsign", treat as data
                        if header and header[0].strip():
                            out.append(header[0].strip())
                    for row in rdr:
                        if row and len(row) > idx and row[idx].strip():
                            out.append(row[idx].strip())
            except Exception as e:
                self.log(f"[error] CSV read error: {e}")

        # Pasted
        txt = (self.calls_text.get("1.0", "end") or "").strip()
        if txt:
            parts = [x.strip() for x in txt.replace(",", "\n").splitlines()]
            out.extend([p for p in parts if p])

        # Dedupe/validate
        seen = set()
        clean = []
        for c in out:
            cu = c.upper()
            if cu not in seen and CALL_RE.match(cu):
                seen.add(cu)
                clean.append(cu)
            elif not CALL_RE.match(cu):
                self.log(f"[info] Skipping invalid callsign token: {c}")
        return clean

    def run_action(self):
        if not self.session_key:
            messagebox.showinfo("QRZ", "Login or provide an API key first.")
            return
        if self.worker and self.worker.is_alive():
            messagebox.showinfo("Running", "Already in progress.")
            return
        calls = self.gather_callsigns()
        if not calls:
            messagebox.showinfo("No input", "Provide callsigns via CSV or paste.")
            return
        self.records = []
        self.progress["maximum"] = len(calls)
        self.progress["value"] = 0
        self.status_var.set("Starting...")
        self.log(f"[info] Processing {len(calls)} callsigns; geocode={self.gc_mode.get()}")

        self.worker = LookupWorker(
            callsigns=calls,
            session_key=self.session_key,
            geocode_mode=self.gc_mode.get(),
            google_key=(self.google_var.get() or "").strip(),
            nominatim_email=(self.email_var.get() or "you@example.com").strip(),
            out_q=self.queue,
            verbose=self.verbose.get(),
        )
        self.worker.start()

    def stop(self):
        if self.worker and self.worker.is_alive():
            self.worker.stop()
            self.status_var.set("Stopping…")
            self.log("[info] Stop requested.")

    # ----- Queue / logging -----
    def poll_queue(self):
        try:
            while True:
                typ, payload = self.queue.get_nowait()
                if typ == "log":
                    self.log(payload)
                elif typ == "progress":
                    d = payload
                    self.progress["value"] = d["processed"]
                    self.status_var.set(f"{d['processed']}/{d['total']}  Elapsed: {nice_elapsed(d['elapsed'])}  ETA: {nice_elapsed(d['eta'])}")
                elif typ == "finished":
                    self.records = payload
                    self.progress["value"] = len(self.records)
                    self.status_var.set("Finished")
                    self.log(f"[info] Finished: {len(self.records)} records")
        except queue.Empty:
            pass
        self.root.after(200, self.poll_queue)

    def log(self, line):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_text.insert("end", f"[{ts}] {line}\n")
        self.log_text.see("end")

    # ----- Exports -----
    def export_csv(self):
        if not self.records:
            messagebox.showinfo("No data", "No results to export.")
            return
        p = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not p:
            return
        preferred = ["callsign", "fname", "addr1", "addr2", "city", "state", "county",
                     "zipcode", "country", "grid", "email", "address", "lat", "lon"]
        present = set().union(*(r.keys() for r in self.records))
        fieldnames = [k for k in preferred if k in present] + [k for k in sorted(present) if k not in preferred]
        try:
            with open(p, "w", newline="", encoding="utf-8") as fh:
                w = csv.DictWriter(fh, fieldnames=fieldnames)
                w.writeheader()
                for r in self.records:
                    w.writerow(r)
            self.log(f"[info] CSV exported: {p}")
        except Exception as e:
            self.log(f"[error] CSV export error: {e}")

    def export_kml(self):
        if not self.records:
            messagebox.showinfo("No data", "No results to export.")
            return
        p = filedialog.asksaveasfilename(defaultextension=".kml", filetypes=[("KML", "*.kml")])
        if not p:
            return
        k = simplekml.Kml()
        for r in self.records:
            lat = r.get("lat"); lon = r.get("lon")
            if lat and lon:
                try:
                    latf, lonf = float(lat), float(lon)
                except Exception:
                    continue
                name = r.get("callsign", "")
                desc = r.get("address", "")
                k.newpoint(name=name, coords=[(lonf, latf)], description=desc)
        try:
            k.save(p)
            self.log(f"[info] KML saved: {p}")
        except Exception as e:
            self.log(f"[error] KML save error: {e}")

    def export_html(self):
        if not self.records:
            messagebox.showinfo("No data", "No results to export.")
            return
        p = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML", "*.html")])
        if not p:
            return

        pts = []
        for r in self.records:
            lat = r.get("lat"); lon = r.get("lon")
            if lat and lon:
                try:
                    latf, lonf = float(lat), float(lon)
                except Exception:
                    continue
                pts.append({
                    "callsign": r.get("callsign", ""),
                    "lat": latf, "lon": lonf,
                    "address": r.get("address", "")
                })
        if not pts:
            messagebox.showinfo("No geocoded points", "No latitude/longitude data available.")
            return

        lats = [pt["lat"] for pt in pts]; lons = [pt["lon"] for pt in pts]
        min_lat, max_lat = min(lats), max(lats)
        min_lon, max_lon = min(lons), max(lons)
        clat = (min_lat + max_lat) / 2.0
        clon = (min_lon + max_lon) / 2.0

        gm_key = (self.google_var.get() or "").strip()
        if gm_key:
            # Google
            markers = []
            for pt in pts:
                markers.append(
                    f"new google.maps.Marker({{position: {{lat: {pt['lat']}, lng: {pt['lon']}}}, map: map, title: {json.dumps(pt['callsign'])}}});"
                )
            html = f"""<!doctype html>
<html>
  <head><meta charset="utf-8"><title>Map</title>
  <style>html,body,#map{{height:100%;margin:0;padding:0}}</style></head>
  <body>
    <div id="map"></div>
    <script src="https://maps.googleapis.com/maps/api/js?key={gm_key}"></script>
    <script>
      function initMap(){{
        var map = new google.maps.Map(document.getElementById('map'), {{zoom: 8, center: {{lat: {clat}, lng: {clon}}}}});
        var bounds = new google.maps.LatLngBounds(
          new google.maps.LatLng({min_lat}, {min_lon}),
          new google.maps.LatLng({max_lat}, {max_lon})
        );
        {''.join(markers)}
        map.fitBounds(bounds);
      }}
      window.onload = initMap;
    </script>
  </body>
</html>"""
        else:
            # Leaflet
            mk = []
            for pt in pts:
                popup = json.dumps(f"{pt['callsign']}\n{pt['address']}").replace("\\n", "<br/>")
                mk.append(f"L.marker([{pt['lat']}, {pt['lon']}]).addTo(map).bindPopup({popup});")
            html = f"""<!doctype html>
<html>
  <head>
    <meta charset="utf-8"><title>Map</title>
    <link rel="stylesheet" href="https://unpkg.com/leaflet/dist/leaflet.css"/>
    <style>html,body,#map{{height:100%;margin:0;padding:0}}</style>
  </head>
  <body>
    <div id="map"></div>
    <script src="https://unpkg.com/leaflet/dist/leaflet.js"></script>
    <script>
      var map = L.map('map');
      var bounds = L.latLngBounds([[{min_lat}, {min_lon}], [{max_lat}, {max_lon}]]);
      map.fitBounds(bounds);
      L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
        maxZoom: 19, attribution: '© OpenStreetMap contributors'
      }}).addTo(map);
      {''.join(mk)}
    </script>
  </body>
</html>"""

        try:
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(html)
            self.log(f"[info] HTML map saved: {p}")
        except Exception as e:
            self.log(f"[error] HTML save error: {e}")

    # ----- County UI helper -----
    def open_qrz_search(self):
        webbrowser.open_new_tab("https://www.qrz.com/db/")  # opens Advanced Search UI

def main():
    root = tk.Tk()
    app = App(root)
    root.mainloop()

if __name__ == "__main__":
    main()
