#!/usr/bin/env python3
"""
QRZ County / Callsign Mapper (GUI + Dependency Auto-Install + API Key Option)

- Verifies and installs missing dependencies at runtime.
- Supports providing a QRZ XML API session key directly (if you already have it).
- GUI for callsign lookup, geocoding, progress/ETA display.
- Export to CSV, KML, HTML map (Google Maps or Leaflet fallback).
"""

import sys
import subprocess
import importlib

def check_and_install_dependencies(verbose=False):
    """
    Checks for required Python packages and installs missing ones automatically.
    Returns True if all are present (or successfully installed); else exits.
    """
    required = [
        "requests",
        "tkinter",       # for GUI
        "geojson",       # optional if you want geojson export later (not mandatory)
        "simplekml",
        # not strictly needed but commonly used in mapping
        "pandas",
        "geopy",
    ]
    missing = []
    for pkg in required:
        # For tkinter, the module name is "tkinter" in Python 3
        modname = pkg
        try:
            importlib.import_module(modname)
            if verbose:
                print(f"[OK] {pkg} importable")
        except ImportError:
            missing.append(pkg)
    if not missing:
        if verbose:
            print("[INFO] All dependencies satisfied")
        return True

    print(f"[INFO] Missing packages: {missing}")
    print("[INFO] Attempting to install missing packages via pip...")
    for pkg in missing:
        # For "tkinter" on some systems, pip package might be "tk" or the system might not allow installing
        pip_name = pkg
        if pkg == "tkinter":
            pip_name = "tk"  # try installing package "tk"
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", pip_name])
            if verbose:
                print(f"[INSTALLED] {pip_name}")
        except Exception as e:
            print(f"[ERROR] Could not install {pip_name}: {e}")
            print("Please install missing dependency manually and re-run.")
            sys.exit(1)
    print("[INFO] All missing dependencies installed.")
    return True

# Run dependency check early
check_and_install_dependencies(verbose=True)

# Now import the modules needed
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import queue
import time
import csv
import requests
import xml.etree.ElementTree as ET
from datetime import datetime

# Optionally import geocoding packages if installed
# We'll fallback to our custom simple geocode routines if not
try:
    from geopy.geocoders import Nominatim as GeoNominatim
    GEO_AVAILABLE = True
except ImportError:
    GEO_AVAILABLE = False

import simplekml

# ---------- Utility functions ----------

def now_ts():
    return time.time()

def nice_elapsed(seconds):
    if seconds < 60:
        return f"{seconds:.1f}s"
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h}h {m}m {s}s"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"

# Basic geocode by OpenStreetMap Nominatim (no third-party library)
def geocode_nominatim(address, pause=1.0, verbose=False):
    url = "https://nominatim.openstreetmap.org/search"
    headers = {"User-Agent": "QRZ-Mapper/1.0 (example@example.com)"}
    params = {"q": address, "format": "json", "limit": 1}
    if verbose:
        print(f"[geocode_nominatim] querying: {address}")
    resp = requests.get(url, params=params, headers=headers, timeout=20)
    time.sleep(pause)
    if resp.status_code != 200:
        raise RuntimeError(f"Nominatim HTTP {resp.status_code}")
    arr = resp.json()
    if not arr:
        return None
    lat = float(arr[0]["lat"])
    lon = float(arr[0]["lon"])
    return (lat, lon)

# Google geocoding
def geocode_google(address, api_key, verbose=False):
    url = "https://maps.googleapis.com/maps/api/geocode/json"
    params = {"address": address, "key": api_key}
    if verbose:
        print(f"[geocode_google] querying: {address}")
    resp = requests.get(url, params=params, timeout=20)
    if resp.status_code != 200:
        raise RuntimeError(f"Google geocode HTTP {resp.status_code}")
    j = resp.json()
    if j.get("status") != "OK":
        return None
    loc = j["results"][0]["geometry"]["location"]
    return loc["lat"], loc["lng"]

# ---------- QRZ XML API logic ----------

QRZ_XML_BASE = "https://xmldata.qrz.com/xml/current/"
QRZ_XML_LOGIN_URL = QRZ_XML_BASE
USER_AGENT = "QRZ-Mapper/1.0"


# Simple XML helper that ignores namespaces when searching for tags.
def find_first(elem, *tag_names):
    """Return the first descendant whose local-name matches any of ``tag_names``."""
    if elem is None:
        return None
    wanted = {name.lower() for name in tag_names}
    for node in elem.iter():
        local = node.tag.split('}', 1)[-1].lower()
        if local in wanted:
            return node
    return None


def find_text(elem, *tag_names):
    if elem is None:
        return ""
    node = find_first(elem, *tag_names)
    if node is not None and node.text:
        return node.text.strip()
    return ""


# QRZ XML API: login to get session key
def qrz_login(username, password, verbose=False):
    """
    Logs into QRZ XML API using username/password, returns session key.
    """
    if verbose:
        print("[qrz_login] attempting login")

    def parse_session_key(xml_text):
        root = ET.fromstring(xml_text)
        session = find_first(root, "Session")
        key = find_text(session, "Key") if session is not None else ""
        if not key and session is not None and session.text:
            key = session.text.strip()
        return key

    # QRZ XML login is performed by POSTing an XML request to the XML endpoint and parsing.
    # Some users place credentials as URL params; implement both fallback approaches.
    try:
        xml_payload = (
            f"<QRZDatabase><USERNAME>{username}</USERNAME><PASSWORD>{password}</PASSWORD>"
            "<OPTIONS><keeplogin>1</keeplogin></OPTIONS></QRZDatabase>"
        )
        resp = requests.post(
            QRZ_XML_LOGIN_URL,
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
            print("[qrz_login] xml-post method failed:", e)

    # Fallback: try GET style (older installations used query params)
    try:
        params = {"username": username, "password": password}
        resp2 = requests.get(
            QRZ_XML_LOGIN_URL,
            params=params,
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
            print("[qrz_login] fallback method failed:", e)
    raise RuntimeError(
        "QRZ login failed. Make sure your account has XML privileges (subscription) and credentials are correct."
    )

def qrz_lookup_call(session_key, callsign, verbose=False):
    """
    Looks up a single callsign via QRZ XML API, returns dict or None.
    """
    params = {"s": session_key, "callsign": callsign}
    resp = requests.get(QRZ_XML_BASE, params=params, headers={"User-Agent": USER_AGENT}, timeout=20)
    if resp.status_code != 200:
        raise RuntimeError(f"QRZ lookup HTTP {resp.status_code}")
    root = ET.fromstring(resp.text)
    # The QRZ xml returns <Callsign><addr>... etc. We'll try to extract name, address fields.
    call = find_first(root, "call", "Callsign")
    if call is None:
        return None

    def get_text(tag):
        return find_text(call, tag)

    data = {
        "callsign": get_text("call") or callsign,
        "fname": get_text("fname") or get_text("name"),
        "addr1": get_text("addr1"),
        "addr2": get_text("addr2"),
        "city": get_text("city"),
        "state": get_text("state"),
        "zipcode": get_text("zipcode") or get_text("postcode"),
        "country": get_text("country"),
    }
    parts = [data.get("addr1"), data.get("addr2"), data.get("city"), data.get("state"), data.get("zipcode"), data.get("country")]
    addr = ", ".join([p for p in parts if p])
    data["address"] = addr
    if verbose:
        print(f"[qrz_lookup_call] {callsign} -> {addr}")
    return data

# ---------- Worker Thread ----------

class LookupWorker(threading.Thread):
    def __init__(self, callsigns, session_key, geocode_mode, google_key, output_queue, verbose=False):
        super().__init__()
        self.callsigns = callsigns
        self.session_key = session_key
        self.geocode_mode = geocode_mode
        self.google_key = google_key
        self.out_q = output_queue
        self.verbose = verbose
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        start = now_ts()
        total = len(self.callsigns)
        processed = 0
        recs = []
        for cs in self.callsigns:
            if self._stop.is_set():
                break
            try:
                if self.session_key:
                    info = qrz_lookup_call(self.session_key, cs, verbose=self.verbose)
                    if info is None:
                        self.out_q.put(("log", f"No QRZ result for {cs}"))
                        info = {"callsign": cs, "address": ""}
                else:
                    info = {"callsign": cs, "address": ""}
                # geocode if address exists
                lat = lon = None
                addr = info.get("address", "")
                if addr:
                    try:
                        if self.geocode_mode == "google" and self.google_key:
                            loc = geocode_google(addr, self.google_key, verbose=self.verbose)
                        else:
                            loc = geocode_nominatim(addr, verbose=self.verbose)
                        if loc:
                            lat, lon = loc
                            info["lat"] = lat
                            info["lon"] = lon
                        else:
                            info["lat"] = info["lon"] = ""
                    except Exception as ge:
                        info["lat"] = info["lon"] = ""
                        self.out_q.put(("log", f"Geocode error for {cs}: {ge}"))
                else:
                    info["lat"] = info["lon"] = ""
                recs.append(info)
            except Exception as e:
                self.out_q.put(("log", f"Error processing {cs}: {e}"))
            processed += 1
            elapsed = now_ts() - start
            avg = elapsed / processed if processed else 0.0001
            remaining = total - processed
            eta = remaining * avg
            self.out_q.put(("progress", {"processed": processed, "total": total, "elapsed": elapsed, "eta": eta, "last": cs}))
        self.out_q.put(("finished", recs))

# ---------- GUI Application ----------

class App:
    def __init__(self, root):
        self.root = root
        root.title("QRZ County / Callsign Mapper")

        frm = ttk.Frame(root, padding=10)
        frm.grid(row=0, column=0, sticky="nsew")

        # CSV input
        ttk.Label(frm, text="CSV of callsigns (optional):").grid(row=0, column=0, sticky="w")
        self.csv_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.csv_var, width=60).grid(row=0, column=1)
        ttk.Button(frm, text="Browse", command=self.browse_csv).grid(row=0, column=2)

        # Paste callsigns
        ttk.Label(frm, text="Or paste callsigns (comma / newline):").grid(row=1, column=0, sticky="w")
        self.callsign_text = scrolledtext.ScrolledText(frm, width=60, height=4)
        self.callsign_text.grid(row=1, column=1, columnspan=2)

        # QRZ API key or user/pass
        ttk.Label(frm, text="QRZ XML API Session Key (optional):").grid(row=2, column=0, sticky="w")
        self.api_key_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.api_key_var, width=60).grid(row=2, column=1, columnspan=2)

        ttk.Label(frm, text="OR QRZ Username:").grid(row=3, column=0, sticky="w")
        self.u_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.u_var).grid(row=3, column=1)
        ttk.Label(frm, text="QRZ Password:").grid(row=4, column=0, sticky="w")
        self.p_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.p_var, show="*").grid(row=4, column=1)
        ttk.Button(frm, text="Login", command=self.login_action).grid(row=3, column=2, rowspan=2)

        ttk.Separator(frm, orient="horizontal").grid(row=5, column=0, columnspan=3, sticky="ew", pady=6)

        # Geocoding choice
        ttk.Label(frm, text="Geocoding mode:").grid(row=6, column=0, sticky="w")
        self.gc_mode = tk.StringVar(value="nominatim")
        ttk.Radiobutton(frm, text="OpenStreetMap (no API key)", variable=self.gc_mode, value="nominatim").grid(row=6, column=1, sticky="w")
        ttk.Radiobutton(frm, text="Google Geocoding (requires key)", variable=self.gc_mode, value="google").grid(row=6, column=2, sticky="w")

        ttk.Label(frm, text="Google API key (optional):").grid(row=7, column=0, sticky="w")
        self.google_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.google_var, width=60).grid(row=7, column=1, columnspan=2)

        self.verbose = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            frm,
            text="Verbose output",
            variable=self.verbose,
            command=self.toggle_verbose,
        ).grid(row=8, column=0, sticky="w")

        # Progress bar and controls
        ttk.Separator(frm, orient="horizontal").grid(row=9, column=0, columnspan=3, sticky="ew", pady=6)
        self.progress = ttk.Progressbar(frm, orient="horizontal", length=400, mode="determinate")
        self.progress.grid(row=10, column=0, columnspan=2, sticky="w")
        self.status_var = tk.StringVar(value="Idle")
        ttk.Label(frm, textvariable=self.status_var).grid(row=10, column=2, sticky="w")

        ttk.Button(frm, text="Start", command=self.start).grid(row=11, column=0, sticky="we", pady=6)
        ttk.Button(frm, text="Stop", command=self.stop).grid(row=11, column=1, sticky="we", pady=6)
        ttk.Button(frm, text="Export CSV", command=self.export_csv).grid(row=11, column=2, sticky="we", pady=6)

        # Log / verbose pane
        ttk.Label(root, text="Log / Output:").grid(row=1, column=0, sticky="w")
        self.log_text = scrolledtext.ScrolledText(root, height=12, width=100)
        self.log_text.grid(row=2, column=0, sticky="nsew")

        # Map export
        mfrm = ttk.Frame(root, padding=6)
        mfrm.grid(row=3, column=0, sticky="ew")
        ttk.Button(mfrm, text="Export KML", command=self.export_kml).grid(row=0, column=0, padx=4)
        ttk.Button(mfrm, text="Export HTML Map", command=self.export_html).grid(row=0, column=1, padx=4)

        self.worker = None
        self.queue = queue.Queue()
        self.records = []
        self.session_key = None

        self.root.after(200, self.poll_queue)

    def toggle_verbose(self):
        state = "enabled" if self.verbose.get() else "disabled"
        self.log(f"Verbose output {state}", lvl="info")

    def browse_csv(self):
        p = filedialog.askopenfilename(filetypes=[("CSV","*.csv"), ("All files","*.*")])
        if p:
            self.csv_var.set(p)

    def login_action(self):
        # If an API key is provided, use it; else use username/password
        key = self.api_key_var.get().strip()
        if key:
            self.session_key = key
            self.log(f"Using provided QRZ session key (length {len(key)})", lvl="info")
        else:
            u = self.u_var.get().strip()
            p = self.p_var.get()
            if not (u and p):
                messagebox.showinfo("Login", "Either enter a QRZ API session key or username/password.")
                return
            self.log(f"Logging into QRZ as {u} ...", lvl="info")
            def do_login():
                try:
                    sk = qrz_login(u, p, verbose=self.verbose.get())
                    self.session_key = sk
                    self.log(f"QRZ session key obtained (stored in memory).", lvl="info")
                except Exception as e:
                    self.log(f"QRZ login failed: {e}", lvl="error")
            threading.Thread(target=do_login, daemon=True).start()

    def gather_callsigns(self):
        calls = []
        # from CSV
        p = self.csv_var.get().strip()
        if p:
            try:
                with open(p, newline="", encoding="utf-8") as fh:
                    rdr = csv.reader(fh)
                    for row in rdr:
                        if row and row[0].strip():
                            calls.append(row[0].strip())
            except Exception as e:
                self.log(f"Error reading CSV: {e}", lvl="error")
        # from text area
        txt = self.callsign_text.get("1.0", "end").strip()
        if txt:
            parts = [x.strip() for x in (txt.replace(",", "\n")).splitlines()]
            calls.extend([c for c in parts if c])
        # dedupe, uppercase
        seen = set()
        out = []
        for c in calls:
            cu = c.upper()
            if cu not in seen:
                seen.add(cu)
                out.append(cu)
        return out

    def start(self):
        if self.worker and self.worker.is_alive():
            messagebox.showinfo("Running", "Already in progress")
            return
        calls = self.gather_callsigns()
        if not calls:
            messagebox.showinfo("No callsigns", "Provide callsigns via CSV or paste")
            return
        self.records = []
        self.progress["maximum"] = len(calls)
        self.progress["value"] = 0
        self.status_var.set("Starting...")
        self.log(f"Processing {len(calls)} callsigns; geocode: {self.gc_mode.get()}", lvl="info")
        self.worker = LookupWorker(calls, self.session_key, self.gc_mode.get(), self.google_var.get().strip(), self.queue, verbose=self.verbose.get())
        self.worker.daemon = True
        self.worker.start()

    def stop(self):
        if self.worker:
            self.worker.stop()
            self.status_var.set("Stopping...")
            self.log("Stop requested", lvl="info")

    def poll_queue(self):
        try:
            while True:
                typ, payload = self.queue.get_nowait()
                if typ == "log":
                    self.log(payload)
                elif typ == "progress":
                    d = payload
                    processed = d["processed"]
                    total = d["total"]
                    elapsed = d["elapsed"]
                    eta = d["eta"]
                    self.progress["value"] = processed
                    self.status_var.set(f"{processed}/{total}  Elapsed: {nice_elapsed(elapsed)}  ETA: {nice_elapsed(eta)}")
                elif typ == "finished":
                    recs = payload
                    self.records = recs
                    self.progress["value"] = len(recs)
                    self.status_var.set("Finished")
                    self.log(f"Finished: {len(recs)} records", lvl="info")
        except queue.Empty:
            pass
        self.root.after(200, self.poll_queue)

    def log(self, msg, lvl="info"):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_text.insert("end", f"[{ts}] [{lvl}] {msg}\n")
        self.log_text.see("end")

    def export_csv(self):
        if not self.records:
            messagebox.showinfo("No data", "No results to export")
            return
        p = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")])
        if not p:
            return
        # collect all keys
        keys = set()
        for r in self.records:
            keys.update(r.keys())
        keys = list(keys)
        try:
            with open(p, "w", newline="", encoding="utf-8") as fh:
                w = csv.DictWriter(fh, fieldnames=keys)
                w.writeheader()
                for r in self.records:
                    w.writerow(r)
            self.log(f"CSV exported: {p}", lvl="info")
        except Exception as e:
            self.log(f"CSV export error: {e}", lvl="error")

    def export_kml(self):
        if not self.records:
            messagebox.showinfo("No data", "No results to export")
            return
        p = filedialog.asksaveasfilename(defaultextension=".kml", filetypes=[("KML","*.kml")])
        if not p:
            return
        k = simplekml.Kml()
        for r in self.records:
            lat = r.get("lat")
            lon = r.get("lon")
            if lat and lon:
                name = r.get("callsign", "")
                desc = r.get("address", "")
                k.newpoint(name=name, coords=[(float(lon), float(lat))], description=desc)
        try:
            k.save(p)
            self.log(f"KML saved: {p}", lvl="info")
        except Exception as e:
            self.log(f"KML save error: {e}", lvl="error")

    def export_html(self):
        if not self.records:
            messagebox.showinfo("No data", "No results to export")
            return
        p = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML","*.html")])
        if not p:
            return
        pts = []
        for r in self.records:
            lat = r.get("lat")
            lon = r.get("lon")
            if lat and lon:
                pts.append({"callsign": r.get("callsign",""), "lat": lat, "lon": lon, "address": r.get("address","")})
        if not pts:
            messagebox.showinfo("No geocoded points", "No latitude/longitude data available")
            return
        # center
        clat = sum(float(p["lat"]) for p in pts)/len(pts)
        clon = sum(float(p["lon"]) for p in pts)/len(pts)
        gm_key = self.google_var.get().strip()
        if gm_key:
            # Google Maps HTML
            markers = []
            for pt in pts:
                markers.append(f"new google.maps.Marker({{position: {{lat: {pt['lat']}, lng: {pt['lon']}}}, map: map, title: '{pt['callsign']}'}});")
            html = f"""<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Map</title>
    <style>html,body,#map{{height:100%;margin:0;padding:0}}</style>
  </head>
  <body>
    <div id="map"></div>
    <script src="https://maps.googleapis.com/maps/api/js?key={gm_key}"></script>
    <script>
      function initMap() {{
        var center = {{lat: {clat}, lng: {clon}}};
        var map = new google.maps.Map(document.getElementById('map'), {{zoom: 8, center: center}});
        {"".join(markers)}
      }}
      window.onload = initMap;
    </script>
  </body>
</html>"""
        else:
            # Leaflet fallback
            mk = []
            for pt in pts:
                popup = f"{pt['callsign']}<br/>{pt['address']}".replace("'", "\\'")
                mk.append(f"L.marker([{pt['lat']}, {pt['lon']}]).addTo(map).bindPopup('{popup}');")
            html = f"""<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Map</title>
    <link rel="stylesheet" href="https://unpkg.com/leaflet/dist/leaflet.css"/>
    <style>html,body,#map{{height:100%;margin:0;padding:0}}</style>
  </head>
  <body>
    <div id="map"></div>
    <script src="https://unpkg.com/leaflet/dist/leaflet.js"></script>
    <script>
      var map = L.map('map').setView([{clat}, {clon}], 8);
      L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
        maxZoom: 19,
        attribution: '© OpenStreetMap contributors'
      }}).addTo(map);
      {''.join(mk)}
    </script>
  </body>
</html>"""
        try:
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(html)
            self.log(f"HTML map saved: {p}", lvl="info")
        except Exception as e:
            self.log(f"HTML save error: {e}", lvl="error")

def main():
    root = tk.Tk()
    app = App(root)
    root.mainloop()

if __name__ == "__main__":
    main()
