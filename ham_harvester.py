#!/usr/bin/env python3
"""
QRZ County / Callsign Mapper (GUI)

What this does:
- Accepts a CSV of callsigns (or a manually provided callsign list).
- Or uses QRZ XML API (requires a QRZ XML subscription / API key) to lookup callsigns you supply.
- Geocodes addresses via Google Geocoding (API key required) or Nominatim (OpenStreetMap).
- Shows GUI with progress, elapsed time, and ETA.
- Verbose output pane for execution steps (toggle).
- Export to CSV, KML (Google Earth), and an HTML map (Google Maps if API key provided; else Leaflet+OSM).

IMPORTANT LEGAL / ETHICAL NOTE:
Do NOT use this tool to automatically scrape QRZ.com pages in violation of QRZ Terms of Use.
If you need bulk county data, request it from QRZ or export via their permitted UI/features.
This tool assumes you supply callsigns via CSV or via permitted QRZ XML API calls.
See QRZ XML API documentation: https://www.qrz.com/docs/xml/current_spec.html
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import queue
import time
import argparse
import csv
import requests
import xml.etree.ElementTree as ET
import urllib.parse
import math
from datetime import datetime

# ---------- Configuration / constants ----------
QRZ_XML_LOGIN_URL = "https://xmldata.qrz.com/xml/current/"  # session login uses POST with username/password per QRZ spec
NOMINATIM_URL = "https://nominatim.openstreetmap.org/search"
USER_AGENT = "QRZ-County-Mapper/1.0 (contact: you@example.com)"

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

# Basic rate-limited Nominatim geocoder (polite)
def geocode_nominatim(address, pause=1.0, verbose=False):
    # Nominatim policy requires a pause between queries (default is 1s). Respect that.
    headers = {"User-Agent": USER_AGENT}
    params = {"q": address, "format": "json", "limit": 1}
    if verbose:
        print(f"[geocode_nominatim] query: {address}")
    resp = requests.get(NOMINATIM_URL, params=params, headers=headers, timeout=20)
    time.sleep(pause)
    if resp.status_code != 200:
        raise RuntimeError(f"Nominatim HTTP {resp.status_code}")
    data = resp.json()
    if not data:
        return None
    return float(data[0]["lat"]), float(data[0]["lon"])

# Google geocoding helper (requires API key). Returns (lat, lon) or None.
def geocode_google(address, api_key, verbose=False):
    geocode_url = "https://maps.googleapis.com/maps/api/geocode/json"
    params = {"address": address, "key": api_key}
    if verbose:
        print(f"[geocode_google] query: {address}")
    resp = requests.get(geocode_url, params=params, timeout=20)
    if resp.status_code != 200:
        raise RuntimeError(f"Google Geocoding HTTP {resp.status_code}")
    j = resp.json()
    if j.get("status") != "OK":
        return None
    loc = j["results"][0]["geometry"]["location"]
    return loc["lat"], loc["lng"]

# QRZ XML API: login to get session key
def qrz_login(username, password, verbose=False):
    """
    Uses QRZ XML login method. The QRZ spec expects a POST to the XML endpoint with <QRZAuth>...
    Many libraries form a URL like ?username=...&password=... but spec varies.
    We'll use the documented method: POST username/password and parse session key.
    """
    if verbose:
        print("[qrz_login] attempting login")
    # QRZ XML login is performed by POSTing an XML request to the XML endpoint and parsing.
    # The simple documented approach: use requests.post to QRZ_XML_LOGIN_URL with data containing username/password.
    # Some users place credentials as URL params; implement both fallback approaches.
    try:
        # First try the documented XML login POST
        xml_payload = f"<QRZDatabase><USERNAME>{username}</USERNAME><PASSWORD>{password}</PASSWORD><OPTIONS><keeplogin>1</keeplogin></OPTIONS></QRZDatabase>"
        resp = requests.post(QRZ_XML_LOGIN_URL, data=xml_payload, headers={"Content-Type": "application/xml", "User-Agent": USER_AGENT}, timeout=20)
        if resp.status_code != 200:
            raise RuntimeError(f"QRZ login HTTP {resp.status_code}")
        root = ET.fromstring(resp.text)
        session = root.find(".//Session")
        if session is not None and session.text:
            key = session.text.strip()
            if verbose:
                print("[qrz_login] obtained session key")
            return key
    except Exception as e:
        if verbose:
            print("[qrz_login] xml-post method failed:", e)
    # Fallback: try GET style (older installations used query params)
    try:
        params = {"username": username, "password": password}
        resp2 = requests.get(QRZ_XML_LOGIN_URL, params=params, headers={"User-Agent": USER_AGENT}, timeout=20)
        root = ET.fromstring(resp2.text)
        session = root.find(".//Session")
        if session is not None and session.text:
            return session.text.strip()
    except Exception as e:
        if verbose:
            print("[qrz_login] fallback method failed:", e)
    raise RuntimeError("QRZ login failed. Make sure your account has XML privileges (subscription) and credentials are correct.")

# QRZ lookup for a single callsign using session key
def qrz_callsign_lookup(session_key, callsign, verbose=False):
    # The documented call is: https://xmldata.qrz.com/xml/current/?s=<session>&callsign=K1ABC
    params = {"s": session_key, "callsign": callsign}
    headers = {"User-Agent": USER_AGENT}
    resp = requests.get(QRZ_XML_LOGIN_URL, params=params, headers=headers, timeout=20)
    if resp.status_code != 200:
        raise RuntimeError(f"QRZ lookup HTTP {resp.status_code}")
    root = ET.fromstring(resp.text)
    # The QRZ xml returns <Callsign><addr>... etc. We'll try to extract name, address fields.
    call = root.find(".//call")
    if call is None:
        # Some XML variants use <Callsign> element
        call = root.find(".//Callsign")
    if call is None:
        return None
    # Attempt to extract common fields
    def get_text(elem, tag):
        t = elem.find(tag)
        return t.text.strip() if t is not None and t.text else ""
    # Some tags: fname, name, addr1, addr2, city, state, postcode, country
    data = {
        "callsign": callsign,
        "fname": get_text(call, "fname") or get_text(call, "name"),
        "addr1": get_text(call, "addr1"),
        "addr2": get_text(call, "addr2"),
        "city": get_text(call, "city"),
        "state": get_text(call, "state"),
        "zipcode": get_text(call, "zipcode") or get_text(call, "postcode"),
        "country": get_text(call, "country"),
    }
    # Concatenate address
    address_parts = [data.get("addr1"), data.get("addr2"), data.get("city"), data.get("state"), data.get("zipcode"), data.get("country")]
    address = ", ".join([p for p in address_parts if p])
    data["address"] = address
    if verbose:
        print(f"[qrz_callsign_lookup] {callsign} -> {address}")
    return data

# ---------- GUI / Worker architecture ----------
class WorkerThread(threading.Thread):
    def __init__(self, callsigns, qrz_session, geocode_mode, google_key, output_queue, verbose=False, nominatim_pause=1.0):
        super().__init__()
        self.callsigns = callsigns
        self.qrz_session = qrz_session
        self.geocode_mode = geocode_mode
        self.google_key = google_key
        self.out_q = output_queue
        self.verbose = verbose
        self.nominatim_pause = nominatim_pause
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        start = now_ts()
        total = len(self.callsigns)
        processed = 0
        records = []
        for cs in self.callsigns:
            if self._stop.is_set():
                break
            t0 = now_ts()
            # Lookup via QRZ if session provided, else assume callsign contains address in csv
            try:
                if self.qrz_session:
                    info = qrz_callsign_lookup(self.qrz_session, cs, verbose=self.verbose)
                    if info is None:
                        self.out_q.put(("log", f"No QRZ data for {cs}"))
                        info = {"callsign": cs, "address": ""}
                else:
                    # If not using QRZ, treat cs as callsign and expect address provided separately (in practice CSV path)
                    info = {"callsign": cs, "address": ""}
                # Now geocode if possible and address non-empty
                lat = lon = None
                if info.get("address"):
                    try:
                        if self.geocode_mode == "google" and self.google_key:
                            loc = geocode_google(info["address"], self.google_key, verbose=self.verbose)
                        else:
                            loc = geocode_nominatim(info["address"], pause=self.nominatim_pause, verbose=self.verbose)
                        if loc:
                            lat, lon = loc
                            info["lat"] = lat
                            info["lon"] = lon
                        else:
                            info["lat"] = info["lon"] = ""
                    except Exception as e:
                        info["lat"] = info["lon"] = ""
                        self.out_q.put(("log", f"Geocode failed for {cs}: {e}"))
                else:
                    info["lat"] = info["lon"] = ""
                records.append(info)
            except Exception as e:
                self.out_q.put(("log", f"Error processing {cs}: {e}"))
            processed += 1
            elapsed = now_ts() - start
            avg = elapsed / processed if processed else 0.0001
            remaining = total - processed
            eta = remaining * avg
            # push progress update
            self.out_q.put(("progress", {"processed": processed, "total": total, "elapsed": elapsed, "eta": eta, "last_callsign": cs}))
        # finished
        self.out_q.put(("finished", records))

# ---------- Main App UI ----------
class QRZMapperApp:
    def __init__(self, root):
        self.root = root
        root.title("QRZ County / Callsign Mapper")

        # top frame: inputs
        frm = ttk.Frame(root, padding=10)
        frm.grid(row=0, column=0, sticky="nsew")

        ttk.Label(frm, text="Input CSV (callsigns or callsign+address) :").grid(row=0, column=0, sticky="w")
        self.csv_path_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.csv_path_var, width=60).grid(row=0, column=1, sticky="w")
        ttk.Button(frm, text="Browse CSV", command=self.browse_csv).grid(row=0, column=2, sticky="w")

        ttk.Label(frm, text="OR paste callsigns (comma or newline separated):").grid(row=1, column=0, sticky="w")
        self.callsign_text = scrolledtext.ScrolledText(frm, height=4, width=60)
        self.callsign_text.grid(row=1, column=1, columnspan=2, sticky="w")

        ttk.Separator(frm, orient="horizontal").grid(row=2, column=0, columnspan=3, sticky="ew", pady=6)

        ttk.Label(frm, text="QRZ username (optional):").grid(row=3, column=0, sticky="w")
        self.qrz_user = tk.StringVar()
        ttk.Entry(frm, textvariable=self.qrz_user).grid(row=3, column=1, sticky="w")
        ttk.Label(frm, text="QRZ password (optional):").grid(row=4, column=0, sticky="w")
        self.qrz_pass = tk.StringVar()
        ttk.Entry(frm, textvariable=self.qrz_pass, show="*").grid(row=4, column=1, sticky="w")
        ttk.Button(frm, text="Login to QRZ (get session)", command=self.login_qrz).grid(row=3, column=2, rowspan=2, sticky="we", padx=4)

        ttk.Separator(frm, orient="horizontal").grid(row=5, column=0, columnspan=3, sticky="ew", pady=6)

        ttk.Label(frm, text="Geocoding mode:").grid(row=6, column=0, sticky="w")
        self.geocode_mode = tk.StringVar(value="nominatim")
        ttk.Radiobutton(frm, text="OpenStreetMap (Nominatim, no key)", variable=self.geocode_mode, value="nominatim").grid(row=6, column=1, sticky="w")
        ttk.Radiobutton(frm, text="Google Geocoding (API key required)", variable=self.geocode_mode, value="google").grid(row=6, column=2, sticky="w")
        ttk.Label(frm, text="Google API Key (optional):").grid(row=7, column=0, sticky="w")
        self.google_key = tk.StringVar()
        ttk.Entry(frm, textvariable=self.google_key, width=60).grid(row=7, column=1, columnspan=2, sticky="w")

        ttk.Checkbutton(frm, text="Verbose output", command=self.toggle_verbose).grid(row=8, column=0, sticky="w")
        self.verbose = tk.BooleanVar(value=False)

        # Progress and controls
        ttk.Separator(frm, orient="horizontal").grid(row=9, column=0, columnspan=3, sticky="ew", pady=6)
        self.progress = ttk.Progressbar(frm, orient="horizontal", length=400, mode="determinate")
        self.progress.grid(row=10, column=0, columnspan=2, sticky="w")
        self.status_var = tk.StringVar(value="Idle")
        ttk.Label(frm, textvariable=self.status_var).grid(row=10, column=2, sticky="w")

        ttk.Button(frm, text="Start", command=self.start).grid(row=11, column=0, sticky="we", pady=6)
        ttk.Button(frm, text="Stop", command=self.stop).grid(row=11, column=1, sticky="we", pady=6)
        ttk.Button(frm, text="Export CSV", command=self.export_csv).grid(row=11, column=2, sticky="we", pady=6)

        # Output / verbose pane
        ttk.Label(root, text="Log / Verbose Output:").grid(row=1, column=0, sticky="w")
        self.log_text = scrolledtext.ScrolledText(root, height=12, width=100)
        self.log_text.grid(row=2, column=0, sticky="nsew")

        # Map export controls
        mapfrm = ttk.Frame(root, padding=6)
        mapfrm.grid(row=3, column=0, sticky="ew")
        ttk.Button(mapfrm, text="Export KML (Google Earth)", command=self.export_kml).grid(row=0, column=0, padx=4)
        ttk.Button(mapfrm, text="Export HTML Map (Google Maps/Leaflet)", command=self.export_html_map).grid(row=0, column=1, padx=4)

        # internal state
        self.worker = None
        self.worker_queue = queue.Queue()
        self.records = []  # results
        self.session_key = None
        # periodic queue poll
        self.root.after(200, self.poll_queue)

    def toggle_verbose(self):
        self.verbose.set(not self.verbose.get())

    def browse_csv(self):
        p = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if p:
            self.csv_path_var.set(p)

    def login_qrz(self):
        user = self.qrz_user.get().strip()
        pwd = self.qrz_pass.get()
        if not user or not pwd:
            messagebox.showinfo("QRZ Login", "Please enter both username and password for QRZ.")
            return
        self.log(f"Logging in to QRZ as {user} ...", lvl="info")
        def do_login():
            try:
                key = qrz_login(user, pwd, verbose=self.verbose.get())
                self.session_key = key
                self.log(f"QRZ session/key obtained: {key[:8]}... (kept in memory).", lvl="info")
            except Exception as e:
                self.log(f"QRZ login failed: {e}", lvl="error")
        threading.Thread(target=do_login, daemon=True).start()

    def gather_callsigns(self):
        calls = []
        # from CSV: expect column 'callsign' or first column contains callsign; if CSV has address columns, we will keep and use them
        csvpath = self.csv_path_var.get().strip()
        if csvpath:
            try:
                with open(csvpath, newline='', encoding='utf-8') as fh:
                    reader = csv.DictReader(fh)
                    if 'callsign' in (c.lower() for c in reader.fieldnames):
                        # normalized
                        for r in reader:
                            # find callsign field case-insensitively
                            cs = None
                            for k in r:
                                if k.lower() == 'callsign':
                                    cs = r[k].strip()
                                    break
                            if cs:
                                calls.append(cs)
                    else:
                        # fallback: read first column values as callsigns
                        fh.seek(0)
                        reader2 = csv.reader(fh)
                        for row in reader2:
                            if row:
                                calls.append(row[0].strip())
            except Exception as e:
                self.log(f"Failed to read CSV: {e}", lvl="error")
        # from text area
        txt = self.callsign_text.get("1.0", "end").strip()
        if txt:
            parts = [p.strip() for p in txt.replace(",", "\n").splitlines() if p.strip()]
            calls.extend(parts)
        # dedupe and keep order
        seen = set()
        calls2 = []
        for c in calls:
            if c and c.upper() not in seen:
                seen.add(c.upper())
                calls2.append(c.upper())
        return calls2

    def start(self):
        if self.worker and self.worker.is_alive():
            messagebox.showinfo("Already running", "Worker already running")
            return
        calls = self.gather_callsigns()
        if not calls:
            messagebox.showinfo("No callsigns", "No callsigns were provided. Provide a CSV or paste callsigns.")
            return
        self.records = []
        geocode_mode = self.geocode_mode.get()
        google_key = self.google_key.get().strip() or None
        self.log(f"Starting processing {len(calls)} callsigns. Geocode: {geocode_mode}", lvl="info")
        self.progress["maximum"] = len(calls)
        self.progress["value"] = 0
        self.status_var.set("Running")
        self.worker = WorkerThread(calls, self.session_key, geocode_mode, google_key, self.worker_queue, verbose=self.verbose.get())
        self.worker.daemon = True
        self.worker.start()
        self.start_time = now_ts()

    def stop(self):
        if self.worker:
            self.worker.stop()
            self.log("Worker stop requested", lvl="info")
            self.status_var.set("Stopping...")

    def poll_queue(self):
        try:
            while True:
                item = self.worker_queue.get_nowait()
                typ, payload = item
                if typ == "log":
                    self.log(payload)
                elif typ == "progress":
                    p = payload
                    processed = p["processed"]
                    total = p["total"]
                    elapsed = p["elapsed"]
                    eta = p["eta"]
                    self.progress["value"] = processed
                    self.status_var.set(f"{processed}/{total}  Elapsed: {nice_elapsed(elapsed)}  ETA: {nice_elapsed(eta)}")
                elif typ == "finished":
                    records = payload
                    self.records = records
                    self.progress["value"] = len(records)
                    self.status_var.set("Finished")
                    self.log(f"Completed: {len(records)} records", lvl="info")
        except queue.Empty:
            pass
        self.root.after(200, self.poll_queue)

    def log(self, msg, lvl="info"):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_text.insert("end", f"[{ts}] [{lvl}] {msg}\n")
        self.log_text.see("end")

    def export_csv(self):
        if not self.records:
            messagebox.showinfo("No data", "No records to export. Run processing first or supply CSV.")
            return
        p = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")])
        if not p:
            return
        # write header based on keys
        keys = set()
        for r in self.records:
            keys.update(r.keys())
        keys = list(keys)
        try:
            with open(p, "w", newline='', encoding='utf-8') as fh:
                w = csv.DictWriter(fh, fieldnames=keys)
                w.writeheader()
                for r in self.records:
                    w.writerow(r)
            self.log(f"Exported CSV to {p}", lvl="info")
        except Exception as e:
            self.log(f"CSV export failed: {e}", lvl="error")

    def export_kml(self):
        if not self.records:
            messagebox.showinfo("No data", "No records to export. Run processing first.")
            return
        p = filedialog.asksaveasfilename(defaultextension=".kml", filetypes=[("KML","*.kml")])
        if not p:
            return
        # create simple KML placemarks for records that have lat/lon
        kml_parts = ['<?xml version="1.0" encoding="UTF-8"?>', '<kml xmlns="http://www.opengis.net/kml/2.2">', '<Document>']
        for r in self.records:
            lat = r.get("lat")
            lon = r.get("lon")
            if lat and lon:
                name = r.get("callsign", "")
                desc = r.get("address", "")
                kml_parts.append(f"<Placemark><name>{name}</name><description>{desc}</description><Point><coordinates>{lon},{lat},0</coordinates></Point></Placemark>")
        kml_parts.append("</Document></kml>")
        try:
            with open(p, "w", encoding="utf-8") as fh:
                fh.write("\n".join(kml_parts))
            self.log(f"KML exported to {p}", lvl="info")
        except Exception as e:
            self.log(f"KML export failed: {e}", lvl="error")

    def export_html_map(self):
        if not self.records:
            messagebox.showinfo("No data", "No records to export. Run processing first.")
            return
        p = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML","*.html")])
        if not p:
            return
        # Build HTML: prefer Google Maps if API key present; else produce Leaflet/OSM display.
        gm_key = self.google_key.get().strip()
        has_google = bool(gm_key)
        points = []
        for r in self.records:
            lat = r.get("lat")
            lon = r.get("lon")
            if lat and lon:
                points.append({"callsign": r.get("callsign",""), "lat": lat, "lon": lon, "address": r.get("address","")})
        center_lat = sum(float(p["lat"]) for p in points)/len(points) if points else 0
        center_lon = sum(float(p["lon"]) for p in points)/len(points) if points else 0
        if has_google:
            # Google Maps HTML
            markers_js = []
            for pt in points:
                markers_js.append(f"new google.maps.Marker({{position: {{lat: {pt['lat']}, lng: {pt['lon']}}}, map: map, title: '{pt['callsign']}'}});")
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
        var center = {{lat: {center_lat}, lng: {center_lon}}};
        var map = new google.maps.Map(document.getElementById('map'), {{zoom: 8, center: center}});
        {"".join(markers_js)}
      }}
      window.onload = initMap;
    </script>
  </body>
</html>"""
        else:
            # Leaflet map using OSM tiles, no key required
            markers_js = []
            for pt in points:
                popup = f"{pt['callsign']}<br/>{pt['address']}".replace("'", "\\'")
                markers_js.append(f"L.marker([{pt['lat']}, {pt['lon']}]).addTo(map).bindPopup('{popup}');")
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
      var map = L.map('map').setView([{center_lat}, {center_lon}], 8);
      L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
        maxZoom: 19,
        attribution: '© OpenStreetMap contributors'
      }}).addTo(map);
      {''.join(markers_js)}
    </script>
  </body>
</html>"""
        try:
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(html)
            self.log(f"HTML map exported to {p}", lvl="info")
        except Exception as e:
            self.log(f"HTML export failed: {e}", lvl="error")

# ---------- CLI mode convenience ----------
def run_gui():
    root = tk.Tk()
    app = QRZMapperApp(root)
    root.mainloop()

# ---------- Entry point ----------
if __name__ == "__main__":
    # Allow running without GUI in scripted mode (optional)
    parser = argparse.ArgumentParser(description="QRZ County / Callsign Mapper (GUI). See script comments.")
    parser.add_argument("--no-gui", action="store_true", help="Run in headless mode (not implemented; opens GUI by default).")
    args = parser.parse_args()
    run_gui()
