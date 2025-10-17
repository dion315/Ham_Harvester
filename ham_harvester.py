#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Ham Harvester — QRZ County + XML Enrichment
- Discovers QRZ county pages via FIPS links (no manual URLs needed)
- Harvests calls for selected state/counties from public qrz.com pages
- Enriches with QRZ XML API (name, address, grid, email, etc.)
- Supports direct callsign input and CSV list mode
- Exports CSV; optional KML + Leaflet map
- Tkinter GUI with login/API key prompt first; verbose logging; progress; Stop

NOTE: Requires a QRZ XML subscription for enrichment. Scraping uses public pages.
"""

from __future__ import annotations
import os
import re
import sys
import csv
import time
import math
import queue
import json
import html
import signal
import random
import zipfile
import threading
import webbrowser
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Iterable, Tuple
from urllib.parse import urljoin, urlencode, urlparse, parse_qs

# ---- Dependency checks -------------------------------------------------------

missing = []
try:
    import requests
except Exception:
    print("[FATAL] requests missing")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
except Exception:
    missing.append("beautifulsoup4")

try:
    import simplekml
except Exception:
    simplekml = None  # Optional

try:
    from geopy.geocoders import Nominatim
    from geopy.extra.rate_limiter import RateLimiter
except Exception:
    Nominatim = None  # Optional

if missing:
    print(f"[INFO] Missing packages: {missing}")
    print("[INFO] Please install into your venv, e.g.:")
    print("       pip install " + " ".join(missing))
    # continue; we can still run most UI, but scraping needs bs4

# ---- Tk UI -------------------------------------------------------------------

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# ---- Constants ---------------------------------------------------------------

QRZ_WEB_BASE = "https://www.qrz.com"
QRZ_DB_PATH = "/db"
QRZ_XML_BASE = "https://xmldata.qrz.com/xml/current/"
USER_AGENT = "HamHarvester/1.3 (+https://github.com/your-org/ham_harvester)"

ALL_STATES = {
    "AL":"Alabama","AK":"Alaska","AZ":"Arizona","AR":"Arkansas","CA":"California","CO":"Colorado","CT":"Connecticut",
    "DE":"Delaware","DC":"District of Columbia","FL":"Florida","GA":"Georgia","HI":"Hawaii","ID":"Idaho","IL":"Illinois",
    "IN":"Indiana","IA":"Iowa","KS":"Kansas","KY":"Kentucky","LA":"Louisiana","ME":"Maine","MD":"Maryland","MA":"Massachusetts",
    "MI":"Michigan","MN":"Minnesota","MS":"Mississippi","MO":"Missouri","MT":"Montana","NE":"Nebraska","NV":"Nevada",
    "NH":"New Hampshire","NJ":"New Jersey","NM":"New Mexico","NY":"New York","NC":"North Carolina","ND":"North Dakota",
    "OH":"Ohio","OK":"Oklahoma","OR":"Oregon","PA":"Pennsylvania","RI":"Rhode Island","SC":"South Carolina","SD":"South Dakota",
    "TN":"Tennessee","TX":"Texas","UT":"Utah","VT":"Vermont","VA":"Virginia","WA":"Washington","WV":"West Virginia",
    "WI":"Wisconsin","WY":"Wyoming","PR":"Puerto Rico","GU":"Guam","AS":"American Samoa","VI":"U.S. Virgin Islands",
    "MP":"Northern Mariana Islands"
}

CSV_DEFAULT_FIELDS = ["callsign","name","street","city","state","county","zip","grid","email"]

CALL_RE = re.compile(r"\b([A-Z0-9]{1,2}\d{1,4}[A-Z]{1,3})\b", re.I)

def clean_call(cs: str) -> Optional[str]:
    cs = (cs or "").upper().strip()
    m = CALL_RE.fullmatch(cs)
    return m.group(1) if m else None

# ---- Utility: logging to UI thread-safely ------------------------------------

class UiLogger:
    def __init__(self, text_widget: tk.Text):
        self.text = text_widget
        self.lock = threading.Lock()

    def log(self, line: str):
        with self.lock:
            self.text.configure(state="normal")
            self.text.insert("end", line.rstrip() + "\n")
            self.text.see("end")
            self.text.configure(state="disabled")

    def hr(self):
        self.log("-" * 70)

# ---- Networking helpers ------------------------------------------------------

def new_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT})
    s.timeout = 20
    return s

def get_html(sess: requests.Session, url: str, params: dict | None = None, method: str = "GET", data: dict | None = None) -> str:
    if method.upper() == "POST":
        r = sess.post(url, data=data, params=params, timeout=20)
    else:
        r = sess.get(url, params=params, timeout=20)
    r.raise_for_status()
    return r.text

# ---- QRZ: County index discovery via FIPS links ------------------------------

def parse_fips_county_links(html_text: str) -> List[Dict[str, str]]:
    """
    Parse any page that contains a list of county anchors like:
      <a href="https://www.qrz.com/db?fips=01001">Autauga, Alabama</a>
    Returns list of dicts: {fips, county, state, url}
    """
    soup = BeautifulSoup(html_text, "lxml")
    out: List[Dict[str, str]] = []
    seen = set()
    for a in soup.select('a[href*="db?fips="]'):
        href = a.get("href", "")
        m = re.search(r"[?&]fips=(\d{5})\b", href)
        if not m:
            continue
        fips = m.group(1)
        label = (a.get_text() or "").strip()
        if "," in label:
            county, state = [p.strip() for p in label.split(",", 1)]
        else:
            county, state = label, ""
        url = urljoin(QRZ_WEB_BASE, href)
        key = (fips, county, state)
        if key in seen:
            continue
        seen.add(key)
        out.append({"fips": fips, "county": county, "state": state, "url": url})
    return out

def fetch_state_counties(sess: requests.Session, state_abbrev: str) -> List[Dict[str, str]]:
    """
    Loads the global county index (query mode=county) and filters counties to the given state.
    """
    full = ALL_STATES.get(state_abbrev.upper())
    if not full:
        return []
    # This payload produces a big index page of counties across the US
    url = urljoin(QRZ_WEB_BASE, QRZ_DB_PATH)
    payload = {"query":"*","cs":"*","sel":"","cmd":"Search","mode":"county"}
    html_text = get_html(sess, url, params=payload, method="GET")
    items = parse_fips_county_links(html_text)
    return [i for i in items if i["state"] == full]

# ---- QRZ: County page → callsigns + pagination -------------------------------

def extract_calls_from_page(html_text: str) -> Tuple[List[str], Optional[str]]:
    """
    Returns (calls_on_page, next_url)
    - calls are discovered via href="/db/CALL" or "/lookup/CALL" and table text fallback
    - next_url discovered via rel="next" or text 'Next', '»', '›'
    """
    soup = BeautifulSoup(html_text, "lxml")

    # calls via links
    calls: set[str] = set()
    for a in soup.find_all("a", href=True):
        href = a["href"]
        # absolute or relative OK
        if "/db/" in href or "/lookup/" in href:
            # last path segment may be the call
            try:
                path = urlparse(href).path
            except Exception:
                path = href
            parts = [p for p in path.split("/") if p]
            if parts:
                maybe = parts[-1].upper()
                c = clean_call(maybe)
                if c:
                    calls.add(c)
        # Also scrape visible text that looks like a call
        t = (a.get_text() or "").strip()
        c2 = clean_call(t)
        if c2:
            calls.add(c2)

    # very defensive: scan table cells
    if not calls:
        for td in soup.find_all(["td","span","div"]):
            txt = (td.get_text() or "").strip()
            c3 = clean_call(txt)
            if c3:
                calls.add(c3)

    # next link
    next_url: Optional[str] = None
    # rel=next
    rel_next = soup.find("a", rel=lambda v: v and "next" in v.lower(), href=True)
    if rel_next:
        next_url = urljoin(QRZ_WEB_BASE, rel_next["href"])
    else:
        # textual next
        for a in soup.find_all("a", href=True):
            t = (a.get_text() or "").strip().lower()
            if t in ("next", "»", "›", "next ›", "next »"):
                next_url = urljoin(QRZ_WEB_BASE, a["href"])
                break

    return sorted(calls), next_url

def crawl_county_calls(sess: requests.Session, county_url: str, logger: UiLogger | None = None, stop_evt: threading.Event | None = None) -> List[str]:
    url = county_url
    all_calls: List[str] = []
    page_no = 0
    while url:
        if stop_evt and stop_evt.is_set():
            if logger: logger.log("[info] Stop requested — halting pagination.")
            break
        page_no += 1
        if logger: logger.log(f"[info]  Fetching county page {page_no}: {url}")
        html_text = get_html(sess, url)
        calls, next_url = extract_calls_from_page(html_text)
        if logger: logger.log(f"[info]   + {len(calls)} calls on page {page_no}")
        # append while preserving order and uniqueness
        seen = set(all_calls)
        for c in calls:
            if c not in seen:
                all_calls.append(c)
                seen.add(c)
        if not next_url:
            break
        url = next_url
        time.sleep(0.75)  # be polite
    return all_calls

# ---- QRZ XML: auth + lookup --------------------------------------------------

@dataclass
class QrzCreds:
    username: str = ""
    password: str = ""
    api_key: str = ""      # If QRZ provided a direct key, you can store it here to skip username/password

@dataclass
class QrzSession:
    sess: requests.Session
    xml_session_key: Optional[str] = None
    creds: QrzCreds = field(default_factory=QrzCreds)

def qrz_xml_login(q: QrzSession) -> str:
    """
    Login to QRZ XML. If api_key provided, it’s used as 's=' session (some deployments allow that).
    Otherwise we get 'Key' by username/password.
    """
    if q.creds.api_key:
        q.xml_session_key = q.creds.api_key.strip()
        return q.xml_session_key

    params = {"username": q.creds.username, "password": q.creds.password}
    r = q.sess.get(QRZ_XML_BASE, params=params, timeout=20)
    r.raise_for_status()
    text = r.text
    # crude parse for <Key>...</Key>
    m = re.search(r"<Key>([^<]+)</Key>", text)
    if not m:
        em = re.search(r"<Error>([^<]+)</Error>", text)
        raise RuntimeError(f"QRZ XML login failed: {em.group(1) if em else 'unknown error'}")
    key = m.group(1).strip()
    q.xml_session_key = key
    return key

def qrz_xml_lookup(q: QrzSession, callsign: str) -> Dict[str, str]:
    """
    Fetches XML record for a callsign. Returns a dict with desired fields.
    """
    if not q.xml_session_key:
        raise RuntimeError("Not logged in to QRZ XML")
    params = {"s": q.xml_session_key, "callsign": callsign}
    r = q.sess.get(QRZ_XML_BASE, params=params, timeout=20)
    r.raise_for_status()
    t = r.text

    # retry if session expired
    if "<Session>" in t and "<Error>Session Timeout" in t:
        qrz_xml_login(q)
        params["s"] = q.xml_session_key
        r = q.sess.get(QRZ_XML_BASE, params=params, timeout=20)
        r.raise_for_status()
        t = r.text

    # quick-n-dirty XML field extraction
    def gx(tag):
        m = re.search(rf"<{tag}>(.*?)</{tag}>", t, flags=re.S)
        return html.unescape(m.group(1)).strip() if m else ""

    # map out fields
    info = {
        "callsign": gx("call") or callsign.upper(),
        "name": f"{gx('fname')} {gx('name')}".strip() or gx("attn") or gx("name"),
        "street": gx("addr2") or gx("addr1"),
        "city": gx("addr3") or gx("addr2"),
        "state": gx("state"),
        "county": gx("county"),
        "zip": gx("zip"),
        "grid": gx("grid"),
        "email": gx("email"),
        "country": gx("country"),
    }
    # normalize whitespace
    for k, v in list(info.items()):
        if isinstance(v, str):
            info[k] = re.sub(r"\s+", " ", v).strip()
    return info

# ---- Exporters ---------------------------------------------------------------

def write_csv(rows: List[Dict[str, str]], path: str, preferred: List[str] | None = None) -> None:
    if not rows:
        with open(path, "w", newline="", encoding="utf-8") as f:
            f.write("")  # create empty
        return
    if preferred is None:
        preferred = CSV_DEFAULT_FIELDS
    present = set()
    for r in rows:
        present.update(r.keys())
    fieldnames = [k for k in preferred if k in present] + [k for k in sorted(present) if k not in preferred]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fieldnames})

def write_kml(rows: List[Dict[str, str]], path: str) -> None:
    if simplekml is None:
        raise RuntimeError("simplekml not installed")
    kml = simplekml.Kml()
    for r in rows:
        name = r.get("callsign","")
        desc = "\n".join(f"{k}: {v}" for k, v in r.items() if v and k != "callsign")
        # Try basic city, state point if no lat/lon
        p = kml.newpoint(name=name, description=desc)
        # No geocoding here; KML will just have named points
    kml.save(path)

def write_leaflet_map(rows: List[Dict[str, str]], path: str) -> None:
    """
    Minimal Leaflet map with markers using city/state (no geocoding here).
    """
    import json
    points = []
    for r in rows:
        label = r.get("callsign","")
        popup = "<br>".join(f"<b>{html.escape(k)}</b>: {html.escape(v)}" for k,v in r.items() if v)
        points.append({"label": label, "popup": popup})
    html_doc = f"""<!doctype html>
<html><head><meta charset="utf-8">
<title>Ham Harvester Map</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<style>html,body,#map{{height:100%;margin:0;}} .marker-label{{font: 12px/1.2 sans-serif;}}</style>
</head>
<body>
<div id="map"></div>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script>
var map = L.map('map').setView([39.5,-98.35], 4);
L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png',{{
    maxZoom: 19, attribution: '&copy; OpenStreetMap'
}}).addTo(map);
var pts = {json.dumps(points)};
pts.forEach(p => {{
    L.marker(map.getCenter()).addTo(map).bindPopup(p.popup);
}});
</script>
</body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html_doc)

# ---- Worker thread -----------------------------------------------------------

class HarvesterThread(threading.Thread):
    def __init__(self, app: "App"):
        super().__init__(daemon=True)
        self.app = app
        self.stop_evt = threading.Event()

    def request_stop(self):
        self.stop_evt.set()

    def run(self):
        try:
            self._run_impl()
        except Exception as e:
            self.app.log(f"[error] {e.__class__.__name__}: {e}")

    # Core flow based on selected mode
    def _run_impl(self):
        app = self.app
        logger = app.logger
        logger.hr()

        sess = new_session()
        qrz = QrzSession(sess=sess, creds=QrzCreds(app.username.get(), app.password.get(), app.api_key.get()))
        logger.log(f"[info] Logging in to QRZ ...")
        key = qrz_xml_login(qrz)
        logger.log("[info] QRZ XML session ready.")

        mode = app.mode.get()  # A: callsigns; B: CSV; C: counties
        out_rows: List[Dict[str, str]] = []

        if mode == "A":
            # Direct callsigns typed
            raw = app.callsigns_text.get("1.0","end").strip().splitlines()
            calls = []
            for line in raw:
                for token in re.split(r"[,\s]+", line.strip()):
                    c = clean_call(token)
                    if c: calls.append(c)
            calls = sorted(set(calls))
            logger.log(f"[info] {len(calls)} calls queued for lookup.")
            out_rows = self.process_calls(qrz, calls, logger)

        elif mode == "B":
            # CSV of callsigns
            path = app.csv_path.get().strip()
            if not os.path.isfile(path):
                logger.log("[error] CSV file not found.")
                return
            calls = []
            with open(path, "r", encoding="utf-8", newline="") as f:
                rdr = csv.reader(f)
                for row in rdr:
                    for cell in row:
                        c = clean_call(cell)
                        if c: calls.append(c)
            calls = sorted(set(calls))
            logger.log(f"[info] {len(calls)} calls from CSV queued for lookup.")
            out_rows = self.process_calls(qrz, calls, logger)

        else:
            # Counties mode
            state = app.state_var.get().strip().upper()
            chosen = [app.counties_listbox.get(i) for i in app.counties_listbox.curselection()]
            if app.all_counties_var.get():
                # populate via live fetch if not already cached in UI
                if not app.state_counties.get(state):
                    logger.log(f"[info] Loading counties for {state} ...")
                    items = fetch_state_counties(sess, state)
                    app.state_counties[state] = items
                chosen = [i["county"] for i in app.state_counties[state]]
            if not chosen:
                logger.log("[error] No counties selected.")
                return

            # for each county, get county URL, crawl calls, then XML enrich
            # ensure state counties map exists
            if not app.state_counties.get(state):
                logger.log(f"[info] Loading counties for {state} ...")
                items = fetch_state_counties(sess, state)
                app.state_counties[state] = items

            county_map = {i["county"]: i["url"] for i in app.state_counties[state]}
            all_calls: List[str] = []
            for county in chosen:
                if self.stop_evt.is_set():
                    logger.log("[info] Stop requested — exiting before next county.")
                    break
                url = county_map.get(county)
                if not url:
                    logger.log(f"[warn] No FIPS URL found for {county}, {state}")
                    continue
                logger.log(f"[info] Harvesting {county}, {state} ...")
                calls = crawl_county_calls(sess, url, logger, self.stop_evt)
                logger.log(f"[info] {county}: collected {len(calls)} calls")
                all_calls.extend(calls)
                time.sleep(0.5)

            uniq_calls = sorted(set(all_calls))
            logger.log(f"[info] Total unique calls to enrich: {len(uniq_calls)}")
            out_rows = self.process_calls(qrz, uniq_calls, logger)

        # export
        if out_rows:
            out_csv = app.out_csv_path.get().strip() or f"harvest_{int(time.time())}.csv"
            write_csv(out_rows, out_csv, CSV_DEFAULT_FIELDS)
            logger.log(f"[info] CSV written: {out_csv}")
            if app.make_kml_var.get():
                try:
                    out_kml = os.path.splitext(out_csv)[0] + ".kml"
                    write_kml(out_rows, out_kml)
                    logger.log(f"[info] KML written: {out_kml}")
                except Exception as e:
                    logger.log(f"[warn] KML not created: {e}")
            if app.make_map_var.get():
                try:
                    out_html = os.path.splitext(out_csv)[0] + "_map.html"
                    write_leaflet_map(out_rows, out_html)
                    logger.log(f"[info] Map written: {out_html}")
                except Exception as e:
                    logger.log(f"[warn] Map not created: {e}")
        else:
            logger.log("[info] Nothing to export.")

        logger.hr()
        logger.log("[info] Finished.")

    def process_calls(self, qrz: QrzSession, calls: List[str], logger: UiLogger) -> List[Dict[str, str]]:
        out_rows: List[Dict[str, str]] = []
        total = len(calls)
        for idx, c in enumerate(calls, 1):
            if self.stop_evt.is_set():
                logger.log("[info] Stop requested — halting call lookups.")
                break
            logger.log(f"[info] [{idx}/{total}] XML: {c}")
            try:
                info = qrz_xml_lookup(qrz, c)
                out_rows.append(info)
            except Exception as e:
                logger.log(f"[error] {c}: {e}")
            # progress
            pct = int(idx * 100 / max(1,total))
            self.app.progress["value"] = pct
            self.app.progress.update_idletasks()
            time.sleep(0.25)
        return out_rows

# ---- Tk App ------------------------------------------------------------------

class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Ham Harvester — QRZ County + XML")
        self.state_counties: Dict[str, List[Dict[str,str]]] = {}
        self.worker: Optional[HarvesterThread] = None

        # Top: QRZ creds / API key
        creds = ttk.LabelFrame(root, text="QRZ Login / API Key (required first)")
        creds.pack(fill="x", padx=8, pady=8)

        self.username = tk.StringVar()
        self.password = tk.StringVar()
        self.api_key = tk.StringVar()

        row = ttk.Frame(creds); row.pack(fill="x", padx=6, pady=4)
        ttk.Label(row, text="Username:").pack(side="left")
        ttk.Entry(row, textvariable=self.username, width=18).pack(side="left", padx=6)
        ttk.Label(row, text="Password:").pack(side="left")
        ttk.Entry(row, textvariable=self.password, width=18, show="*").pack(side="left", padx=6)
        ttk.Label(row, text="or XML API Key:").pack(side="left")
        ttk.Entry(row, textvariable=self.api_key, width=28).pack(side="left", padx=6)
        ttk.Button(row, text="Test Login", command=self.test_login).pack(side="right")

        # Mode chooser
        modes = ttk.LabelFrame(root, text="Mode")
        modes.pack(fill="x", padx=8, pady=4)
        self.mode = tk.StringVar(value="C")  # default counties
        ttk.Radiobutton(modes, text="A) Callsigns (typed below)", variable=self.mode, value="A", command=self.on_mode_change).pack(anchor="w")
        ttk.Radiobutton(modes, text="B) Callsign CSV file", variable=self.mode, value="B", command=self.on_mode_change).pack(anchor="w")
        ttk.Radiobutton(modes, text="C) State + Counties (QRZ public)", variable=self.mode, value="C", command=self.on_mode_change).pack(anchor="w")

        # A) callsigns text
        a_frame = ttk.LabelFrame(root, text="A) Enter callsigns (comma/space/line separated)")
        a_frame.pack(fill="both", padx=8, pady=4)
        self.callsigns_text = tk.Text(a_frame, height=5, width=80)
        self.callsigns_text.pack(fill="both", padx=6, pady=6)

        # B) CSV chooser
        b_frame = ttk.LabelFrame(root, text="B) Callsign CSV path")
        b_frame.pack(fill="x", padx=8, pady=4)
        self.csv_path = tk.StringVar()
        b_row = ttk.Frame(b_frame); b_row.pack(fill="x", padx=6, pady=4)
        ttk.Entry(b_row, textvariable=self.csv_path).pack(side="left", fill="x", expand=True)
        ttk.Button(b_row, text="Browse…", command=self.choose_csv).pack(side="left", padx=6)

        # C) State + counties
        c_frame = ttk.LabelFrame(root, text="C) Select State and County/Counties")
        c_frame.pack(fill="both", padx=8, pady=6)
        c_row1 = ttk.Frame(c_frame); c_row1.pack(fill="x", padx=6, pady=4)
        self.state_var = tk.StringVar(value="NY")
        ttk.Label(c_row1, text="State:").pack(side="left")
        self.state_combo = ttk.Combobox(c_row1, state="readonly", values=sorted(ALL_STATES.keys()), textvariable=self.state_var, width=6)
        self.state_combo.pack(side="left")
        ttk.Button(c_row1, text="Load Counties", command=self.load_counties).pack(side="left", padx=8)

        self.all_counties_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(c_row1, text="All counties in state", variable=self.all_counties_var).pack(side="left", padx=8)

        c_row2 = ttk.Frame(c_frame); c_row2.pack(fill="both", padx=6, pady=4, expand=True)
        self.counties_listbox = tk.Listbox(c_row2, selectmode="extended", height=8)
        self.counties_listbox.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(c_row2, orient="vertical", command=self.counties_listbox.yview)
        sb.pack(side="left", fill="y")
        self.counties_listbox.configure(yscrollcommand=sb.set)

        c_row3 = ttk.Frame(c_frame); c_row3.pack(fill="x", padx=6, pady=4)
        ttk.Button(c_row3, text="Test County Page", command=self.test_county_page).pack(side="left")

        # Output options
        out_frame = ttk.LabelFrame(root, text="Output")
        out_frame.pack(fill="x", padx=8, pady=6)
        self.out_csv_path = tk.StringVar(value="harvest.csv")
        of = ttk.Frame(out_frame); of.pack(fill="x", padx=6, pady=4)
        ttk.Label(of, text="CSV file:").pack(side="left")
        ttk.Entry(of, textvariable=self.out_csv_path, width=40).pack(side="left", padx=6)
        ttk.Button(of, text="Browse…", command=self.choose_out_csv).pack(side="left")
        self.make_kml_var = tk.BooleanVar(value=False)
        self.make_map_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(of, text="Also create KML", variable=self.make_kml_var).pack(side="left", padx=10)
        ttk.Checkbutton(of, text="Also create HTML map", variable=self.make_map_var).pack(side="left")

        # Controls + progress
        ctrl = ttk.Frame(root); ctrl.pack(fill="x", padx=8, pady=4)
        ttk.Button(ctrl, text="Run", command=self.run_action).pack(side="left")
        ttk.Button(ctrl, text="Stop", command=self.stop).pack(side="left", padx=6)
        self.progress = ttk.Progressbar(ctrl, orient="horizontal", mode="determinate", length=280, maximum=100)
        self.progress.pack(side="left", padx=10, fill="x", expand=True)

        # Log output
        logf = ttk.LabelFrame(root, text="Log")
        logf.pack(fill="both", padx=8, pady=6, expand=True)
        self.log_text = tk.Text(logf, height=14, state="disabled")
        self.log_text.pack(side="left", fill="both", expand=True)
        logsb = ttk.Scrollbar(logf, orient="vertical", command=self.log_text.yview)
        logsb.pack(side="left", fill="y")
        self.log_text.configure(yscrollcommand=logsb.set)
        self.logger = UiLogger(self.log_text)

        self.on_mode_change()

    # --- UI helpers -----------------------------------------------------------

    def log(self, line: str):
        self.logger.log(line)

    def on_mode_change(self):
        mode = self.mode.get()
        # Enable/disable panes to guide user
        def set_state(widget, enabled: bool):
            try:
                widget.configure(state=("normal" if enabled else "disabled"))
            except tk.TclError:
                pass

        # A
        set_state(self.callsigns_text, mode == "A")
        # B
        for w in ():
            set_state(w, mode == "B")
        # C
        for w in (self.state_combo, self.counties_listbox):
            set_state(w, mode == "C")

    def choose_csv(self):
        p = filedialog.askopenfilename(title="Choose callsign CSV", filetypes=[("CSV","*.csv"),("All files","*.*")])
        if p:
            self.csv_path.set(p)

    def choose_out_csv(self):
        p = filedialog.asksaveasfilename(title="Save CSV as...", defaultextension=".csv",
                                         filetypes=[("CSV","*.csv"),("All files","*.*")])
        if p:
            self.out_csv_path.set(p)

    # --- QRZ login test -------------------------------------------------------

    def test_login(self):
        try:
            sess = new_session()
            q = QrzSession(sess=sess, creds=QrzCreds(self.username.get(), self.password.get(), self.api_key.get()))
            key = qrz_xml_login(q)
            self.log("[info] QRZ XML login OK.")
        except Exception as e:
            self.log(f"[error] Login failed: {e}")

    # --- Counties loading / test ---------------------------------------------

    def load_counties(self):
        st = (self.state_var.get() or "").upper().strip()
        if not st or st not in ALL_STATES:
            messagebox.showerror("State", "Choose a valid state.")
            return
        try:
            self.log(f"[info] Loading counties for {st} ...")
            sess = new_session()
            items = fetch_state_counties(sess, st)
            items = sorted(items, key=lambda d: d["county"])
            self.state_counties[st] = items
            self.counties_listbox.delete(0, "end")
            for it in items:
                self.counties_listbox.insert("end", it["county"])
            self.log(f"[info] Counties loaded: {len(items)}")
        except Exception as e:
            self.log(f"[error] Could not load counties: {e}")

    def test_county_page(self):
        st = (self.state_var.get() or "").upper().strip()
        sel = self.counties_listbox.curselection()
        if not sel:
            messagebox.showinfo("Test", "Select a county in the list first.")
            return
        county = self.counties_listbox.get(sel[0])
        items = self.state_counties.get(st) or []
        url = None
        for it in items:
            if it["county"] == county:
                url = it["url"]; break
        if not url:
            self.log(f"[warn] No URL found for {county}, {st}. Load counties first.")
            return
        try:
            sess = new_session()
            self.log(f"[info] Test county page: {county}, {st}")
            html_text = get_html(sess, url)
            calls, nxt = extract_calls_from_page(html_text)
            self.log(f"[info] Found {len(calls)} calls on first page. next={'yes' if nxt else 'no'}")
        except Exception as e:
            self.log(f"[error] Test county failed: {e}")

    # --- Run / Stop -----------------------------------------------------------

    def run_action(self):
        # require login/API first
        if not (self.api_key.get().strip() or (self.username.get().strip() and self.password.get().strip())):
            messagebox.showerror("QRZ Login", "Please enter QRZ username+password or XML API key first.")
            return
        if self.worker and self.worker.is_alive():
            messagebox.showwarning("Busy", "A run is already in progress.")
            return
        self.progress["value"] = 0
        self.worker = HarvesterThread(self)
        self.worker.start()
        self.log("[info] Started.")

    def stop(self):
        if self.worker and self.worker.is_alive():
            self.worker.request_stop()
            self.log("[info] Stop requested.")

# ---- main --------------------------------------------------------------------

def main():
    root = tk.Tk()
    app = App(root)
    root.mainloop()

if __name__ == "__main__":
    main()
