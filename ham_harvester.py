#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ham Harvester — QRZ county harvester (public site via /db) + QRZ XML enrich

What it does
------------
1) Prompt-first QRZ login or XML session key (required for detail enrichment).
2) Mode A: Callsigns/CSV -> QRZ XML lookup -> optional geocode -> export CSV/KML/HTML map.
3) Mode B: State/Counties -> Uses QRZ public `/db` county index:
     - Calls https://www.qrz.com/db with payload like:
         query=*&cs=*&sel=&cmd=Search&mode=county&state=<ABBR>   (several fallbacks tried)
       to retrieve the **official county list for that state** with links.
     - Follows each county link, paginates, collects all callsigns.
     - Enriches each callsign via QRZ XML (name/street/city/state/county/zip/grid/email).
4) Verbose logging, progress/ETA, Stop button. Exports CSV/KML/HTML map.

Notes
-----
- Works only with public qrz.com and the QRZ XML API (for per-callsign detail).
- If QRZ changes parameter names, this script already tries multiple variants and logs which worked.
- If a CAPTCHA/login wall appears while scraping public pages, log in first (XML) — that often grants a cookie that also helps for /db pages.
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
import os
from urllib.parse import urljoin, urlencode

# ---- tkinter first (system package) ----
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext
except Exception:
    print("[ERROR] tkinter is not available.\n"
          "Debian/Ubuntu: sudo apt-get install python3-tk\n"
          "Fedora:       sudo dnf install python3-tkinter\n"
          "Windows/macOS: install Python from python.org (includes tkinter).")
    sys.exit(1)

# ---- pip deps ----
def ensure_deps(verbose=False):
    pkgs = ["requests", "simplekml", "geopy", "beautifulsoup4", "lxml"]
    missing = []
    for m in pkgs:
        try:
            importlib.import_module(m)
            if verbose: print(f"[OK] {m} importable")
        except ImportError:
            missing.append(m)
    if not missing:
        if verbose: print("[INFO] All dependencies satisfied")
        return
    print(f"[INFO] Missing packages: {missing}")
    print("[INFO] Installing into current environment...")
    for m in missing:
        subprocess.check_call([sys.executable, "-m", "pip", "install", m])
        print(f"[INSTALLED] {m}")

ensure_deps(verbose=True)

# ---- external imports now safe ----
from geopy.geocoders import Nominatim as GeoNominatim
import simplekml
from bs4 import BeautifulSoup

# ---- HTTP / globals ----
APP_UA = "HamHarvester/QRZCounty/1.2 (+contact: you@example.com)"
HTTP = requests.Session()
HTTP.headers.update({"User-Agent": APP_UA})

QRZ_WEB_BASE   = "https://www.qrz.com"
QRZ_XML_BASE   = "https://xmldata.qrz.com/xml/current/"
QRZ_DB_URL     = "https://www.qrz.com/db"

# conservative, US-centric callsign pattern (accept portable suffixes)
CALL_RE = re.compile(r"^[A-Z0-9]{1,2}\d[A-Z]{1,3}(?:/[A-Z0-9]+)?$", re.I)

US_STATES = {
    "AL":"Alabama","AK":"Alaska","AZ":"Arizona","AR":"Arkansas","CA":"California","CO":"Colorado",
    "CT":"Connecticut","DE":"Delaware","FL":"Florida","GA":"Georgia","HI":"Hawaii","ID":"Idaho",
    "IL":"Illinois","IN":"Indiana","IA":"Iowa","KS":"Kansas","KY":"Kentucky","LA":"Louisiana",
    "ME":"Maine","MD":"Maryland","MA":"Massachusetts","MI":"Michigan","MN":"Minnesota","MS":"Mississippi",
    "MO":"Missouri","MT":"Montana","NE":"Nebraska","NV":"Nevada","NH":"New Hampshire","NJ":"New Jersey",
    "NM":"New Mexico","NY":"New York","NC":"North Carolina","ND":"North Dakota","OH":"Ohio","OK":"Oklahoma",
    "OR":"Oregon","PA":"Pennsylvania","RI":"Rhode Island","SC":"South Carolina","SD":"South Dakota",
    "TN":"Tennessee","TX":"Texas","UT":"Utah","VT":"Vermont","VA":"Virginia","WA":"Washington",
    "WV":"West Virginia","WI":"Wisconsin","WY":"Wyoming","DC":"District of Columbia","PR":"Puerto Rico",
    "GU":"Guam","VI":"U.S. Virgin Islands","AS":"American Samoa","MP":"N. Mariana Islands"
}

# ---- helpers ----
def now_ts(): return time.time()

def nice_elapsed(seconds: float) -> str:
    if seconds < 60: return f"{seconds:.1f}s"
    m, s = divmod(int(seconds), 60); h, m = divmod(m, 60)
    return f"{h}h {m}m {s}s" if h else (f"{m}m {s}s" if m else f"{s}s")

def is_callsign(s: str) -> bool:
    return bool(s and CALL_RE.match(s.strip()))

# ---- XML helpers ----
def find_first(elem, *tag_names):
    if elem is None: return None
    want = {t.lower() for t in tag_names}
    for node in elem.iter():
        local = node.tag.split('}', 1)[-1].lower()
        if local in want:
            return node
    return None

def find_text(elem, *tag_names):
    if elem is None: return ""
    node = find_first(elem, *tag_names)
    if node is not None and node.text:
        return node.text.strip()
    return ""

# ---- QRZ XML API ----
def qrz_login(username, password, verbose=False):
    if verbose: print("[qrz_login] POST login")
    payload = (f"<QRZDatabase><USERNAME>{username}</USERNAME>"
               f"<PASSWORD>{password}</PASSWORD>"
               "<OPTIONS><keeplogin>1</keeplogin></OPTIONS></QRZDatabase>")
    try:
        r = HTTP.post(QRZ_XML_BASE, data=payload,
                      headers={"Content-Type":"application/xml", "User-Agent":APP_UA},
                      timeout=30)
        r.raise_for_status()
        root = ET.fromstring(r.text)
        ses = find_first(root, "Session")
        key = find_text(ses, "Key")
        if key: return key
    except Exception:
        pass
    if verbose: print("[qrz_login] GET fallback")
    r = HTTP.get(QRZ_XML_BASE,
                 params={"username":username, "password":password},
                 headers={"User-Agent":APP_UA}, timeout=30)
    r.raise_for_status()
    root = ET.fromstring(r.text)
    ses = find_first(root, "Session")
    key = find_text(ses, "Key")
    if not key:
        err = find_text(ses, "Error") if ses is not None else "unknown"
        raise RuntimeError(f"QRZ login failed: {err}")
    return key

def qrz_lookup_call(session_key: str, callsign: str) -> dict:
    r = HTTP.get(QRZ_XML_BASE, params={"s":session_key, "callsign":callsign}, timeout=30)
    r.raise_for_status()
    root = ET.fromstring(r.text)
    ses = find_first(root, "Session")
    err = find_text(ses, "Error") if ses is not None else ""
    if err:
        raise RuntimeError(f"QRZ XML error: {err}")
    call = find_first(root, "Callsign")
    if call is None:
        return {"callsign": callsign}

    def gt(tag): return find_text(call, tag)

    data = {
        "callsign": gt("call") or callsign,
        "name": gt("fname") or gt("name"),
        "addr1": gt("addr1"),
        "addr2": gt("addr2"),
        "city":  gt("city") or gt("addr2"),
        "state": gt("state"),
        "zip":   gt("zip") or gt("zipcode") or gt("postcode"),
        "country": gt("country"),
        "grid":  gt("grid"),
        "email": gt("email"),
        "county": gt("county"),
    }
    street = data["addr1"] or ""
    if data["addr2"]:
        street = f"{street}, {data['addr2']}" if street else data["addr2"]
    data["street"] = street
    parts = [p for p in [street, data["city"], data["state"], data["zip"], data["country"]] if p]
    data["address"] = ", ".join(parts)
    return data

# ---- public QRZ /db helpers ----

def http_get(url_or_path: str) -> requests.Response:
    url = url_or_path if url_or_path.startswith("http") else urljoin(QRZ_WEB_BASE, url_or_path)
    r = HTTP.get(url, timeout=45, headers={"User-Agent": APP_UA})
    r.raise_for_status()
    return r

def http_get_with_params(url: str, params: dict) -> requests.Response:
    r = HTTP.get(url, params=params, timeout=45, headers={"User-Agent": APP_UA})
    r.raise_for_status()
    return r

def extract_calls_and_next(html: str, base_url: str) -> tuple[list[str], str|None]:
    """
    Extract callsigns from a QRZ result page and a possible next-page URL.
    """
    soup = BeautifulSoup(html, "lxml")
    calls = []
    seen  = set()

    # primary: links to /db/<CALL> or /lookup/<CALL> with anchor text == callsign
    for a in soup.select("a[href]"):
        href = a.get("href","")
        text = (a.get_text() or "").strip()
        if ("/db/" in href or "/lookup/" in href) and is_callsign(text):
            cu = text.upper()
            if cu not in seen:
                seen.add(cu); calls.append(cu)

    if not calls:
        # fallback: table cells
        for td in soup.select("table td, table th"):
            t = (td.get_text() or "").strip()
            if is_callsign(t):
                cu = t.upper()
                if cu not in seen:
                    seen.add(cu); calls.append(cu)

    # next page candidates
    next_href = None
    a_next = soup.find("a", rel=lambda x: x and "next" in x.lower())
    if a_next and a_next.get("href"):
        next_href = urljoin(base_url, a_next["href"])
    else:
        for a in soup.select("a[href]"):
            lbl = (a.get_text() or "").strip().lower()
            if lbl in {"next", "next >", "next »", "›", "»", "next›", "next»"}:
                next_href = urljoin(base_url, a["href"])
                break

    return calls, next_href

def qrz_county_index_for_state(state_abbr: str, log) -> dict:
    """
    Hit https://www.qrz.com/db with the 'county mode' payload (and fallbacks)
    to obtain a list of counties and their result links for the given state.
    Returns: { county_name: absolute_url_to_results }
    """
    # Primary payload per user guidance
    base_payloads = [
        {"query":"*","cs":"*","sel":"","cmd":"Search","mode":"county","state":state_abbr},
        {"query":"*","cs":"*","cmd":"Search","mode":"county","state":state_abbr},
        {"query":"*","cs":"*","sel":"","cmd":"Search","mode":"county","st":state_abbr},
        {"query":"*","cs":"*","cmd":"Search","mode":"county","st":state_abbr},
        # uppercase fallbacks (some sites care)
        {"QUERY":"*","CS":"*","SEL":"","CMD":"Search","MODE":"county","STATE":state_abbr},
        {"QUERY":"*","CS":"*","CMD":"Search","MODE":"county","STATE":state_abbr},
        {"QUERY":"*","CS":"*","CMD":"Search","MODE":"county","ST":state_abbr},
    ]

    last_err = None
    for payload in base_payloads:
        try:
            log(f"[info] QRZ county index query: {payload}")
            r = http_get_with_params(QRZ_DB_URL, payload)
            soup = BeautifulSoup(r.text, "lxml")

            # Strategy: find the list/table of counties; anchors likely say "<County> County"
            county_map = {}
            for a in soup.select("a[href]"):
                label = (a.get_text() or "").strip()
                if not label:
                    continue
                # Normalize label -> "Madison" even if "Madison County" or "MADISON County"
                if "county" in label.lower():
                    cname = label.replace("County", "").replace("COUNTY","").strip()
                    href = a.get("href")
                    if href:
                        county_map[cname] = urljoin(r.url, href)

            # Fallback heuristic: anchors whose href contains something county-like
            if not county_map:
                for a in soup.select("a[href]"):
                    href = (a.get("href") or "")
                    if "county" in href.lower() or "co=" in href.lower():
                        label = (a.get_text() or "").strip()
                        if label:
                            cname = label.replace("County", "").replace("COUNTY","").strip()
                        else:
                            # last-ditch: take query arg value-ish chunk
                            cname = " ".join(re.findall(r"(?:county|co)=([^&]+)", href, flags=re.I)) or href
                            cname = cname.replace("+"," ").strip().title()
                        county_map[cname] = urljoin(r.url, href)

            if county_map:
                # Clean dupes / blank keys
                county_map = {k:v for k,v in county_map.items() if k}
                log(f"[info] County index loaded: {len(county_map)} counties")
                return county_map

            # Save last error-like state
            last_err = "No counties parsed from response."
        except Exception as e:
            last_err = str(e)
            log(f"[error] County index attempt failed: {e}")

    raise RuntimeError(f"Could not retrieve county index for {state_abbr}. Last error: {last_err}")

def harvest_qrz_from_county_urls(county_urls: list[str], log) -> list[str]:
    """
    Given one or more county result URLs from /db, walk and collect calls (with pagination).
    """
    all_calls, seen = [], set()
    for url in county_urls:
        log(f"[info] Harvesting county URL: {url}")
        try:
            r = http_get(url)
            html, page_url = r.text, r.url
        except Exception as e:
            log(f"[error] county URL fetch failed: {e}")
            continue

        page = 1
        while True:
            found, next_url = extract_calls_and_next(html, page_url)
            new = 0
            for cs in found:
                if cs not in seen:
                    seen.add(cs); all_calls.append(cs); new += 1
            log(f"[info]  page {page}: +{new} (total {len(all_calls)})")
            if not next_url: break
            try:
                r = http_get(next_url)
                html, page_url = r.text, r.url
                page += 1
                time.sleep(0.5)
            except Exception as e:
                log(f"[error] next page fetch failed: {e}")
                break
    log(f"[info] Harvest complete: {len(all_calls)} unique calls")
    return all_calls

# ---- Geocoding ----
def geocode_addr(address: str, mode: str, google_key: str, email_contact: str):
    if not address: return None
    try:
        if mode == "google" and google_key:
            url = "https://maps.googleapis.com/maps/api/geocode/json"
            r = HTTP.get(url, params={"address":address, "key":google_key}, timeout=30)
            r.raise_for_status()
            j = r.json()
            if j.get("status") == "OK":
                loc = j["results"][0]["geometry"]["location"]
                return float(loc["lat"]), float(loc["lng"])
            return None
        else:
            geon = GeoNominatim(user_agent=f"{APP_UA} ({email_contact})")
            lo = geon.geocode(address, timeout=30)
            if lo:
                time.sleep(1.0)
                return float(lo.latitude), float(lo.longitude)
            return None
    except Exception:
        return None

# ---- Worker ----
class Worker(threading.Thread):
    def __init__(self, mode, session_key, items, state_abbr, counties,
                 geocode_mode, google_key, email_contact, out_q, verbose=False,
                 county_url_map=None):
        super().__init__(daemon=True)
        self.mode = mode            # "calls" or "county"
        self.session_key = session_key
        self.items = items          # list[calls] for "calls"; unused for "county"
        self.state_abbr = state_abbr
        self.counties = counties or []
        self.geocode_mode = geocode_mode
        self.google_key = google_key
        self.email = email_contact or "you@example.com"
        self.q = out_q
        self.verbose = verbose
        self.stop_event = threading.Event()
        self.county_url_map = county_url_map or {}

    def stop(self): self.stop_event.set()

    def run(self):
        start = now_ts()
        recs = []

        # Build calls
        if self.mode == "county":
            urls = []
            for c in self.counties:
                u = self.county_url_map.get(c)
                if u: urls.append(u)
                else: self.q.put(("log", f"[info] Skipping (no URL): {c}"))
            calls = harvest_qrz_from_county_urls(urls, log=lambda m: self.q.put(("log", m)))
        else:
            calls = self.items

        total = len(calls)
        if total == 0:
            self.q.put(("finished", recs)); return

        processed = 0
        for cs in calls:
            if self.stop_event.is_set(): break
            try:
                info = qrz_lookup_call(self.session_key, cs)
                loc = geocode_addr(info.get("address",""), self.geocode_mode, self.google_key, self.email)
                if loc: info["lat"], info["lon"] = loc
                else:   info["lat"] = info["lon"] = ""
                recs.append({
                    "callsign": info.get("callsign",""),
                    "name":     info.get("name",""),
                    "street":   info.get("street",""),
                    "addr1":    info.get("addr1",""),
                    "addr2":    info.get("addr2",""),
                    "city":     info.get("city",""),
                    "state":    info.get("state",""),
                    "county":   info.get("county",""),
                    "zip":      info.get("zip",""),
                    "grid":     info.get("grid",""),
                    "email":    info.get("email",""),
                    "address":  info.get("address",""),
                    "lat":      info.get("lat",""),
                    "lon":      info.get("lon",""),
                })
            except Exception as e:
                self.q.put(("log", f"[error] {cs}: {e}"))

            processed += 1
            elapsed = now_ts() - start
            avg = elapsed/processed if processed else 0.001
            eta = (total-processed)*avg
            self.q.put(("progress", {"processed": processed, "total": total, "elapsed": elapsed, "eta": eta, "last": cs}))

        self.q.put(("finished", recs))

# ---- GUI ----
class App:
    def __init__(self, root):
        self.root = root
        root.title("Ham Harvester — QRZ /db county + XML enrich")
        root.rowconfigure(2, weight=1)
        root.columnconfigure(0, weight=1)

        self.session_key = None
        self.worker = None
        self.records = []
        self.queue = queue.Queue()

        # cache: state -> {county_name: url}
        self.state_county_cache = {}
        self.county_url_map = {}

        main = ttk.Frame(root, padding=10); main.grid(row=0, column=0, sticky="nsew")
        main.columnconfigure(1, weight=1)

        # Login
        ttk.Label(main, text="QRZ XML API session key:").grid(row=0, column=0, sticky="w")
        self.key_var = tk.StringVar()
        ttk.Entry(main, textvariable=self.key_var, width=50).grid(row=0, column=1, sticky="we", padx=4)
        ttk.Button(main, text="Use Key", command=self.use_key).grid(row=0, column=2, padx=2)

        ttk.Label(main, text="— or —").grid(row=1, column=0, sticky="w")
        ttk.Label(main, text="QRZ Username:").grid(row=2, column=0, sticky="w")
        self.user_var = tk.StringVar(); ttk.Entry(main, textvariable=self.user_var, width=24).grid(row=2, column=1, sticky="w")
        ttk.Label(main, text="Password:").grid(row=3, column=0, sticky="w")
        self.pass_var = tk.StringVar(); ttk.Entry(main, textvariable=self.pass_var, show="*").grid(row=3, column=1, sticky="w")
        ttk.Button(main, text="Login", command=self.login_action).grid(row=2, column=2, rowspan=2, padx=2)

        ttk.Separator(main).grid(row=4, column=0, columnspan=3, sticky="ew", pady=8)

        # Modes
        self.mode = tk.StringVar(value="county")
        ttk.Radiobutton(main, text="A) Callsigns / CSV", variable=self.mode, value="calls", command=self.update_mode).grid(row=5, column=0, sticky="w")
        ttk.Radiobutton(main, text="B) State / Counties (QRZ /db county index)", variable=self.mode, value="county", command=self.update_mode).grid(row=5, column=1, sticky="w")

        # Calls input
        callsf = ttk.LabelFrame(main, text="Callsigns Input")
        callsf.grid(row=6, column=0, columnspan=3, sticky="we")
        callsf.columnconfigure(1, weight=1)
        ttk.Label(callsf, text="CSV (first col or header 'callsign')").grid(row=0, column=0, sticky="w")
        self.csv_path = tk.StringVar()
        ttk.Entry(callsf, textvariable=self.csv_path).grid(row=0, column=1, sticky="we", padx=4)
        ttk.Button(callsf, text="Browse", command=self.browse_csv).grid(row=0, column=2)
        ttk.Label(callsf, text="Paste calls (comma/newlines):").grid(row=1, column=0, sticky="nw")
        self.calls_text = scrolledtext.ScrolledText(callsf, height=4); self.calls_text.grid(row=1, column=1, columnspan=2, sticky="we")

        # County input
        countyf = ttk.LabelFrame(main, text="County Harvester (QRZ /db)")
        countyf.grid(row=7, column=0, columnspan=3, sticky="we")
        countyf.columnconfigure(1, weight=1)
        ttk.Label(countyf, text="State:").grid(row=0, column=0, sticky="w")
        self.state_var = tk.StringVar(value="NY")
        self.state_combo = ttk.Combobox(countyf, textvariable=self.state_var, state="readonly",
                                        values=[f"{k} — {v}" for k,v in US_STATES.items()])
        self.state_combo.grid(row=0, column=1, sticky="we", padx=4)
        self.state_combo.bind("<<ComboboxSelected>>", lambda e: self.load_counties())

        self.all_counties_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(countyf, text="All counties in state", variable=self.all_counties_var,
                        command=self.toggle_all_counties).grid(row=1, column=0, sticky="w", pady=(4,2))
        ttk.Label(countyf, text="Counties (multi-select):").grid(row=2, column=0, sticky="nw")
        self.county_list = tk.Listbox(countyf, selectmode="extended", height=10, exportselection=False)
        self.county_list.grid(row=2, column=1, sticky="we", padx=4)
        ttk.Button(countyf, text="Load/Refresh from QRZ", command=self.load_counties).grid(row=2, column=2, sticky="w")

        # Geocoding + controls
        geof = ttk.LabelFrame(main, text="Geocoding")
        geof.grid(row=8, column=0, columnspan=3, sticky="we", pady=4)
        self.gc_mode = tk.StringVar(value="nominatim")
        ttk.Radiobutton(geof, text="OpenStreetMap (no key)", variable=self.gc_mode, value="nominatim").grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(geof, text="Google (API key)", variable=self.gc_mode, value="google").grid(row=0, column=1, sticky="w")
        ttk.Label(geof, text="Google API key:").grid(row=0, column=2, sticky="e")
        self.google_var = tk.StringVar(); ttk.Entry(geof, textvariable=self.google_var, width=40).grid(row=0, column=3, sticky="we", padx=4)
        ttk.Label(geof, text="Nominatim contact email:").grid(row=1, column=2, sticky="e")
        self.email_var = tk.StringVar(value="you@example.com"); ttk.Entry(geof, textvariable=self.email_var, width=40).grid(row=1, column=3, sticky="we", padx=4)

        ctl = ttk.Frame(main); ctl.grid(row=9, column=0, columnspan=3, sticky="we", pady=6)
        self.verbose = tk.BooleanVar(value=True)
        ttk.Checkbutton(ctl, text="Verbose", variable=self.verbose).grid(row=0, column=0, sticky="w")
        ttk.Button(ctl, text="Run", command=self.run_action).grid(row=0, column=1, padx=4)
        ttk.Button(ctl, text="Stop", command=self.stop).grid(row=0, column=2, padx=2)
        ttk.Button(ctl, text="Export CSV", command=self.export_csv).grid(row=0, column=3, padx=2)
        ttk.Button(ctl, text="Export KML", command=self.export_kml).grid(row=0, column=4, padx=2)
        ttk.Button(ctl, text="Export HTML Map", command=self.export_html).grid(row=0, column=5, padx=2)

        self.progress = ttk.Progressbar(main, orient="horizontal", length=420, mode="determinate")
        self.progress.grid(row=10, column=0, columnspan=2, sticky="w")
        self.status_var = tk.StringVar(value="Idle")
        ttk.Label(main, textvariable=self.status_var).grid(row=10, column=2, sticky="w")

        # Log
        ttk.Label(root, text="Log / Output:").grid(row=1, column=0, sticky="w")
        self.log_text = scrolledtext.ScrolledText(root, height=16, width=120)
        self.log_text.grid(row=2, column=0, sticky="nsew")

        # init
        self.update_mode()
        self.load_counties()
        self.root.after(200, self.poll_queue)

    # ----- login -----
    def use_key(self):
        k = (self.key_var.get() or "").strip()
        if not k:
            messagebox.showinfo("QRZ", "Paste your QRZ XML session key.")
            return
        self.session_key = k
        mk = k[:4]+"..."+k[-4:] if len(k)>=8 else "****"
        self.log(f"[info] Using QRZ session key ({mk})")

    def login_action(self):
        u = (self.user_var.get() or "").strip()
        p = self.pass_var.get() or ""
        if not (u and p):
            messagebox.showinfo("QRZ", "Enter username and password or paste an API key.")
            return
        self.log(f"[info] Logging in to QRZ as {u} ...")
        def do_login():
            try:
                sk = qrz_login(u, p, verbose=self.verbose.get())
                self.session_key = sk
                self.log("[info] QRZ session key obtained.")
            except Exception as e:
                self.log(f"[error] QRZ login failed: {e}")
        threading.Thread(target=do_login, daemon=True).start()

    # ----- mode wiring -----
    def update_mode(self):
        m = self.mode.get()
        def set_state(widget, enable):
            try:
                widget.configure(state=("normal" if enable else "disabled"))
            except Exception:
                pass
        # calls widgets
        set_state(self.calls_text, m=="calls")
        for w in self.calls_text.master.grid_slaves(row=0):
            try: w.configure(state=("normal" if m=="calls" else "disabled"))
            except: pass
        # county widgets
        set_state(self.state_combo, m=="county")
        set_state(self.county_list, m=="county")

    # ----- county loading from QRZ /db -----
    def toggle_all_counties(self):
        if self.all_counties_var.get():
            self.county_list.selection_set(0, "end")
        else:
            self.county_list.selection_clear(0, "end")

    def load_counties(self):
        abbr = (self.state_var.get() or "NY").split("—")[0].strip()
        self.log(f"[info] Loading counties for {abbr} from QRZ /db ...")
        # use cache if available
        if abbr in self.state_county_cache:
            self.county_url_map = self.state_county_cache[abbr].copy()
            self._populate_county_list(self.county_url_map)
            return
        try:
            county_map = qrz_county_index_for_state(abbr, log=self.log)
            if not county_map:
                raise RuntimeError("No counties returned.")
            self.state_county_cache[abbr] = county_map.copy()
            self.county_url_map = county_map
            self._populate_county_list(county_map)
        except Exception as e:
            self.log(f"[error] Could not load counties for {abbr}: {e}")
            # leave previous list intact

    def _populate_county_list(self, cmap: dict):
        self.county_list.delete(0, "end")
        for name in sorted(cmap.keys(), key=lambda s: s.lower()):
            self.county_list.insert("end", name)
        self.log(f"[info] Counties loaded: {self.county_list.size()}")

    # ----- file browse -----
    def browse_csv(self):
        p = filedialog.askopenfilename(filetypes=[("CSV","*.csv"),("All files","*.*")])
        if p: self.csv_path.set(p)

    # ----- gather inputs -----
    def gather_calls_from_inputs(self):
        out = []
        # CSV first
        p = (self.csv_path.get() or "").strip()
        if p and os.path.exists(p):
            try:
                with open(p, newline="", encoding="utf-8") as fh:
                    rdr = csv.reader(fh)
                    header = next(rdr, None)
                    idx = 0
                    if header and any(h.lower()=="callsign" for h in header):
                        idx = [i for i,h in enumerate(header) if h.lower()=="callsign"][0]
                    else:
                        if header and header[0].strip():
                            out.append(header[0].strip())
                    for row in rdr:
                        if row and len(row)>idx and row[idx].strip():
                            out.append(row[idx].strip())
            except Exception as e:
                self.log(f"[error] CSV read: {e}")
        # Pasted
        txt = (self.calls_text.get("1.0","end") or "").strip()
        if txt:
            for token in txt.replace(",","\n").splitlines():
                t = token.strip()
                if t: out.append(t)
        # Clean
        seen = set(); clean = []
        for c in out:
            cu = c.upper()
            if is_callsign(cu) and cu not in seen:
                seen.add(cu); clean.append(cu)
            elif not is_callsign(cu):
                self.log(f"[info] Skipping invalid token: {c}")
        return clean

    def gather_selected_counties(self):
        if self.all_counties_var.get():
            return [self.county_list.get(i) for i in range(self.county_list.size())]
        sel = [self.county_list.get(i) for i in self.county_list.curselection()]
        return sel

    # ----- run/stop -----
    def run_action(self):
        if not self.session_key:
            messagebox.showinfo("QRZ", "Login or paste a QRZ XML session key first.")
            return
        if self.worker and self.worker.is_alive():
            messagebox.showinfo("Running", "Already in progress.")
            return

        mode = self.mode.get()
        if mode == "calls":
            calls = self.gather_calls_from_inputs()
            if not calls:
                messagebox.showinfo("No input", "Provide calls via CSV or paste.")
                return
            items = calls
            self.progress["maximum"] = len(items)
            self.log(f"[info] Mode A: {len(items)} calls")
            state_abbr = ""
            counties = []
        else:
            abbr = (self.state_var.get() or "NY").split("—")[0].strip()
            counties = self.gather_selected_counties()
            if not counties:
                messagebox.showinfo("No counties", "Select at least one county or check All counties.")
                return
            # ensure county_url_map is ready
            if abbr not in self.state_county_cache:
                self.load_counties()
                if abbr not in self.state_county_cache:
                    messagebox.showerror("QRZ", "Could not load county list from QRZ.")
                    return
            self.county_url_map = self.state_county_cache[abbr].copy()
            items = []  # not used in county mode
            self.progress["maximum"] = 1
            self.log(f"[info] Mode B: {abbr} / {len(counties)} county(ies)")
            state_abbr = abbr

        self.records = []
        self.progress["value"] = 0
        self.status_var.set("Starting...")

        self.worker = Worker(
            mode=mode,
            session_key=self.session_key,
            items=items,
            state_abbr=state_abbr,
            counties=counties,
            geocode_mode=self.gc_mode.get(),
            google_key=(self.google_var.get() or "").strip(),
            email_contact=(self.email_var.get() or "you@example.com").strip(),
            out_q=self.queue,
            verbose=self.verbose.get(),
            county_url_map=self.county_url_map
        )
        self.worker.start()

    def stop(self):
        if self.worker and self.worker.is_alive():
            self.worker.stop()
            self.status_var.set("Stopping…")
            self.log("[info] Stop requested")

    def poll_queue(self):
        try:
            while True:
                typ, payload = self.queue.get_nowait()
                if typ == "log":
                    self.log(payload)
                elif typ == "progress":
                    d = payload
                    self.progress["maximum"] = max(self.progress["maximum"], d["total"])
                    self.progress["value"] = d["processed"]
                    self.status_var.set(f"{d['processed']}/{d['total']}  Elapsed: {nice_elapsed(d['elapsed'])}  ETA: {nice_elapsed(d['eta'])}")
                elif typ == "finished":
                    self.records = payload
                    self.progress["value"] = self.progress["maximum"]
                    self.status_var.set("Finished")
                    self.log(f"[info] Finished: {len(self.records)} records")
        except queue.Empty:
            pass
        self.root.after(200, self.poll_queue)

    # ----- logging -----
    def log(self, line):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_text.insert("end", f"[{ts}] {line}\n")
        self.log_text.see("end")

    # ----- exports -----
    def export_csv(self):
        if not self.records:
            messagebox.showinfo("No data","No results to export."); return
        p = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")])
        if not p: return
        preferred = ["callsign","name","street","addr1","addr2","city","state","county","zip","grid","email","address","lat","lon"]
        present = set().union(*(r.keys() for r in self.records))
        fieldnames = [k for k in preferred if k in present] + [k for k in sorted(present) if k not in preferred]
        try:
            with open(p,"w",newline="",encoding="utf-8") as fh:
                w = csv.DictWriter(fh, fieldnames=fieldnames)
                w.writeheader()
                for r in self.records: w.writerow(r)
            self.log(f"[info] CSV exported: {p}")
        except Exception as e:
            self.log(f"[error] CSV export: {e}")

    def export_kml(self):
        if not self.records:
            messagebox.showinfo("No data","No results to export."); return
        p = filedialog.asksaveasfilename(defaultextension=".kml", filetypes=[("KML","*.kml")])
        if not p: return
        k = simplekml.Kml()
        for r in self.records:
            try:
                lat = float(r.get("lat")); lon=float(r.get("lon"))
            except Exception:
                continue
            k.newpoint(name=r.get("callsign",""), coords=[(lon,lat)], description=r.get("address",""))
        try:
            k.save(p); self.log(f"[info] KML saved: {p}")
        except Exception as e:
            self.log(f"[error] KML save: {e}")

    def export_html(self):
        if not self.records:
            messagebox.showinfo("No data","No results to export."); return
        p = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML","*.html")])
        if not p: return

        pts = []
        for r in self.records:
            try:
                lat = float(r.get("lat")); lon=float(r.get("lon"))
            except Exception:
                continue
            pts.append({"callsign":r.get("callsign",""),"lat":lat,"lon":lon,"address":r.get("address","")})
        if not pts:
            messagebox.showinfo("No geocoded points","No latitude/longitude data available."); return

        lats=[pt["lat"] for pt in pts]; lons=[pt["lon"] for pt in pts]
        min_lat,max_lat=min(lats),max(lats); min_lon,max_lon=min(lons),max(lons)
        clat=(min_lat+max_lat)/2.0; clon=(min_lon+max_lon)/2.0

        gm_key=(self.google_var.get() or "").strip()
        if gm_key:
            markers=[]
            for pt in pts:
                markers.append(
                    f"new google.maps.Marker({{position: {{lat: {pt['lat']}, lng: {pt['lon']}}}, map: map, title: {json.dumps(pt['callsign'])}}});"
                )
            html=f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Map</title>
<style>html,body,#map{{height:100%;margin:0;padding:0}}</style></head>
<body><div id="map"></div>
<script src="https://maps.googleapis.com/maps/api/js?key={gm_key}"></script>
<script>
function initMap(){{
  var map=new google.maps.Map(document.getElementById('map'),{{zoom:8,center:{{lat:{clat},lng:{clon}}}}});
  var bounds=new google.maps.LatLngBounds(new google.maps.LatLng({min_lat},{min_lon}),new google.maps.LatLng({max_lat},{max_lon}));
  {''.join(markers)}
  map.fitBounds(bounds);
}}
window.onload=initMap;
</script>
</body></html>"""
        else:
            mk=[]
            for pt in pts:
                popup=json.dumps(f"{pt['callsign']}\n{pt['address']}").replace("\\n","<br/>")
                mk.append(f"L.marker([{pt['lat']},{pt['lon']}]).addTo(map).bindPopup({popup});")
            html=f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Map</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet/dist/leaflet.css"/>
<style>html,body,#map{{height:100%;margin:0;padding:0}}</style></head>
<body><div id="map"></div>
<script src="https://unpkg.com/leaflet/dist/leaflet.js"></script>
<script>
var map=L.map('map');
var bounds=L.latLngBounds([[{min_lat},{min_lon}],[{max_lat},{max_lon}]]);
map.fitBounds(bounds);
L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png',{{maxZoom:19,attribution:'© OpenStreetMap contributors'}}).addTo(map);
{''.join(mk)}
</script></body></html>"""

        try:
            with open(p,"w",encoding="utf-8") as fh: fh.write(html)
            self.log(f"[info] HTML map saved: {p}")
        except Exception as e:
            self.log(f"[error] HTML save: {e}")

def main():
    root = tk.Tk()
    root.rowconfigure(2, weight=1)
    root.columnconfigure(0, weight=1)
    app = App(root)
    root.mainloop()

if __name__ == "__main__":
    main()
