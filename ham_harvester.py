#!/usr/bin/env python3
"""
Ham Harvester / QRZ Mapper — Guided Flow

Flow:
1) Modal login (QRZ XML API key or username/password).
2) Choose ONE mode:
   - Mode A: Pasted/CSV callsigns → enrich via QRZ → geocode → reverse-geocode county → grid
   - Mode B: Harvest by selected counties in a state (FCC → QRZ → geocode → grid) 
   - Mode C: Harvest entire state (all counties)
3) Export CSV (callsign, name, address, city, state, county, zip, grid, email, lat, lon)
4) Export KML / HTML map
5) Verbose logging + progress + stop

Notes:
- Email may be absent on QRZ depending on privacy settings.
- Be polite to remote services; "Polite mode" slows requests & reduces errors.
"""

import sys
import subprocess
import importlib
import time
import csv
import json
import re
import threading
import queue
from datetime import datetime

# ---- tkinter first (OS-provided) ----
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext
except Exception:
    print("[ERROR] tkinter is not available.\n"
          "On Debian/Ubuntu: sudo apt-get install python3-tk\n"
          "On Fedora: sudo dnf install python3-tkinter\n"
          "On Windows/macOS: install standard Python from python.org (tkinter included).")
    sys.exit(1)

# ---- ensure deps (pip) ----
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
            if verbose:
                print(f"[INSTALLED] {m}")
        except Exception as e:
            print(f"[ERROR] Could not install {m}: {e}")
            print("Install the missing package(s) and rerun.")
            sys.exit(1)

ensure_deps(verbose=True)

# ---- imports safe now ----
import requests
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
from geopy.geocoders import Nominatim as GeoNominatim  # optional; using direct API too
import simplekml

# ---------- Globals ----------
APP_AGENT = "HamHarvester/3.0"
HTTP = requests.Session()
HTTP.headers.update({"User-Agent": APP_AGENT})

QRZ_XML_BASE = "https://xmldata.qrz.com/xml/current/"
USER_AGENT = APP_AGENT

# FCC constants
FCC_BASE = "https://wireless2.fcc.gov/UlsApp/UlsSearch/searchGeographic.jsp"

# Census datasets to try (any of these should return NAME for county geography)
CENSUS_DATASETS = [
    ("PEP 2023",   "https://api.census.gov/data/2023/pep/population?get=NAME&for=county:*&in=state:{state_fips}"),
    ("ACS 2022",   "https://api.census.gov/data/2022/acs/acs5?get=NAME&for=county:*&in=state:{state_fips}"),
    ("DEC 2020",   "https://api.census.gov/data/2020/dec/pl?get=NAME&for=county:*&in=state:{state_fips}"),
]

# Embedded USPS → FIPS (50 states + DC + PR)
STATE_ABBR_TO_FIPS = {
    "AL":"01","AK":"02","AZ":"04","AR":"05","CA":"06","CO":"08","CT":"09","DE":"10","DC":"11",
    "FL":"12","GA":"13","HI":"15","ID":"16","IL":"17","IN":"18","IA":"19","KS":"20","KY":"21",
    "LA":"22","ME":"23","MD":"24","MA":"25","MI":"26","MN":"27","MS":"28","MO":"29",
    "MT":"30","NE":"31","NV":"32","NH":"33","NJ":"34","NM":"35","NY":"36","NC":"37","ND":"38",
    "OH":"39","OK":"40","OR":"41","PA":"42","RI":"44","SC":"45","SD":"46","TN":"47","TX":"48",
    "UT":"49","VT":"50","VA":"51","WA":"53","WV":"54","WI":"55","WY":"56",
    "PR":"72"
}

CALL_RE = re.compile(r"^[A-Z0-9/]{3,}$")

# ---------- Utils ----------
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

# Maidenhead (6-char) from lat/lon
def maidenhead_from_latlon(lat, lon, precision=3):
    if lat is None or lon is None:
        return ""
    lon += 180.0
    lat += 90.0
    A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    a = "abcdefghijklmnopqrstuvwxyz"
    F_lon = int(lon // 20)
    F_lat = int(lat // 10)
    S_lon = int((lon % 20) // 2)
    S_lat = int((lat % 10) // 1)
    ss_lon = int(((lon % 2) / 2) * 24)
    ss_lat = int(((lat % 1) / 1) * 24)
    grid = f"{A[F_lon]}{A[F_lat]}{S_lon}{S_lat}{a[ss_lon]}{a[ss_lat]}"
    return grid[:precision * 2]

# --- Geocoding (forward + reverse) ---
def geocode_nominatim(address, email="you@example.com", pause=1.0, verbose=False):
    url = "https://nominatim.openstreetmap.org/search"
    headers = {"User-Agent": f"{USER_AGENT} ({email})"}
    params = {"q": address, "format": "json", "limit": 1, "email": email}
    for attempt in range(3):
        if verbose:
            print(f"[geocode_nominatim] {address} (try {attempt + 1})")
        resp = HTTP.get(url, params=params, headers=headers, timeout=20)
        if resp.status_code == 200:
            arr = resp.json()
            if arr:
                lat = float(arr[0]["lat"])
                lon = float(arr[0]["lon"])
                time.sleep(pause)
                return lat, lon
            time.sleep(pause)
            return None
        if resp.status_code in (429, 503):
            time.sleep(pause * (2 ** attempt))
            continue
        raise RuntimeError(f"Nominatim HTTP {resp.status_code}")
    return None

def reverse_geocode_nominatim(lat, lon, email="you@example.com", pause=1.0, verbose=False):
    url = "https://nominatim.openstreetmap.org/reverse"
    headers = {"User-Agent": f"{USER_AGENT} ({email})"}
    params = {"lat": lat, "lon": lon, "format": "json", "zoom": 10, "email": email, "addressdetails": 1}
    for attempt in range(3):
        if verbose:
            print(f"[reverse_geocode_nominatim] {lat},{lon} (try {attempt + 1})")
        resp = HTTP.get(url, params=params, headers=headers, timeout=20)
        if resp.status_code == 200:
            j = resp.json()
            addr = j.get("address", {})
            # Nominatim county can be under 'county' or similar keys
            county = addr.get("county") or addr.get("state_district") or addr.get("region")
            time.sleep(pause)
            return county or ""
        if resp.status_code in (429, 503):
            time.sleep(pause * (2 ** attempt))
            continue
        raise RuntimeError(f"Nominatim reverse HTTP {resp.status_code}")
    return ""

def geocode_google(address, api_key, verbose=False):
    url = "https://maps.googleapis.com/maps/api/geocode/json"
    params = {"address": address, "key": api_key}
    if verbose:
        print(f"[geocode_google] {address}")
    resp = HTTP.get(url, params=params, timeout=20)
    if resp.status_code != 200:
        raise RuntimeError(f"Google geocode HTTP {resp.status_code}")
    j = resp.json()
    status = j.get("status", "UNKNOWN")
    if status != "OK":
        return None, status
    loc = j["results"][0]["geometry"]["location"]
    return (loc["lat"], loc["lng"]), "OK"

# ---------- QRZ helpers ----------
def find_first(elem, *tag_names):
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

def qrz_login(username, password, verbose=False):
    if verbose:
        print("[qrz_login] attempting login")
    def parse_session_key(xml_text):
        root = ET.fromstring(xml_text)
        session = find_first(root, "Session")
        key = find_text(session, "Key") if session is not None else ""
        if not key and session is not None and session.text:
            key = session.text.strip()
        return key
    # Try POST
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
            print("[qrz_login] xml-post method failed:", e)
    # Fallback GET
    try:
        params = {"username": username, "password": password}
        resp2 = HTTP.get(QRZ_XML_BASE, params=params, headers={"User-Agent": USER_AGENT}, timeout=20)
        if resp2.status_code != 200:
            raise RuntimeError(f"QRZ login HTTP {resp2.status_code}")
        key = parse_session_key(resp2.text)
        if key:
            return key
    except Exception as e:
        if verbose:
            print("[qrz_login] fallback method failed:", e)
    raise RuntimeError("QRZ login failed. Ensure XML subscription and correct credentials.")

def qrz_lookup_call(session_key, callsign, verbose=False):
    params = {"s": session_key, "callsign": callsign}
    resp = HTTP.get(QRZ_XML_BASE, params=params, headers={"User-Agent": USER_AGENT}, timeout=20)
    if resp.status_code != 200:
        raise RuntimeError(f"QRZ lookup HTTP {resp.status_code}")
    root = ET.fromstring(resp.text)
    call = find_first(root, "call", "Callsign")
    if call is None:
        return None

    def get(tag):
        return find_text(call, tag)

    data = {
        "callsign": get("call") or callsign,
        "fname": get("fname") or get("name"),
        "attn": get("attn"),
        "addr1": get("addr1"),
        "addr2": get("addr2"),
        "city": get("city"),
        "state": get("state"),
        "zipcode": get("zipcode") or get("postcode"),
        "country": get("country"),
        "email": get("email"),
        "grid": get("grid"),
    }
    parts = [data.get("addr1"), data.get("addr2"), data.get("city"), data.get("state"),
             data.get("zipcode"), data.get("country")]
    data["address"] = ", ".join([p for p in parts if p])
    if verbose:
        print(f"[qrz_lookup_call] {callsign} -> {data['address']}")
    return data

# ---------- County loader (Census + FCC fallback) ----------
def fetch_counties_from_census(state_abbr, log=None):
    st = (state_abbr or "").strip().upper()
    fips = STATE_ABBR_TO_FIPS.get(st)
    if not fips:
        if log: log(f"State '{st}' not in FIPS map.", "error")
        return []

    for label, template in CENSUS_DATASETS:
        url = template.format(state_fips=fips)
        try:
            r = HTTP.get(url, timeout=20)
            if r.status_code != 200:
                if log: log(f"Census {label} HTTP {r.status_code}", "error")
                continue
            data = r.json()
            out = []
            for row in data[1:]:
                name = row[0]  # "Albany County, New York"
                if "," in name:
                    name = name.split(",", 1)[0].strip()
                out.append(name)
            out = sorted(set(out))
            if out:
                if log: log(f"Census source OK: {label} ({len(out)} counties)", "info")
                return out
        except Exception as e:
            if log: log(f"Census {label} error: {e}", "error")

    return []

def fetch_counties_from_fcc(state_abbr, log=None):
    st = (state_abbr or "").strip().upper()
    try:
        params = {"state": st}
        r = HTTP.get(FCC_BASE, params=params, timeout=30)
        if r.status_code != 200:
            if log: log(f"FCC county list HTTP {r.status_code}", "error")
            return []
        soup = BeautifulSoup(r.text, "html.parser")
        cand = soup.find("select", attrs={"name": re.compile("county", re.I)})
        if not cand:
            selects = soup.find_all("select")
            for s in selects:
                opts = s.find_all("option")
                if sum(1 for o in opts if "county" in (o.text or "").lower()) > 5:
                    cand = s
                    break
        if not cand:
            if log: log("FCC county select not found.", "error")
            return []
        names = []
        for opt in cand.find_all("option"):
            txt = (opt.text or "").strip()
            if not txt or txt.lower().startswith(("select", "all ")):
                continue
            names.append(txt)
        out = sorted(set(names))
        if out and log:
            log(f"FCC fallback OK ({len(out)} counties)", "info")
        return out
    except Exception as e:
        if log: log(f"FCC fallback error: {e}", "error")
        return []

def fetch_counties_for_state(state_abbr, log=None):
    out = fetch_counties_from_census(state_abbr, log=log)
    if out:
        return out
    return fetch_counties_from_fcc(state_abbr, log=log)

# ---------- FCC ULS harvesting (scraper, paginated) ----------
def fcc_search_active_callsigns(state_abbr, county_name, polite_sleep=1.5, verbose=False, stopper=None):
    """
    Scrapes FCC ULS Geographic Search results for Amateur (HA/HV) Active licenses.
    Returns a set of callsigns.
    """
    calls = set()
    try:
        HTTP.get(FCC_BASE, timeout=30)
        payload = {
            "state": state_abbr,
            "county": county_name,
            "servRadioServiceCode": "HA,HV",
            "licStatus": "Active",
            "ulsSearchType": "geographic",
            "pageNumToReturn": "1",
        }
        resp = HTTP.post(FCC_BASE, data=payload, timeout=30)
        if resp.status_code != 200:
            raise RuntimeError(f"FCC search HTTP {resp.status_code}")

        while True:
            if stopper and stopper.is_set():
                break
            soup = BeautifulSoup(resp.text, "html.parser")
            for a in soup.find_all("a"):
                txt = (a.get_text() or "").strip().upper()
                if CALL_RE.match(txt):
                    calls.add(txt)
            nxt = soup.find("a", string=re.compile(r"Next", re.I))
            if not nxt or not nxt.get("href"):
                break
            next_url = nxt.get("href")
            if not next_url.startswith("http"):
                next_url = requests.compat.urljoin(FCC_BASE, next_url)
            time.sleep(polite_sleep)
            resp = HTTP.get(next_url, timeout=30)
            if resp.status_code != 200:
                break
        return calls
    except Exception as e:
        if verbose:
            print(f"[fcc_search] error for {state_abbr}/{county_name}: {e}")
        return calls

# ---------- Workers ----------
class StoppableThread(threading.Thread):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._stop = threading.Event()
        self.daemon = True
    def stop(self): self._stop.set()
    def stopped(self): return self._stop.is_set()

class CountyHarvestWorker(StoppableThread):
    def __init__(self, state_abbr, counties, session_key, geocode_mode, google_key,
                 nominatim_email, out_q, polite=True, verbose=False):
        super().__init__()
        self.state_abbr = state_abbr
        self.counties = counties
        self.session_key = session_key
        self.geocode_mode = geocode_mode
        self.google_key = google_key
        self.nominatim_email = nominatim_email or "you@example.com"
        self.out_q = out_q
        self.polite = polite
        self.verbose = verbose

    def run(self):
        start = now_ts()
        all_records = []
        total_tasks = len(self.counties)
        done = 0

        for county in self.counties:
            if self.stopped(): break
            if self.polite:
                time.sleep(0.8)
            self.out_q.put(("log", f"FCC: searching {county}, {self.state_abbr} ..."))

            calls = fcc_search_active_callsigns(
                self.state_abbr, county,
                polite_sleep=1.0 if self.polite else 0.2,
                verbose=self.verbose,
                stopper=self._stop
            )

            if not calls:
                self.out_q.put(("log", f"No calls returned for {county}. If persistent, try removing 'County' suffix or verify on FCC.",))
            # Enrich each call
            for idx, cs in enumerate(sorted(calls), 1):
                if self.stopped(): break
                rec = {"callsign": cs, "county": county, "state": self.state_abbr}
                try:
                    if self.session_key:
                        q = qrz_lookup_call(self.session_key, cs, verbose=self.verbose) or {}
                        rec.update(q)
                    # ensure county is set (prefer known FCC county if reverse says otherwise)
                    # Geocode & grid if possible
                    addr = rec.get("address") or ", ".join(
                        [rec.get("addr1", ""), rec.get("city", ""), rec.get("state", ""),
                         rec.get("zipcode", ""), rec.get("country", "")]
                    )
                    addr = ", ".join([p for p in [a.strip() for a in addr.split(",")] if p])
                    lat = lon = None
                    if addr:
                        try:
                            if self.geocode_mode == "google" and self.google_key:
                                loc, status = geocode_google(addr, self.google_key, verbose=self.verbose)
                                if loc: lat, lon = loc
                            else:
                                loc = geocode_nominatim(addr, email=self.nominatim_email,
                                                        pause=0.8 if self.polite else 0.2,
                                                        verbose=self.verbose)
                                if loc: lat, lon = loc
                        except Exception as ge:
                            self.out_q.put(("log", f"Geocode error for {cs}: {ge}",))
                    if lat is not None and lon is not None:
                        rec["lat"] = lat
                        rec["lon"] = lon
                        rec["grid"] = maidenhead_from_latlon(lat, lon, precision=3)
                        # reverse county if empty
                        if not rec.get("county"):
                            try:
                                cty = reverse_geocode_nominatim(lat, lon, email=self.nominatim_email,
                                                                pause=0.5 if self.polite else 0.2,
                                                                verbose=self.verbose)
                                if cty: rec["county"] = cty
                            except Exception:
                                pass
                    else:
                        rec.setdefault("lat", "")
                        rec.setdefault("lon", "")
                        rec.setdefault("grid", "")

                except Exception as e:
                    self.out_q.put(("log", f"Error processing {cs}: {e}",))
                all_records.append(rec)

                # progress within county harvest
                elapsed = now_ts() - start
                self.out_q.put(("progress", {
                    "processed": idx, "total": max(len(calls), 1),
                    "elapsed": elapsed, "eta": 0, "last": cs
                }))
                if self.polite:
                    time.sleep(0.1)

            done += 1
            elapsed = now_ts() - start
            self.out_q.put(("progress", {
                "processed": done, "total": total_tasks,
                "elapsed": elapsed, "eta": 0, "last": f"{county}"
            }))

        self.out_q.put(("finished", all_records))

class CallListWorker(StoppableThread):
    def __init__(self, calls, session_key, geocode_mode, google_key, email_contact, out_q, polite=True, verbose=False):
        super().__init__()
        self.calls = calls
        self.session_key = session_key
        self.geocode_mode = geocode_mode
        self.google_key = google_key
        self.email_contact = email_contact or "you@example.com"
        self.out_q = out_q
        self.polite = polite
        self.verbose = verbose

    def run(self):
        start = now_ts()
        recs = []
        total = max(len(self.calls), 1)
        for i, cs in enumerate(self.calls, 1):
            if self.stopped(): break
            try:
                info = {"callsign": cs}
                if self.session_key:
                    q = qrz_lookup_call(self.session_key, cs, verbose=self.verbose) or {}
                    info.update(q)
                # Geocode + grid
                addr = info.get("address") or ", ".join([
                    info.get("addr1", ""), info.get("city", ""),
                    info.get("state", ""), info.get("zipcode", ""),
                    info.get("country", "")
                ])
                addr = ", ".join([p for p in [a.strip() for a in addr.split(",")] if p])
                lat = lon = None
                if addr:
                    try:
                        if self.geocode_mode == "google" and self.google_key:
                            loc, status = geocode_google(addr, self.google_key, verbose=self.verbose)
                            if loc: lat, lon = loc
                        else:
                            loc = geocode_nominatim(
                                addr, email=self.email_contact,
                                pause=0.8 if self.polite else 0.2,
                                verbose=self.verbose
                            )
                            if loc: lat, lon = loc
                    except Exception as ge:
                        self.out_q.put(("log", f"Geocode error for {cs}: {ge}",))
                if lat is not None and lon is not None:
                    info["lat"] = lat
                    info["lon"] = lon
                    info["grid"] = maidenhead_from_latlon(lat, lon, precision=3)
                    # Reverse-geocode to county
                    try:
                        cty = reverse_geocode_nominatim(lat, lon, email=self.email_contact,
                                                        pause=0.6 if self.polite else 0.2,
                                                        verbose=self.verbose)
                        info["county"] = cty or info.get("county", "")
                    except Exception:
                        info.setdefault("county", "")
                else:
                    info.setdefault("lat", "")
                    info.setdefault("lon", "")
                    info.setdefault("grid", "")
                    info.setdefault("county", "")
                recs.append(info)
            except Exception as e:
                self.out_q.put(("log", f"Error processing {cs}: {e}",))
            elapsed = now_ts() - start
            eta = (elapsed / i) * (total - i) if i else 0
            self.out_q.put(("progress", {"processed": i, "total": total, "elapsed": elapsed, "eta": eta, "last": cs}))
            if self.polite: time.sleep(0.1)
        self.out_q.put(("finished", recs))

# ---------- GUI ----------
class LoginDialog:
    def __init__(self, parent):
        self.top = tk.Toplevel(parent)
        self.top.title("QRZ Login")
        self.top.grab_set()
        self.top.transient(parent)
        self.result = None

        frm = ttk.Frame(self.top, padding=10)
        frm.grid(row=0, column=0, sticky="nsew")

        ttk.Label(frm, text="Provide a QRZ XML API Session Key OR your username/password").grid(row=0, column=0, columnspan=3, sticky="w", pady=(0,8))

        ttk.Label(frm, text="API Key:").grid(row=1, column=0, sticky="e")
        self.api_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.api_var, width=40).grid(row=1, column=1, columnspan=2, sticky="w")

        ttk.Label(frm, text="Username:").grid(row=2, column=0, sticky="e")
        self.u_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.u_var, width=24).grid(row=2, column=1, sticky="w")

        ttk.Label(frm, text="Password:").grid(row=3, column=0, sticky="e")
        self.p_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.p_var, show="*", width=24).grid(row=3, column=1, sticky="w")

        btns = ttk.Frame(frm)
        btns.grid(row=4, column=0, columnspan=3, pady=10, sticky="e")
        ttk.Button(btns, text="Continue", command=self.on_ok).grid(row=0, column=0, padx=5)
        ttk.Button(btns, text="Quit", command=self.top.destroy).grid(row=0, column=1)

        self.top.bind("<Return>", lambda e: self.on_ok())
        self.top.protocol("WM_DELETE_WINDOW", self.top.destroy)

    def on_ok(self):
        api = self.api_var.get().strip()
        u = self.u_var.get().strip()
        p = self.p_var.get()
        self.result = (api, u, p)
        self.top.destroy()

class App:
    def __init__(self, root):
        self.root = root
        root.title("Ham Harvester / QRZ Mapper")

        # State
        self.session_key = None
        self.worker = None
        self.queue = queue.Queue()
        self.records = []

        # --- Modal login first ---
        self.prompt_login()

        # Main UI
        frm = ttk.Frame(root, padding=10)
        frm.grid(row=0, column=0, sticky="nsew")

        # Mode choice
        self.mode = tk.StringVar(value="calls")
        mode_box = ttk.LabelFrame(frm, text="Mode")
        mode_box.grid(row=0, column=0, columnspan=3, sticky="ew", pady=(0,8))

        ttk.Radiobutton(mode_box, text="A) Lookup pasted/CSV callsigns", variable=self.mode, value="calls",
                        command=self.update_mode_state).grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(mode_box, text="B) Harvest by counties", variable=self.mode, value="counties",
                        command=self.update_mode_state).grid(row=0, column=1, sticky="w", padx=10)
        ttk.Radiobutton(mode_box, text="C) Harvest entire state", variable=self.mode, value="state",
                        command=self.update_mode_state).grid(row=0, column=2, sticky="w", padx=10)

        # Callsigns inputs (Mode A)
        calls_frame = ttk.LabelFrame(frm, text="Callsigns")
        calls_frame.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(0,8))
        self.calls_frame = calls_frame

        ttk.Label(calls_frame, text="CSV of callsigns (optional):").grid(row=0, column=0, sticky="w")
        self.csv_var = tk.StringVar()
        ttk.Entry(calls_frame, textvariable=self.csv_var, width=60).grid(row=0, column=1)
        ttk.Button(calls_frame, text="Browse", command=self.browse_csv).grid(row=0, column=2)

        ttk.Label(calls_frame, text="Or paste callsigns (comma / newline):").grid(row=1, column=0, sticky="w", pady=(6,0))
        self.callsign_text = scrolledtext.ScrolledText(calls_frame, width=60, height=4)
        self.callsign_text.grid(row=1, column=1, columnspan=2, pady=(6,0))

        # State/County inputs (Modes B & C)
        geo_frame = ttk.LabelFrame(frm, text="Geography")
        geo_frame.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(0,8))
        self.geo_frame = geo_frame

        ttk.Label(geo_frame, text="State:").grid(row=0, column=0, sticky="w")
        self.state_var = tk.StringVar(value="")
        self.state_combo = ttk.Combobox(geo_frame, textvariable=self.state_var, width=6,
                                        values=sorted(STATE_ABBR_TO_FIPS.keys()))
        self.state_combo.grid(row=0, column=1, sticky="w", padx=4)
        self.state_combo.bind("<<ComboboxSelected>>", self.on_state_selected)
        self.state_var.trace_add("write", lambda *_: self.on_state_selected())

        ttk.Label(geo_frame, text="Counties (multi-select):").grid(row=0, column=2, padx=(16,4), sticky="w")
        self.county_list = tk.Listbox(geo_frame, selectmode="extended", width=40, height=7, exportselection=False)
        self.county_list.grid(row=0, column=3, sticky="w")

        # Geocoding settings
        geocode_frame = ttk.LabelFrame(frm, text="Geocoding")
        geocode_frame.grid(row=3, column=0, columnspan=3, sticky="ew", pady=(0,8))
        ttk.Label(geocode_frame, text="Mode:").grid(row=0, column=0, sticky="w")
        self.gc_mode = tk.StringVar(value="nominatim")
        ttk.Radiobutton(geocode_frame, text="OpenStreetMap (no API key)", variable=self.gc_mode, value="nominatim").grid(row=0, column=1, sticky="w")
        ttk.Radiobutton(geocode_frame, text="Google Geocoding (requires key)", variable=self.gc_mode, value="google").grid(row=0, column=2, sticky="w", padx=8)

        ttk.Label(geocode_frame, text="Google API key (optional):").grid(row=1, column=0, sticky="w", pady=(6,0))
        self.google_var = tk.StringVar()
        ttk.Entry(geocode_frame, textvariable=self.google_var, width=60).grid(row=1, column=1, columnspan=2, sticky="w", pady=(6,0))

        ttk.Label(geocode_frame, text="Nominatim contact email (OSM policy):").grid(row=2, column=0, sticky="w", pady=(6,0))
        self.email_var = tk.StringVar(value="you@example.com")
        ttk.Entry(geocode_frame, textvariable=self.email_var, width=60).grid(row=2, column=1, columnspan=2, sticky="w", pady=(6,0))

        # Options + buttons
        opts = ttk.Frame(frm)
        opts.grid(row=4, column=0, columnspan=3, sticky="ew", pady=(0,8))
        self.verbose = tk.BooleanVar(value=False)
        self.polite = tk.BooleanVar(value=True)
        ttk.Checkbutton(opts, text="Verbose output", variable=self.verbose).grid(row=0, column=0, sticky="w")
        ttk.Checkbutton(opts, text="Polite mode (slow & gentle)", variable=self.polite).grid(row=0, column=1, sticky="w", padx=12)

        bfrm = ttk.Frame(frm)
        bfrm.grid(row=5, column=0, columnspan=3, sticky="we")
        ttk.Button(bfrm, text="Run", command=self.run_action).grid(row=0, column=0, sticky="we", padx=2)
        ttk.Button(bfrm, text="Stop", command=self.stop).grid(row=0, column=1, sticky="we", padx=2)
        ttk.Button(bfrm, text="Export CSV", command=self.export_csv).grid(row=0, column=2, sticky="we", padx=2)
        ttk.Button(bfrm, text="Export KML", command=self.export_kml).grid(row=0, column=3, sticky="we", padx=2)
        ttk.Button(bfrm, text="Export HTML Map", command=self.export_html).grid(row=0, column=4, sticky="we", padx=2)
        ttk.Button(bfrm, text="Clear Log", command=self.clear_log).grid(row=0, column=5, sticky="we", padx=2)

        # Progress + status
        self.progress = ttk.Progressbar(frm, orient="horizontal", length=480, mode="determinate")
        self.progress.grid(row=6, column=0, columnspan=2, sticky="w", pady=(6,0))
        self.status_var = tk.StringVar(value="Idle")
        ttk.Label(frm, textvariable=self.status_var).grid(row=6, column=2, sticky="w", pady=(6,0))

        # Log
        ttk.Label(root, text="Log / Output:").grid(row=1, column=0, sticky="w")
        self.log_text = scrolledtext.ScrolledText(root, height=12, width=110)
        self.log_text.grid(row=2, column=0, sticky="nsew")

        # Fill layout stretch
        root.rowconfigure(2, weight=1)
        root.columnconfigure(0, weight=1)

        self.update_mode_state()
        self.root.after(200, self.poll_queue)

    # --- Login first ---
    def prompt_login(self):
        dlg = LoginDialog(self.root)
        self.root.wait_window(dlg.top)
        if dlg.result is None:
            sys.exit(0)
        api, u, p = dlg.result
        if api:
            self.session_key = api
            self.log_direct("[info] Using provided QRZ session key")
            return
        if not (u and p):
            messagebox.showerror("Login required", "You must provide an API key or username/password.")
            sys.exit(1)
        self.log_direct(f"[info] Logging in to QRZ as {u} ...")
        try:
            sk = qrz_login(u, p, verbose=False)
            self.session_key = sk
            self.log_direct("[info] QRZ session key obtained.")
        except Exception as e:
            messagebox.showerror("QRZ Login Failed", str(e))
            sys.exit(1)

    # --- Mode management ---
    def update_mode_state(self):
        m = self.mode.get()
        # Mode A: show calls_frame; Mode B/C: show geo_frame
        if m == "calls":
            self.calls_frame.state(["!disabled"])
            for child in self.calls_frame.winfo_children():
                child.configure(state="normal")
            self.geo_frame.state(["disabled"])
            for child in self.geo_frame.winfo_children():
                child.configure(state="disabled")
        else:
            self.geo_frame.state(["!disabled"])
            for child in self.geo_frame.winfo_children():
                child.configure(state="normal")
            self.calls_frame.state(["disabled"])
            for child in self.calls_frame.winfo_children():
                child.configure(state="disabled")

    # --- UI helpers ---
    def log_direct(self, line):
        self.log_text.insert("end", line + "\n")
        self.log_text.see("end")

    def log(self, msg, lvl="info"):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_text.insert("end", f"[{ts}] [{lvl}] {msg}\n")
        self.log_text.see("end")

    def clear_log(self):
        self.log_text.delete("1.0", "end")

    def browse_csv(self):
        p = filedialog.askopenfilename(filetypes=[("CSV", "*.csv"), ("All files", "*.*")])
        if p:
            self.csv_var.set(p)

    def on_state_selected(self, _evt=None):
        # Only load in county-related modes
        if self.mode.get() == "calls":
            return
        st = (self.state_var.get() or "").strip().upper()
        self.county_list.delete(0, "end")
        if not st or st not in STATE_ABBR_TO_FIPS:
            return
        self.log(f"Loading counties for {st} ...", "info")
        counties = fetch_counties_for_state(st, log=self.log)
        if not counties:
            self.log(f"Could not load counties for {st}. Check network or try again.", "error")
            return
        for c in counties:
            self.county_list.insert("end", c)

    def get_selected_counties(self):
        idxs = self.county_list.curselection()
        return [self.county_list.get(i) for i in idxs]

    # --- Actions ---
    def run_action(self):
        if self.worker and self.worker.is_alive():
            messagebox.showinfo("Running", "Already in progress")
            return

        self.records = []
        self.progress["value"] = 0
        self.status_var.set("Starting...")

        m = self.mode.get()
        polite = self.polite.get()

        if m == "calls":
            calls = self.gather_callsigns()
            if not calls:
                messagebox.showinfo("No callsigns", "Provide callsigns via CSV or paste")
                return
            self.progress["maximum"] = len(calls)
            self.log(f"Mode A: processing {len(calls)} callsigns; geocode: {self.gc_mode.get()}", "info")
            self.worker = CallListWorker(
                calls=calls,
                session_key=self.session_key,
                geocode_mode=self.gc_mode.get(),
                google_key=self.google_var.get().strip(),
                email_contact=self.email_var.get().strip() or "you@example.com",
                out_q=self.queue,
                polite=polite,
                verbose=self.verbose.get(),
            )
            self.worker.start()
            return

        # county modes
        st = (self.state_var.get() or "").strip().upper()
        if not st:
            messagebox.showinfo("Select State", "Pick a state first")
            return

        if m == "counties":
            counties = self.get_selected_counties()
            if not counties:
                messagebox.showinfo("Select Counties", "Pick one or more counties")
                return
        else:
            # entire state
            counties = fetch_counties_for_state(st, log=self.log)
            if not counties:
                messagebox.showerror("County Load Failed", f"Could not load county list for {st}")
                return

        self.progress["maximum"] = len(counties)
        self.log(f"Mode {'B' if m=='counties' else 'C'}: Harvesting FCC in {st} / {len(counties)} county(ies) [polite={polite}]", "info")
        self.worker = CountyHarvestWorker(
            state_abbr=st,
            counties=counties,
            session_key=self.session_key,
            geocode_mode=self.gc_mode.get(),
            google_key=self.google_var.get().strip(),
            nominatim_email=self.email_var.get().strip() or "you@example.com",
            out_q=self.queue,
            polite=polite,
            verbose=self.verbose.get(),
        )
        self.worker.start()

    def stop(self):
        if self.worker and self.worker.is_alive():
            self.worker.stop()
            self.status_var.set("Stop requested")
            self.log("Stop requested (current operation will finish its step).", "info")

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
                    eta = d.get("eta", 0)
                    self.progress["value"] = min(processed, self.progress["maximum"])
                    self.status_var.set(f"{processed}/{total}  Elapsed: {nice_elapsed(elapsed)}  ETA: {nice_elapsed(eta)}")
                elif typ == "finished":
                    recs = payload
                    self.records = recs
                    self.progress["value"] = self.progress["maximum"]
                    self.status_var.set("Finished")
                    self.log(f"Finished: {len(recs)} records", "info")
        except queue.Empty:
            pass
        self.root.after(200, self.poll_queue)

    # --- Data helpers ---
    def gather_callsigns(self):
        calls = []
        # CSV
        p = self.csv_var.get().strip()
        if p:
            try:
                with open(p, newline="", encoding="utf-8") as fh:
                    rdr = csv.reader(fh)
                    header = next(rdr, None)
                    idx = 0
                    if header and any(h.lower() == "callsign" for h in header):
                        idx = [i for i, h in enumerate(header) if h.lower() == "callsign"][0]
                    else:
                        if header and header[0].strip().upper() != "CALLSIGN":
                            calls.append(header[0].strip())
                    for row in rdr:
                        if row and len(row) > idx and row[idx].strip():
                            calls.append(row[idx].strip())
            except Exception as e:
                self.log(f"Error reading CSV: {e}", "error")
        # Pasted
        txt = self.callsign_text.get("1.0", "end").strip()
        if txt:
            parts = [x.strip() for x in (txt.replace(",", "\n")).splitlines()]
            calls.extend([c for c in parts if c])

        # dedupe/validate
        out, seen = [], set()
        for c in calls:
            cu = c.upper()
            if cu not in seen and CALL_RE.match(cu):
                seen.add(cu)
                out.append(cu)
        return out

    # --- Exports ---
    def export_csv(self):
        if not self.records:
            messagebox.showinfo("No data", "No results to export")
            return
        p = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not p:
            return
        # required columns order
        preferred = ["callsign", "fname", "addr1", "addr2", "city", "state", "county", "zipcode",
                     "country", "address", "grid", "email", "lat", "lon"]
        present = set().union(*(r.keys() for r in self.records))
        fieldnames = [k for k in preferred if k in present] + [k for k in sorted(present) if k not in preferred]
        try:
            with open(p, "w", newline="", encoding="utf-8") as fh:
                w = csv.DictWriter(fh, fieldnames=fieldnames)
                w.writeheader()
                for r in self.records:
                    w.writerow(r)
            self.log(f"CSV exported: {p}", "info")
        except Exception as e:
            self.log(f"CSV export error: {e}", "error")

    def export_kml(self):
        if not self.records:
            messagebox.showinfo("No data", "No results to export")
            return
        p = filedialog.asksaveasfilename(defaultextension=".kml", filetypes=[("KML", "*.kml")])
        if not p:
            return
        k = simplekml.Kml()
        for r in self.records:
            try:
                lat = float(r.get("lat"))
                lon = float(r.get("lon"))
            except Exception:
                continue
            name = r.get("callsign", "")
            desc_lines = [
                f"Name: {r.get('fname', '')}",
                f"Address: {r.get('address', '')}",
                f"City/State/ZIP: {r.get('city','')}, {r.get('state','')} {r.get('zipcode','')}",
                f"County: {r.get('county','')}",
                f"Grid: {r.get('grid', '')}",
                f"Email: {r.get('email', '')}",
            ]
            k.newpoint(name=name, coords=[(lon, lat)], description="\n".join(desc_lines))
        try:
            k.save(p)
            self.log(f"KML saved: {p}", "info")
        except Exception as e:
            self.log(f"KML save error: {e}", "error")

    def export_html(self):
        if not self.records:
            messagebox.showinfo("No data", "No results to export")
            return
        p = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML", "*.html")])
        if not p:
            return
        pts = []
        for r in self.records:
            try:
                lat = float(r.get("lat"))
                lon = float(r.get("lon"))
            except Exception:
                continue
            pts.append({"callsign": r.get("callsign",""), "lat": lat, "lon": lon,
                        "addr": r.get("address","")})
        if not pts:
            messagebox.showinfo("No geocoded points", "No latitude/longitude data available")
            return
        lats = [pt["lat"] for pt in pts]
        lons = [pt["lon"] for pt in pts]
        min_lat, max_lat = min(lats), max(lats)
        min_lon, max_lon = min(lons), max(lons)
        clat = (min_lat + max_lat) / 2.0
        clon = (min_lon + max_lon) / 2.0

        gm_key = self.google_var.get().strip()
        if gm_key:
            markers_js = []
            for pt in pts:
                title = json.dumps(pt['callsign'])
                markers_js.append(
                    f"new google.maps.Marker({{position: {{lat: {pt['lat']}, lng: {pt['lon']}}}, map: map, title: {title}}});"
                )
            html = f"""<!doctype html>
<html>
<head><meta charset="utf-8"><title>Map</title>
<style>html,body,#map{{height:100%;margin:0;padding:0}}</style>
</head>
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
  {''.join(markers_js)}
  map.fitBounds(bounds);
}}
window.onload = initMap;
</script></body></html>"""
        else:
            mk = []
            for pt in pts:
                popup = json.dumps(f"{pt['callsign']}\n{pt['addr']}").replace("\\n", "<br/>")
                mk.append(f"L.marker([{pt['lat']}, {pt['lon']}]).addTo(map).bindPopup({popup});")
            html = f"""<!doctype html>
<html>
<head><meta charset="utf-8"><title>Map</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet/dist/leaflet.css"/>
<style>html,body,#map{{height:100%;margin:0;padding:0}}</style></head>
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
</script></body></html>"""
        try:
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(html)
            self.log(f"HTML map saved: {p}", "info")
        except Exception as e:
            self.log(f"HTML save error: {e}", "error")

# ---------- main ----------
def main():
    root = tk.Tk()
    app = App(root)
    root.mainloop()

if __name__ == "__main__":
    main()
