#!/usr/bin/env python3
"""
Ham Harvester (QRZ + FCC License View API)

- First prompts for QRZ API key or username/password.
- Mode A: Callsign(s) pasted and/or CSV of callsigns.
- Mode B: State + (optional multi-)County selection:
    • Enumerates Active Amateur licenses (HA/HV) via FCC License View API.
    • Filters locally to chosen county(ies).
    • Enriches each callsign via QRZ XML (name, address, grid, email).
- Exports CSV (name, street, city, state, county, zip, grid, email, callsign).
- Exports KML and HTML map (Google or Leaflet).
- Verbose logging, progress/ETA, and Stop control.

Notes:
- We no longer scrape ULS HTML; scraping is fragile. We use the public FCC
  License View API to list calls, then QRZ to enrich records.
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

# ---------- Tkinter first (OS-provided) ----------
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext
except Exception:
    print("[ERROR] tkinter is not available.\n"
          "Debian/Ubuntu: sudo apt-get install python3-tk\n"
          "Fedora:       sudo dnf install python3-tkinter\n"
          "Windows/macOS: Install Python from python.org (includes Tk).")
    sys.exit(1)

# ---------- Ensure pip deps (inside venv is fine) ----------
def ensure_deps(verbose=False):
    reqs = ["requests", "simplekml", "geopy", "beautifulsoup4"]
    missing = []
    for m in reqs:
        try:
            importlib.import_module(m)
            if verbose:
                print(f"[OK] {m} importable")
        except ImportError:
            missing.append(m)
    if not missing:
        return
    print(f"[INFO] Missing packages: {missing}")
    print("[INFO] Attempting to install missing packages into the current environment...")
    for m in missing:
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", m])
            print(f"[INSTALLED] {m}")
        except Exception as e:
            print(f"[ERROR] Could not install {m}: {e}")
            print("Please install and rerun.")
            sys.exit(1)

ensure_deps(verbose=True)

# ---------- Imports now safe ----------
from geopy.geocoders import Nominatim as GeoNominatim  # optional use
import simplekml

# ---------- Globals ----------
USER_AGENT = "HamHarvester/2.0 (+email: you@example.com)"
HTTP = requests.Session()
HTTP.headers.update({"User-Agent": USER_AGENT})

QRZ_XML_BASE = "https://xmldata.qrz.com/xml/current/"
QRZ_XML_LOGIN_URL = QRZ_XML_BASE

FCC_LV_BASE = "https://data.fcc.gov/api/license-view/basicSearch/getLicenses"

# Census county list (ACS fallback)
CENSUS_ACS_COUNTY_API = "https://api.census.gov/data/2022/acs/acs5/profile"
# We use a harmless variable (DP02_0001E) just to hit a table; we only need NAME + county/state FIPS
CENSUS_ACS_PARAMS = {"get": "NAME", "for": "county:*", "in": "state:{}"}

# Callsign sanity
CALL_RE = re.compile(r"^[A-Z0-9/]{3,}$")

# ---------- Utils ----------
def now_ts(): return time.time()

def nice_elapsed(seconds):
    if seconds < 60:
        return f"{seconds:.1f}s"
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    if h: return f"{h}h {m}m {s}s"
    if m: return f"{m}m {s}s"
    return f"{s}s"

def us_state_items():
    # USPS codes; shown as "NY — New York"
    states = [
        ("AL","Alabama"),("AK","Alaska"),("AZ","Arizona"),("AR","Arkansas"),
        ("CA","California"),("CO","Colorado"),("CT","Connecticut"),("DE","Delaware"),
        ("FL","Florida"),("GA","Georgia"),("HI","Hawaii"),("ID","Idaho"),
        ("IL","Illinois"),("IN","Indiana"),("IA","Iowa"),("KS","Kansas"),
        ("KY","Kentucky"),("LA","Louisiana"),("ME","Maine"),("MD","Maryland"),
        ("MA","Massachusetts"),("MI","Michigan"),("MN","Minnesota"),("MS","Mississippi"),
        ("MO","Missouri"),("MT","Montana"),("NE","Nebraska"),("NV","Nevada"),
        ("NH","New Hampshire"),("NJ","New Jersey"),("NM","New Mexico"),("NY","New York"),
        ("NC","North Carolina"),("ND","North Dakota"),("OH","Ohio"),("OK","Oklahoma"),
        ("OR","Oregon"),("PA","Pennsylvania"),("RI","Rhode Island"),("SC","South Carolina"),
        ("SD","South Dakota"),("TN","Tennessee"),("TX","Texas"),("UT","Utah"),
        ("VT","Vermont"),("VA","Virginia"),("WA","Washington"),("WV","West Virginia"),
        ("WI","Wisconsin"),("WY","Wyoming"),("DC","District of Columbia"),
        ("PR","Puerto Rico"),("GU","Guam"),("VI","U.S. Virgin Islands"),
        ("MP","Northern Mariana Islands"),("AS","American Samoa"),
    ]
    return [f"{abbrev} — {name}" for abbrev, name in states]

def state_abbrev_from_display(s):
    # Input like "NY — New York" -> "NY"
    if not s: return ""
    return s.split("—",1)[0].strip()

# ---------- QRZ XML helpers ----------
def find_first(elem, *tag_names):
    if elem is None: return None
    wanted = {t.lower() for t in tag_names}
    for node in elem.iter():
        local = node.tag.split('}', 1)[-1].lower()
        if local in wanted:
            return node
    return None

def find_text(elem, *tag_names):
    n = find_first(elem, *tag_names)
    return (n.text.strip() if (n is not None and n.text) else "")

def qrz_login(username, password, verbose=False):
    if verbose:
        print("[qrz_login] attempting login")
    def parse_key(xml_text):
        root = ET.fromstring(xml_text)
        session = find_first(root, "Session")
        key = find_text(session, "Key") if session is not None else ""
        if not key and session is not None and session.text:
            key = session.text.strip()
        return key
    # POST XML
    try:
        payload = (f"<QRZDatabase><USERNAME>{username}</USERNAME><PASSWORD>{password}</PASSWORD>"
                   "<OPTIONS><keeplogin>1</keeplogin></OPTIONS></QRZDatabase>")
        r = HTTP.post(QRZ_XML_LOGIN_URL, data=payload,
                      headers={"Content-Type":"application/xml","User-Agent":USER_AGENT},
                      timeout=20)
        r.raise_for_status()
        key = parse_key(r.text)
        if key:
            if verbose: print("[qrz_login] obtained session key")
            return key
    except Exception as e:
        if verbose: print("[qrz_login] xml-post failed:", e)
    # GET fallback
    try:
        r2 = HTTP.get(QRZ_XML_LOGIN_URL, params={"username":username, "password":password},
                      headers={"User-Agent":USER_AGENT}, timeout=20)
        r2.raise_for_status()
        key = parse_key(r2.text)
        if key:
            return key
    except Exception as e:
        if verbose: print("[qrz_login] get fallback failed:", e)
    raise RuntimeError("QRZ login failed (XML privileges required).")

def qrz_lookup_call(session_key, callsign, verbose=False, relogin_cb=None):
    # Return dict with desired fields, may be partially empty if QRZ doesn't have them.
    params = {"s": session_key, "callsign": callsign}
    r = HTTP.get(QRZ_XML_BASE, params=params, headers={"User-Agent":USER_AGENT}, timeout=20)
    r.raise_for_status()
    root = ET.fromstring(r.text)

    # Check for session error
    session = find_first(root, "Session")
    err = find_text(session, "Error") if session is not None else ""
    if err and ("Session Timeout" in err or "Invalid session key" in err) and relogin_cb:
        if verbose: print("[qrz_lookup_call] session timeout; re-login")
        new_key = relogin_cb()
        if not new_key:
            raise RuntimeError("QRZ session expired and re-login failed")
        params["s"] = new_key
        r = HTTP.get(QRZ_XML_BASE, params=params, headers={"User-Agent":USER_AGENT}, timeout=20)
        r.raise_for_status()
        root = ET.fromstring(r.text)

    call = find_first(root, "Callsign")
    if call is None:
        return {"callsign": callsign}

    def gt(tag): return find_text(call, tag)

    data = {
        "callsign": gt("call") or callsign,
        "name": gt("fname") or gt("name"),
        "addr1": gt("addr1"),
        "addr2": gt("addr2"),
        "city": gt("city"),
        "state": gt("state"),
        "zip": gt("zipcode") or gt("postcode"),
        "country": gt("country"),
        "grid": gt("grid"),
        "email": gt("email"),
        "county": gt("county"),
    }
    # Compose single-line street
    street = data["addr1"]
    if data["addr2"]:
        street = f"{street}, {data['addr2']}" if street else data["addr2"]
    data["street"] = street
    # Single address line too
    parts = [p for p in [street, data["city"], data["state"], data["zip"], data["country"]] if p]
    data["address"] = ", ".join(parts)
    return data

# ---------- FCC License View API ----------
def fcc_list_callsigns(state_abbrev, verbose=False, page_size=1000, max_pages=200):
    """
    Enumerate ACTIVE Amateur licenses (HA/HV) for a state via FCC License View API.
    Returns a list of dicts with at least {"callsign", "statusDesc", "state", "zip", "licName"}.
    We then enrich per callsign from QRZ.
    Notes:
      • License View API historically accepted fields:
        - searchValue (string)
        - state (USPS)
        - status (Active, Expired, etc.)
        - radioServiceCode (comma sep, e.g., HA,HV)
        - pageNum (1-based) and pageSize (<=1000 typical)
      • We try a couple of parameter spellings to be robust.
    """
    all_rows = []
    page = 1
    tries = 0
    while page <= max_pages:
        params_variants = [
            {"format":"json", "state":state_abbrev, "status":"Active", "radioServiceCode":"HA,HV", "pageNum":page, "pageSize":page_size},
            {"format":"json", "state":state_abbrev, "status":"A",     "radioServiceCode":"HA,HV", "pageNum":page, "pageSize":page_size},
            # Fallback to index/rows if pageNum rejected
            {"format":"json", "state":state_abbrev, "status":"Active", "radioServiceCode":"HA,HV", "pageIndex":page-1, "rowsPerPage":page_size},
        ]
        got = None
        last_err = None
        for pv in params_variants:
            try:
                r = HTTP.get(FCC_LV_BASE, params=pv, timeout=30)
                r.raise_for_status()
                j = r.json()
                if isinstance(j, dict) and j.get("status","").upper()=="OK":
                    lic = j.get("Licenses") or j.get("licenses") or {}
                    rows = lic.get("License") if isinstance(lic, dict) else None
                    if isinstance(rows, list):
                        got = rows
                        break
            except Exception as e:
                last_err = e
                continue
        if got is None:
            if verbose:
                print(f"[fcc] page {page} no data ({last_err})")
            break
        if not got:
            break
        all_rows.extend(got)
        if verbose:
            print(f"[fcc] page {page}: {len(got)} rows (total {len(all_rows)})")
        # If fewer than page_size, likely last page
        if len(got) < page_size:
            break
        page += 1
        tries += 1
    return all_rows

def fcc_filter_by_counties(rows, county_names):
    """
    Filter FCC rows to those matching any county in county_names.
    The License View payload often includes 'county' (not guaranteed).
    We try license row fields and some heuristics.
    """
    if not county_names:
        return rows
    wanted = {c.upper() for c in county_names}
    out = []
    for r in rows:
        # field names vary: try common ones
        cand = []
        for k in ("county", "countyName", "cntyName", "facCounty", "operatingCounty"):
            v = r.get(k)
            if v:
                cand.append(str(v))
        # Sometimes location city string can include "MADISON" (rare)
        for k in ("city", "location", "locCity"):
            v = r.get(k)
            if v:
                cand.append(str(v))
        match = False
        for c in cand:
            cu = c.upper()
            if cu in wanted or any(cu.endswith(f" COUNTY") and cu.replace(" COUNTY","") in wanted for _ in [0]):
                match = True
                break
        if match:
            out.append(r)
    # If nothing matched, return original (let QRZ filter by county later)
    return out or rows

# ---------- Counties via Census (ACS fallback) ----------
def census_counties_for_state(state_abbrev, log=None):
    # Map USPS -> FIPS2
    usps_to_fips = {
        'AL':'01','AK':'02','AZ':'04','AR':'05','CA':'06','CO':'08','CT':'09','DE':'10',
        'DC':'11','FL':'12','GA':'13','HI':'15','ID':'16','IL':'17','IN':'18','IA':'19',
        'KS':'20','KY':'21','LA':'22','ME':'23','MD':'24','MA':'25','MI':'26','MN':'27',
        'MS':'28','MO':'29','MT':'30','NE':'31','NV':'32','NH':'33','NJ':'34','NM':'35',
        'NY':'36','NC':'37','ND':'38','OH':'39','OK':'40','OR':'41','PA':'42','RI':'44',
        'SC':'45','SD':'46','TN':'47','TX':'48','UT':'49','VT':'50','VA':'51','WA':'53',
        'WV':'54','WI':'55','WY':'56','PR':'72','VI':'78','GU':'66','MP':'69','AS':'60',
    }
    stfips = usps_to_fips.get(state_abbrev)
    if not stfips:
        return []
    params = dict(CENSUS_ACS_PARAMS)
    params["in"] = params["in"].format(stfips)
    try:
        r = HTTP.get(CENSUS_ACS_COUNTY_API, params=params, timeout=30)
        r.raise_for_status()
        arr = r.json()
        header, *rows = arr
        # Each row: [NAME, state, county]
        out = []
        for name, st, cnty in rows:
            # NAME example: "Madison County, New York"
            if ", " in name:
                county = name.split(",",1)[0].replace("County","").strip()
            else:
                county = name.strip()
            out.append(county)
        return sorted(out)
    except requests.HTTPError as he:
        if log: log(f"[error] Census ACS HTTP {he.response.status_code}")
        return []
    except Exception:
        return []

# ---------- Worker ----------
class Harvester(threading.Thread):
    def __init__(self, mode, session_key, callsigns, state, counties, geocode_mode,
                 google_key, nominatim_email, out_q, relogin_cb=None, verbose=False):
        super().__init__(daemon=True)
        self.mode = mode  # "calls" or "state"
        self.session_key = session_key
        self.callsigns = callsigns or []
        self.state = state
        self.counties = counties or []
        self.gc_mode = geocode_mode
        self.google_key = google_key
        self.email = nominatim_email or "you@example.com"
        self.q = out_q
        self.relogin_cb = relogin_cb
        self.verbose = verbose
        self._stop_event = threading.Event()

    def stop(self): self._stop_event.set()
    def stopped(self): return self._stop_event.is_set()

    def geocode(self, addr):
        if not addr: return None
        try:
            if self.gc_mode == "google" and self.google_key:
                url = "https://maps.googleapis.com/maps/api/geocode/json"
                r = HTTP.get(url, params={"address":addr, "key":self.google_key}, timeout=20)
                r.raise_for_status()
                j = r.json()
                if j.get("status") == "OK":
                    loc = j["results"][0]["geometry"]["location"]
                    return (loc["lat"], loc["lng"])
                return None
            else:
                geon = GeoNominatim(user_agent=f"{USER_AGENT} ({self.email})")
                lo = geon.geocode(addr, timeout=20)
                if lo:
                    time.sleep(1.0)  # polite
                    return (lo.latitude, lo.longitude)
                return None
        except Exception:
            return None

    def run(self):
        start = now_ts()
        recs = []
        # Build calls list
        if self.mode == "state":
            self.q.put(("log", f"[info] Enumerating FCC Active Amateur licenses for {self.state} ..."))
            rows = fcc_list_callsigns(self.state, verbose=self.verbose)
            if self.counties:
                rows = fcc_filter_by_counties(rows, self.counties)
            # extract callsigns, dedupe
            calls = []
            seen = set()
            for r in rows:
                cs = r.get("callsign") or r.get("callSign") or r.get("callSignDesc")
                if cs:
                    csu = str(cs).upper().strip()
                    if CALL_RE.match(csu) and csu not in seen:
                        seen.add(csu)
                        calls.append(csu)
            self.callsigns = calls
            self.q.put(("log", f"[info] Found {len(self.callsigns)} candidate calls in FCC for selection."))

        total = len(self.callsigns)
        if total == 0:
            self.q.put(("finished", recs))
            return

        self.q.put(("progress", {"processed":0,"total":total,"elapsed":0,"eta":0,"last":""}))

        processed = 0
        for cs in self.callsigns:
            if self.stopped():
                break
            try:
                info = qrz_lookup_call(self.session_key, cs, verbose=self.verbose, relogin_cb=self.relogin_cb)
                # Simple county filter if running state+county and QRZ has county
                if self.mode == "state" and self.counties:
                    cty = (info.get("county") or "").upper().replace(" COUNTY","").strip()
                    if cty and cty not in {c.upper() for c in self.counties}:
                        # Skip if QRZ says it's a different county
                        pass
                # Geocode
                loc = self.geocode(info.get("address"))
                if loc:
                    info["lat"], info["lon"] = loc
                else:
                    info["lat"] = info["lon"] = ""
                # Keep only the required output fields + callsign
                keep = {
                    "callsign": info.get("callsign",""),
                    "name": info.get("name",""),
                    "street": info.get("street",""),
                    "city": info.get("city",""),
                    "state": info.get("state",""),
                    "county": info.get("county",""),
                    "zip": info.get("zip",""),
                    "grid": info.get("grid",""),
                    "email": info.get("email",""),
                    "address": info.get("address",""),
                    "lat": info.get("lat",""),
                    "lon": info.get("lon",""),
                }
                recs.append(keep)
            except Exception as e:
                self.q.put(("log", f"[error] {cs}: {e}"))
            processed += 1
            elapsed = now_ts() - start
            avg = elapsed / processed if processed else 0.001
            eta = (total - processed) * avg
            self.q.put(("progress", {"processed":processed,"total":total,"elapsed":elapsed,"eta":eta,"last":cs}))

        self.q.put(("finished", recs))

# ---------- GUI ----------
class App:
    def __init__(self, root):
        self.root = root
        root.title("Ham Harvester")

        # state
        self.session_key = None
        self.cached_user = ""
        self.cached_pass = ""
        self.worker = None
        self.q = queue.Queue()
        self.records = []

        # layout
        root.rowconfigure(2, weight=1)
        root.columnconfigure(0, weight=1)

        frm = ttk.Frame(root, padding=10)
        frm.grid(row=0, column=0, sticky="nsew")

        # Mode choices
        self.mode = tk.StringVar(value="calls")  # "calls" or "state"
        ttk.Label(frm, text="Choose input mode:").grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(frm, text="A) Callsign(s) / CSV", variable=self.mode, value="calls",
                        command=self.update_mode).grid(row=0, column=1, sticky="w")
        ttk.Radiobutton(frm, text="B) State + County", variable=self.mode, value="state",
                        command=self.update_mode).grid(row=0, column=2, sticky="w")

        # Calls mode widgets
        self.csv_var = tk.StringVar()
        ttk.Label(frm, text="CSV of callsigns (optional):").grid(row=1, column=0, sticky="w")
        ttk.Entry(frm, width=45, textvariable=self.csv_var).grid(row=1, column=1, sticky="we")
        ttk.Button(frm, text="Browse", command=self.browse_csv).grid(row=1, column=2, sticky="w")

        ttk.Label(frm, text="Paste callsigns (comma/newline):").grid(row=2, column=0, sticky="w")
        self.calls_text = scrolledtext.ScrolledText(frm, width=60, height=4)
        self.calls_text.grid(row=2, column=1, columnspan=2, sticky="we")

        # State/County widgets
        ttk.Label(frm, text="State:").grid(row=3, column=0, sticky="w", pady=(8,0))
        self.state_var = tk.StringVar()
        self.state_combo = ttk.Combobox(frm, textvariable=self.state_var, width=30, state="readonly")
        self.state_combo.grid(row=3, column=1, sticky="w", pady=(8,0))
        self.state_combo["values"] = us_state_items()
        self.state_combo.bind("<<ComboboxSelected>>", self.on_state_selected)

        ttk.Button(frm, text="Load Counties", command=self.load_counties).grid(row=3, column=2, sticky="w", pady=(8,0))
        ttk.Label(frm, text="Counties (multi-select):").grid(row=4, column=0, sticky="nw")
        self.county_list = tk.Listbox(frm, selectmode="extended", width=40, height=8)
        self.county_list.grid(row=4, column=1, sticky="we")
        self.county_scroll = ttk.Scrollbar(frm, orient="vertical", command=self.county_list.yview)
        self.county_list.configure(yscrollcommand=self.county_scroll.set)
        self.county_scroll.grid(row=4, column=2, sticky="nsw")

        # Geocode, verbosity
        ttk.Separator(frm, orient="horizontal").grid(row=5, column=0, columnspan=3, sticky="ew", pady=6)
        self.gc_mode = tk.StringVar(value="nominatim")
        ttk.Label(frm, text="Geocoding:").grid(row=6, column=0, sticky="w")
        ttk.Radiobutton(frm, text="OpenStreetMap (no key)", variable=self.gc_mode, value="nominatim").grid(row=6, column=1, sticky="w")
        ttk.Radiobutton(frm, text="Google (key below)", variable=self.gc_mode, value="google").grid(row=6, column=2, sticky="w")

        ttk.Label(frm, text="Google API key:").grid(row=7, column=0, sticky="w")
        self.google_var = tk.StringVar()
        ttk.Entry(frm, width=60, textvariable=self.google_var).grid(row=7, column=1, columnspan=2, sticky="we")

        self.verbose = tk.BooleanVar(value=False)
        ttk.Checkbutton(frm, text="Verbose output", variable=self.verbose).grid(row=8, column=0, sticky="w")

        # Controls
        ttk.Separator(frm, orient="horizontal").grid(row=9, column=0, columnspan=3, sticky="ew", pady=6)
        self.progress = ttk.Progressbar(frm, orient="horizontal", length=420, mode="determinate")
        self.progress.grid(row=10, column=0, columnspan=2, sticky="w")
        self.status_var = tk.StringVar(value="Idle")
        ttk.Label(frm, textvariable=self.status_var).grid(row=10, column=2, sticky="w")

        b = ttk.Frame(frm)
        b.grid(row=11, column=0, columnspan=3, sticky="we", pady=6)
        ttk.Button(b, text="Run", command=self.run_action).grid(row=0, column=0, padx=2)
        ttk.Button(b, text="Stop", command=self.stop).grid(row=0, column=1, padx=2)
        ttk.Button(b, text="Export CSV", command=self.export_csv).grid(row=0, column=2, padx=2)
        ttk.Button(b, text="Export KML", command=self.export_kml).grid(row=0, column=3, padx=2)
        ttk.Button(b, text="Export HTML Map", command=self.export_html).grid(row=0, column=4, padx=2)
        ttk.Button(b, text="Test FCC Query", command=self.test_fcc).grid(row=0, column=5, padx=2)

        # Log area
        ttk.Label(root, text="Log / Output:").grid(row=1, column=0, sticky="w")
        self.log_text = scrolledtext.ScrolledText(root, height=14, width=100)
        self.log_text.grid(row=2, column=0, sticky="nsew")
        ttk.Button(root, text="Clear Log", command=self.clear_log).grid(row=3, column=0, sticky="w", padx=10, pady=(2,8))

        # Login prompt
        self.prompt_login()

        # Queue poll
        self.root.after(200, self.poll_queue)

        # Init
        self.update_mode()

    # ----- Logging -----
    def log(self, msg, lvl="info"):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_text.insert("end", f"[{ts}] [{lvl}] {msg}\n")
        self.log_text.see("end")

    def clear_log(self): self.log_text.delete("1.0", "end")

    # ----- Login modal -----
    def prompt_login(self):
        dlg = tk.Toplevel(self.root)
        dlg.title("Sign into QRZ (or paste API key)")
        dlg.transient(self.root)
        dlg.grab_set()

        ttk.Label(dlg, text="QRZ XML API session key (if you already have one):").grid(row=0, column=0, sticky="w", padx=10, pady=(10,2))
        api_var = tk.StringVar()
        ttk.Entry(dlg, width=55, textvariable=api_var).grid(row=0, column=1, padx=10, pady=(10,2))

        ttk.Label(dlg, text="OR Username:").grid(row=1, column=0, sticky="w", padx=10)
        u_var = tk.StringVar()
        ttk.Entry(dlg, width=30, textvariable=u_var).grid(row=1, column=1, sticky="w", padx=10)

        ttk.Label(dlg, text="Password:").grid(row=2, column=0, sticky="w", padx=10)
        p_var = tk.StringVar()
        ttk.Entry(dlg, width=30, textvariable=p_var, show="*").grid(row=2, column=1, sticky="w", padx=10)

        status = tk.StringVar(value="")
        ttk.Label(dlg, textvariable=status).grid(row=3, column=0, columnspan=2, sticky="w", padx=10)

        def do_ok():
            key = api_var.get().strip()
            if key:
                self.session_key = key
                mk = key[:4] + "..." + key[-4:] if len(key)>=8 else "****"
                self.log(f"[info] Using provided QRZ session key ({mk})")
                dlg.destroy()
                return
            u = u_var.get().strip()
            p = p_var.get()
            if not (u and p):
                messagebox.showinfo("Login", "Enter QRZ API key OR username & password.")
                return
            self.cached_user, self.cached_pass = u, p
            self.log(f"[info] Logging in to QRZ as {u} ...")
            status.set("Logging in ...")
            dlg.update()
            try:
                sk = qrz_login(u, p, verbose=self.verbose.get())
                self.session_key = sk
                status.set("Success.")
                self.log(f"[info] QRZ session key obtained.")
                dlg.destroy()
            except Exception as e:
                status.set(f"Login failed: {e}")
                self.log(f"[error] QRZ login failed: {e}")

        ttk.Button(dlg, text="OK", command=do_ok).grid(row=4, column=0, padx=10, pady=10, sticky="e")
        ttk.Button(dlg, text="Cancel", command=lambda: (self.root.destroy())).grid(row=4, column=1, padx=10, pady=10, sticky="w")
        dlg.wait_window()

    def relogin_cb(self):
        if self.cached_user and self.cached_pass:
            try:
                sk = qrz_login(self.cached_user, self.cached_pass, verbose=self.verbose.get())
                self.session_key = sk
                self.log("[info] QRZ session renewed.")
                return sk
            except Exception as e:
                self.log(f"[error] Re-login failed: {e}")
                return None
        return None

    # ----- Mode wiring -----
    def update_mode(self):
        m = self.mode.get()
        # Enable/disable relevant controls
        calls_widgets = [self.calls_text]
        # CSV line widgets:
        calls_widgets.extend([w for w in self.calls_text.master.grid_slaves(row=1) if isinstance(w,(ttk.Entry,ttk.Button))])
        for w in calls_widgets:
            w.configure(state=("normal" if m=="calls" else "disabled"))
        for w in [self.state_combo, self.county_list]:
            w.configure(state=("readonly" if m=="state" and w is self.state_combo else ("normal" if m=="state" else "disabled")))

    def browse_csv(self):
        p = filedialog.askopenfilename(filetypes=[("CSV","*.csv"),("All files","*.*")])
        if p: self.csv_var.set(p)

    def on_state_selected(self, _evt=None):
        self.load_counties()

    def load_counties(self):
        disp = self.state_var.get().strip()
        if not disp:
            messagebox.showinfo("State", "Choose a state first.")
            return
        st = state_abbrev_from_display(disp)
        self.log(f"[info] Loading counties for {st} ...")
        counties = census_counties_for_state(st, log=self.log)
        if counties:
            self.county_list.delete(0,"end")
            for c in counties: self.county_list.insert("end", c)
            self.log(f"[info] Counties loaded: {len(counties)}")
        else:
            self.log(f"[error] Could not load counties for {st}. Check network or try again.")

    def gather_callsigns(self):
        calls = []
        # CSV
        p = self.csv_var.get().strip()
        if p and os.path.exists(p):
            try:
                with open(p, newline="", encoding="utf-8") as fh:
                    rdr = csv.reader(fh)
                    header = next(rdr, None)
                    col = 0
                    if header and any(h.lower()=="callsign" for h in header):
                        col = [i for i,h in enumerate(header) if h.lower()=="callsign"][0]
                    else:
                        if header and header and header[0] and header[0].strip().upper()!="CALLSIGN":
                            calls.append(header[0].strip())
                    for row in rdr:
                        if row and len(row)>col and row[col].strip():
                            calls.append(row[col].strip())
            except Exception as e:
                self.log(f"[error] reading CSV: {e}")
        # Text
        txt = self.calls_text.get("1.0","end").strip()
        if txt:
            parts = [x.strip() for x in (txt.replace(",", "\n")).splitlines()]
            calls.extend([c for c in parts if c])

        # Dedupe, validate
        out, seen = [], set()
        for c in calls:
            cu = c.upper()
            if CALL_RE.match(cu) and cu not in seen:
                seen.add(cu); out.append(cu)
        return out

    def current_counties(self):
        sel = self.county_list.curselection()
        return [self.county_list.get(i) for i in sel]

    # ----- Actions -----
    def run_action(self):
        if not self.session_key:
            messagebox.showinfo("QRZ", "Please sign into QRZ first.")
            return
        if self.worker and self.worker.is_alive():
            messagebox.showinfo("Running", "Already running.")
            return
        mode = self.mode.get()
        calls = self.gather_callsigns() if mode=="calls" else []
        st = ""
        ctys = []
        if mode == "state":
            disp = self.state_var.get().strip()
            if not disp:
                messagebox.showinfo("State", "Choose a state.")
                return
            st = state_abbrev_from_display(disp)
            ctys = self.current_counties()
            if not calls and not st:
                messagebox.showinfo("Input", "Provide calls or choose a state.")
                return
        # Start worker
        self.records = []
        total = len(calls) if mode=="calls" else 0  # unknown yet for state
        self.progress["value"] = 0
        self.progress["maximum"] = max(1, total)
        self.status_var.set("Starting...")
        if mode=="calls":
            self.log(f"[info] Mode A: {len(calls)} calls")
        else:
            self.log(f"[info] Mode B: {st} / {len(ctys) if ctys else 'all counties'}")
        self.worker = Harvester(
            mode=mode,
            session_key=self.session_key,
            callsigns=calls,
            state=st,
            counties=ctys,
            geocode_mode=self.gc_mode.get(),
            google_key=self.google_var.get().strip(),
            nominatim_email="you@example.com",
            out_q=self.q,
            relogin_cb=self.relogin_cb,
            verbose=self.verbose.get(),
        )
        self.worker.start()

    def stop(self):
        if self.worker and self.worker.is_alive():
            self.worker.stop()
            self.status_var.set("Stopping...")
            self.log("[info] Stop requested")

    def poll_queue(self):
        try:
            while True:
                typ, payload = self.q.get_nowait()
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

    # ----- FCC Test -----
    def test_fcc(self):
        disp = self.state_var.get().strip()
        if not disp:
            messagebox.showinfo("State", "Choose a state first.")
            return
        st = state_abbrev_from_display(disp)
        counties = self.current_counties()
        self.log(f"[info] Test FCC: State={st}  County filter={counties or 'NONE'}")
        # Try first page only to check connectivity and schema
        params = {"format":"json","state":st,"status":"Active","radioServiceCode":"HA,HV","pageNum":1,"pageSize":50}
        url = FCC_LV_BASE + "?" + "&".join(f"{k}={requests.utils.quote(str(v))}" for k,v in params.items())
        self.log(f"[info] FCC URL: {url}")
        try:
            r = HTTP.get(FCC_LV_BASE, params=params, timeout=20); r.raise_for_status()
            j = r.json()
            status = j.get("status")
            lic = j.get("Licenses") or {}
            rows = lic.get("License") if isinstance(lic, dict) else None
            n = len(rows) if isinstance(rows, list) else 0
            self.log(f"[info] FCC status={status} rows={n}")
            if counties and rows:
                rows2 = fcc_filter_by_counties(rows, counties)
                self.log(f"[info] County-filtered rows (page 1 preview): {len(rows2)}")
        except Exception as e:
            self.log(f"[error] Test FCC: {e}")

    # ----- Export -----
    def export_csv(self):
        if not self.records:
            messagebox.showinfo("No data", "No results to export.")
            return
        p = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")])
        if not p: return
        preferred = ["callsign","name","street","city","state","county","zip","grid","email","address","lat","lon"]
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
            self.log(f"[error] CSV export: {e}")

    def export_kml(self):
        if not self.records:
            messagebox.showinfo("No data", "No results to export.")
            return
        p = filedialog.asksaveasfilename(defaultextension=".kml", filetypes=[("KML","*.kml")])
        if not p: return
        k = simplekml.Kml()
        for r in self.records:
            try:
                lat = float(r.get("lat"))
                lon = float(r.get("lon"))
            except Exception:
                continue
            nm = r.get("callsign","")
            desc = r.get("address","")
            k.newpoint(name=nm, coords=[(lon,lat)], description=desc)
        try:
            k.save(p)
            self.log(f"[info] KML saved: {p}")
        except Exception as e:
            self.log(f"[error] KML save: {e}")

    def export_html(self):
        if not self.records:
            messagebox.showinfo("No data", "No results to export.")
            return
        p = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML","*.html")])
        if not p: return
        pts = []
        for r in self.records:
            try:
                pts.append({
                    "callsign": r.get("callsign",""),
                    "lat": float(r.get("lat")),
                    "lon": float(r.get("lon")),
                    "address": r.get("address",""),
                })
            except Exception:
                continue
        if not pts:
            messagebox.showinfo("No geocoded points", "No latitude/longitude data available.")
            return
        lats = [p["lat"] for p in pts]; lons = [p["lon"] for p in pts]
        min_lat, max_lat = min(lats), max(lats)
        min_lon, max_lon = min(lons), max(lons)
        clat = (min_lat + max_lat)/2.0
        clon = (min_lon + max_lon)/2.0

        gm_key = self.google_var.get().strip()
        if gm_key:
            markers_js = [f"new google.maps.Marker({{position:{{lat:{pt['lat']},lng:{pt['lon']}}},map:map,title:{json.dumps(pt['callsign'])}}});" for pt in pts]
            html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Map</title>
<style>html,body,#map{{height:100%;margin:0;padding:0}}</style></head>
<body><div id="map"></div>
<script src="https://maps.googleapis.com/maps/api/js?key={gm_key}"></script>
<script>
function initMap(){{
  var map=new google.maps.Map(document.getElementById('map'),{{zoom:8,center:{{lat:{clat},lng:{clon}}}}});
  var bounds=new google.maps.LatLngBounds(new google.maps.LatLng({min_lat},{min_lon}), new google.maps.LatLng({max_lat},{max_lon}));
  {''.join(markers_js)}
  map.fitBounds(bounds);
}}
window.onload=initMap;
</script></body></html>"""
        else:
            mk = []
            for pt in pts:
                popup = json.dumps(f"{pt['callsign']}\n{pt['address']}").replace("\\n","<br/>")
                mk.append(f"L.marker([{pt['lat']},{pt['lon']}]).addTo(map).bindPopup({popup});")
            html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Map</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet/dist/leaflet.css"/>
<style>html,body,#map{{height:100%;margin:0;padding:0}}</style></head>
<body><div id="map"></div>
<script src="https://unpkg.com/leaflet/dist/leaflet.js"></script>
<script>
var map=L.map('map'); var b=L.latLngBounds([[{min_lat},{min_lon}],[{max_lat},{max_lon}]]);
map.fitBounds(b);
L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png',{{maxZoom:19,attribution:'© OpenStreetMap contributors'}}).addTo(map);
{''.join(mk)}
</script></body></html>"""

        try:
            with open(p,"w",encoding="utf-8") as fh: fh.write(html)
            self.log(f"[info] HTML map saved: {p}")
        except Exception as e:
            self.log(f"[error] HTML save: {e}")

# ---------- main ----------
def main():
    root = tk.Tk()
    app = App(root)
    root.mainloop()

if __name__ == "__main__":
    main()
