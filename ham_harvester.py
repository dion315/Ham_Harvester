#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ham Harvester
- QRZ public county harvester (no pasted URLs)
- QRZ XML API enrichment (name, address, grid, email)
- CSV export (+ optional KML if simplekml present)
- GUI (Tkinter) with verbose logging, progress, and Stop control
- Uses BeautifulSoup with built-in "html.parser" (no lxml dependency)
- Robust county index parsing (mode=county) and state filtering
- County page pagination + resilient callsign scraping
- Modes:
    A) Call list or CSV of calls
    B) State + one/more counties (or All counties)
- Quick Self-Test button on the Counties tab
"""
import csv
import os
import re
import sys
import time
import queue
import threading
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs

# ---- Minimal deps check (we install only if inside a venv) -------------------
def in_venv() -> bool:
    return (
        hasattr(sys, "real_prefix") or
        (hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix) or
        os.environ.get("VIRTUAL_ENV")
    ) is not None

def ensure_packages(pkgs: List[str]):
    missing = []
    for p in pkgs:
        try:
            __import__(p)
        except Exception:
            missing.append(p)
    if missing:
        print(f"[INFO] Missing packages: {missing}")
        if in_venv():
            print("[INFO] Attempting to install missing packages into the current environment...")
            try:
                import subprocess
                subprocess.check_call([sys.executable, "-m", "pip", "install", *missing])
                for p in missing:
                    print(f"[INSTALLED] {p}")
            except Exception as e:
                print(f"[ERROR] Could not install {missing}: {e}")
        else:
            print("[WARN] Not in a virtualenv; please install manually:")
            print(f"       {sys.executable} -m pip install " + " ".join(missing))

ensure_packages(["requests", "bs4"])
# Optional
try:
    import simplekml  # type: ignore
    HAVE_KML = True
except Exception:
    HAVE_KML = False

import requests
from bs4 import BeautifulSoup

# ---- Constants ---------------------------------------------------------------
QRZ_WEB_BASE = "https://www.qrz.com/"
QRZ_DB_PATH = "db"
QRZ_XML_LOGIN = "https://xmldata.qrz.com/xml/current/?"
DEFAULT_UA = "HamHarvester/1.0 (+https://example.local)"

ALL_STATES = {
    "AL":"Alabama","AK":"Alaska","AZ":"Arizona","AR":"Arkansas","CA":"California",
    "CO":"Colorado","CT":"Connecticut","DE":"Delaware","DC":"District of Columbia",
    "FL":"Florida","GA":"Georgia","HI":"Hawaii","ID":"Idaho","IL":"Illinois",
    "IN":"Indiana","IA":"Iowa","KS":"Kansas","KY":"Kentucky","LA":"Louisiana",
    "ME":"Maine","MD":"Maryland","MA":"Massachusetts","MI":"Michigan","MN":"Minnesota",
    "MS":"Mississippi","MO":"Missouri","MT":"Montana","NE":"Nebraska","NV":"Nevada",
    "NH":"New Hampshire","NJ":"New Jersey","NM":"New Mexico","NY":"New York","NC":"North Carolina",
    "ND":"North Dakota","OH":"Ohio","OK":"Oklahoma","OR":"Oregon","PA":"Pennsylvania",
    "RI":"Rhode Island","SC":"South Carolina","SD":"South Dakota","TN":"Tennessee",
    "TX":"Texas","UT":"Utah","VT":"Vermont","VA":"Virginia","WA":"Washington",
    "WV":"West Virginia","WI":"Wisconsin","WY":"Wyoming","AS":"American Samoa",
    "GU":"Guam","MP":"Northern Mariana Islands","PR":"Puerto Rico","VI":"U.S. Virgin Islands"
}

CALL_RE = re.compile(r"^[A-Z0-9]{1,2}\d[A-Z0-9]{1,3}$")

# ---- HTTP helpers ------------------------------------------------------------
def new_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": DEFAULT_UA})
    s.timeout = 20
    return s

def get_html(sess: requests.Session, url: str, params: Optional[Dict]=None, method: str="GET") -> str:
    if method.upper() == "GET":
        r = sess.get(url, params=params)
    else:
        r = sess.post(url, data=params)
    r.raise_for_status()
    return r.text

# ---- QRZ XML API -------------------------------------------------------------
@dataclass
class QrzAuth:
    session_key: Optional[str] = None
    using_xml: bool = False

def qrz_xml_login(user: str, password: str) -> QrzAuth:
    """
    Returns QrzAuth with session_key if successful, else using_xml=False.
    """
    sess = new_session()
    params = {"username": user, "password": password}
    try:
        txt = get_html(sess, QRZ_XML_LOGIN, params=params, method="GET")
        # naive parse for <Key>...</Key>
        m = re.search(r"<Key>([^<]+)</Key>", txt)
        if m:
            return QrzAuth(session_key=m.group(1), using_xml=True)
    except Exception:
        pass
    return QrzAuth(session_key=None, using_xml=False)

def qrz_xml_lookup(session_key: str, callsign: str) -> Dict[str, str]:
    """
    Lookup a callsign via QRZ XML. Returns dict with desired fields; missing fields blank.
    """
    sess = new_session()
    params = {"s": session_key, "callsign": callsign}
    out = {
        "callsign": callsign,
        "name": "",
        "street": "",
        "city": "",
        "state": "",
        "county": "",
        "zip": "",
        "grid": "",
        "email": ""
    }
    try:
        txt = get_html(sess, QRZ_XML_LOGIN, params=params, method="GET")
        # minimal pulls (avoid full xml parsing to keep deps light)
        def g(tag):
            m = re.search(fr"<{tag}>([^<]*)</{tag}>", txt, re.I)
            return m.group(1).strip() if m else ""
        out["name"] = g("fname") + (" " if g("fname") and g("name") else "") + g("name")
        out["street"] = g("addr1") or g("addr2")
        out["city"] = g("addr2") if out["street"] else g("addr3")
        out["state"] = g("state")
        out["zip"] = g("zip")
        out["grid"] = g("grid")
        out["email"] = g("email")
        # QRZ sometimes has <county>Madison</county>
        out["county"] = g("county")
    except Exception:
        pass
    return out

# ---- QRZ county index & results scraping (public site) -----------------------
def parse_fips_county_links(html_text: str) -> List[Dict[str, str]]:
    """
    Parse anchors like:
      <a href="https://www.qrz.com/db?fips=36053">Madison, New York</a>
    Returns list of dicts: {fips, county, state, url, label}
    """
    soup = BeautifulSoup(html_text, "html.parser")
    out: List[Dict[str, str]] = []
    seen = set()

    for a in soup.select('a[href*="db?fips="]'):
        href = a.get("href", "")
        m = re.search(r"[?&]fips=(\d{5})\b", href)
        if not m:
            continue
        fips = m.group(1)
        label = (a.get_text() or "").strip()
        county, state = (label, "")
        if "," in label:
            county, state = [p.strip() for p in label.split(",", 1)]
        url = urljoin(QRZ_WEB_BASE, href)
        key = (fips, county, state)
        if key in seen:
            continue
        seen.add(key)
        out.append({"fips": fips, "county": county, "state": state, "url": url, "label": label})
    return out

def fetch_state_counties(sess: requests.Session, state_abbrev: str) -> List[Dict[str, str]]:
    """
    Loads the global county index (mode=county) and filters to the chosen state.
    """
    full = ALL_STATES.get(state_abbrev.upper())
    if not full:
        return []
    url = urljoin(QRZ_WEB_BASE, QRZ_DB_PATH)
    payload = {"query": "*", "cs": "*", "sel": "", "cmd": "Search", "mode": "county"}
    html_text = get_html(sess, url, params=payload, method="GET")
    items_all = parse_fips_county_links(html_text)

    target = full.lower().strip()
    filtered: List[Dict[str, str]] = []
    for it in items_all:
        label = (it.get("label") or "").lower()
        st_in_field = (it.get("state") or "").lower().strip()
        if st_in_field == target:
            filtered.append(it)
        elif label.endswith(", " + target):
            filtered.append(it)
        elif (", " + target) in label:
            filtered.append(it)
    return filtered or []

def extract_calls_from_page(html_text: str) -> Tuple[List[str], Optional[str]]:
    """
    Find calls on a county result page; return (calls, next_url or None)
    """
    soup = BeautifulSoup(html_text, "html.parser")

    calls = set()

    # 1) obvious: links to /db/CALL or /lookup/CALL
    for a in soup.find_all("a", href=True):
        href = a["href"]
        # Normalize
        if href.startswith("//"):
            href = "https:" + href
        url = urljoin(QRZ_WEB_BASE, href)

        # Extract callsign from /db/<CALL> or /lookup/<CALL>
        p = urlparse(url)
        if p.path.startswith("/db/") or p.path.startswith("/lookup/"):
            call = p.path.split("/")[-1].upper()
            if CALL_RE.match(call):
                calls.add(call)
        else:
            # Sometimes links like ?callsign=... appear
            qs = parse_qs(p.query)
            for k, vs in qs.items():
                for v in vs:
                    vv = v.upper()
                    if CALL_RE.match(vv):
                        calls.add(vv)

    # 2) fallback: scan table cells for ALL CAPS calls
    if not calls:
        text = soup.get_text(" ", strip=True)
        for token in re.findall(r"[A-Z0-9]{1,2}\d[A-Z0-9]{1,3}", text):
            tok = token.upper()
            if CALL_RE.match(tok):
                calls.add(tok)

    # Next-page link discovery
    next_url = None
    # rel="next"
    a_rel = soup.find("a", attrs={"rel": lambda v: v and "next" in v})
    if a_rel and a_rel.get("href"):
        next_url = urljoin(QRZ_WEB_BASE, a_rel["href"])
    else:
        # by label
        for a in soup.find_all("a", href=True):
            t = (a.get_text() or "").strip().lower()
            if t in {"next", "»", "›", "next ›", "next »"}:
                next_url = urljoin(QRZ_WEB_BASE, a["href"])
                break

    return sorted(calls), next_url

def harvest_county_calls(sess: requests.Session, county_url: str, stop_ev: threading.Event, log_fn) -> List[str]:
    """
    Follow pagination over a county listing, collect calls.
    """
    calls: List[str] = []
    url = county_url
    page = 1
    seen_pages = set()
    while url and not stop_ev.is_set():
        if url in seen_pages:
            log_fn(f"[warn] Looping pagination detected; breaking.")
            break
        seen_pages.add(url)

        try:
            html = get_html(sess, url, method="GET")
        except Exception as e:
            log_fn(f"[error] County page fetch failed (page {page}): {e}")
            break

        found, next_url = extract_calls_from_page(html)
        log_fn(f"[info] Page {page}: +{len(found)} call(s)")
        calls.extend([c for c in found if c not in calls])

        url = next_url
        page += 1
        time.sleep(0.3)  # be polite
    return calls

# ---- KML (optional) ----------------------------------------------------------
def export_kml(recs: List[Dict[str, str]], path: str):
    if not HAVE_KML:
        return
    kml = simplekml.Kml()
    for r in recs:
        name = r.get("callsign", "")
        addr = ", ".join(filter(None, [r.get("street",""), r.get("city",""), r.get("state",""), r.get("zip","")]))
        pm = kml.newpoint(name=name, description=addr)
        # No geocode here (would need external service); KML will at least list entries.
    kml.save(path)

# ---- GUI ---------------------------------------------------------------------
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Ham Harvester")
        self.root.geometry("950x650")

        # State
        self.auth = QrzAuth()
        self.stop_ev = threading.Event()
        self.worker: Optional[threading.Thread] = None
        self.log_q: "queue.Queue[str]" = queue.Queue()
        self.state_counties: Dict[str, List[Dict[str, str]]] = {}

        # UI
        self.build_ui()

        # Prompt login/API key first
        self.root.after(200, self.prompt_login)

        # log pump
        self.root.after(100, self.flush_logs)

    # ---------- UI building ----------
    def build_ui(self):
        main = ttk.Frame(self.root, padding=8)
        main.pack(fill="both", expand=True)

        # Top controls
        top = ttk.Frame(main)
        top.pack(fill="x")
        self.btn_stop = ttk.Button(top, text="Stop", command=self.stop, state="disabled")
        self.btn_stop.pack(side="right", padx=4)
        self.btn_run = ttk.Button(top, text="Run", command=self.run_action)
        self.btn_run.pack(side="right", padx=4)

        # Notebook
        nb = ttk.Notebook(main)
        nb.pack(fill="both", expand=True, pady=(6,0))

        # Mode A tab (calls)
        self.tab_calls = ttk.Frame(nb)
        nb.add(self.tab_calls, text="Mode A: Calls/CSV")
        self.build_tab_calls(self.tab_calls)

        # Mode B tab (counties)
        self.tab_counties = ttk.Frame(nb)
        nb.add(self.tab_counties, text="Mode B: State/Counties")
        self.build_tab_counties(self.tab_counties)

        # Bottom: output + log
        bottom = ttk.Frame(main)
        bottom.pack(fill="both", expand=True)

        out_frame = ttk.LabelFrame(bottom, text="Output Options")
        out_frame.pack(fill="x", pady=6)
        self.out_csv_var = tk.StringVar(value="output.csv")
        ttk.Label(out_frame, text="CSV path:").grid(row=0, column=0, sticky="w", padx=6, pady=4)
        ttk.Entry(out_frame, textvariable=self.out_csv_var, width=50).grid(row=0, column=1, sticky="w", padx=6, pady=4)
        ttk.Button(out_frame, text="Browse...", command=self.pick_csv).grid(row=0, column=2, padx=6, pady=4)
        self.kml_enable = tk.BooleanVar(value=False)
        ttk.Checkbutton(out_frame, text="Also write KML (simple list)", variable=self.kml_enable).grid(row=0, column=3, padx=8)

        # Log
        log_frame = ttk.LabelFrame(bottom, text="Log")
        log_frame.pack(fill="both", expand=True)
        self.log_text = tk.Text(log_frame, height=14, wrap="word")
        self.log_text.pack(fill="both", expand=True)
        self.log("[info] Ready.")

    def build_tab_calls(self, parent: ttk.Frame):
        frm = ttk.Frame(parent, padding=8)
        frm.pack(fill="both", expand=True)

        self.calls_in_var = tk.StringVar()
        ttk.Label(frm, text="Call(s), comma/space-separated:").grid(row=0, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.calls_in_var, width=60).grid(row=1, column=0, sticky="w", pady=4)

        ttk.Separator(frm, orient="horizontal").grid(row=2, column=0, sticky="ew", pady=6)

        csv_row = ttk.Frame(frm)
        csv_row.grid(row=3, column=0, sticky="w")
        self.csv_path_var = tk.StringVar()
        ttk.Label(csv_row, text="Or CSV with column 'callsign':").pack(side="left")
        ttk.Entry(csv_row, textvariable=self.csv_path_var, width=50).pack(side="left", padx=6)
        ttk.Button(csv_row, text="Choose...", command=self.pick_calls_csv).pack(side="left")

    def build_tab_counties(self, parent: ttk.Frame):
        frm = ttk.Frame(parent, padding=8)
        frm.pack(fill="both", expand=True)

        # State select
        row1 = ttk.Frame(frm)
        row1.pack(fill="x")
        ttk.Label(row1, text="State:").pack(side="left")
        self.state_var = tk.StringVar()
        st = ttk.Combobox(row1, textvariable=self.state_var, width=6, state="readonly",
                          values=sorted(ALL_STATES.keys()))
        st.pack(side="left", padx=6)
        ttk.Button(row1, text="Load counties", command=self.load_counties).pack(side="left", padx=6)

        # County list
        mid = ttk.Frame(frm)
        mid.pack(fill="both", expand=True, pady=(8,4))
        ttk.Label(mid, text="Counties (select one or more; empty = ALL):").pack(anchor="w")
        self.counties_listbox = tk.Listbox(mid, height=12, selectmode="extended")
        self.counties_listbox.pack(fill="both", expand=True)

        # Quick Self-Test
        row2 = ttk.Frame(frm)
        row2.pack(fill="x")
        ttk.Button(row2, text="Quick Self-Test (parse county page for sample)",
                   command=self.quick_self_test).pack(side="left", pady=6)

    # ---------- Small helpers ----------
    def pick_csv(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                            filetypes=[("CSV","*.csv")],
                                            initialfile=self.out_csv_var.get() or "output.csv")
        if path:
            self.out_csv_var.set(path)

    def pick_calls_csv(self):
        path = filedialog.askopenfilename(filetypes=[("CSV","*.csv")])
        if path:
            self.csv_path_var.set(path)

    def log(self, msg: str):
        stamp = time.strftime("[%Y-%m-%d %H:%M:%S]")
        self.log_q.put(f"{stamp} {msg}")

    def flush_logs(self):
        try:
            while True:
                line = self.log_q.get_nowait()
                self.log_text.insert("end", line + "\n")
                self.log_text.see("end")
        except queue.Empty:
            pass
        self.root.after(100, self.flush_logs)

    # ---------- Login prompt ----------
    def prompt_login(self):
        dlg = tk.Toplevel(self.root)
        dlg.title("QRZ Login / API Key")
        dlg.transient(self.root)
        dlg.grab_set()

        ttk.Label(dlg, text="Provide either QRZ XML username/password OR an existing XML session key.\n"
                            "If you only want to scrape calls (no enrichment), leave all blank.",
                  justify="left").grid(row=0, column=0, columnspan=2, padx=10, pady=8, sticky="w")

        u_var = tk.StringVar()
        p_var = tk.StringVar()
        k_var = tk.StringVar()

        ttk.Label(dlg, text="User:").grid(row=1, column=0, sticky="e", padx=6, pady=2)
        ttk.Entry(dlg, textvariable=u_var, width=30).grid(row=1, column=1, sticky="w", padx=6)
        ttk.Label(dlg, text="Pass:").grid(row=2, column=0, sticky="e", padx=6, pady=2)
        ttk.Entry(dlg, textvariable=p_var, width=30, show="•").grid(row=2, column=1, sticky="w", padx=6)
        ttk.Label(dlg, text="XML Session Key:").grid(row=3, column=0, sticky="e", padx=6, pady=2)
        ttk.Entry(dlg, textvariable=k_var, width=30).grid(row=3, column=1, sticky="w", padx=6)

        def do_ok():
            user = u_var.get().strip()
            pw = p_var.get().strip()
            key = k_var.get().strip()
            if key:
                self.auth = QrzAuth(session_key=key, using_xml=True)
                self.log("[info] Using provided QRZ XML session key.")
            elif user and pw:
                self.log(f"[info] Logging in to QRZ as {user} ...")
                a = qrz_xml_login(user, pw)
                if a.using_xml:
                    self.auth = a
                    self.log("[info] QRZ session key obtained.")
                else:
                    self.log("[warn] QRZ XML login failed; proceeding without enrichment.")
            else:
                self.log("[info] Proceeding without QRZ XML enrichment.")
            dlg.destroy()

        ttk.Button(dlg, text="OK", command=do_ok).grid(row=4, column=0, columnspan=2, pady=8)

        self.root.wait_window(dlg)

    # ---------- Counties ----------
    def load_counties(self):
        st = (self.state_var.get() or "").upper().strip()
        if not st or st not in ALL_STATES:
            messagebox.showerror("State", "Choose a valid state.")
            return
        try:
            self.log(f"[info] Loading counties for {st} ...")
            sess = new_session()
            items = fetch_state_counties(sess, st)
            total = len(items)
            self.log(f"[info] County index filtered to {st}: {total} item(s)")
            items = sorted(items, key=lambda d: d["county"])

            self.state_counties[st] = items
            self.counties_listbox.delete(0, "end")
            for it in items:
                self.counties_listbox.insert("end", it["county"])

            if total == 0:
                self.log("[warn] No counties matched this state. "
                         "The QRZ index page may have shifted format or is temporarily incomplete.")
            else:
                self.log(f"[info] Counties loaded: {total}")
        except Exception as e:
            self.log(f"[error] Could not load counties: {e}")

    def quick_self_test(self):
        st = (self.state_var.get() or "").upper().strip()
        if not st or st not in self.state_counties:
            messagebox.showinfo("Self-Test", "Load counties first.")
            return
        items = self.state_counties[st]
        if not items:
            messagebox.showinfo("Self-Test", "No counties loaded.")
            return
        sample = items[0]
        url = sample["url"]
        self.log(f"[info] Self-Test: fetching sample county page → {sample['county']}, {st}")
        try:
            sess = new_session()
            html = get_html(sess, url, method="GET")
            calls, next_url = extract_calls_from_page(html)
            self.log(f"[info] Self-Test: extracted {len(calls)} call(s) from first page; next={bool(next_url)}")
            if calls[:10]:
                self.log("[info] Sample calls: " + ", ".join(calls[:10]))
        except Exception as e:
            self.log(f"[error] Self-Test failed: {e}")

    # ---------- Run / Stop ----------
    def run_action(self):
        if self.worker and self.worker.is_alive():
            messagebox.showinfo("Busy", "A job is already running. Press Stop to cancel.")
            return
        self.stop_ev.clear()
        self.btn_run.config(state="disabled")
        self.btn_stop.config(state="normal")
        # Decide mode by presence of calls input or CSV
        calls_raw = self.calls_in_var.get().strip()
        csv_in = self.csv_path_var.get().strip()
        if calls_raw or csv_in:
            self.worker = threading.Thread(target=self.run_mode_a, daemon=True)
        else:
            self.worker = threading.Thread(target=self.run_mode_b, daemon=True)
        self.worker.start()

    def stop(self):
        self.stop_ev.set()
        self.log("[info] Stop requested.")
        # UI buttons will be flipped back by the thread's finally block

    # ---------- Mode A: direct calls / CSV ----------
    def run_mode_a(self):
        try:
            self.log("[info] Mode A: processing calls")
            calls = []
            # parse manual
            if self.calls_in_var.get().strip():
                text = self.calls_in_var.get().upper()
                for tok in re.split(r"[,\s]+", text):
                    t = tok.strip().upper()
                    if CALL_RE.match(t):
                        calls.append(t)
            # parse CSV
            if self.csv_path_var.get().strip():
                path = self.csv_path_var.get().strip()
                if os.path.isfile(path):
                    with open(path, newline="", encoding="utf-8") as f:
                        rdr = csv.DictReader(f)
                        for row in rdr:
                            c = (row.get("callsign") or "").strip().upper()
                            if CALL_RE.match(c):
                                calls.append(c)
                else:
                    self.log(f"[warn] CSV not found: {path}")
            calls = sorted(set(calls))
            self.log(f"[info] {len(calls)} unique call(s) to process.")

            out = []
            if self.auth.using_xml and self.auth.session_key:
                for i, c in enumerate(calls, 1):
                    if self.stop_ev.is_set():
                        break
                    rec = qrz_xml_lookup(self.auth.session_key, c)
                    out.append(rec)
                    if i % 25 == 0:
                        self.log(f"[info] Progress: {i}/{len(calls)}")
                    time.sleep(0.15)
            else:
                # No enrichment; just output calls
                out = [{"callsign": c} for c in calls]

            self.write_outputs(out)
            self.log(f"[info] Finished: {len(out)} record(s)")
        except Exception as e:
            self.log(f"[error] Mode A failed: {e}")
        finally:
            self.btn_run.config(state="normal")
            self.btn_stop.config(state="disabled")

    # ---------- Mode B: state + counties ----------
    def run_mode_b(self):
        try:
            st = (self.state_var.get() or "").upper().strip()
            if not st or st not in ALL_STATES:
                self.log("[error] Choose a valid state on the Counties tab.")
                return
            items = self.state_counties.get(st)
            if not items:
                self.log("[error] Load counties first.")
                return

            sel_indices = list(self.counties_listbox.curselection())
            if sel_indices:
                chosen = [items[i] for i in sel_indices]
            else:
                chosen = items  # ALL
            self.log(f"[info] Mode B: {st} / {len(chosen)} county(ies)")

            sess = new_session()
            calls: List[str] = []
            for idx, county in enumerate(chosen, 1):
                if self.stop_ev.is_set():
                    break
                self.log(f"[info] [{idx}/{len(chosen)}] Harvesting {county['county']}, {st} ...")
                cs = harvest_county_calls(sess, county["url"], self.stop_ev, self.log)
                before = len(calls)
                for c in cs:
                    if c not in calls:
                        calls.append(c)
                self.log(f"[info] Added {len(calls) - before} new call(s); total={len(calls)}")

            calls = sorted(calls)
            self.log(f"[info] Unique calls gathered: {len(calls)}")

            # Enrich
            out = []
            if self.auth.using_xml and self.auth.session_key:
                for i, c in enumerate(calls, 1):
                    if self.stop_ev.is_set():
                        break
                    rec = qrz_xml_lookup(self.auth.session_key, c)
                    out.append(rec)
                    if i % 25 == 0:
                        self.log(f"[info] Enrich progress: {i}/{len(calls)}")
                    time.sleep(0.15)
            else:
                out = [{"callsign": c} for c in calls]

            self.write_outputs(out)
            self.log(f"[info] Finished: {len(out)} record(s)")
        except Exception as e:
            self.log(f"[error] Mode B failed: {e}")
        finally:
            self.btn_run.config(state="normal")
            self.btn_stop.config(state="disabled")

    # ---------- Write outputs ----------
    def write_outputs(self, rows: List[Dict[str, str]]):
        if not rows:
            self.log("[info] Nothing to write.")
            return
        # Order columns
        preferred = ["callsign","name","street","city","state","county","zip","grid","email"]
        present = set()
        for r in rows:
            present.update(r.keys())
        fieldnames = [k for k in preferred if k in present] + [k for k in sorted(present) if k not in preferred]

        out_csv = self.out_csv_var.get().strip() or "output.csv"
        with open(out_csv, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            for r in rows:
                w.writerow(r)
        self.log(f"[info] Wrote CSV: {out_csv}")

        if self.kml_enable.get():
            try:
                out_kml = os.path.splitext(out_csv)[0] + ".kml"
                export_kml(rows, out_kml)
                if HAVE_KML:
                    self.log(f"[info] Wrote KML: {out_kml}")
                else:
                    self.log("[warn] simplekml not installed; KML skipped.")
            except Exception as e:
                self.log(f"[error] KML export failed: {e}")

# ---- Main --------------------------------------------------------------------
def main():
    root = tk.Tk()
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except Exception:
        pass
    App(root)
    root.mainloop()

if __name__ == "__main__":
    main()
