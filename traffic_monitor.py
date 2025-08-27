# traffic_monitor.py
# MIT License
# Windows 11 network anomaly monitor with live UI + toast (optional) + packet snapshots + OSINT enrichment
# + PCAP export (Wireshark), JA3 TLS fingerprints, DNS query logging
# + Startup API key validation popup (every run)

import argparse, json, os, sys, time, threading, binascii, re, struct, hashlib
from datetime import datetime
from collections import defaultdict, deque

import psutil
import tkinter as tk
from tkinter import ttk, messagebox

# Optional deps (runtime-checked)
HAVE_PYDIVERT = HAVE_REQUESTS = HAVE_SCAPY = False
try:
    import pydivert  # WinDivert wrapper (Admin needed)
    HAVE_PYDIVERT = True
except Exception:
    pass
try:
    import requests
    HAVE_REQUESTS = True
except Exception:
    pass
try:
    # Only used to write pcaps if available. We also have a builtin writer fallback.
    from scapy.utils import wrpcap  # noqa: F401  (import presence check only)
    HAVE_SCAPY = True
except Exception:
    pass

# ---------------------------
# Paths pinned next to this script
# ---------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def HERE(*p):
    return os.path.join(SCRIPT_DIR, *p)

# ---------------------------
# Config
# ---------------------------
POLL_INTERVAL_SEC = 2
BASELINE_FILE     = HERE("baseline.json")
LOG_FILE          = HERE("suspicious_log.txt")
SNAPSHOT_DIR      = HERE("snapshots")
SNAPSHOT_PKTS     = 18       # capture up to N packets per flagged flow
SNAPSHOT_TIMEOUT  = 4.0      # seconds of capture per event
MAX_HEX_PER_PKT   = 768      # bytes of payload to dump per packet

# Heuristics / noise controls
SUPPRESS_ALERTS_DURING_LEARN = True
IGNORE_STATES = {"TIME_WAIT", "CLOSE_WAIT"}
IGNORE_LOCALHOST = True
IGNORE_REMOTE_PORTS_BASELINE = {53}
SUSPICIOUS_PORTS = set([3389, *range(5900,6000), 22,23,4444,1337,6969,135,139,445,5985,47001,1433,3306,5432,5555])
SUSPICIOUS_PROCS = {"powershell.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","certutil.exe","bitsadmin.exe","wmic.exe"}
SUSPICIOUS_PATH_HINTS = ["\\AppData\\Local\\Temp\\","\\AppData\\Roaming\\","\\Temp\\"]

# Beaconing
BEACON_WINDOW = 20
BEACON_MIN_EVENTS = 5
BEACON_MIN_PERIOD = 5
BEACON_MAX_PERIOD = 180
BEACON_MAX_JITTER = 1.25

# ---------------------------
# Util
# ---------------------------

def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def write_log(line):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def ensure_dir(p):
    if not os.path.isdir(p):
        os.makedirs(p, exist_ok=True)


def safe_proc_info(pid):
    name = exe = parent_name = "unknown"; ppid = None
    try:
        p = psutil.Process(pid)
        name = (p.name() or "unknown").lower()
        exe  = (p.exe()  or "unknown")
        parent = p.parent()
        if parent:
            ppid = parent.pid
            parent_name = (parent.name() or "unknown").lower()
    except Exception:
        pass
    return name, exe, ppid, parent_name


def signature_for_baseline(proc_name, exe, conn):
    rport = conn.raddr.port if conn.raddr else None
    return (proc_name, exe.lower(), rport)


def load_baseline(path):
    if not os.path.exists(path):
        return set()
    try:
        data = json.load(open(path, "r", encoding="utf-8"))
        return set(tuple(x) for x in data.get("signatures", []))
    except Exception:
        return set()


def save_baseline(path, sigs):
    data = {"signatures": [list(t) for t in sorted(sigs)]}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

# sanitize filename components (IPv6 etc.)

def safe_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s or "")

# ---------------------------
# Safe notifier wrapper (avoids win10toast WNDPROC crash)
# ---------------------------

class Notifier:
    def __init__(self, enable_toasts: bool):
        self.enable = bool(enable_toasts)
        self.toaster = None
        if self.enable:
            try:
                from win10toast import ToastNotifier
                self.toaster = ToastNotifier()
            except Exception:
                self.enable = False
                self.toaster = None

    def show(self, title: str, msg: str):
        if not self.enable or not self.toaster:
            return
        try:
            # Use non-threaded mode to avoid WNDPROC callback issues on some Python/pywin32 combos
            self.toaster.show_toast(title, msg, duration=5, threaded=False)
        except Exception:
            # Disable further toasts if this platform is unstable
            self.enable = False
            self.toaster = None

# ---------------------------
# TLS / HTTP / DNS parsers + JA3
# ---------------------------

# GREASE detector per RFC 8701

def _is_grease(v: int) -> bool:
    return ((v & 0x0f0f) == 0x0a0a) and ((v >> 8) & 0xff) == (v & 0xff)


def parse_tls_client_hello(payload: bytes):
    """Very light TLS ClientHello parser to pull SNI + ALPN + JA3."""
    out = {"sni": None, "alpn": [], "version": None, "ja3": None, "ja3_str": None}
    if len(payload) < 5 or payload[0] != 0x16:  # TLS record type: Handshake
        return {}
    rec_len = int.from_bytes(payload[3:5], "big")
    if 5 + rec_len > len(payload):
        return {}
    hs = payload[5:5+rec_len]
    if not hs or hs[0] != 0x01 or len(hs) < 4:  # Handshake type: ClientHello
        return {}

    # Handshake header
    hs_len = int.from_bytes(hs[1:4], "big")
    body = hs[4:4+hs_len]
    if len(body) < 34:
        return {}

    legacy_ver = int.from_bytes(body[0:2], "big")
    out["version"] = f"TLS {body[0]}.{body[1]}"
    i = 34  # skip random

    # session id
    sid_len = body[i]; i += 1 + sid_len

    # cipher suites
    if i + 2 > len(body):
        return out
    cs_len = int.from_bytes(body[i:i+2], "big"); i += 2
    ciphers = []
    for j in range(0, min(cs_len, max(0, len(body)-i)), 2):
        if i+j+2 <= len(body):
            v = int.from_bytes(body[i+j:i+j+2], "big")
            if not _is_grease(v):
                ciphers.append(str(v))
    i += cs_len

    # compression methods
    if i >= len(body):
        return out
    cm_len = body[i]; i += 1 + cm_len
    if i + 2 > len(body):
        return out

    # extensions
    ext_total = int.from_bytes(body[i:i+2], "big"); i += 2
    end = min(len(body), i + ext_total)
    extensions = []
    curves = []
    ecpf   = []
    while i + 4 <= end:
        etype = int.from_bytes(body[i:i+2], "big")
        elen  = int.from_bytes(body[i+2:i+4], "big")
        edata = body[i+4:i+4+elen]
        i += 4 + elen
        if not _is_grease(etype):
            extensions.append(str(etype))
        # SNI
        if etype == 0x00 and len(edata) >= 5 and edata[2] == 0x00:
            nlen = int.from_bytes(edata[3:5], "big")
            if 5+nlen <= len(edata):
                try:
                    out["sni"] = edata[5:5+nlen].decode("idna", errors="ignore")
                except Exception:
                    pass
        # ALPN
        if etype == 0x10 and len(edata) >= 3:
            try:
                j = 2
                while j < len(edata):
                    l = edata[j]; j += 1
                    out["alpn"].append(edata[j:j+l].decode("ascii","ignore"))
                    j += l
            except Exception:
                pass
        # Supported Groups (curves)
        if etype == 0x0a and len(edata) >= 2:
            glen = int.from_bytes(edata[0:2], "big")
            for k in range(0, min(glen, len(edata)-2), 2):
                v = int.from_bytes(edata[2+k:2+k+2], "big")
                if not _is_grease(v):
                    curves.append(str(v))
        # EC Point Formats
        if etype == 0x0b and len(edata) >= 1:
            flen = edata[0]
            for k in range(0, min(flen, len(edata)-1)):
                ecpf.append(str(edata[1+k]))

    ja3_fields = [str(legacy_ver), "-".join(ciphers), "-".join(extensions), "-".join(curves), "-".join(ecpf)]
    ja3_str = ",".join(ja3_fields)
    out["ja3_str"] = ja3_str
    out["ja3"] = hashlib.md5(ja3_str.encode("ascii", errors="ignore")).hexdigest()
    return out


# Minimal DNS decoder (queries only; handles compression pointers)

def _dns_read_name(buf: bytes, off: int, depth: int = 0):
    labels = []
    orig_off = off
    jumped = False
    for _ in range(128):  # safety
        if off >= len(buf):
            break
        l = buf[off]
        if l == 0:
            off += 1
            break
        # pointer
        if (l & 0xC0) == 0xC0:
            if off + 1 >= len(buf):
                break
            ptr = ((l & 0x3F) << 8) | buf[off+1]
            off += 2
            name, _ = _dns_read_name(buf, ptr, depth+1)
            labels.append(name)
            jumped = True
            break
        else:
            off += 1
            if off + l > len(buf):
                break
            labels.append(buf[off:off+l].decode("idna", "ignore"))
            off += l
    name = ".".join([x for x in labels if x])
    return name, (orig_off + (0 if jumped else (off - orig_off)))


def parse_dns_snippet(payload: bytes):
    if len(payload) < 12:
        return {}
    tid = int.from_bytes(payload[0:2], "big")
    flags = int.from_bytes(payload[2:4], "big")
    qd = int.from_bytes(payload[4:6], "big")
    # ns/ar ignored
    off = 12
    questions = []
    try:
        for _ in range(min(qd, 3)):
            qname, off2 = _dns_read_name(payload, off)
            if off2 + 4 > len(payload):
                break
            qtype = int.from_bytes(payload[off2:off2+2], "big")
            qclass = int.from_bytes(payload[off2+2:off2+4], "big")
            questions.append({"qname": qname, "qtype": qtype, "qclass": qclass})
            off = off2 + 4
    except Exception:
        pass
    qr = (flags >> 15) & 1
    return {"dns_id": tid, "qr": qr, "questions": questions}

# ---------------------------
# PCAP writer (uses scapy if present; else raw PCAP)
# ---------------------------

def write_pcap_from_raw(packets_with_ts, path):
    """packets_with_ts: list of (epoch_float, raw_bytes)"""
    if HAVE_SCAPY:
        try:
            from scapy.utils import RawPcapWriter
            writer = RawPcapWriter(path, linktype=101)  # LINKTYPE_RAW
            for ts, raw in packets_with_ts:
                sec = int(ts)
                usec = int((ts - sec) * 1_000_000)
                writer.write(raw, sec=sec, usec=usec)
            writer.close()
            return True
        except Exception:
            pass
    # Fallback: simple PCAP writer
    try:
        ensure_dir(os.path.dirname(path))
        with open(path, 'wb') as f:
            # Global header (little-endian)
            f.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 0xffff, 101))  # LINKTYPE_RAW
            for ts, raw in packets_with_ts:
                sec = int(ts)
                usec = int((ts - sec) * 1_000_000)
                f.write(struct.pack('<IIII', sec, usec, len(raw), len(raw)))
                f.write(raw)
        return True
    except Exception:
        return False

# ---------------------------
# OSINT enrichment + Keys loader + Startup validation
# ---------------------------

def load_keys():
    p = HERE("intel_keys.json")
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def check_api_keys(keys: dict, timeout=4.0):
    """
    Returns a dict:
      {
        'abuseipdb': {'configured': bool, 'ok': bool, 'status': 'OK/…', 'detail': str},
        'otx':       {...},
        'greynoise': {...},
        'requests':  {'installed': bool}
      }
    """
    status = {
        "requests": {"installed": HAVE_REQUESTS},
        "abuseipdb": {"configured": False, "ok": False, "status": "Not configured", "detail": ""},
        "otx":       {"configured": False, "ok": False, "status": "Not configured", "detail": ""},
        "greynoise": {"configured": False, "ok": False, "status": "Not configured", "detail": ""},
    }
    if not HAVE_REQUESTS:
        return status

    test_ip = "1.1.1.1"

    # AbuseIPDB
    ak = (keys or {}).get("abuseipdb_key") or ""
    if ak:
        status["abuseipdb"]["configured"] = True
        try:
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": test_ip, "maxAgeInDays": 30},
                headers={"Key": ak, "Accept": "application/json"},
                timeout=timeout,
            )
            if r.ok:
                j = r.json()
                ok = isinstance(j, dict) and "data" in j
                status["abuseipdb"].update(ok=ok, status=("OK" if ok else "Unexpected response"), detail=f"HTTP {r.status_code}")
            else:
                status["abuseipdb"].update(ok=False, status="HTTP error", detail=f"HTTP {r.status_code}")
        except Exception as e:
            status["abuseipdb"].update(ok=False, status="Network error", detail=str(e))

    # OTX
    oky = (keys or {}).get("otx_key") or ""
    if oky:
        status["otx"]["configured"] = True
        try:
            r = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{test_ip}/general",
                headers={"X-OTX-API-KEY": oky},
                timeout=timeout,
            )
            if r.ok:
                j = r.json()
                ok = isinstance(j, dict) and ("pulse_info" in j or "indicator" in j)
                status["otx"].update(ok=ok, status=("OK" if ok else "Unexpected response"), detail=f"HTTP {r.status_code}")
            else:
                status["otx"].update(ok=False, status="HTTP error", detail=f"HTTP {r.status_code}")
        except Exception as e:
            status["otx"].update(ok=False, status="Network error", detail=str(e))

    # GreyNoise Community
    gk = (keys or {}).get("greynoise_key") or ""
    if gk:
        status["greynoise"]["configured"] = True
        try:
            hdrs = {"Accept": "application/json", "key": gk}
            r = requests.get(f"https://api.greynoise.io/v3/community/{test_ip}", headers=hdrs, timeout=timeout)
            if r.ok:
                j = r.json()
                ok = isinstance(j, dict) and ("classification" in j or "noise" in j or "name" in j)
                status["greynoise"].update(ok=ok, status=("OK" if ok else "Unexpected response"), detail=f"HTTP {r.status_code}")
            else:
                status["greynoise"].update(ok=False, status="HTTP error", detail=f"HTTP {r.status_code}")
        except Exception as e:
            status["greynoise"].update(ok=False, status="Network error", detail=str(e))

    return status


def enrich_ip(ip: str, keys: dict):
    """Queries community/free TI if keys are present. Returns dict."""
    out = {"ip": ip, "sources": {}}
    if not HAVE_REQUESTS:
        return out

    # AbuseIPDB
    k = keys.get("abuseipdb_key") or ""
    if k:
        try:
            r = requests.get("https://api.abuseipdb.com/api/v2/check",
                             params={"ipAddress": ip, "maxAgeInDays": 90},
                             headers={"Key": k, "Accept": "application/json"}, timeout=5)
            if r.ok:
                j = r.json()
                data = j.get("data", {})
                out["sources"]["abuseipdb"] = {
                    "abuseConfidenceScore": data.get("abuseConfidenceScore"),
                    "countryCode": data.get("countryCode"),
                    "isp": data.get("isp"),
                    "totalReports": data.get("totalReports")
                }
        except Exception:
            pass

    # AlienVault OTX
    k = keys.get("otx_key") or ""
    if k:
        try:
            r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                             headers={"X-OTX-API-KEY": k}, timeout=5)
            if r.ok:
                j = r.json()
                out["sources"]["otx"] = {
                    "pulse_count": j.get("pulse_info", {}).get("count"),
                    "reputation": j.get("reputation"),
                    "asn": (j.get("asn") or {}).get("asn")
                }
        except Exception:
            pass

    # GreyNoise Community (key optional but recommended)
    gk = keys.get("greynoise_key") or ""
    try:
        hdrs = {"Accept":"application/json"}
        if gk:
            hdrs["key"] = gk
        url_try = [f"https://api.greynoise.io/v3/community/{ip}",
                   f"https://api.greynoise.io/v3/community/ip/{ip}",
                   f"https://api.greynoise.io/v2/noise/ip/{ip}"]
        for u in url_try:
            r = requests.get(u, headers=hdrs, timeout=5)
            if r.ok:
                j = r.json()
                out["sources"]["greynoise"] = {
                    "classification": j.get("classification") or j.get("noise"),
                    "name": j.get("name") or j.get("metadata",{}).get("name"),
                    "link": j.get("link") or j.get("permalink")
                }
                break
    except Exception:
        pass

    return out

# ---------------------------
# Suspicion logic
# ---------------------------

def is_suspicious(conn, proc_name, exe, parent_name, baseline_sigs, beacon_tracker, learn_mode=False):
    reasons = []

    if conn.status in IGNORE_STATES:
        return False, reasons
    if IGNORE_LOCALHOST and conn.raddr and (conn.raddr.ip in ("127.0.0.1","::1")):
        return False, reasons

    # baseline deviation (skip during learn or for DNS)
    if conn.raddr:
        rport = conn.raddr.port
        if (not learn_mode) and (rport not in IGNORE_REMOTE_PORTS_BASELINE):
            sig = signature_for_baseline(proc_name, exe, conn)
            if sig not in baseline_sigs:
                reasons.append("deviates_from_baseline")

    lport = conn.laddr.port if conn.laddr else None
    rport = conn.raddr.port if conn.raddr else None
    if (lport in SUSPICIOUS_PORTS) or (rport in SUSPICIOUS_PORTS):
        reasons.append("high_risk_port")

    if proc_name in SUSPICIOUS_PROCS:
        reasons.append("lolfbin_network_activity")

    exe_l = exe.lower()
    if any(hint.lower() in exe_l for hint in SUSPICIOUS_PATH_HINTS):
        reasons.append("unusual_exe_path")

    # beaconing
    if conn.raddr:
        key = (proc_name, exe_l, conn.raddr.ip, conn.raddr.port)
        ts_deque = beacon_tracker[key]
        if len(ts_deque) >= BEACON_MIN_EVENTS:
            intervals = [ts_deque[i]-ts_deque[i-1] for i in range(1, len(ts_deque))]
            if all(BEACON_MIN_PERIOD <= d <= BEACON_MAX_PERIOD for d in intervals):
                if intervals and (max(intervals)/max(1e-6,min(intervals))) <= BEACON_MAX_JITTER:
                    reasons.append("regular_beaconing_pattern")

    return (len(reasons) > 0), reasons

# ---------------------------
# Packet snapshot worker
# ---------------------------

def hexdump(b: bytes, maxlen=512):
    data = b[:maxlen]
    return binascii.hexlify(data).decode("ascii")


def build_filter(local_ip, local_port, remote_ip, remote_port, proto="tcp"):
    def is_ipv6(addr: str) -> bool:
        return ":" in addr and not addr.count(".") == 3
    if is_ipv6(local_ip) or is_ipv6(remote_ip):
        fam = "ipv6"
        sip = f"{fam}.SrcAddr == {remote_ip}"
        dip = f"{fam}.DstAddr == {local_ip}"
        rsip = f"{fam}.SrcAddr == {local_ip}"
        rdip = f"{fam}.DstAddr == {remote_ip}"
    else:
        fam = "ip"
        sip = f"{fam}.SrcAddr == {remote_ip}"
        dip = f"{fam}.DstAddr == {local_ip}"
        rsip = f"{fam}.SrcAddr == {local_ip}"
        rdip = f"{fam}.DstAddr == {remote_ip}"
    if proto == "tcp":
        return f"(tcp and {fam} and ((tcp.SrcPort == {remote_port} and {sip} and tcp.DstPort == {local_port} and {dip}) or (tcp.SrcPort == {local_port} and {rsip} and tcp.DstPort == {remote_port} and {rdip})))"
    else:
        return f"(udp and {fam} and ((udp.SrcPort == {remote_port} and {sip} and udp.DstPort == {local_port} and {dip}) or (udp.SrcPort == {local_port} and {rsip} and udp.DstPort == {remote_port} and {rdip})))"


def capture_snapshot(local_ip, local_port, remote_ip, remote_port, proto="tcp", timeout=SNAPSHOT_TIMEOUT, max_pkts=SNAPSHOT_PKTS, pcap_path=None):
    if not HAVE_PYDIVERT:
        return {"error":"pydivert not available / not admin"}
    filt = build_filter(local_ip, local_port, remote_ip, remote_port, proto)
    out = {"filter": filt, "packets": [], "pcap_path": None}
    raws = []
    try:
        with pydivert.WinDivert(filt) as w:
            w.sniff()  # set to sniffing mode
            start = time.time()
            while len(out["packets"]) < max_pkts and (time.time()-start) < timeout:
                pkt = w.recv()
                tsf = time.time()
                raws.append((tsf, bytes(pkt.raw)))
                meta = {
                    "ts": now_str(),
                    "inbound": pkt.direction == pydivert.Direction.INBOUND,
                    "iface": pkt.iface,
                    "ifsub": pkt.sub_iface,
                    "length": len(pkt.raw),
                    "payload_len": len(pkt.payload or b""),
                    "tcp_flags": getattr(pkt.tcp,'flags',None) if hasattr(pkt,'tcp') and pkt.tcp else None
                }
                pay = pkt.payload or b""

                # Protocol hints
                hints = {}
                if remote_port == 443 or local_port == 443:
                    hints.update(parse_tls_client_hello(pay))  # includes JA3 when CH observed
                elif remote_port == 80 or local_port == 80:
                    hints.update(parse_http_snippet(pay))
                elif remote_port == 53 or local_port == 53:
                    hints.update(parse_dns_snippet(pay))

                meta["hints"] = hints
                if pay:
                    meta["payload_hex_prefix"] = hexdump(pay, MAX_HEX_PER_PKT)
                out["packets"].append(meta)
    except Exception as e:
        out["error"] = f"{e}"

    # Write PCAP
    try:
        if pcap_path:
            ok = write_pcap_from_raw(raws, pcap_path)
        else:
            ok = False
        if ok:
            out["pcap_path"] = pcap_path
    except Exception:
        pass
    return out

# Basic HTTP request-line / host parser (for port 80)

def parse_http_snippet(payload: bytes):
    try:
        first = payload[:8]
        if first.startswith(b"GET ") or first.startswith(b"POST ") or first.startswith(b"PUT ") or first.startswith(b"HEAD ") or first.startswith(b"DELETE "):
            text = payload.split(b"\r\n\r\n",1)[0].decode("iso-8859-1","ignore")
            host = ""; path = ""
            lines = text.split("\r\n")
            if lines:
                parts = lines[0].split(" ")
                if len(parts) >= 2:
                    path = parts[1]
            for ln in lines[1:]:
                if ln.lower().startswith("host:"):
                    host = ln.split(":",1)[1].strip()
                    break
            return {"http_method": lines[0].split(" ")[0], "http_host": host, "http_path": path}
    except Exception:
        pass
    return {}

# ---------------------------
# GUI App
# ---------------------------

class NetMonitorApp:
    def __init__(self, args):
        self.args = args
        self.notifier = Notifier(enable_toasts=args.toasts)
        self.root = tk.Tk()
        self.root.title("Traffic Monitor — Active Network Traffic (Windows 11)")
        self.root.geometry("1240x560")

        self.status_var = tk.StringVar(value="Initializing…")
        ttk.Label(self.root, textvariable=self.status_var, anchor="w").pack(fill="x")

        cols = ("time","proc","pid","pproc","laddr","raddr","status","flags")
        self.tree = ttk.Treeview(self.root, columns=cols, show="headings", height=20)
        for c in cols:
            self.tree.heading(c, text=c.upper())
            self.tree.column(c, width=150 if c not in ("time","flags") else 200, anchor="w")
        self.tree.pack(fill="both", expand=True)

        self.baseline_sigs = load_baseline(self.args.baseline)
        self.learn_mode = self.args.learn > 0
        self.learn_deadline = time.time() + self.args.learn if self.learn_mode else None
        self.new_baseline_sigs = set(self.baseline_sigs)

        self.last_rows = set()
        self.beacon_tracker = defaultdict(lambda: deque(maxlen=BEACON_WINDOW))

        self.keys = load_keys()
        self.api_status = None  # filled after startup check
        ensure_dir(SNAPSHOT_DIR)

        # initial banner
        banner = []
        banner.append(f"LEARN: {'ON' if self.learn_mode else 'OFF'}{f' ({int(self.args.learn)}s)' if self.learn_mode else ''}")
        banner.append(f"Baseline: {os.path.abspath(self.args.baseline)}")
        banner.append(f"Capture: {'ON' if HAVE_PYDIVERT else 'OFF (install pydivert & run as Admin)'}")
        banner.append(f"PCAP: {'ON' if HAVE_PYDIVERT else 'OFF'} | JA3: {'ON' if HAVE_PYDIVERT else 'OFF'} | DNS: {'ON' if HAVE_PYDIVERT else 'OFF'}")
        banner.append(f"OSINT: {'Configured' if self.keys else 'Not configured'} (requests={'yes' if HAVE_REQUESTS else 'no'})")
        banner.append(f"Toasts: {'ON' if self.args.toasts else 'OFF'}")
        banner.append(f"Polling: {POLL_INTERVAL_SEC}s | Log: {os.path.abspath(LOG_FILE)}")
        self.status_var.set(" | ".join(banner))

        # Schedule key validation popup (every run)
        self.root.after(300, self.start_api_validation)

        # Start polling
        self.root.after(600, self.poll_once)
        self.root.mainloop()

    # ---- Startup API key validation ----
    def start_api_validation(self):
        # Run tests off the UI thread
        threading.Thread(target=self._validate_keys_worker, daemon=True).start()

    def _validate_keys_worker(self):
        if not self.keys:
            msg = "intel_keys.json not found or empty.\n\nOSINT enrichment is optional.\nPlace intel_keys.json next to traffic_monitor.py."
            self._popup_info("OSINT API Keys: Not configured", msg)
            self.api_status = {"requests":{"installed":HAVE_REQUESTS}}
            return
        sts = check_api_keys(self.keys, timeout=4.0)
        self.api_status = sts
        # Summarize
        lines = []
        if not sts.get("requests", {}).get("installed", False):
            lines.append("Python 'requests' not installed — OSINT disabled.")
        for name, label in [("abuseipdb","AbuseIPDB"), ("otx","AlienVault OTX"), ("greynoise","GreyNoise")]:
            s = sts.get(name, {})
            if not s.get("configured"):
                lines.append(f"{label}: not configured")
            else:
                ok = s.get("ok", False)
                stat = s.get("status", "")
                det = s.get("detail","")
                lines.append(f"{label}: {'OK' if ok else 'FAIL'} ({stat}{' - '+det if det else ''})")
        text = "API Key Connectivity Check\n\n" + "\n".join(lines)
        self._popup_info("OSINT API Keys — Status", text)
        # Update banner line with result
        ok_any = any(sts.get(k,{}).get("ok", False) for k in ("abuseipdb","otx","greynoise"))
        self._set_status_osint(ok_any)

    def _popup_info(self, title, message):
        try:
            # Toast (optional & safe)
            self.notifier.show(title, message[:64])
        except Exception:
            pass
        # Ensure shown on UI thread
        def _show():
            try:
                messagebox.showinfo(title, message, parent=self.root)
            except Exception:
                # fallback: put in status bar
                self.status_var.set(f"{self.status_var.get()} | {title}: {message.replace(os.linesep,' ')}")
        self.root.after(0, _show)

    def _set_status_osint(self, ok_any: bool):
        # Recompose status bar with OSINT signal
        parts = self.status_var.get().split(" | ")
        for i,p in enumerate(parts):
            if p.startswith("OSINT:"):
                parts[i] = f"OSINT: {'OK' if ok_any else 'Configured' if self.keys else 'Not configured'} (requests={'yes' if HAVE_REQUESTS else 'no'})"
                break
        self.status_var.set(" | ".join(parts))

    # ---- Toast helper ----
    def toast_alert(self, title, msg):
        try:
            self.notifier.show(title, msg)
        except Exception:
            pass

    # ---- Poller ----
    def poll_once(self):
        start = time.time()
        rows_now = set()
        suspicious_events = []

        try:
            conns = psutil.net_connections(kind="inet")
        except Exception as e:
            conns = []
            self.status_var.set(f"Error reading connections: {e}")

        # clear table
        for item in self.tree.get_children():
            self.tree.delete(item)

        pid_cache = {}
        for c in conns:
            if c.pid is None:
                proc_name, exe, ppid, parent_name = "system", "system", None, "n/a"
            else:
                if c.pid not in pid_cache:
                    pid_cache[c.pid] = safe_proc_info(c.pid)
                proc_name, exe, ppid, parent_name = pid_cache[c.pid]

            k = (c.pid, f"{getattr(c.laddr,'ip', '')}:{getattr(c.laddr,'port','')}", f"{getattr(c.raddr,'ip','')}:{getattr(c.raddr,'port','')}", c.status)
            rows_now.add(k)

            # beacon track
            if c.raddr:
                key = (proc_name, exe.lower(), c.raddr.ip, c.raddr.port)
                self.beacon_tracker[key].append(time.time())

            # learn baseline
            if self.learn_mode and c.raddr:
                self.new_baseline_sigs.add(signature_for_baseline(proc_name, exe, c))

            # suspicion
            is_susp, reasons = is_suspicious(c, proc_name, exe, parent_name, self.baseline_sigs, self.beacon_tracker, learn_mode=self.learn_mode)

            ts = now_str()
            laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
            raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
            flags = ",".join(reasons) if is_susp else ""
            self.tree.insert("", "end", values=(ts, proc_name, c.pid, parent_name, laddr, raddr, c.status, flags))

            if is_susp and (k not in self.last_rows):
                if not (self.learn_mode and SUPPRESS_ALERTS_DURING_LEARN):
                    suspicious_events.append((ts, proc_name, exe, parent_name, c, reasons))

        # end learn & save
        if self.learn_mode and time.time() >= self.learn_deadline:
            save_baseline(self.args.baseline, self.new_baseline_sigs)
            self.baseline_sigs = set(self.new_baseline_sigs)
            self.learn_mode = False
            self.learn_deadline = None
            self.status_var.set(self.status_var.get() + " | Learn ended — baseline saved.")
        elif self.learn_mode:
            # incremental save
            if not hasattr(self, "_last_learn_save"):
                self._last_learn_save = 0
            if time.time() - self._last_learn_save >= 5:
                save_baseline(self.args.baseline, self.new_baseline_sigs)
                self._last_learn_save = time.time()

        # handle events (alerts + logging + snapshot + OSINT) — do capture in threads
        for (ts, proc_name, exe, parent_name, conn, reasons) in suspicious_events:
            l_ip = getattr(conn.laddr, "ip", "")
            l_po = getattr(conn.laddr, "port", 0)
            r_ip = getattr(conn.raddr, "ip", "")
            r_po = getattr(conn.raddr, "port", 0)
            status = conn.status

            title = "Suspicious network activity"
            msg = f"{proc_name}  |  {l_ip}:{l_po} → {r_ip}:{r_po}  |  {','.join(reasons)}"
            self.toast_alert(title, msg)

            # spawn a worker thread so UI remains smooth
            threading.Thread(target=self.snapshot_and_log,
                             args=(ts, proc_name, exe, parent_name, l_ip, l_po, r_ip, r_po, status, reasons),
                             daemon=True).start()

        self.last_rows = rows_now

        dur_ms = int((time.time()-start)*1000)
        self.status_var.set(f"Connections: {len(conns)} | Suspicious(new): {len(suspicious_events)} | Poll: {dur_ms} ms | {'LEARNING…' if self.learn_mode else 'MONITORING'}")
        self.root.after(POLL_INTERVAL_SEC*1000, self.poll_once)

    def snapshot_and_log(self, ts, proc_name, exe, parent_name, l_ip, l_po, r_ip, r_po, status, reasons):
        pcap_file = os.path.join(SNAPSHOT_DIR, f"{ts.replace(':','-').replace(' ','_')}_{safe_name(proc_name)}_{safe_name(l_ip)}_{l_po}_to_{safe_name(r_ip)}_{r_po}.pcap")
        snap = {}
        if HAVE_PYDIVERT and l_ip and r_ip and (l_po and r_po):
            # TCP unless the port hint suggests UDP (e.g., 53). Keep it simple for now.
            proto = "udp" if (l_po == 53 or r_po == 53) else "tcp"
            snap = capture_snapshot(l_ip, l_po, r_ip, r_po, proto=proto, pcap_path=pcap_file)
        intel = enrich_ip(r_ip, self.keys) if r_ip else {}

        # log block
        block = {
            "time": ts,
            "proc": proc_name,
            "exe": exe,
            "parent": parent_name,
            "local": f"{l_ip}:{l_po}",
            "remote": f"{r_ip}:{r_po}",
            "status": status,
            "reasons": reasons,
            "snapshot": snap,
            "intel": intel,
            "intel_sources_active": [k for k,v in (self.api_status or {}).items() if k in ("abuseipdb","otx","greynoise") and isinstance(v, dict) and v.get("ok")]
        }

        # write to main log (1-line JSON)
        try:
            write_log(json.dumps(block, ensure_ascii=False))
        except Exception:
            # fallback minimal line
            write_log(f"{ts} SUSPICIOUS {proc_name} {l_ip}:{l_po}->{r_ip}:{r_po} {status} reasons={','.join(reasons)} (snapshot/intel not serialized)")

        # also drop a pretty file per event
        try:
            ensure_dir(SNAPSHOT_DIR)
            json_name = os.path.join(SNAPSHOT_DIR, f"{ts.replace(':','-').replace(' ','_')}_{safe_name(proc_name)}_{safe_name(l_ip)}_{l_po}_to_{safe_name(r_ip)}_{r_po}.json")
            with open(json_name, "w", encoding="utf-8") as f:
                json.dump(block, f, indent=2)
        except Exception:
            pass

# ---------------------------
# CLI
# ---------------------------

def parse_args():
    ap = argparse.ArgumentParser(description="Live network anomaly monitor (baseline + heuristics + packet snapshots + PCAP + JA3 + DNS + OSINT).")
    ap.add_argument("--baseline", default=BASELINE_FILE, help="Path to baseline JSON")
    ap.add_argument("--learn", type=int, default=0, help="Learn baseline for N seconds, then monitor")
    ap.add_argument("--toasts", type=int, default=0, help="Enable Windows toasts via win10toast (0/1). Default 0 (off) to avoid WNDPROC crashes on some setups.")
    return ap.parse_args()


if __name__ == "__main__":
    try:
        import ctypes, time as _t
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    NetMonitorApp(parse_args())