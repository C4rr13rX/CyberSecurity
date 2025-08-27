# CyberSecurity
Just some scripts for Cyber Security purposes. Mainly Python.

1. Traffic Monitor (Windows 11)

Live, local network anomaly monitor for Windows 11 with a real-time UI, baseline learning, heuristics, packet snapshots (PCAP for Wireshark), TLS JA3 fingerprints, DNS parsing, optional OSINT enrichment (AbuseIPDB, AlienVault OTX, GreyNoise), and startup API key self-test.

Use case: keep an eye on host outbound and inbound connections, surface unusual behavior such as new destinations, high-risk ports, beaconing, and LOLBins, and automatically capture a short packet trace for investigation.

----------------------------------------------------------------

FEATURES

- Real-time UI (Tkinter). Table of active connections so you know it is running.
- Baseline learning. --learn N records your normal connections for N seconds. Later, new or rare destinations flag as deviates_from_baseline.
- Heuristics.
  - High-risk ports such as 3389, 445, 59xx, 22, 23.
  - Windows LOLBins that should not usually talk on the network such as powershell.exe and rundll32.exe.
  - Unusual executable paths such as temp or roaming locations.
  - Beaconing detector that looks for regular intervals with low jitter.
- Packet snapshots. Short capture for each new suspicious flow (WinDivert) with:
  - pcap written to snapshots (open in Wireshark).
  - JSON event file including TLS ClientHello hints (SNI and ALPN plus JA3), basic HTTP, DNS queries, and a safe hex prefix of payloads.
- OSINT enrichment (optional). Looks up remote IPs against AbuseIPDB, AlienVault OTX, and GreyNoise. On every run the app checks your keys and shows a status popup.
- Logging. JSONL suspicious_log.txt plus per-event pretty JSON in snapshots.
- Noise controls. Ignores TIME_WAIT and CLOSE_WAIT. Ignores localhost traffic by default.

All packet capture is local only. Nothing is sent anywhere unless you configure OSINT APIs.

----------------------------------------------------------------

REQUIREMENTS

- Windows 11
- Python 3.9 or newer
- Administrator shell for packet capture and the WinDivert driver
- Recommended Python packages (see requirements.txt):
  psutil
  requests
  pydivert
  scapy (optional pcap writer)
  win10toast (only if using toasts)

Example requirements.txt

psutil>=5.9
requests>=2.31
pydivert>=2.1.0 ; platform_system == "Windows"
scapy>=2.5.0
win10toast>=0.9

Install

pip install -r requirements.txt

Note: pydivert bundles the WinDivert driver. Run your terminal as Administrator for capture to work.

----------------------------------------------------------------

FILES AND FOLDERS

traffic_monitor.py      The application.
baseline.json           Auto-created. Learned signatures of normal connections.
suspicious_log.txt      JSONL log of suspicious events.
snapshots/              Per-event JSON and pcap files.
intel_keys.json         Optional. API keys for OSINT.

Suggested .gitignore entries

__pycache__/
*.pyc
baseline.json
suspicious_log.txt
snapshots/
*.pcap
intel_keys.json

----------------------------------------------------------------

SETUP

1. Clone or download this repository.
2. Open Windows Terminal or PowerShell as Administrator.
3. Install dependencies:
   pip install -r requirements.txt
4. Optional. Create intel_keys.json next to traffic_monitor.py with your keys:
   {
     "abuseipdb_key": "YOUR_ABUSEIPDB_KEY",
     "otx_key": "YOUR_ALIENVAULT_OTX_KEY",
     "greynoise_key": "YOUR_GREYNOISE_KEY"
   }
   Leaving keys out disables OSINT. On startup, the app shows a popup with key status.

----------------------------------------------------------------

USAGE

Learn a baseline, then monitor

python traffic_monitor.py --learn 600

Learns for 10 minutes and saves baseline.json incrementally. Afterwards, flags connections that deviate from the baseline.

Enable Windows toast notifications (optional)

python traffic_monitor.py --learn 600 --toasts 1

If you see WNDPROC or LRESULT errors on your system, run without --toasts (the default). The app still shows Tk popups and logs everything.

Other useful flags

--baseline PATH    Use a different baseline file. Default is ./baseline.json
--learn N          Learn for N seconds. Zero disables learning.
--toasts 0 or 1    Disable or enable Windows toasts. Default is 0 (off) for stability.

----------------------------------------------------------------

HOW IT WORKS (HIGH LEVEL)

1. Connection polling with psutil. Every two seconds the app lists current TCP and UDP connections including PID, process path, local and remote endpoints, and state.
2. Learning. During --learn it records signatures (process_name, exe_path, remote_port) as normal.
3. Detection. After learning, each connection is evaluated for:
   Baseline deviation (not seen during learning),
   High-risk port,
   LOLBins using network,
   Unusual executable paths,
   Beaconing pattern (N events with similar intervals and low jitter).
4. Snapshot and enrichment. For new suspicious flows it:
   Starts a short WinDivert capture for that flow and writes a pcap,
   Parses TLS ClientHello (SNI and ALPN and JA3), HTTP request line and Host, DNS queries,
   Optionally queries AbuseIPDB, OTX, and GreyNoise for reputation.
5. Notify and log. Shows an alert (Tk or optional toast), appends a JSONL line to suspicious_log.txt, and writes a detailed JSON under snapshots alongside the pcap.

----------------------------------------------------------------

EVENT JSON SCHEMA (EXCERPT)

Each suspicious event produces a pretty JSON file under snapshots and a one-line JSON in suspicious_log.txt.

{
  "time": "2025-08-26 20:51:03",
  "proc": "msedge.exe",
  "exe": "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
  "parent": "msedge.exe",
  "local": "10.0.0.10:51550",
  "remote": "52.191.162.85:443",
  "status": "ESTABLISHED",
  "reasons": ["deviates_from_baseline", "regular_beaconing_pattern"],
  "snapshot": {
    "filter": "(tcp and ip and ...)",
    "pcap_path": "snapshots/2025-08-26_20-51-03_msedge.exe_...pcap",
    "packets": [{
      "ts": "2025-08-26 20:51:03",
      "inbound": false,
      "length": 517,
      "payload_len": 481,
      "hints": {
        "sni": "example.com",
        "alpn": ["h2", "http/1.1"],
        "ja3": "b3c3...",
        "ja3_str": "771,4865-4866-...,0-11-10-..."
      },
      "payload_hex_prefix": "16030101..."
    }]
  },
  "intel": {
    "sources": {
      "abuseipdb": {"abuseConfidenceScore": 0, "totalReports": 0},
      "otx": {"pulse_count": 0},
      "greynoise": {"classification": "benign"}
    }
  }
}

----------------------------------------------------------------

PRIVACY AND SECURITY

PCAP and JSON outputs may contain sensitive metadata such as hostnames, paths, process names, and partial payloads. Keep the snapshots folder private. Run locally and share artifacts only with trusted parties. This tool is for monitoring and diagnostics, not for evasion or intrusion.

----------------------------------------------------------------

TROUBLESHOOTING

No packets captured or WinDivert permission error. Run terminal as Administrator. Close conflicting packet tools such as VPN clients or other sniffers if needed.
WNDPROC or LRESULT TypeError. Run without --toasts (default). Tk popups and logging continue to work.
API status popup shows FAIL. Verify keys in intel_keys.json, firewall egress, and that the requests package is installed.
High CPU. Increase the polling interval in the script. The default is two seconds.

----------------------------------------------------------------

ROADMAP AND IDEAS

CLI toggles for OSINT and PCAP durations, rotating logs, IP intel caching and rate limiting.
ETW-based SNI capture using the Windows TLS provider for low noise.
Rule packs per environment with tight, normal, or loose heuristics.

----------------------------------------------------------------

CONTRIBUTING

Pull requests are welcome. Do not commit real logs, pcaps, or API keys. Open issues with reproducible steps.

----------------------------------------------------------------

LICENSE

MIT. See LICENSE.
