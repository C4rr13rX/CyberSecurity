# CyberSecurity

This repository now bundles a native "Paranoid" host-defense toolkit together with the original Windows traffic monitor script. The native component is written in modern C++ and focuses on aggressive process telemetry, heuristic-based anomaly detection, and pluggable signature/AI analysis for artefacts.

## Paranoid Antivirus Suite (C++)

### Highlights

* **Deep process visibility** – enumerates `/proc` with enriched context: parent lineage, namespace bindings, seccomp posture, live socket inventory, and executable SHA-256 fingerprints.
* **Heuristic scoring** – an expanded analytic engine scores each process using academically grounded TTP references (MITRE ATT&CK IDs) covering LOLBins, namespace abuse, anonymous RX/RWX memory, capability misuse, external beacons, and stealthy tracing activity.
* **Execution hygiene checks** – detects deleted-on-disk binaries, privileged listeners without root, temp-backed shared objects, and risky environment variables such as `LD_PRELOAD` or writable `PATH` entries.
* **Structured reporting** – choose compact tables, JSON for SIEM ingestion, or verbose dossiers (`--detailed`) that break down sockets, memory maps, and capability posture per process.
* **Signature scanning** – integrates with ClamAV when installed. Optional YARA support (`--yara`) unlocks rule-driven hunting alongside signature matches.
* **OpenAI-assisted triage (optional)** – when the `OPENAI_API_KEY` environment variable is present and `curl` is available, the suite can ship artefacts for a defensive review by OpenAI’s models. Output is captured verbatim for offline review and auditing.
* **Continuous monitoring** – a looped mode lets you keep watch over process churn with a configurable interval. All heuristics and scoring run on every pass.
* **Host hygiene auditing** – a dedicated `--system-audit` pass inspects kernel modules, cron/systemd persistence, `ld.so.preload`, suspicious setuid binaries, and duplicate UID 0 accounts.

### Build

```bash
mkdir build
cd build
cmake ..
cmake --build .
```

This produces the `paranoid_av` executable. The project targets C++20 and depends on CMake ≥ 3.15 plus a POSIX-like environment that exposes `/proc`.

### Usage

```bash
# single snapshot with heuristic scoring
./paranoid_av --monitor

# verbose dossier for all processes
./paranoid_av --monitor --detailed

# machine-readable telemetry
./paranoid_av --monitor --json

# continuous monitoring every 10 seconds
./paranoid_av --monitor-loop 10

# host-level hygiene sweep
./paranoid_av --system-audit

# signature scan (requires clamscan)
./paranoid_av --scan /path/to/suspicious

# YARA scan (requires yara)
./paranoid_av --yara rules/index.yar /path/to/suspicious

# AI assisted review of a dumped artefact
OPENAI_API_KEY=sk-... ./paranoid_av --openai /tmp/suspicious_script.sh
```

Tips:

* Install ClamAV (`clamscan`) to enable signature scanning.
* Install the official `yara` CLI to unlock rule-based scanning.
* The OpenAI module is best-effort. It simply wraps the public HTTPS API and records the raw JSON response so you can parse or redact it later.
* Output is human-readable by default; redirect stdout/stderr to build your own pipelines.
* Run `--system-audit` after incident response actions or baseline updates to spot suspicious persistence and privilege artefacts.

### Extending

The C++ code is intentionally modular. Core capabilities live in `include/AntivirusSuite/*.hpp` and `src/*.cpp`, so you can swap heuristics, enrich metadata, or plug in additional external scanners without rewriting the CLI.

## Windows Traffic Monitor (Python)

The legacy `traffic_monitor.py` script remains available for Windows 11 environments. It offers a Tkinter UI, baseline learning, OSINT enrichment, and packet captures powered by WinDivert. See the original documentation below for installation and usage specifics.

### Requirements

* Windows 11
* Python 3.9+
* Administrator shell (packet capture)
* `pip install -r requirements.txt`

### Setup

```powershell
pip install -r requirements.txt
python traffic_monitor.py --learn 600
```

Optional: supply `intel_keys.json` with your AbuseIPDB, OTX, and GreyNoise keys to unlock enrichment.

### Notes

* Packet capture stays local. Nothing is uploaded unless you configure OSINT APIs.
* Suggested `.gitignore` entries include `__pycache__/`, `snapshots/`, `baseline.json`, and any PCAP artefacts.

## License

MIT. See `LICENSE` for details.
