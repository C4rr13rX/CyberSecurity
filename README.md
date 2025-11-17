# CyberSecurity

This repository now bundles a native "Paranoid" host-defense toolkit together with the original Windows traffic monitor script. The native component is written in modern C++ and focuses on aggressive process telemetry, heuristic-based anomaly detection, and pluggable signature/AI analysis for artefacts. A desktop console built with Ionic + Angular inside Electron provides an operator-friendly cockpit for the native tooling.

## Paranoid Antivirus Suite (C++)

### Highlights

* **Deep process visibility** – enumerates `/proc` with enriched context: parent lineage, namespace bindings, seccomp posture, live socket inventory, and executable SHA-256 fingerprints.
* **Heuristic scoring** – an expanded analytic engine scores each process using academically grounded TTP references (MITRE ATT&CK IDs) covering LOLBins, namespace abuse, anonymous RX/RWX memory, capability misuse, external beacons, threat-intel hits, and stealthy tracing activity.
* **Execution hygiene checks** – detects deleted-on-disk binaries, privileged listeners without root, temp-backed shared objects, writable executables/working directories, and risky environment variables such as `LD_PRELOAD` or writable `PATH` entries.
* **Structured reporting** – choose compact tables, JSON for SIEM ingestion, or verbose dossiers (`--detailed`) that break down sockets, memory maps, and capability posture per process.
* **Signature scanning** – integrates with ClamAV when installed. Optional YARA support (`--yara`) unlocks rule-driven hunting alongside signature matches.
* **OpenAI-assisted triage (optional)** – when the `OPENAI_API_KEY` environment variable is present and `curl` is available, the suite can ship artefacts for a defensive review by OpenAI’s models. Output is captured verbatim for offline review and auditing.
* **Continuous monitoring** – a looped mode lets you keep watch over process churn with a configurable interval. All heuristics and scoring run on every pass.
* **Host hygiene auditing** – a dedicated `--system-audit` pass inspects kernel modules, cron/systemd persistence, `ld.so.preload`, suspicious setuid binaries, duplicate UID 0 accounts, unsafe autostart files, risky sudoers entries, and permissive SSH configurations.
* **Rootkit detection** – dedicated `--rootkit-scan` heuristics track stealthy kernel modules, suspicious `/sys/module` parameters, and filesystem artefacts favoured by academic and in-the-wild implants.
* **Threat intelligence fusion** – load or append IP/hash/domain indicators (`--threat-intel-*`) so the heuristic engine can surface real-time matches against live sockets, environment variables, and binary hashes.
* **Integrity and ransomware defenses** – baseline trusted directories (`--integrity-baseline`), verify drift (`--integrity-verify`), and watch hot directories for ransomware-style bursts (`--ransomware-watch`).
* **Containment tooling** – isolate artefacts with `--quarantine-file`, terminate rogue processes with `--quarantine-pid` / `--kill-pid`, and feed the results back into hunting.
* **Dark web reconnaissance (experimental)** – point the suite at a Tor SOCKS proxy (`--tor-proxy`) and query onion services for leaked keywords via `--darkweb-scan`. The scanner now parses structured leaks (emails, credential pairs, SSNs, street addresses, license plates, card numbers, and phone numbers), decodes Base64 blobs that hide search terms, follows simple redirects, and records HTTP timing metrics to help prioritise high-signal responses.
* **Windows firewall orchestration** – manage host policies directly from the CLI with `--firewall-*` helpers, record exception snapshots, remove stale allowances, and surface profile state/diagnostics in JSON so automation stacks can react.
* **Security Center registration** – advertise Paranoid as a first-class antivirus/firewall to Windows Security Center via `--security-center-register`, ensuring the operating system knows the suite is handling both vectors.
* **USB incident toolkit** – `--usb-create` provisions a bootable Linux image on removable media so responders can cold-boot compromised systems into a trusted scanning environment with optional Tor packages.
* **Windows baseline repair** – capture clean manifests, audit live installations, and stage replacement files per Windows version using the `--windows-repair-*` workflow.

### Build

```bash
mkdir build
cd build
cmake ..
cmake --build .
```

This produces the `paranoid_av` executable. The project targets C++20 and depends on CMake ≥ 3.15 plus a POSIX-like environment that exposes `/proc`.

### Windows automation scripts

Three PowerShell helpers under `scripts/` streamline the full Windows toolchain setup:

1. `scripts/install_dependencies.ps1` - installs Visual Studio Build Tools, CMake, Ninja, Git, Python, Node.js, NSIS, Qt, and `vswhere` via `winget` (or Chocolatey as a fallback). Run from an elevated shell.
2. `scripts/build_windows.ps1 [-Configuration Release] [-Package] [-RunTests]` - detects the newest Visual Studio (2017-2022), configures the correct generator, builds the native binary plus Ionic/Electron UI, and optionally produces the NSIS installer through CPack.
3. `scripts/install_suite.ps1 [-InstallerPath path\to\setup.exe] [-Silent]` - locates the latest installer produced by the build script (or uses the provided path) and launches it interactively or unattended.

### One-shot Windows setup

For repeatable end-to-end provisioning there is now a hardened orchestrator: `scripts/setup_paranoid.ps1`. It enforces elevation, runs a transcript log, and executes the dependency install, build, and installation phases sequentially. Typical usage from an elevated PowerShell prompt:

```powershell
pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass `
    -File .\scripts\setup_paranoid.ps1 `
    -Configuration Release `
    -SilentInstall
```

Useful switches:

| Switch | Effect |
| --- | --- |
| `-SkipDependencies` | Assume the build toolchain is already present. |
| `-SkipBuild` | Reuse a previously packaged installer. |
| `-SkipInstall` | Produce the installer without launching it (useful for CI). |
| `-InstallerPath <path>` | Force a specific installer when multiple builds exist. |
| `-LogDirectory <path>` | Override the transcript directory (default: `<repo>/logs`). |

Transcript logs are emitted to `<repo>/logs/setup_YYYYMMDD_HHMMSS.log`, making failures easy to diagnose.

Example end-to-end workflow on Windows:

```powershell
cd C:\src\CyberSecurity
pwsh scripts/install_dependencies.ps1
pwsh scripts/build_windows.ps1 -Configuration Release -Package
pwsh scripts/install_suite.ps1
```

The build script emits rich error messages whenever Visual Studio or toolchain prerequisites are missing, so issues can be triaged quickly. Generated installers live under `build/` in the `_CPack_Packages` tree and expose a GUI backed by NSIS.

> **Note**: the NSIS package currently deploys the C++ command-line interface. The Ionic/Angular bundle is compiled (see `ui/dist/`) but is not yet wrapped inside the Windows installer—launch `paranoid_av.exe` with the desired arguments (e.g., `paranoid_av.exe --monitor`) from an elevated terminal.

### Runtime shutdown log

Every invocation of `paranoid_av.exe` now records its lifecycle under `%PROGRAMDATA%\ParanoidAntivirusSuite\logs\shutdown.log` (or `~/.paranoid_av/logs/shutdown.log` outside Windows). The log captures the full command line, runtime duration, and exit code so unexpected exits can be correlated even when the window closes immediately. Inspect this file first when troubleshooting operator-side issues.

### Paranoid Desktop Console (Ionic + Electron)

The `ui/` directory hosts a modern Ionic + Angular front-end bundled in Electron. It orchestrates the native `paranoid_av` binary via IPC so analysts can launch continuous monitoring, system audits, Tor reconnaissance, and signature scans from an opinionated workflow.

**Interface overview**

* **Dashboard** – snapshot risk panels summarise the highest scoring processes and most recent hygiene findings while streaming all activity in a structured console.
* **Processes** – start/stop continuous monitoring loops, search live telemetry, and review heuristic rationales with wide, high-contrast controls.
* **Filesystem Integrity** – manage baselines and verification runs with guidance around ransomware burst detection and quarantine workflows.
* **Threat Intelligence** – reload indicator CSVs, run ClamAV/YARA scans, and execute process/file quarantine actions from prominent controls.
* **Dark Web Recon** – configure onion host/path/port and persistent keyword hunts; Tor-backed lookups stream structured PII hits and raw console output.
* **Firewall & Security Center** – stream the current Windows firewall posture, add or remove allowances, load/save policy snapshots, build USB media, and register the suite with Windows Security Center using large-format controls.
* **System Hygiene** – trigger host audits and review severity-badged findings alongside the live log stream.

```bash
# install dependencies (requires Node.js 18+)
cd ui
npm install

# launch the Angular dev server together with Electron in watch mode
npm start

# build the Angular bundle and launch Electron against the static assets
npm run build
```

By default the desktop shell looks for the C++ executable at `../build/paranoid_av`; override with `PARANOID_AV_BIN=/custom/path/paranoid_av npm start` if you keep the binary elsewhere. The UI streams live stdout/stderr from the native tooling into the activity consoles on each tab and decorates the process, dark web, and system views with structured data when the CLI emits JSON.

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

# kernel/rootkit indicator sweep
./paranoid_av --rootkit-scan

# signature scan (requires clamscan)
./paranoid_av --scan /path/to/suspicious

# YARA scan (requires yara)
./paranoid_av --yara rules/index.yar /path/to/suspicious

# AI assisted review of a dumped artefact
OPENAI_API_KEY=sk-... ./paranoid_av --openai /tmp/suspicious_script.sh

# load threat intel, then monitor with context
./paranoid_av --threat-intel-load indicators.csv --monitor --detailed

# create and verify a filesystem baseline
./paranoid_av --integrity-baseline /etc /tmp/etc.baseline
./paranoid_av --integrity-verify /etc /tmp/etc.baseline

# watch a directory for ransomware-style bursts
./paranoid_av --ransomware-watch /srv/shares 60

# quarantine a suspicious artefact and terminate a process
./paranoid_av --quarantine-file /tmp/malicious.sh
./paranoid_av --kill-pid 4242

# flash a USB drive with the autonomous scanning environment
sudo ./paranoid_av --usb-create /dev/sdb /tmp/paranoid-usb

# query a dark-web onion for leaked credentials (Tor proxy must be listening on localhost:9050)
./paranoid_av --tor-proxy 9050 --darkweb-scan exampleonion.onion /search "your-company.com,password"
# the scanner extracts keyword hits, structured data like SSNs, and Base64-encoded leaks while reporting HTTP status and latency

# inspect and tune the Windows firewall (run on Windows for full coverage)
./paranoid_av --json --firewall-status
./paranoid_av --firewall-allow-app "C:\\Program Files\\Tor\\tor.exe" "Tor" outbound
./paranoid_av --firewall-allow-port 8443 TCP inbound "Secure proxy"
./paranoid_av --firewall-save-policy policies/workstations.policy
./paranoid_av --firewall-remove-rule "Secure proxy"
./paranoid_av --firewall-load-policy policies/workstations.policy

# advertise the suite to Windows Security Center (requires Administrator privileges)
./paranoid_av --security-center-register "Paranoid Endpoint" "C:\\Program Files\\Paranoid\\paranoid_av.exe" mode=both

# capture a clean manifest from a trusted Windows volume (run on Windows with Administrator privileges)
./paranoid_av --windows-repair-capture C:\\Windows "Windows 11" 22621 win11 manifests/win11.manifest

# audit a mounted Windows installation from Linux using a stored manifest and emit JSON for dashboards
./paranoid_av --windows-root /mnt/windows/Windows --json --windows-repair-audit manifests/win10.manifest /tmp/win10.plan

# stage replacement files for the detected host version and save a repair plan next to the output tree
./paranoid_av --windows-root /mnt/windows/Windows --windows-repair-collect /srv/windows-baselines /tmp/rebuild
```

Tips:

* Install ClamAV (`clamscan`) to enable signature scanning.
* Install the official `yara` CLI to unlock rule-based scanning.
* The OpenAI module is best-effort. It simply wraps the public HTTPS API and records the raw JSON response so you can parse or redact it later.
* Pair `--json` with `--rootkit-scan` to feed kernel anomaly data into dashboards or the Ionic desktop console.
* Output is human-readable by default; redirect stdout/stderr to build your own pipelines.
* Run `--system-audit` after incident response actions or baseline updates to spot suspicious persistence and privilege artefacts.
* Maintain an indicator CSV (`type,value`) to share across teams and reload with `--threat-intel-load` for consistent detection.
* When using dark-web lookups, ensure the Tor daemon is already running locally and that your policies permit outbound Tor usage.
* Keep Windows manifest repositories organised as `<repo>/<manifestKey>/*.dll` alongside `<repo>/<manifestKey>.manifest` so the `--windows-repair-collect` workflow can copy clean replacements into a staging directory.

### USB Incident Toolkit

The helper script under `tools/create_usb_scanner.sh` automates provisioning of a bootable response environment:

```bash
# create a bootable scanner on /dev/sdb using /tmp/paranoid-usb as a staging area
sudo tools/create_usb_scanner.sh /dev/sdb /tmp/paranoid-usb

# include Tor client packages in the image for live dark web reconnaissance
sudo tools/create_usb_scanner.sh --include-tor /dev/sdb

# invoke the wrapper via the C++ CLI (uses the same script internally)
sudo ./paranoid_av --usb-include-tor --usb-create /dev/sdb /tmp/paranoid-usb
```

The USB image installs a minimal Debian userspace, copies the freshly built `paranoid_av` binary, and enables a systemd unit that runs `--system-audit`, `--rootkit-scan`, and `--monitor --json` on boot. Logs stream to `/var/log/paranoid-usb-scan.log`, making it easy to triage air-gapped hosts.

### Windows Baseline & Repair Staging

The Windows repair workflow expects a repository of clean system files laid out as:

```
<repo>/
  win10.manifest
  win10/
    System32/...
  win11.manifest
  win11/
    System32/...
```

Each manifest line records the relative path, SHA-256 hash, and size for critical DLL/SYS/EXE artefacts. Populate the clean tree by booting a trusted image and running `--windows-repair-capture C:\Windows "Windows 11" 22621 win11 path/to/win11.manifest`. The capture command walks `System32`, `SysWOW64`, and `WinSxS`, hashes files, and marks critical extensions so later audits prioritise them.

During response you can:

* Detect the host version and manifest key – `./paranoid_av --json --windows-repair-detect`
* Audit a mounted or live installation – `./paranoid_av --windows-root /mnt/windows/Windows --windows-repair-audit path/to/win10.manifest /tmp/plan.txt`
* Stage replacements into a working directory – `./paranoid_av --windows-root /mnt/windows/Windows --windows-repair-collect /srv/windows-baselines /tmp/rebuild`

The audit command emits JSON or human-readable summaries with missing/mismatched files. Supplying an optional plan path writes a text manifest of the findings. The collect command reuses the same manifest, copies clean binaries into the output tree, and saves a refreshed plan (`<output>/<manifestKey>_plan.txt`). Any missing sources or copy failures are surfaced in both the CLI and the Electron console.

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
