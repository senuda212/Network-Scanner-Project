# Network Scanner

A multi-threaded TCP network scanner built in Python for internal network auditing and security assessments. Supports CIDR subnet scanning, configurable port ranges, concurrent thread execution, a professional `argparse` CLI, and a modern `customtkinter` GUI.

> Built as coursework for the **Python Programming — Network Programming Design** module at NIBM School of Computing & Engineering.

---

## Features

- **TCP port scanning** via Python's `socket` module with configurable timeouts
- **CIDR subnet support** — scan entire blocks like `192.168.1.0/24` using the `ipaddress` module
- **Multi-threaded scanning** — up to 10–100× faster than sequential via `concurrent.futures`
- **Professional CLI** with `argparse` — flags for target, ports, threads, timeout, and output
- **Modern GUI** built with `customtkinter` — dark/light mode, live results, progress bar, export
- **Rich terminal output** — coloured tables, spinners, and scan summaries

---

## Project Structure

```
Network-Scanner-Project/
├── scanner.py        # Core engine + CLI interface (main deliverable)
├── gui.py            # Desktop GUI application
├── run.sh            # One-command launcher for GUI / CLI / smoke test
├── setup.bat         # Windows launcher for PowerShell / cmd.exe
├── requirements.txt  # Python dependencies
└── README.md
```

---

## Installation

**Requirements:** Python 3.10+

```bash
# 1. Clone the repository
git clone git@github.com:senuda212/Network-Scanner-Project.git
cd Network-Scanner-Project

# 2. Install dependencies
pip install -r requirements.txt
```

---

## Usage

### CLI

```bash
# Scan a single host on common ports
python scanner.py --target 192.168.1.1

# Scan a full subnet on ports 1–1024
python scanner.py --target 192.168.1.0/24 --ports 1-1024

# Specify ports, thread count, and timeout
python scanner.py --target 10.0.0.1 --ports 22,80,443,3306 --threads 200 --timeout 0.5

# Save results to a file
python scanner.py --target 192.168.1.0/24 --output results.txt
```

#### Available Flags

| Flag | Description | Default |
|---|---|---|
| `--target` | IP address, hostname, or CIDR block (required) | — |
| `--ports` | Port or range: `80`, `1-1024`, `22,80,443` | `1-1024` |
| `--threads` | Number of concurrent threads | `100` |
| `--timeout` | Seconds per port before marking filtered | `3.0` |
| `--output` | Save results to a `.txt` file | disabled |

### GUI

```bash
python gui.py
```

The GUI supports CIDR targets, multi-select port toggles for common ports, an optional custom port field for ranges/lists, live threaded progress, and export of the most recent scan results.

### One-command launcher

```bash
bash run.sh
```

By default this starts the desktop GUI. Use `bash run.sh cli -- --target ...` for the CLI, or `bash run.sh smoke` for a quick localhost test scan.

### Windows launcher

```bat
setup.bat
```

On Windows, `setup.bat` creates the virtual environment if needed, installs dependencies, and starts the desktop GUI by default.

---

## Development Phases

| Phase | Focus | Status |
|---|---|---|
| 1 | Core TCP socket engine | ✅ Complete |
| 2 | Subnet & port parsing (`ipaddress`) | ✅ Complete |
| 3 | Multi-threading (`concurrent.futures`) | ✅ Complete |
| 4 | CLI interface (`argparse`) | ✅ Complete |
| 5 | Desktop GUI (`customtkinter`) | ✅ Complete |

---

## Legal Notice

Only scan networks and hosts you own or have explicit written permission to test. Unauthorised port scanning may be illegal in your jurisdiction. The public test host `scanme.nmap.org` is provided by the Nmap project for legitimate scanner testing.

---

## Group Members

| Name | Contributions |
|---|---|
| Member 1 | Phase 1 — Core engine |
| Member 2 | Phase 2 — Subnet parsing |
| Member 3 | Phase 3 — Multi-threading |
| Member 4 | Phase 4 — CLI / Phase 5 — GUI |

---
