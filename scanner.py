#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║           Network Scanner — scanner.py                   ║
║           Phase 2: Subnet & Port Parsing                 ║
╚══════════════════════════════════════════════════════════╝

Module  : Python Programming — Network Programming Design
Phase   : 2 of 5 — ipaddress module integration

What this phase adds (on top of Phase 1):
    - resolve_targets() → accepts IP, hostname, or CIDR block
                                                returns a flat list of target IP strings
    - parse_ports()     → accepts "80", "22,80,443", or "1-1024"
                                                returns a sorted list of integer port numbers
    - Updated demo      → shows both parsers working, then scans a
                                                real target using the new pipeline

Phase 1 functions (scan_port, get_service_name) and all Rich
display helpers are unchanged and remain importable.
"""

import socket
import os
import uuid
import ipaddress
import threading
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from pathlib import Path

from env_loader import load_dotenv

load_dotenv(Path(__file__).resolve().with_name(".env"), override=True)

# ──────────────────────────────────────────────────────────
#  Global console — single instance shared across all helpers
# ──────────────────────────────────────────────────────────

console = Console()

# ──────────────────────────────────────────────────────────
#  Common port reference list (used by Phase 1 demo)
#  All subsequent phases accept arbitrary port ranges via CLI.
# ──────────────────────────────────────────────────────────

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111,
    135, 139, 143, 443, 445, 993, 995,
    1433, 1723, 3306, 3389, 5432, 5900,
    6379, 8080, 8443, 8888, 27017,
]

# ══════════════════════════════════════════════════════════
#  PHASE 1 — Core Functions (unchanged)
# ══════════════════════════════════════════════════════════

def get_service_name(port: int) -> str:
    """
    Resolve a TCP port number to its well-known service name.

    Uses the OS service database (same source as /etc/services on Linux).
    Returns 'unknown' gracefully when no mapping exists.

    Args:
        port: TCP port number (0-65535)

    Returns:
        Service name string, e.g. 'http', 'ssh', 'ftp', or 'unknown'
    """
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def scan_port(host: str, port: int, timeout: float = 3.0, retries: int = 1) -> dict:
    """
    Attempt a TCP connection to host:port with retries and smart detection.

    Improved version with:
    - Longer default timeout (3.0s instead of 1.0s) for slow services
    - Automatic retry logic for unreliable connections
    - Socket option optimizations (TCP_NODELAY, SO_LINGER)
    - Better distinction between closed vs filtered vs open

    Port States:
        'open'     -> connect_ex() returned 0; port accepted the SYN
        'closed'   -> connection refused (RST or ICMP error)
        'filtered' -> socket.timeout; no response after retries
        'error'    -> DNS or network error

    Args:
        host:    Target IP address or hostname string
        port:    TCP port number to probe
        timeout: Seconds to wait per attempt (default 3.0)
        retries: Number of retry attempts if connection times out (default 1)

    Returns:
        dict with keys: port (int), state (str), service (str)
    """
    result = {
        "port":    port,
        "state":   "filtered",
        "service": get_service_name(port),
    }

    for attempt in range(retries + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b'\x01\x00\x00\x00\x00\x00\x00\x00')
                sock.settimeout(timeout)
                error_code = sock.connect_ex((host, port))
                if error_code == 0:
                    result["state"] = "open"
                    return result
                elif error_code in (111, 10061):
                    result["state"] = "closed"
                    return result
        except socket.timeout:
            if attempt < retries:
                continue
            result["state"] = "filtered"
            return result
        except socket.gaierror:
            result["state"] = "error"
            result["service"] = "DNS resolution failed"
            return result
        except OSError:
            if attempt < retries:
                continue
            result["state"] = "filtered"
            return result

    return result


# ══════════════════════════════════════════════════════════
#  PHASE 2 — Subnet & Port Parsing
# ══════════════════════════════════════════════════════════

def resolve_targets(target: str) -> list:
    """
    Expand a target string into a flat list of IP address strings.

    Handles three input formats:

        1. Single IP address  ->  "192.168.1.1"
           Returns ["192.168.1.1"] directly.

        2. CIDR notation      ->  "192.168.1.0/24"
           Uses ipaddress.ip_network() to enumerate all host addresses
           in the block (excludes network and broadcast addresses).
           e.g. /24 yields 254 hosts, /16 yields 65534 hosts.

        3. Hostname           ->  "scanme.nmap.org"
           Resolves to an IP via socket.gethostbyname(), then wraps
           it in a single-item list. This keeps all downstream code
           working with plain IP strings, never hostnames.

    Args:
        target: IP address, CIDR block, or resolvable hostname

    Returns:
        List of IP address strings ready to pass to scan_port()

    Raises:
        ValueError: if the input is not a valid IP, CIDR, or hostname
    """
    target = target.strip()

    # Try CIDR first (e.g. "192.168.1.0/24")
    # strict=False means "192.168.1.5/24" is treated the same as
    # "192.168.1.0/24" — the host bits are silently zeroed.
    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
            # .hosts() excludes the network address (.0) and
            # broadcast address (.255) automatically
            hosts = [str(ip) for ip in network.hosts()]
            if not hosts:
                raise ValueError(f"Network '{target}' contains no host addresses.")
            return hosts
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR block '{target}': {exc}") from exc

    # Try parsing as a bare IP address
    try:
        ipaddress.ip_address(target)
        return [target]
    except ValueError:
        pass

    # Fall back to hostname resolution
    try:
        resolved_ip = socket.gethostbyname(target)
        console.print(
            f"  [dim]Resolved [cyan]{target}[/cyan]"
            f" -> [cyan]{resolved_ip}[/cyan][/dim]"
        )
        return [resolved_ip]
    except socket.gaierror as exc:
        raise ValueError(
            f"Could not resolve hostname '{target}': {exc}"
        ) from exc


def parse_ports(port_arg: str) -> list:
    """
    Parse a port specification string into a sorted list of integers.

    Accepts three formats (which can be combined with commas):
        "80"            -> single port       -> [80]
        "22,80,443"     -> comma list        -> [22, 80, 443]
        "1-1024"        -> inclusive range   -> [1, 2, ..., 1024]
        "22,80,100-200" -> mixed             -> [22, 80, 100, ..., 200]

    Port numbers are validated against the legal TCP range (1-65535).
    Duplicates are removed and the final list is sorted ascending.

    Args:
        port_arg: Port specification string from user input or argparse

    Returns:
        Sorted list of unique integer port numbers

    Raises:
        ValueError: if any token is not a valid port or range
    """
    ports = set()

    for token in port_arg.split(","):
        token = token.strip()

        if "-" in token:
            # Range format: "1-1024"
            parts = token.split("-")
            if len(parts) != 2:
                raise ValueError(
                    f"Invalid port range '{token}'. Use format: start-end"
                )
            try:
                start, end = int(parts[0]), int(parts[1])
            except ValueError:
                raise ValueError(f"Non-integer in port range '{token}'.")

            if not (1 <= start <= 65535 and 1 <= end <= 65535):
                raise ValueError(
                    f"Port range '{token}' out of bounds. Ports must be 1-65535."
                )
            if start > end:
                raise ValueError(
                    f"Range start ({start}) must be <= end ({end}) in '{token}'."
                )
            ports.update(range(start, end + 1))

        else:
            # Single port format: "80"
            try:
                port = int(token)
            except ValueError:
                raise ValueError(f"'{token}' is not a valid port number.")

            if not (1 <= port <= 65535):
                raise ValueError(f"Port {port} out of bounds. Must be 1-65535.")

            ports.add(port)

    if not ports:
        raise ValueError("No valid ports parsed from input.")

    return sorted(ports)


def validate_threads(threads: int) -> int:
    if not isinstance(threads, int):
        raise ValueError("--threads must be an integer")
    if not (1 <= threads <= 500):
        raise ValueError("--threads must be between 1 and 500")
    return threads


def validate_timeout(timeout: float) -> float:
    try:
        timeout_value = float(timeout)
    except (TypeError, ValueError) as exc:
        raise ValueError("--timeout must be a number") from exc
    if timeout_value <= 0:
        raise ValueError("--timeout must be greater than 0")
    return timeout_value


def run_scan(
    targets: list,
    ports: list,
    threads: int,
    timeout: float,
    progress_callback=None,
    retries: int = 1,
) -> list:
    """
    Scan every host/port combination using a thread pool.

    Args:
        targets: List of IP address strings returned by resolve_targets().
        ports: List of integer ports returned by parse_ports().
        threads: Maximum worker threads to use.
        timeout: Per-port socket timeout passed to scan_port().
        progress_callback: Optional callable receiving (completed, total, result).
        retries: Number of retry attempts per port if connection times out (default 1).

    Returns:
        List of scan result dictionaries sorted by host then port.
    """
    combinations = [(host, port) for host in targets for port in ports]
    total = len(combinations)
    results = []
    results_lock = threading.Lock()
    completed = 0

    def scan_one(host: str, port: int) -> dict:
        return scan_port(host, port, timeout, retries=retries)

    with ThreadPoolExecutor(max_workers=max(1, threads)) as executor:
        future_map = {
            executor.submit(scan_one, host, port): (host, port)
            for host, port in combinations
        }

        for future in as_completed(future_map):
            host, port = future_map[future]
            result = future.result()
            result["host"] = host

            with results_lock:
                results.append(result)
                completed += 1

            if progress_callback is not None:
                progress_callback(completed, total, result)

    results.sort(key=lambda item: (item.get("host", ""), item["port"]))
    return results


def export_results(results: list, filepath: str, metadata: dict | None = None) -> None:
    """Write scan results to a plain-text report file."""
    metadata = metadata or {}

    counts = {"open": 0, "closed": 0, "filtered": 0, "error": 0}
    for result in results:
        counts[result["state"]] = counts.get(result["state"], 0) + 1

    with open(filepath, "w", encoding="utf-8") as handle:
        handle.write("Network Scanner Report\n")
        handle.write("=" * 24 + "\n\n")

        for key, value in metadata.items():
            handle.write(f"{key}: {value}\n")

        if metadata:
            handle.write("\n")

        handle.write("Results\n")
        handle.write("-" * 7 + "\n")
        for result in results:
            host = result.get("host", metadata.get("host", ""))
            handle.write(
                f"{host}:{result['port']} | {result['state']} | {result['service']}\n"
            )

        handle.write("\nSummary\n")
        handle.write("-" * 7 + "\n")
        handle.write(f"Open: {counts['open']}\n")
        handle.write(f"Closed: {counts['closed']}\n")
        handle.write(f"Filtered: {counts['filtered']}\n")
        handle.write(f"Error: {counts['error']}\n")


# ══════════════════════════════════════════════════════════
#  Rich Display Helpers (Phase 1, unchanged)
# ══════════════════════════════════════════════════════════

STATE_STYLE: dict = {
    "open":     ("bold green",   "●"),
    "closed":   ("dim red",      "○"),
    "filtered": ("bold yellow",  "◌"),
    "error":    ("bold magenta", "✕"),
}


def build_results_table(results: list, show_closed: bool = False) -> Table:
    """Build a Rich Table from a list of scan_port() result dicts."""
    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white on grey11",
        border_style="grey42",
        show_lines=False,
        pad_edge=True,
        expand=False,
    )

    table.add_column("PORT",    style="cyan",         justify="right", min_width=7)
    table.add_column("STATE",   justify="center",     min_width=12)
    table.add_column("SERVICE", style="bright_white", min_width=14)

    visible = results if show_closed else [
        r for r in results if r["state"] != "closed"
    ]

    if not visible:
        table.add_row(
            "[dim]-[/dim]",
            "[dim]no open/filtered ports[/dim]",
            "[dim]-[/dim]",
        )
        return table

    for r in visible:
        colour, dot = STATE_STYLE.get(r["state"], ("white", "?"))
        state_text  = Text(f"{dot}  {r['state']}", style=colour)
        table.add_row(str(r["port"]), state_text, r["service"])

    return table


def print_banner(
    host: str, ports: list, timeout: float, mode: str = "Sequential"
) -> None:
    """Render the scan configuration header panel."""
    port_display = (
        f"{ports[0]}-{ports[-1]}  [dim]({len(ports)} ports)[/dim]"
        if len(ports) > 1 else str(ports[0])
    )
    content = (
        f"  [bold]Target  [/bold] {host}\n"
        f"  [bold]Ports   [/bold] {port_display}\n"
        f"  [bold]Timeout [/bold] {timeout}s per port\n"
        f"  [bold]Mode    [/bold] {mode}"
    )
    console.print(
        Panel(
            content,
            title="[bold cyan] Network Scanner [/bold cyan][dim] Threaded CLI [/dim]",
            border_style="cyan",
            padding=(0, 1),
        )
    )


def print_summary(results: list, elapsed: float) -> None:
    """Render a compact summary panel after the scan completes."""
    counts = {"open": 0, "closed": 0, "filtered": 0, "error": 0}
    for r in results:
        counts[r["state"]] = counts.get(r["state"], 0) + 1

    open_ports = [str(r["port"]) for r in results if r["state"] == "open"]

    summary_lines = [
        f"[bold green]  ● Open     [/bold green] {counts['open']}",
        f"[dim red]  ○ Closed   [/dim red] {counts['closed']}",
        f"[bold yellow]  ◌ Filtered [/bold yellow] {counts['filtered']}",
        f"\n  [dim]Scanned {len(results)} ports in {elapsed:.2f}s[/dim]",
    ]

    if open_ports:
        summary_lines.append(
            f"\n  [bold]Open ports[/bold] [cyan]{', '.join(open_ports)}[/cyan]"
        )

    console.print(
        Panel(
            "\n".join(summary_lines),
            title="[bold] Scan Complete [/bold]",
            border_style="green" if counts["open"] else "grey42",
            padding=(0, 1),
        )
    )


def build_arg_parser() -> argparse.ArgumentParser:
    """Build the command-line parser for Phase 4 usage."""
    parser = argparse.ArgumentParser(description="Network Scanner")
    parser.add_argument("--target", help="IP address, hostname, or CIDR block")
    parser.add_argument("--ports", default="1-1024", help="Single port, list, or range")
    parser.add_argument("--threads", type=int, default=100, help="Number of worker threads")
    parser.add_argument("--timeout", type=float, default=3.0, help="Seconds per port timeout (default 3.0s for nmap-like accuracy)")
    parser.add_argument("--output", help="Optional text file path for scan results")
    parser.add_argument("--db", action="store_true", help="Save results to PostgreSQL using DATABASE_URL env var")
    return parser


def run_cli(target: str, ports_arg: str, threads: int, timeout: float, output: str | None, db_enabled: bool = False) -> None:
    """Execute the scanner in CLI mode using the threaded engine."""
    # Strict input validation
    targets = resolve_targets(target)
    ports = parse_ports(ports_arg)

    threads = validate_threads(threads)
    timeout = validate_timeout(timeout)

    console.print()
    print_banner(targets[0], ports, timeout, mode=f"ThreadPoolExecutor ({threads} workers)")
    console.print()

    progress = {"completed": 0, "total": len(targets) * len(ports)}

    # Optional DB writer (initialized only if caller configured it)
    db_writer = None
    db_pool = None

    def try_init_db():
        nonlocal db_writer, db_pool
        try:
            # lazy import to avoid hard dependency when not used
            from db import init_db, DBWriter
            db_url = os.environ.get("DATABASE_URL")
            if not db_url:
                console.print("[yellow]DATABASE_URL not set; skipping DB writes[/yellow]")
                return
            db_pool = init_db(db_url)
            db_writer = DBWriter(db_pool, batch_size=100)
            db_writer.start()
            console.print("[green]DB writer started[/green]")
        except Exception as exc:
            console.print(f"[red]Failed to init DB writer: {exc}[/red]")

    def on_progress(completed: int, total: int, result: dict) -> None:
        progress["completed"] = completed
        progress["total"] = total
        if result["state"] == "open":
            console.log(
                f"[bold green]  ● OPEN[/bold green]  "
                f"[cyan]{result['host']}:{result['port']:<6}[/cyan] {result['service']}"
            )
        # If DB writer active, enqueue a lightweight record
        if db_writer is not None:
            try:
                db_writer.enqueue({
                    "scan_id": scan_id,
                    "ip": result.get("host"),
                    "port": int(result.get("port")),
                    "status": result.get("state"),
                    "service": result.get("service"),
                })
            except Exception:
                pass

    import time

    # unique scan session id
    scan_id = str(uuid.uuid4())

    # initialize DB writer if requested by caller
    if db_enabled:
        try_init_db()

    start_ts = time.perf_counter()
    with console.status(
        f"[cyan]Scanning [bold]{progress['total']}[/bold] host/port checks "
        f"with [bold]{threads}[/bold] workers...[/cyan]",
        spinner="dots",
        spinner_style="cyan",
    ):
        results = run_scan(targets, ports, threads, timeout, progress_callback=on_progress)

    elapsed = time.perf_counter() - start_ts

    console.print()
    console.print(build_results_table(results, show_closed=False))
    console.print()
    print_summary(results, elapsed)
    console.print()

    if output:
        export_results(
            results,
            output,
            metadata={
                "target": target,
                "ports": ports_arg,
                "threads": threads,
                "timeout": timeout,
                "elapsed_seconds": f"{elapsed:.2f}",
            },
        )
        console.print(f"[green]Saved results to {output}[/green]")

    # shutdown DB writer gracefully if it was started
    if db_writer is not None:
        try:
            db_writer.stop(flush=True)
        except Exception:
            pass
    if db_pool is not None:
        try:
            db_pool.closeall()
        except Exception:
            pass


# ══════════════════════════════════════════════════════════
#  Threaded Demo / CLI Entry Point
#
#  Run:  python scanner.py
#
#  Part A — Parser validation table (no network traffic)
#  Part B — Live scan using the full Phase 2 pipeline
# ══════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    parser = build_arg_parser()
    args = parser.parse_args()

    if args.target:
        try:
            run_cli(args.target, args.ports, args.threads, args.timeout, args.output, db_enabled=args.db)
        except ValueError as exc:
            parser.error(str(exc))
    else:
        import time

        # ── Part A: Parser validation (instant, no network) ──
        console.print()
        console.print(
            Panel(
                "[bold]Phase 2 — Parser Validation[/bold]\n"
                "[dim]Verifying resolve_targets() and parse_ports() "
                "before the live scan[/dim]",
                border_style="cyan",
                padding=(0, 1),
            )
        )
        console.print()

        # resolve_targets() showcase
        resolve_cases = [
            ("Single IP",  "93.184.216.34"),
            ("CIDR /30",   "10.0.0.0/30"),
            ("Hostname",   "scanme.nmap.org"),
        ]

        rt = Table(
            box=box.SIMPLE, show_header=True,
            header_style="bold white", border_style="grey42",
        )
        rt.add_column("Input",   style="cyan",         min_width=22)
        rt.add_column("Format",  style="dim",          min_width=12)
        rt.add_column("Expands to",style="bright_white",min_width=32)

        for label, value in resolve_cases:
            try:
                hosts   = resolve_targets(value)
                display = (
                    hosts[0] if len(hosts) == 1
                    else f"{hosts[0]}  ...  {hosts[-1]}  ({len(hosts)} hosts)"
                )
                rt.add_row(value, label, f"[green]✓[/green]  {display}")
            except ValueError as exc:
                rt.add_row(value, label, f"[red]✕  {exc}[/red]")

        console.print("  [bold]resolve_targets()[/bold]")
        console.print(rt)
        console.print()

        # parse_ports() showcase
        port_cases = [
            ("Single",  "443"),
            ("List",    "22,80,443"),
            ("Range",   "8080-8090"),
            ("Mixed",   "21,22,80,443,8000-8003"),
        ]

        pt = Table(
            box=box.SIMPLE, show_header=True,
            header_style="bold white", border_style="grey42",
        )
        pt.add_column("Input",    style="cyan",          min_width=22)
        pt.add_column("Format",   style="dim",           min_width=10)
        pt.add_column("Parsed",   style="bright_white",  min_width=32)

        for label, value in port_cases:
            try:
                parsed  = parse_ports(value)
                display = (
                    str(parsed)
                    if len(parsed) <= 7
                    else f"{parsed[:3]} ... {parsed[-1]}  ({len(parsed)} ports)"
                )
                pt.add_row(value, label, f"[green]✓[/green]  {display}")
            except ValueError as exc:
                pt.add_row(value, label, f"[red]✕  {exc}[/red]")

        console.print("  [bold]parse_ports()[/bold]")
        console.print(pt)

        # ── Part B: Live scan using the threaded Phase 3 pipeline ─
        TARGET_INPUT = "scanme.nmap.org"
        PORT_INPUT   = "21,22,25,53,80,110,443,8080"
        THREADS      = 25
        TIMEOUT      = 3.0

        ports   = parse_ports(PORT_INPUT)
        targets = resolve_targets(TARGET_INPUT)

        console.print()
        print_banner(
            targets[0], ports, TIMEOUT,
            mode=f"ThreadPoolExecutor ({THREADS} workers)",
        )
        console.print()

        progress = {"completed": 0, "total": len(targets) * len(ports)}

        def on_progress(completed: int, total: int, result: dict) -> None:
            progress["completed"] = completed
            progress["total"] = total
            if result["state"] == "open":
                console.log(
                    f"[bold green]  ● OPEN[/bold green]  "
                    f"[cyan]{result['host']}:{result['port']:<6}[/cyan] {result['service']}"
                )

        start_ts = time.perf_counter()

        with console.status(
            f"[cyan]Scanning [bold]{progress['total']}[/bold] host/port checks "
            f"with [bold]{THREADS}[/bold] workers...[/cyan]",
            spinner="dots",
            spinner_style="cyan",
        ):
            results = run_scan(targets, ports, THREADS, TIMEOUT, progress_callback=on_progress)

        elapsed = time.perf_counter() - start_ts

        console.print()
        console.print(build_results_table(results, show_closed=False))
        console.print()
        print_summary(results, elapsed)
        console.print()