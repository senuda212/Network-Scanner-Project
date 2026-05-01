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
import ipaddress
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

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


def scan_port(host: str, port: int, timeout: float = 1.0) -> dict:
    """
    Attempt a TCP connection to host:port and return the port state.

    Uses connect_ex() instead of connect() so that connection failures
    return an error code rather than raising an exception — critical
    for performance when scanning hundreds of closed ports.

    Port States:
        'open'     -> connect_ex() returned 0; port accepted the SYN
        'closed'   -> non-zero OS error code; port is actively rejecting
        'filtered' -> socket.timeout; packet silently dropped (firewall)
        'error'    -> DNS resolution failed; hostname is invalid

    Args:
        host:    Target IP address or hostname string
        port:    TCP port number to probe
        timeout: Seconds to wait before marking 'filtered' (default 1.0)

    Returns:
        dict with keys: port (int), state (str), service (str)
    """
    result = {
        "port":    port,
        "state":   "closed",
        "service": get_service_name(port),
    }

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            error_code = sock.connect_ex((host, port))
            result["state"] = "open" if error_code == 0 else "closed"

    except socket.timeout:
        result["state"] = "filtered"
    except socket.gaierror:
        result["state"] = "error"
        result["service"] = "DNS resolution failed"
    except OSError:
        result["state"] = "filtered"

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
            title="[bold cyan] Network Scanner [/bold cyan][dim] Phase 2 [/dim]",
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


# ══════════════════════════════════════════════════════════
#  Phase 2 Demo Entry Point
#
#  Run:  python scanner.py
#
#  Part A — Parser validation table (no network traffic)
#  Part B — Live scan using the full Phase 2 pipeline
# ══════════════════════════════════════════════════════════

if __name__ == "__main__":
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

    # ── Part B: Live scan using the full Phase 2 pipeline ─
    TARGET_INPUT = "scanme.nmap.org"
    PORT_INPUT   = "21,22,25,53,80,110,443,8080"
    TIMEOUT      = 1.0

    ports   = parse_ports(PORT_INPUT)
    targets = resolve_targets(TARGET_INPUT)
    host    = targets[0]

    console.print()
    print_banner(
        host, ports, TIMEOUT,
        mode="Sequential  [dim](Phase 3 adds threading)[/dim]",
    )
    console.print()

    results  = []
    start_ts = time.perf_counter()

    with console.status(
        f"[cyan]Scanning [bold]{len(ports)}[/bold] ports "
        f"on [bold]{host}[/bold]...[/cyan]",
        spinner="dots",
        spinner_style="cyan",
    ):
        for port in ports:
            result = scan_port(host, port, TIMEOUT)
            results.append(result)
            if result["state"] == "open":
                console.log(
                    f"[bold green]  ● OPEN[/bold green]  "
                    f"[cyan]{port:<6}[/cyan] {result['service']}"
                )

    elapsed = time.perf_counter() - start_ts

    console.print()
    console.print(build_results_table(results, show_closed=False))
    console.print()
    print_summary(results, elapsed)
    console.print()