#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║           Network Scanner — scanner.py                   ║
║           Phase 1: Core TCP Networking Engine            ║
╚══════════════════════════════════════════════════════════╝

Module  : Python Programming — Network Programming Design
Phase   : 1 of 5 — Core socket engine with Rich terminal output

What this phase delivers:
  - scan_port()        → atomic TCP probe for a single host:port
  - get_service_name() → resolves port number to well-known service
  - Rich display       → coloured table, spinner, summary panel
  - Phase 1 demo       → scans common ports on a safe public host

Subsequent phases will import scan_port() and get_service_name()
directly — do not rename or move them.
"""

import socket
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

# ──────────────────────────────────────────────────────────
#  Core Functions
#  These two functions are the atomic units of the scanner.
#  Every later phase depends on them.
# ──────────────────────────────────────────────────────────

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
    return an error code rather than raising an exception — this is
    critical for performance when scanning hundreds of closed ports.

    Port States:
        'open'     -> connect_ex() returned 0; the port accepted the SYN
        'closed'   -> connect_ex() returned a non-zero OS error code;
                     the host is up but the port is actively rejecting
        'filtered' -> socket.timeout was raised; the packet was dropped
                     silently (firewall) or the host is unreachable
        'error'    -> DNS resolution failed; the hostname is invalid

    Args:
        host:    Target IP address or hostname string
        port:    TCP port number to probe
        timeout: Seconds to wait for a response before marking 'filtered'
                 (default: 1.0 — use lower values with threading in Phase 3)

    Returns:
        dict with keys:
            port    (int) — the port that was scanned
            state   (str) — 'open' | 'closed' | 'filtered' | 'error'
            service (str) — well-known name or 'unknown'
    """
    result = {
        "port":    port,
        "state":   "closed",
        "service": get_service_name(port),
    }

    try:
        # AF_INET    = IPv4 address family
        # SOCK_STREAM = TCP (connection-oriented, reliable)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)

            # connect_ex() returns 0 on success, OS errno on failure.
            # This never raises on a refused connection — unlike connect().
            error_code = sock.connect_ex((host, port))

            if error_code == 0:
                result["state"] = "open"
            else:
                # Non-zero: port exists but is actively refusing (ECONNREFUSED)
                # or some other OS-level rejection.
                result["state"] = "closed"

    except socket.timeout:
        # No response within the timeout window -> likely firewalled
        result["state"] = "filtered"

    except socket.gaierror:
        # getaddrinfo() failed — hostname could not be resolved
        result["state"] = "error"
        result["service"] = "DNS resolution failed"

    except OSError:
        # Catch-all for other OS-level socket errors (host unreachable, etc.)
        result["state"] = "filtered"

    return result


# ──────────────────────────────────────────────────────────
#  Rich Display Helpers
# ──────────────────────────────────────────────────────────

# Maps each port state to a (Rich colour, indicator dot) pair
STATE_STYLE: dict = {
    "open":     ("bold green",   "●"),
    "closed":   ("dim red",      "○"),
    "filtered": ("bold yellow",  "◌"),
    "error":    ("bold magenta", "✕"),
}


def build_results_table(results: list, show_closed: bool = False) -> Table:
    """
    Build and return a Rich Table from a list of scan result dicts.

    Args:
        results:     List of dicts returned by scan_port()
        show_closed: If False (default), closed ports are hidden to reduce noise

    Returns:
        A configured rich.table.Table — call console.print(table) to render it
    """
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

    visible = results if show_closed else [r for r in results if r["state"] != "closed"]

    if not visible:
        table.add_row("[dim]-[/dim]", "[dim]no results[/dim]", "[dim]-[/dim]")
        return table

    for r in visible:
        colour, dot = STATE_STYLE.get(r["state"], ("white", "?"))
        state_text  = Text(f"{dot}  {r['state']}", style=colour)
        table.add_row(str(r["port"]), state_text, r["service"])

    return table


def print_banner(host: str, ports: list, timeout: float) -> None:
    """Render the scan configuration header panel."""
    port_range = (
        f"{ports[0]}-{ports[-1]}"
        if len(ports) > 1 else str(ports[0])
    )
    content = (
        f"  [bold]Target  [/bold] {host}\n"
        f"  [bold]Ports   [/bold] {port_range}  [dim]({len(ports)} total)[/dim]\n"
        f"  [bold]Timeout [/bold] {timeout}s per port\n"
        f"  [bold]Mode    [/bold] Sequential  [dim](Phase 3 adds multi-threading)[/dim]"
    )
    console.print(
        Panel(
            content,
            title="[bold cyan] Network Scanner [/bold cyan][dim] Phase 1 [/dim]",
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


# ──────────────────────────────────────────────────────────
#  Phase 1 Demo Entry Point
#
#  Run:  python scanner.py
#
#  Uses scanme.nmap.org — Nmap's official public test host.
#  This is maintained specifically for scanner testing.
#  Scanning it is legal and encouraged by the Nmap project.
# ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    import time

    # ── Demo Configuration ────────────────────────────────
    TARGET  = "scanme.nmap.org"   # Safe, legal, public test target
    PORTS   = COMMON_PORTS        # Defined at the top of this file
    TIMEOUT = 1.0                 # Seconds — lowered in Phase 3 w/ threads
    # ─────────────────────────────────────────────────────

    console.print()
    print_banner(TARGET, PORTS, TIMEOUT)
    console.print()

    results  = []
    start_ts = time.perf_counter()

    with console.status(
        f"[cyan]Probing [bold]{len(PORTS)}[/bold] ports on [bold]{TARGET}[/bold]...[/cyan]",
        spinner="dots",
        spinner_style="cyan",
    ):
        for port in PORTS:
            result = scan_port(TARGET, port, TIMEOUT)
            results.append(result)

            # Live feedback for open ports — visible even during the spinner
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