#!/usr/bin/env python3
"""CustomTkinter GUI for the Network Scanner.

This version is local-only: it runs scans and exports results, but does not
use a web dashboard or database.
"""

from __future__ import annotations

import queue
import threading

import customtkinter as ctk
from tkinter import filedialog, messagebox

from scanner import (
    COMMON_PORTS,
    export_results,
    parse_ports,
    resolve_targets,
    run_scan,
    validate_threads,
    validate_timeout,
)

PORT_LABELS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt2",
    27017: "MongoDB",
}


class NetworkScannerApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()

        self.title("Network Scanner")
        self.geometry("1320x800")
        self.minsize(1100, 720)

        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

        self.scan_queue: queue.Queue = queue.Queue()
        self.scan_running = False
        self.last_results = []
        self.last_metadata = {}
        self.selected_ports: set[int] = set()
        self.port_buttons: dict[int, ctk.CTkButton] = {}
        self.metric_labels: dict[str, ctk.CTkLabel] = {}

        self.grid_columnconfigure(0, weight=3)
        self.grid_columnconfigure(1, weight=2)
        self.grid_rowconfigure(1, weight=1)

        self._build_header()
        self._build_main()
        self._build_footer()

        self.after(50, self._poll_queue)

    def _build_header(self) -> None:
        header = ctk.CTkFrame(self, corner_radius=0, fg_color="#111827")
        header.grid(row=0, column=0, columnspan=2, sticky="ew")
        header.grid_columnconfigure(0, weight=1)

        title_wrap = ctk.CTkFrame(header, fg_color="transparent")
        title_wrap.grid(row=0, column=0, sticky="w", padx=24, pady=18)

        ctk.CTkLabel(
            title_wrap,
            text="Network Scanner",
            font=ctk.CTkFont(size=30, weight="bold"),
        ).pack(anchor="w")
        ctk.CTkLabel(
            title_wrap,
            text="Local TCP port scanner with threaded results and export",
            text_color="#94a3b8",
            font=ctk.CTkFont(size=12),
        ).pack(anchor="w", pady=(4, 0))

        self.status_pill = ctk.CTkLabel(
            header,
            text="Local mode",
            text_color="#cbd5e1",
            fg_color="#1f2937",
            corner_radius=999,
            padx=14,
            pady=8,
            font=ctk.CTkFont(size=11, weight="bold"),
        )
        self.status_pill.grid(row=0, column=1, sticky="e", padx=24, pady=18)

    def _build_main(self) -> None:
        main = ctk.CTkFrame(self, fg_color="transparent")
        main.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=16, pady=12)
        main.grid_columnconfigure(0, weight=1)
        main.grid_columnconfigure(1, weight=1)
        main.grid_rowconfigure(0, weight=1)

        controls = ctk.CTkFrame(main, corner_radius=18, fg_color="#0f172a")
        controls.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        controls.grid_columnconfigure(0, weight=1)

        results = ctk.CTkFrame(main, corner_radius=18, fg_color="#0b1220")
        results.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        results.grid_columnconfigure(0, weight=1)
        results.grid_rowconfigure(2, weight=1)

        self._build_controls(controls)
        self._build_results(results)

    def _build_controls(self, parent: ctk.CTkFrame) -> None:
        form = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        form.pack(fill="both", expand=True, padx=18, pady=18)

        self._section_label(form, "Scan Settings")

        ctk.CTkLabel(form, text="Target", font=ctk.CTkFont(weight="bold")).pack(anchor="w", pady=(10, 4))
        self.target_entry = ctk.CTkEntry(form, height=34, placeholder_text="scanme.nmap.org or 192.168.1.0/24")
        self.target_entry.insert(0, "scanme.nmap.org")
        self.target_entry.pack(fill="x", pady=(0, 12))

        params = ctk.CTkFrame(form, fg_color="transparent")
        params.pack(fill="x", pady=(0, 12))
        params.grid_columnconfigure((0, 1), weight=1)

        ctk.CTkLabel(params, text="Threads").grid(row=0, column=0, sticky="w")
        self.threads_entry = ctk.CTkEntry(params, height=34)
        self.threads_entry.insert(0, "25")
        self.threads_entry.grid(row=1, column=0, sticky="ew", padx=(0, 8))

        ctk.CTkLabel(params, text="Timeout (s)").grid(row=0, column=1, sticky="w")
        self.timeout_entry = ctk.CTkEntry(params, height=34)
        self.timeout_entry.insert(0, "3.0")
        self.timeout_entry.grid(row=1, column=1, sticky="ew", padx=(8, 0))

        self._section_label(form, "Port Selection")

        port_frame = ctk.CTkScrollableFrame(form, height=230, fg_color="#111827", corner_radius=12)
        port_frame.pack(fill="x", pady=(0, 12))
        port_frame.grid_columnconfigure((0, 1, 2), weight=1)

        for index, port in enumerate(COMMON_PORTS):
            row, column = divmod(index, 3)
            label = PORT_LABELS.get(port, "")
            button = ctk.CTkButton(
                port_frame,
                text=f"{port}\n{label}" if label else str(port),
                fg_color="#334155",
                hover_color="#2563eb",
                height=46,
                font=ctk.CTkFont(size=9),
                command=lambda value=port: self.toggle_port(value),
            )
            button.grid(row=row, column=column, sticky="ew", padx=4, pady=4)
            self.port_buttons[port] = button

        ctk.CTkLabel(form, text="Custom Ports", font=ctk.CTkFont(weight="bold")).pack(anchor="w", pady=(4, 4))
        self.custom_ports_entry = ctk.CTkEntry(form, height=34, placeholder_text="e.g. 1-1024 or 22,80,443")
        self.custom_ports_entry.pack(fill="x", pady=(0, 12))
        self.custom_ports_entry.bind("<KeyRelease>", self.sync_from_input)

        actions = ctk.CTkFrame(form, fg_color="transparent")
        actions.pack(fill="x", pady=(8, 4))
        actions.grid_columnconfigure((0, 1, 2), weight=1)

        self.scan_button = ctk.CTkButton(
            actions,
            text="Start Scan",
            height=40,
            command=self.start_scan,
        )
        self.scan_button.grid(row=0, column=0, sticky="ew", padx=(0, 6))

        self.export_button = ctk.CTkButton(
            actions,
            text="Export Results",
            height=40,
            command=self.export_results,
            state="disabled",
        )
        self.export_button.grid(row=0, column=1, sticky="ew", padx=6)

        self.clear_button = ctk.CTkButton(
            actions,
            text="Clear",
            height=40,
            command=self.clear_results,
            fg_color="#334155",
            hover_color="#475569",
        )
        self.clear_button.grid(row=0, column=2, sticky="ew", padx=(6, 0))

    def _build_results(self, parent: ctk.CTkFrame) -> None:
        self._section_label(parent, "Results Overview")

        metrics = ctk.CTkFrame(parent, fg_color="transparent")
        metrics.grid(row=1, column=0, sticky="ew", padx=18, pady=(0, 8))
        for column in range(4):
            metrics.grid_columnconfigure(column, weight=1)

        metric_specs = [
            ("open", "Open"),
            ("closed", "Closed"),
            ("filtered", "Filtered"),
            ("error", "Error"),
        ]
        for column, (key, label) in enumerate(metric_specs):
            card = ctk.CTkFrame(metrics, fg_color="#111827", corner_radius=14)
            card.grid(row=0, column=column, sticky="ew", padx=4)
            ctk.CTkLabel(card, text=label, text_color="#94a3b8", font=ctk.CTkFont(size=11)).pack(anchor="w", padx=14, pady=(12, 0))
            value = ctk.CTkLabel(card, text="0", font=ctk.CTkFont(size=24, weight="bold"))
            value.pack(anchor="w", padx=14, pady=(0, 12))
            self.metric_labels[key] = value

        self.results_box = ctk.CTkTextbox(parent, fg_color="#050b16", corner_radius=14)
        self.results_box.grid(row=2, column=0, sticky="nsew", padx=18, pady=(0, 12))
        self.results_box.insert("end", "Scan results will appear here.\n")

        footer = ctk.CTkFrame(parent, fg_color="transparent")
        footer.grid(row=3, column=0, sticky="ew", padx=18, pady=(0, 18))
        footer.grid_columnconfigure(0, weight=1)
        self.summary_label = ctk.CTkLabel(footer, text="No scan started yet", text_color="#94a3b8")
        self.summary_label.grid(row=0, column=0, sticky="w")

    def _build_footer(self) -> None:
        footer = ctk.CTkFrame(self, corner_radius=0, fg_color="#111827")
        footer.grid(row=2, column=0, columnspan=2, sticky="ew")
        footer.grid_columnconfigure(0, weight=1)

        self.progress = ctk.CTkProgressBar(footer)
        self.progress.grid(row=0, column=0, sticky="ew", padx=16, pady=(12, 6))
        self.progress.set(0)

        self.status = ctk.CTkLabel(footer, text="Ready", text_color="#cbd5e1")
        self.status.grid(row=1, column=0, sticky="w", padx=16, pady=(0, 12))

    def _section_label(self, parent: ctk.CTkFrame, text: str) -> None:
        ctk.CTkLabel(
            parent,
            text=text,
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color="#e2e8f0",
        ).pack(anchor="w", pady=(0, 6))

    def toggle_port(self, port: int) -> None:
        if port in self.selected_ports:
            self.selected_ports.remove(port)
            self.port_buttons[port].configure(fg_color="#334155")
        else:
            self.selected_ports.add(port)
            self.port_buttons[port].configure(fg_color="#2563eb")
        self.update_input()

    def update_input(self) -> None:
        if self.selected_ports:
            self.custom_ports_entry.delete(0, "end")
            self.custom_ports_entry.insert(0, ",".join(map(str, sorted(self.selected_ports))))

    def sync_from_input(self, event=None) -> None:
        try:
            ports = parse_ports(self.custom_ports_entry.get())
        except Exception:
            return

        self.selected_ports = set(ports)
        for port, button in self.port_buttons.items():
            button.configure(fg_color="#2563eb" if port in ports else="#334155")

    def clear_results(self) -> None:
        self.last_results = []
        self.last_metadata = {}
        self.results_box.delete("1.0", "end")
        self.results_box.insert("end", "Scan results will appear here.\n")
        for key in self.metric_labels:
            self.metric_labels[key].configure(text="0")
        self.summary_label.configure(text="No scan started yet")
        self.status.configure(text="Ready")
        self.progress.set(0)
        self.export_button.configure(state="disabled")

    def start_scan(self) -> None:
        if self.scan_running:
            return

        try:
            targets = resolve_targets(self.target_entry.get().strip())
            ports = parse_ports(self.custom_ports_entry.get().strip())
            threads = validate_threads(int(self.threads_entry.get()))
            timeout = validate_timeout(float(self.timeout_entry.get()))
        except Exception as exc:
            messagebox.showerror("Error", str(exc))
            return

        self.scan_running = True
        self.last_results = []
        self.last_metadata = {
            "target": self.target_entry.get().strip(),
            "ports": self.custom_ports_entry.get().strip(),
            "threads": threads,
            "timeout": timeout,
        }
        self.results_box.delete("1.0", "end")
        self.status.configure(text="Starting scan...", text_color="#f59e0b")
        self.progress.set(0)
        self.scan_button.configure(state="disabled")
        self.export_button.configure(state="disabled")
        threading.Thread(
            target=self._scan_worker,
            args=(targets, ports, threads, timeout),
            daemon=True,
        ).start()

    def _scan_worker(self, targets, ports, threads, timeout) -> None:
        def progress_callback(completed: int, total: int, result: dict) -> None:
            self.scan_queue.put(("result", completed, total, result))

        try:
            results = run_scan(targets, ports, threads, timeout, progress_callback=progress_callback)
            self.scan_queue.put(("done", results))
        except Exception as exc:
            self.scan_queue.put(("error", str(exc)))

    def _render_metrics(self, results: list[dict]) -> None:
        counts = {"open": 0, "closed": 0, "filtered": 0, "error": 0}
        for row in results:
            state = row.get("state")
            if state in counts:
                counts[state] += 1
        for key, value in counts.items():
            self.metric_labels[key].configure(text=str(value))
        self.summary_label.configure(text=f"{len(results)} checks completed")

    def _poll_queue(self) -> None:
        try:
            while True:
                item = self.scan_queue.get_nowait()
                kind = item[0]

                if kind == "result":
                    _, completed, total, result = item
                    self.last_results.append(result)
                    state = result.get("state", "error")
                    color = {
                        "open": "#22c55e",
                        "closed": "#ef4444",
                        "filtered": "#f59e0b",
                        "error": "#f43f5e",
                    }.get(state, "#cbd5e1")
                    self.results_box.insert("end", f"{result['host']}:{result['port']} -> {state}\n")
                    self.results_box.tag_add(state, "end-2l", "end-1l")
                    self.results_box.tag_config(state, foreground=color)
                    if total:
                        self.progress.set(completed / total)
                    self.status.configure(text=f"Scanning {completed}/{total}", text_color="#94a3b8")

                elif kind == "done":
                    results = item[1]
                    self.last_results = results
                    self._render_metrics(results)
                    self.scan_running = False
                    self.scan_button.configure(state="normal")
                    self.export_button.configure(state="normal" if results else "disabled")
                    self.progress.set(1)
                    self.status.configure(text=f"Scan complete: {len(results)} results", text_color="#22c55e")

                elif kind == "error":
                    self.scan_running = False
                    self.scan_button.configure(state="normal")
                    self.export_button.configure(state="disabled")
                    self.status.configure(text="Scan failed", text_color="#ef4444")
                    messagebox.showerror("Scan error", item[1])

        except queue.Empty:
            pass

        self.after(50, self._poll_queue)

    def export_results(self) -> None:
        if not self.last_results:
            messagebox.showinfo("Export", "No scan results to export.")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return

        try:
            export_results(self.last_results, path, metadata=self.last_metadata)
            messagebox.showinfo("Export", f"Results exported to {path}")
        except Exception as exc:
            messagebox.showerror("Export error", str(exc))


if __name__ == "__main__":
    app = NetworkScannerApp()
    app.mainloop()
