#!/usr/bin/env python3
"""Phase 5 customtkinter front end for the Network Scanner project."""

from __future__ import annotations

import os
import queue
import threading

import customtkinter as ctk
from tkinter import filedialog, messagebox

from env_loader import load_dotenv
from db import DBWriter, init_db
from scanner import (
    export_results,
    parse_ports,
    resolve_targets,
    run_scan,
    validate_threads,
    validate_timeout,
)

load_dotenv()


class NetworkScannerApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Network Scanner")
        self.geometry("980x680")
        self.minsize(840, 600)

        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

        self.scan_queue: queue.Queue = queue.Queue()
        self.last_results: list = []
        self.last_metadata: dict = {}
        self.scan_summary: dict = {}
        self.scan_running = False

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        header = ctk.CTkLabel(
            self,
            text="Network Scanner",
            font=ctk.CTkFont(size=28, weight="bold"),
        )
        header.grid(row=0, column=0, padx=24, pady=(24, 10), sticky="w")

        subtitle = ctk.CTkLabel(
            self,
            text="CIDR targets, multi-port scans, live progress, and export",
            text_color="#9aa4b2",
        )
        subtitle.grid(row=0, column=0, padx=24, pady=(58, 0), sticky="w")

        self._build_form()
        self._build_results_view()
        self._build_footer()

        self.after(50, self._poll_queue)

    def _build_form(self) -> None:
        form = ctk.CTkFrame(self, corner_radius=16)
        form.grid(row=1, column=0, padx=24, pady=(12, 10), sticky="ew")
        form.grid_columnconfigure((1, 3, 5, 7), weight=1)

        ctk.CTkLabel(form, text="Target").grid(row=0, column=0, padx=(16, 8), pady=(16, 8), sticky="w")
        self.target_entry = ctk.CTkEntry(form, placeholder_text="192.168.1.0/24 or scanme.nmap.org")
        self.target_entry.grid(row=0, column=1, padx=(0, 16), pady=(16, 8), sticky="ew")
        self.target_entry.insert(0, "scanme.nmap.org")

        ctk.CTkLabel(form, text="Ports").grid(row=0, column=2, padx=(16, 8), pady=(16, 8), sticky="w")
        self.ports_entry = ctk.CTkEntry(form, placeholder_text="22,80,443 or 1-1024")
        self.ports_entry.grid(row=0, column=3, padx=(0, 16), pady=(16, 8), sticky="ew")
        self.ports_entry.insert(0, "21,22,25,53,80,110,443,8080")

        ctk.CTkLabel(form, text="Threads").grid(row=1, column=0, padx=(16, 8), pady=(0, 16), sticky="w")
        self.threads_entry = ctk.CTkEntry(form)
        self.threads_entry.grid(row=1, column=1, padx=(0, 16), pady=(0, 16), sticky="ew")
        self.threads_entry.insert(0, "25")

        ctk.CTkLabel(form, text="Timeout").grid(row=1, column=2, padx=(16, 8), pady=(0, 16), sticky="w")
        self.timeout_entry = ctk.CTkEntry(form)
        self.timeout_entry.grid(row=1, column=3, padx=(0, 16), pady=(0, 16), sticky="ew")
        self.timeout_entry.insert(0, "1.0")

        self.scan_button = ctk.CTkButton(form, text="Start Scan", command=self.start_scan)
        self.scan_button.grid(row=0, column=4, rowspan=2, padx=(16, 8), pady=16, sticky="ns")

        self.export_button = ctk.CTkButton(form, text="Export Results", command=self.export_last_results, state="disabled")
        self.export_button.grid(row=0, column=5, rowspan=2, padx=(8, 16), pady=16, sticky="ns")

        self.db_var = ctk.BooleanVar(value=False)
        self.db_toggle = ctk.CTkCheckBox(form, text="Save to Database", variable=self.db_var)
        self.db_toggle.grid(row=2, column=0, padx=(16, 8), pady=(0, 12), sticky="w")

        ctk.CTkLabel(form, text="Database URL").grid(row=2, column=1, padx=(16, 8), pady=(0, 12), sticky="w")
        self.db_url_entry = ctk.CTkEntry(form, placeholder_text="postgresql://user:pass@host:5432/db")
        self.db_url_entry.grid(row=2, column=2, columnspan=3, padx=(0, 16), pady=(0, 12), sticky="ew")
        self.db_url_entry.insert(0, os.environ.get("DATABASE_URL", ""))

    def _build_results_view(self) -> None:
        results_card = ctk.CTkFrame(self, corner_radius=16)
        results_card.grid(row=2, column=0, padx=24, pady=(0, 10), sticky="nsew")
        results_card.grid_columnconfigure(0, weight=1)
        results_card.grid_rowconfigure(1, weight=1)

        results_header = ctk.CTkFrame(results_card, fg_color="transparent")
        results_header.grid(row=0, column=0, padx=16, pady=(16, 8), sticky="ew")
        results_header.grid_columnconfigure((0, 1, 2, 3), weight=1)

        for column, title in enumerate(("Host", "Port", "State", "Service")):
            ctk.CTkLabel(results_header, text=title, font=ctk.CTkFont(weight="bold")).grid(
                row=0, column=column, padx=8, sticky="w"
            )

        self.results_scroll = ctk.CTkScrollableFrame(results_card, corner_radius=12)
        self.results_scroll.grid(row=1, column=0, padx=16, pady=(0, 16), sticky="nsew")
        self.results_scroll.grid_columnconfigure((0, 1, 2, 3), weight=1)

    def _build_footer(self) -> None:
        footer = ctk.CTkFrame(self, corner_radius=16)
        footer.grid(row=3, column=0, padx=24, pady=(0, 24), sticky="ew")
        footer.grid_columnconfigure(0, weight=1)

        self.progress_bar = ctk.CTkProgressBar(footer)
        self.progress_bar.grid(row=0, column=0, padx=16, pady=(16, 6), sticky="ew")
        self.progress_bar.set(0)

        self.status_label = ctk.CTkLabel(footer, text="Ready to scan", text_color="#9aa4b2")
        self.status_label.grid(row=1, column=0, padx=16, pady=(0, 16), sticky="w")

    def clear_results(self) -> None:
        for child in self.results_scroll.winfo_children():
            child.destroy()
        self.last_results = []
        self.last_metadata = {}
        self.scan_summary = {}
        self.export_button.configure(state="disabled")

    def append_result_row(self, result: dict) -> None:
        row = ctk.CTkFrame(self.results_scroll, fg_color=("#1f2937", "#0f172a"), corner_radius=10)
        row.grid(sticky="ew", padx=4, pady=4)
        row.grid_columnconfigure((0, 1, 2, 3), weight=1)

        values = (
            result.get("host", ""),
            str(result.get("port", "")),
            result.get("state", ""),
            result.get("service", ""),
        )

        for column, value in enumerate(values):
            ctk.CTkLabel(row, text=value).grid(row=0, column=column, padx=10, pady=8, sticky="w")

    def set_running_state(self, running: bool) -> None:
        self.scan_running = running
        self.scan_button.configure(state="disabled" if running else "normal")
        if not running and self.last_results:
            self.export_button.configure(state="normal")

    def start_scan(self) -> None:
        if self.scan_running:
            return

        target = self.target_entry.get().strip()
        ports_arg = self.ports_entry.get().strip()
        threads_text = self.threads_entry.get().strip()
        timeout_text = self.timeout_entry.get().strip()

        try:
            targets = resolve_targets(target)
            ports = parse_ports(ports_arg)
            threads = validate_threads(int(threads_text))
            timeout = validate_timeout(float(timeout_text))
        except ValueError as exc:
            messagebox.showerror("Invalid input", str(exc))
            return

        self.clear_results()
        self.progress_bar.set(0)
        self.status_label.configure(text="Starting scan...")
        self.set_running_state(True)

        self.last_metadata = {
            "target": target,
            "ports": ports_arg,
            "threads": threads,
            "timeout": timeout,
        }

        db_enabled = bool(self.db_var.get())
        db_url = self.db_url_entry.get().strip() or os.environ.get("DATABASE_URL", "")
        self.last_metadata["db_enabled"] = db_enabled
        if db_enabled and not db_url:
            messagebox.showerror("Database", "DATABASE_URL is required when Save to Database is enabled.")
            self.set_running_state(False)
            return

        worker = threading.Thread(
            target=self._scan_worker,
            args=(targets, ports, threads, timeout, target, ports_arg, db_enabled, db_url),
            daemon=True,
        )
        worker.start()

    def _scan_worker(
        self,
        targets: list,
        ports: list,
        threads: int,
        timeout: float,
        target_text: str,
        ports_text: str,
        db_enabled: bool,
        db_url: str,
    ) -> None:
        db_writer = None
        db_pool = None
        scan_id = os.urandom(8).hex()

        if db_enabled:
            try:
                db_pool = init_db(db_url)
                db_writer = DBWriter(db_pool, batch_size=100)
                db_writer.start()
                self.scan_queue.put(("status", "Database writer started"))
            except Exception as exc:
                self.scan_queue.put(("status", f"Database disabled: {exc}"))
                db_writer = None
                db_pool = None

        def on_progress(completed: int, total: int, result: dict) -> None:
            self.scan_queue.put(("progress", completed, total))
            self.scan_queue.put(("result", result))
            if db_writer is not None:
                db_writer.enqueue(
                    {
                        "scan_id": scan_id,
                        "ip": result.get("host"),
                        "port": result.get("port"),
                        "status": result.get("state"),
                        "service": result.get("service"),
                    }
                )

        try:
            results = run_scan(targets, ports, threads, timeout, progress_callback=on_progress)
            self.scan_queue.put(("done", results, target_text, ports_text, threads, timeout))
        except Exception as exc:  # pragma: no cover - surfaced via UI queue
            self.scan_queue.put(("error", str(exc)))
        finally:
            if db_writer is not None:
                db_writer.stop(flush=True)
            if db_pool is not None:
                try:
                    db_pool.closeall()
                except Exception:
                    pass

    def _poll_queue(self) -> None:
        try:
            while True:
                item = self.scan_queue.get_nowait()
                kind = item[0]

                if kind == "progress":
                    completed, total = item[1], item[2]
                    self.progress_bar.set(completed / total if total else 0)
                    self.status_label.configure(text=f"Scanning {completed}/{total} targets")

                elif kind == "result":
                    result = item[1]
                    self.append_result_row(result)

                elif kind == "status":
                    self.status_label.configure(text=item[1])

                elif kind == "done":
                    results, target_text, ports_text, threads, timeout = item[1], item[2], item[3], item[4], item[5]
                    self.last_results = results
                    counts = {"open": 0, "closed": 0, "filtered": 0, "error": 0}
                    for result in results:
                        counts[result.get("state", "error")] = counts.get(result.get("state", "error"), 0) + 1
                    self.scan_summary = counts
                    self.last_metadata = {
                        "target": target_text,
                        "ports": ports_text,
                        "threads": threads,
                        "timeout": timeout,
                    }
                    self.status_label.configure(
                        text=(
                            f"Scan complete: {len(results)} checks finished | "
                            f"open {counts['open']}, closed {counts['closed']}, filtered {counts['filtered']}"
                        )
                    )
                    self.progress_bar.set(1)
                    self.set_running_state(False)
                    self.export_button.configure(state="normal")

                elif kind == "error":
                    self.set_running_state(False)
                    self.status_label.configure(text="Scan failed")
                    messagebox.showerror("Scan error", item[1])

        except queue.Empty:
            pass

        self.after(50, self._poll_queue)

    def export_last_results(self) -> None:
        if not self.last_results:
            messagebox.showinfo("Export", "No scan results to export yet.")
            return

        filepath = filedialog.asksaveasfilename(
            title="Save scan results",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not filepath:
            return

        export_results(self.last_results, filepath, metadata=self.last_metadata)
        messagebox.showinfo("Export", f"Saved results to {filepath}")


if __name__ == "__main__":
    app = NetworkScannerApp()
    app.mainloop()