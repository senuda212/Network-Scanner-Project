#!/usr/bin/env python3
"""Advanced customtkinter GUI for Network Scanner"""

from __future__ import annotations

import os
import queue
import threading
import uuid

import customtkinter as ctk
from tkinter import filedialog, messagebox

from env_loader import load_dotenv
from db import DBWriter, init_db
from scanner import (
    COMMON_PORTS,
    export_results,
    parse_ports,
    resolve_targets,
    run_scan,
    validate_threads,
    validate_timeout,
)

load_dotenv()

# Port service name mapping for UI display
PORT_LABELS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC", 135: "RPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1723: "PPTP",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt2",
    27017: "MongoDB",
}


class NetworkScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Network Scanner")
        self.geometry("1200x720")

        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

        self.scan_queue = queue.Queue()
        self.selected_ports = set()
        self.port_buttons = {}
        self.scan_running = False
        self.last_results = []
        self.last_metadata = {}
        self.db_writer = None

        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=0)
        self.grid_rowconfigure(1, weight=1)

        self._build_header()
        self._build_main()
        self._build_sidebar()
        self._build_footer()

        self.after(50, self._poll_queue)

    # ---------------- UI ---------------- #

    def _build_header(self):
        ctk.CTkLabel(self, text="Network Scanner",
                     font=ctk.CTkFont(size=28, weight="bold")).grid(
            row=0, column=0, padx=20, pady=(20, 0), sticky="w"
        )

    def _build_main(self):
        frame = ctk.CTkFrame(self)
        frame.grid(row=1, column=0, padx=20, pady=10, sticky="nsew")

        frame.grid_columnconfigure((1, 3), weight=1)

        # Target
        ctk.CTkLabel(frame, text="Target").grid(row=0, column=0)
        self.target_entry = ctk.CTkEntry(frame)
        self.target_entry.insert(0, "scanme.nmap.org")
        self.target_entry.grid(row=0, column=1, sticky="ew")

        # Threads
        ctk.CTkLabel(frame, text="Threads").grid(row=1, column=0)
        self.threads_entry = ctk.CTkEntry(frame)
        self.threads_entry.insert(0, "25")
        self.threads_entry.grid(row=1, column=1, sticky="ew")

        # Timeout
        ctk.CTkLabel(frame, text="Timeout").grid(row=1, column=2)
        self.timeout_entry = ctk.CTkEntry(frame)
        self.timeout_entry.insert(0, "1.0")
        self.timeout_entry.grid(row=1, column=3, sticky="ew")

        # PORT GRID (using COMMON_PORTS from scanner)
        port_frame = ctk.CTkFrame(frame)
        port_frame.grid(row=0, column=2, rowspan=2, padx=10)

        for i, port in enumerate(COMMON_PORTS):
            r, c = divmod(i, 3)
            name = PORT_LABELS.get(port, "")

            btn = ctk.CTkButton(
                port_frame,
                text=f"{port}\n{name}" if name else str(port),
                fg_color="gray25",
                command=lambda p=port: self.toggle_port(p),
                width=80
            )
            btn.grid(row=r, column=c, padx=5, pady=5)
            self.port_buttons[port] = btn

        # Custom Ports
        ctk.CTkLabel(frame, text="Custom Ports").grid(row=2, column=0)
        self.custom_ports_entry = ctk.CTkEntry(frame, placeholder_text="e.g. 1-1024 or 22,80,443")
        self.custom_ports_entry.grid(row=2, column=1, columnspan=3, sticky="ew")
        self.custom_ports_entry.bind("<KeyRelease>", self.sync_from_input)

        # Database Toggle
        ctk.CTkLabel(frame, text="Database").grid(row=3, column=0)
        self.db_var = ctk.BooleanVar(value=False)
        self.db_toggle = ctk.CTkCheckBox(frame, text="Save to Database", variable=self.db_var)
        self.db_toggle.grid(row=3, column=1, sticky="w")

        # Database URL
        ctk.CTkLabel(frame, text="DB URL").grid(row=3, column=2)
        self.db_url_entry = ctk.CTkEntry(frame, placeholder_text="postgresql://user:pass@host:5432/db")
        self.db_url_entry.grid(row=3, column=3, sticky="ew")
        self.db_url_entry.insert(0, os.environ.get("DATABASE_URL", ""))

        # Buttons
        self.scan_button = ctk.CTkButton(frame, text="Start Scan", command=self.start_scan)
        self.scan_button.grid(row=0, column=4, rowspan=2, padx=10)

        self.export_button = ctk.CTkButton(frame, text="Export", command=self.export_results, state="disabled")
        self.export_button.grid(row=0, column=5, rowspan=2)

        # Results
        self.results_box = ctk.CTkTextbox(frame, height=300)
        self.results_box.grid(row=4, column=0, columnspan=6, sticky="nsew", pady=10)
        frame.grid_rowconfigure(4, weight=1)

    def _build_sidebar(self):
        sidebar = ctk.CTkFrame(self, width=260)
        sidebar.grid(row=1, column=1, sticky="ns", padx=10)

        ctk.CTkLabel(sidebar, text="Scan History",
                     font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)

        self.history_box = ctk.CTkTextbox(sidebar)
        self.history_box.pack(fill="both", expand=True, padx=10)

        ctk.CTkButton(sidebar, text="Refresh", command=self.load_scan_history)\
            .pack(pady=10)

    def _build_footer(self):
        footer = ctk.CTkFrame(self)
        footer.grid(row=2, column=0, columnspan=2, sticky="ew", padx=20)

        self.progress = ctk.CTkProgressBar(footer)
        self.progress.pack(fill="x", pady=5)

        self.status = ctk.CTkLabel(footer, text="Ready")
        self.status.pack(side="left", padx=10)

        self.db_status = ctk.CTkLabel(footer, text="DB: Disconnected", text_color="#ef4444")
        self.db_status.pack(side="right", padx=10)

    # ---------------- PORT LOGIC ---------------- #

    def toggle_port(self, port):
        if port in self.selected_ports:
            self.selected_ports.remove(port)
            self.port_buttons[port].configure(fg_color="gray25")
        else:
            self.selected_ports.add(port)
            self.port_buttons[port].configure(fg_color="#2563eb")

        self.update_input()

    def update_input(self):
        if self.selected_ports:
            self.custom_ports_entry.delete(0, "end")
            self.custom_ports_entry.insert(0, ",".join(map(str, sorted(self.selected_ports))))

    def sync_from_input(self, event=None):
        try:
            ports = parse_ports(self.custom_ports_entry.get())
        except:
            return

        self.selected_ports = set(ports)

        for p, btn in self.port_buttons.items():
            btn.configure(fg_color="#2563eb" if p in ports else "gray25")

    # ---------------- SCAN ---------------- #

    def start_scan(self):
        if self.scan_running:
            return

        try:
            targets = resolve_targets(self.target_entry.get())
            ports = parse_ports(self.custom_ports_entry.get())
            threads = validate_threads(int(self.threads_entry.get()))
            timeout = validate_timeout(float(self.timeout_entry.get()))
        except Exception as e:
            messagebox.showerror("Error", str(e))
            return

        self.last_results = []
        self.last_metadata = {
            "target": self.target_entry.get(),
            "ports": self.custom_ports_entry.get(),
            "threads": threads,
            "timeout": timeout,
        }

        self.results_box.delete("1.0", "end")
        self.scan_running = True
        self.scan_button.configure(state="disabled")
        self.export_button.configure(state="disabled")

        threading.Thread(
            target=self._scan_worker,
            args=(targets, ports, threads, timeout),
            daemon=True
        ).start()

    def _scan_worker(self, targets, ports, threads, timeout):
        scan_id = str(uuid.uuid4())[:8]
        db_enabled = bool(self.db_var.get())
        db_url = self.db_url_entry.get().strip() or os.environ.get("DATABASE_URL", "")
        
        db_pool = None
        db_writer = None

        self.scan_queue.put(("db_status", "connecting" if db_enabled else "disabled"))

        if db_enabled:
            try:
                db_pool = init_db(db_url)
                db_writer = DBWriter(db_pool, batch_size=100)
                db_writer.start()
                self.scan_queue.put(("db_status", "connected"))
            except Exception as e:
                self.scan_queue.put(("db_status", "failed"))
                self.scan_queue.put(("status", f"DB error: {e}"))
                db_writer = None
                db_pool = None

        def progress(c, t, result):
            self.scan_queue.put(("result", result))
            if db_writer is not None:
                db_writer.enqueue({
                    "scan_id": scan_id,
                    "target_ip": result.get("host"),
                    "port": result.get("port"),
                    "status": result.get("state"),
                    "service": result.get("service"),
                })

        try:
            results = run_scan(targets, ports, threads, timeout, progress_callback=progress)
            self.scan_queue.put(("done", results))
        except Exception as e:
            self.scan_queue.put(("error", str(e)))
        finally:
            if db_writer is not None:
                db_writer.stop(flush=True)
            if db_pool is not None:
                try:
                    db_pool.closeall()
                except Exception:
                    pass

    # ---------------- QUEUE ---------------- #

    def _poll_queue(self):
        try:
            while True:
                item = self.scan_queue.get_nowait()

                if item[0] == "result":
                    r = item[1]
                    self.last_results.append(r)
                    state = r["state"]

                    color = {
                        "open": "#22c55e",
                        "closed": "#ef4444",
                        "filtered": "#f59e0b"
                    }.get(state, "#aaa")

                    self.results_box.insert("end", f"{r['host']}:{r['port']} -> {state}\n")
                    self.results_box.tag_add(state, "end-2l", "end-1l")
                    self.results_box.tag_config(state, foreground=color)

                elif item[0] == "done":
                    results = item[1]
                    self.last_results = results
                    self.scan_running = False
                    self.scan_button.configure(state="normal")
                    self.export_button.configure(state="normal")
                    self.status.configure(text=f"Scan complete: {len(results)} results", text_color="#22c55e")

                elif item[0] == "error":
                    self.scan_running = False
                    self.scan_button.configure(state="normal")
                    self.status.configure(text="Scan failed", text_color="#ef4444")
                    messagebox.showerror("Scan error", item[1])

                elif item[0] == "status":
                    self.status.configure(text=item[1])

                elif item[0] == "db_status":
                    status = item[1]
                    if status == "connected":
                        self.db_status.configure(text="DB: Connected", text_color="#22c55e")
                    elif status == "connecting":
                        self.db_status.configure(text="DB: Connecting...", text_color="#f59e0b")
                    elif status == "disabled":
                        self.db_status.configure(text="DB: Disabled", text_color="#6b7280")
                    else:
                        self.db_status.configure(text="DB: Error", text_color="#ef4444")

        except queue.Empty:
            pass

        self.after(50, self._poll_queue)

    # ---------------- DB HISTORY ---------------- #

    def load_scan_history(self):
        import psycopg2

        url = os.environ.get("DATABASE_URL", "")
        if not url:
            messagebox.showerror("DB", "DATABASE_URL not set")
            return

        try:
            conn = psycopg2.connect(url)
            cur = conn.cursor()

            cur.execute("""
                SELECT scan_id, COUNT(*), MAX(timestamp)
                FROM scans
                GROUP BY scan_id
                ORDER BY MAX(timestamp) DESC
                LIMIT 20
            """)

            rows = cur.fetchall()
            self.history_box.delete("1.0", "end")

            for r in rows:
                self.history_box.insert("end", f"{r[0][:8]} | {r[1]} results\n")

            cur.close()
            conn.close()

        except Exception as e:
            messagebox.showerror("DB Error", str(e))

    # ---------------- EXPORT ---------------- #

    def export_results(self):
        if not self.last_results:
            messagebox.showinfo("Export", "No scan results to export.")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if not path:
            return

        try:
            export_results(self.last_results, path, metadata=self.last_metadata)
            messagebox.showinfo("Export", f"Results exported to {path}")
        except Exception as e:
            messagebox.showerror("Export error", str(e))


if __name__ == "__main__":
    app = NetworkScannerApp()
    app.mainloop()