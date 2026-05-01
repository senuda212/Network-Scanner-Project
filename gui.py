#!/usr/bin/env python3
"""Advanced customtkinter GUI for Network Scanner - Modernized UI"""

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
        self.geometry("1400x800")
        self.minsize(1000, 700)

        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

        self.scan_queue = queue.Queue()
        self.selected_ports = set()
        self.port_buttons = {}
        self.scan_running = False
        self.last_results = []
        self.last_metadata = {}
        self.db_writer = None
        self.db_pool = None

        self.grid_columnconfigure(0, weight=3)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=0)
        self.grid_rowconfigure(1, weight=1)
        self.grid_rowconfigure(2, weight=0)

        self._build_header()
        self._build_content()
        self._build_footer()

        # Try to connect to database on startup
        self.after(100, self._init_database)
        self.after(50, self._poll_queue)

    def _build_header(self):
        """Header with title and DB status"""
        header = ctk.CTkFrame(self, fg_color="#1a1a1a", corner_radius=0)
        header.grid(row=0, column=0, columnspan=2, sticky="ew", padx=0, pady=0)
        header.grid_columnconfigure(0, weight=1)

        title_frame = ctk.CTkFrame(header, fg_color="transparent")
        title_frame.grid(row=0, column=0, sticky="w", padx=24, pady=16)

        ctk.CTkLabel(
            title_frame,
            text="Network Scanner",
            font=ctk.CTkFont(size=32, weight="bold")
        ).pack(side="left")

        ctk.CTkLabel(
            title_frame,
            text="Professional TCP Port Scanner",
            font=ctk.CTkFont(size=12),
            text_color="#888"
        ).pack(side="left", padx=(16, 0))

        # DB Status in header
        status_frame = ctk.CTkFrame(header, fg_color="transparent")
        status_frame.grid(row=0, column=1, sticky="e", padx=24, pady=16)

        self.db_status = ctk.CTkLabel(
            status_frame,
            text="● DB: Connecting...",
            text_color="#f59e0b",
            font=ctk.CTkFont(size=11, weight="bold")
        )
        self.db_status.pack()

    def _build_content(self):
        """Main content area: form on left, results + history on right"""
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=16, pady=10)
        content.grid_columnconfigure(0, weight=0)
        content.grid_columnconfigure(1, weight=1)
        content.grid_rowconfigure(0, weight=1)

        # LEFT: Form Panel
        form_panel = ctk.CTkFrame(content, corner_radius=12, fg_color="#111")
        form_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 10), pady=0)
        form_panel.grid_columnconfigure(0, weight=1)

        self._build_form(form_panel)

        # RIGHT: Results + History
        right_panel = ctk.CTkFrame(content, corner_radius=12, fg_color="#111")
        right_panel.grid(row=0, column=1, sticky="nsew", padx=(10, 0), pady=0)
        right_panel.grid_columnconfigure(0, weight=1)
        right_panel.grid_rowconfigure(1, weight=1)

        self._build_results(right_panel)
        self._build_history(right_panel)

    def _build_form(self, parent):
        """Build the scan form with organized sections"""
        # Padding frame
        form = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        form.pack(fill="both", expand=True, padx=20, pady=20)
        form.grid_columnconfigure(0, weight=1)

        # ─── INPUT SETTINGS SECTION ───
        self._section_header(form, "Input Settings")
        row = 1

        # Target
        ctk.CTkLabel(form, text="Target:", font=ctk.CTkFont(weight="bold")).grid(
            row=row, column=0, sticky="w", pady=(12, 4)
        )
        self.target_entry = ctk.CTkEntry(
            form, placeholder_text="192.168.1.0/24 or scanme.nmap.org", height=32
        )
        self.target_entry.insert(0, "scanme.nmap.org")
        self.target_entry.grid(row=row+1, column=0, sticky="ew", pady=(0, 12))
        row += 2

        # Threads & Timeout (side by side)
        ctk.CTkLabel(form, text="Scan Parameters:", font=ctk.CTkFont(weight="bold")).grid(
            row=row, column=0, sticky="w", pady=(12, 4)
        )
        row += 1

        params_frame = ctk.CTkFrame(form, fg_color="transparent")
        params_frame.grid(row=row, column=0, sticky="ew", pady=(0, 12))
        params_frame.grid_columnconfigure((0, 1), weight=1)

        ctk.CTkLabel(params_frame, text="Threads:").grid(row=0, column=0, sticky="w")
        self.threads_entry = ctk.CTkEntry(params_frame, height=32)
        self.threads_entry.insert(0, "25")
        self.threads_entry.grid(row=1, column=0, sticky="ew", padx=(0, 8))

        ctk.CTkLabel(params_frame, text="Timeout (s):").grid(row=0, column=1, sticky="w")
        self.timeout_entry = ctk.CTkEntry(params_frame, height=32)
        self.timeout_entry.insert(0, "1.0")
        self.timeout_entry.grid(row=1, column=1, sticky="ew", padx=(8, 0))

        row += 1

        # ─── PORT SELECTION SECTION ───
        self._section_header(form, "Port Selection", row=row)
        row += 1

        # Port buttons in scrollable frame
        ports_frame = ctk.CTkScrollableFrame(form, height=200, fg_color="#222", corner_radius=8)
        ports_frame.grid(row=row, column=0, sticky="ew", pady=(0, 12))
        ports_frame.grid_columnconfigure((0, 1, 2), weight=1)

        col = 0
        btn_row = 0
        for i, port in enumerate(COMMON_PORTS):
            name = PORT_LABELS.get(port, "")
            var = ctk.BooleanVar(value=False)
            self.port_vars[port] = var

            btn = ctk.CTkButton(
                ports_frame,
                text=f"{port}\n{name}" if name else str(port),
                fg_color="#333",
                hover_color="#2563eb",
                text_color="#fff",
                height=44,
                font=ctk.CTkFont(size=9),
                command=lambda p=port: self.toggle_port(p)
            )
            btn.grid(row=btn_row, column=col, sticky="ew", padx=4, pady=4)
            self.port_buttons[port] = btn

            col += 1
            if col >= 3:
                col = 0
                btn_row += 1

        row += 1

        # Custom Ports
        ctk.CTkLabel(form, text="Custom Ports:", font=ctk.CTkFont(weight="bold")).grid(
            row=row, column=0, sticky="w", pady=(12, 4)
        )
        self.custom_ports_entry = ctk.CTkEntry(
            form,
            placeholder_text="e.g. 1-1024 or 22,80,443 (optional)",
            height=32
        )
        self.custom_ports_entry.grid(row=row+1, column=0, sticky="ew", pady=(0, 12))
        self.custom_ports_entry.bind("<KeyRelease>", self.sync_from_input)
        row += 2

        # ─── DATABASE SECTION ───
        self._section_header(form, "Database", row=row)
        row += 1

        db_toggle_frame = ctk.CTkFrame(form, fg_color="transparent")
        db_toggle_frame.grid(row=row, column=0, sticky="ew", pady=(0, 8))

        self.db_var = ctk.BooleanVar(value=True)
        self.db_toggle = ctk.CTkCheckBox(
            db_toggle_frame,
            text="Save results to database",
            variable=self.db_var,
            font=ctk.CTkFont(weight="bold")
        )
        self.db_toggle.pack(side="left")

        row += 1

        ctk.CTkLabel(form, text="Database URL:").grid(row=row, column=0, sticky="w", pady=(8, 4))
        self.db_url_entry = ctk.CTkEntry(
            form,
            placeholder_text="postgresql://user:pass@host:5432/db",
            height=32
        )
        self.db_url_entry.insert(0, os.environ.get("DATABASE_URL", ""))
        self.db_url_entry.grid(row=row+1, column=0, sticky="ew", pady=(0, 12))
        row += 2

        # ─── ACTION BUTTONS ───
        button_frame = ctk.CTkFrame(form, fg_color="transparent")
        button_frame.grid(row=row, column=0, sticky="ew", pady=(20, 0))
        button_frame.grid_columnconfigure((0, 1), weight=1)

        self.scan_button = ctk.CTkButton(
            button_frame,
            text="▶ Start Scan",
            command=self.start_scan,
            height=40,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#2563eb",
            hover_color="#1d4ed8"
        )
        self.scan_button.grid(row=0, column=0, sticky="ew", padx=(0, 6))

        self.export_button = ctk.CTkButton(
            button_frame,
            text="⬇ Export",
            command=self.export_results,
            height=40,
            font=ctk.CTkFont(size=12, weight="bold"),
            state="disabled"
        )
        self.export_button.grid(row=0, column=1, sticky="ew", padx=(6, 0))

    def _section_header(self, parent, title: str, row: int = None):
        """Create a section header"""
        if row is None:
            frame = ctk.CTkFrame(parent, fg_color="transparent")
            frame.pack(fill="x", pady=(20, 12))
        else:
            frame = ctk.CTkFrame(parent, fg_color="transparent")
            frame.grid(row=row, column=0, sticky="ew", pady=(20, 12))

        ctk.CTkLabel(
            frame,
            text=title,
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#2563eb"
        ).pack(side="left")

        sep = ctk.CTkFrame(frame, height=1, fg_color="#333")
        sep.pack(side="left", fill="x", expand=True, padx=(10, 0))

    def _build_results(self, parent):
        """Build results display area"""
        results_header = ctk.CTkFrame(parent, fg_color="transparent")
        results_header.grid(row=0, column=0, sticky="ew", padx=16, pady=(16, 8))
        results_header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            results_header,
            text="Scan Results",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#2563eb"
        ).pack(side="left")

        self.results_box = ctk.CTkTextbox(parent, height=400, fg_color="#222", text_color="#fff")
        self.results_box.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0, 10))

    def _build_history(self, parent):
        """Build scan history sidebar"""
        history_header = ctk.CTkFrame(parent, fg_color="transparent")
        history_header.grid(row=2, column=0, sticky="ew", padx=16, pady=(10, 8))
        history_header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            history_header,
            text="Recent Scans",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#2563eb"
        ).pack(side="left")

        button_frame = ctk.CTkFrame(history_header, fg_color="transparent")
        button_frame.pack(side="right")

        ctk.CTkButton(
            button_frame,
            text="🔄 Refresh",
            command=self.load_scan_history,
            height=24,
            width=80,
            font=ctk.CTkFont(size=10)
        ).pack(side="left", padx=(4, 0))

        self.history_box = ctk.CTkTextbox(parent, height=150, fg_color="#222", text_color="#888")
        self.history_box.grid(row=3, column=0, sticky="ew", padx=16, pady=(0, 16))

    def _build_footer(self):
        """Footer with progress bar and status"""
        footer = ctk.CTkFrame(self, fg_color="#1a1a1a", corner_radius=0)
        footer.grid(row=2, column=0, columnspan=2, sticky="ew", padx=0, pady=0)
        footer.grid_columnconfigure(0, weight=1)

        self.progress = ctk.CTkProgressBar(footer, height=4)
        self.progress.grid(row=0, column=0, sticky="ew", padx=0, pady=0)
        self.progress.set(0)

        status_frame = ctk.CTkFrame(footer, fg_color="transparent")
        status_frame.grid(row=1, column=0, sticky="ew", padx=16, pady=12)
        status_frame.grid_columnconfigure(0, weight=1)

        self.status = ctk.CTkLabel(
            status_frame,
            text="Ready to scan",
            text_color="#888",
            font=ctk.CTkFont(size=11)
        )
        self.status.grid(row=0, column=0, sticky="w")

    def toggle_port(self, port):
        var = self.port_vars[port]
        var.set(not var.get())
        color = "#2563eb" if var.get() else "#333"
        self.port_buttons[port].configure(fg_color=color)
        self.update_input()

    def update_input(self):
        checked = [port for port, var in self.port_vars.items() if var.get()]
        if checked:
            self.custom_ports_entry.delete(0, "end")
            self.custom_ports_entry.insert(0, ",".join(map(str, sorted(checked))))

    def sync_from_input(self, event=None):
        try:
            ports = parse_ports(self.custom_ports_entry.get())
        except:
            return

        for p, btn in self.port_buttons.items():
            color = "#2563eb" if p in ports else "#333"
            btn.configure(fg_color=color)
            if p in self.port_vars:
                self.port_vars[p].set(p in ports)

    def _init_database(self):
        """Initialize database connection on startup"""
        db_url = self.db_url_entry.get().strip() or os.environ.get("DATABASE_URL", "")

        if not db_url:
            self.db_status.configure(
                text="● DB: Not configured",
                text_color="#6b7280"
            )
            return

        try:
            self.db_pool = init_db(db_url)
            self.db_status.configure(
                text="● DB: Connected",
                text_color="#22c55e"
            )
            self.db_var.set(True)
        except Exception as e:
            self.db_status.configure(
                text="● DB: Connection failed",
                text_color="#ef4444"
            )
            messagebox.showwarning("Database", f"Could not connect to database:\n{e}\n\nScans can still run without database storage.")

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
        self.progress.set(0)
        self.status.configure(text="Initializing scan...", text_color="#f59e0b")
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
        db_enabled = bool(self.db_var.get()) and self.db_pool is not None
        db_url = self.db_url_entry.get().strip() or os.environ.get("DATABASE_URL", "")

        db_writer = None

        if db_enabled:
            try:
                db_writer = DBWriter(self.db_pool, batch_size=100)
                db_writer.start()
                self.scan_queue.put(("status", "Database writer started"))
            except Exception as e:
                self.scan_queue.put(("status", f"DB writer error: {e}"))
                db_writer = None

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

    def _poll_queue(self):
        try:
            while True:
                item = self.scan_queue.get_nowait()

                if item[0] == "result":
                    r = item[1]
                    self.last_results.append(r)
                    state = r["state"]
                    color_map = {"open": "#22c55e", "closed": "#ef4444", "filtered": "#f59e0b"}
                    color = color_map.get(state, "#aaa")

                    self.results_box.insert("end", f"{r['host']}:{r['port']} → {state}\n")
                    self.results_box.tag_add(state, "end-2l", "end-1l")
                    self.results_box.tag_config(state, foreground=color)

                elif item[0] == "done":
                    results = item[1]
                    self.last_results = results
                    self.scan_running = False
                    self.scan_button.configure(state="normal")
                    self.export_button.configure(state="normal")
                    self.progress.set(1)
                    self.status.configure(
                        text=f"✓ Scan complete: {len(results)} results",
                        text_color="#22c55e"
                    )

                elif item[0] == "error":
                    self.scan_running = False
                    self.scan_button.configure(state="normal")
                    self.status.configure(text="✗ Scan failed", text_color="#ef4444")
                    messagebox.showerror("Scan error", item[1])

                elif item[0] == "status":
                    self.status.configure(text=item[1], text_color="#888")

        except queue.Empty:
            pass

        self.after(50, self._poll_queue)

    def load_scan_history(self):
        import psycopg2

        db_url = self.db_url_entry.get().strip() or os.environ.get("DATABASE_URL", "")
        if not db_url or not self.db_pool:
            self.history_box.delete("1.0", "end")
            self.history_box.insert("1.0", "No database connected\n")
            return

        try:
            conn = self.db_pool.getconn()
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
                self.history_box.insert("end", f"{r[0][:8]} | {r[1]} ports\n")

            cur.close()
            self.db_pool.putconn(conn)

        except Exception as e:
            self.history_box.delete("1.0", "end")
            self.history_box.insert("1.0", f"Error: {e}\n")

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
            messagebox.showinfo("Export", f"✓ Results exported to {path}")
        except Exception as e:
            messagebox.showerror("Export error", str(e))

    # Initialize port variables dict
    @property
    def port_vars(self):
        if not hasattr(self, "_port_vars"):
            self._port_vars = {}
        return self._port_vars

    @port_vars.setter
    def port_vars(self, value):
        self._port_vars = value


if __name__ == "__main__":
    app = NetworkScannerApp()
    app.mainloop()

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