#!/usr/bin/env python3
"""Minimal customtkinter front end for the Network Scanner project."""

import customtkinter as ctk

from scanner import scan_port


class NetworkScannerApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Network Scanner")
        self.geometry("720x420")
        self.minsize(640, 360)

        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        header = ctk.CTkLabel(
            self,
            text="Network Scanner",
            font=ctk.CTkFont(size=24, weight="bold"),
        )
        header.grid(row=0, column=0, padx=24, pady=(24, 12), sticky="w")

        form = ctk.CTkFrame(self)
        form.grid(row=1, column=0, padx=24, pady=12, sticky="ew")
        form.grid_columnconfigure((1, 3), weight=1)

        ctk.CTkLabel(form, text="Target").grid(row=0, column=0, padx=(16, 8), pady=16, sticky="w")
        self.target_entry = ctk.CTkEntry(form, placeholder_text="127.0.0.1")
        self.target_entry.grid(row=0, column=1, padx=(0, 16), pady=16, sticky="ew")
        self.target_entry.insert(0, "127.0.0.1")

        ctk.CTkLabel(form, text="Port").grid(row=0, column=2, padx=(16, 8), pady=16, sticky="w")
        self.port_entry = ctk.CTkEntry(form, width=100)
        self.port_entry.grid(row=0, column=3, padx=(0, 16), pady=16, sticky="ew")
        self.port_entry.insert(0, "80")

        ctk.CTkLabel(form, text="Timeout").grid(row=1, column=0, padx=(16, 8), pady=(0, 16), sticky="w")
        self.timeout_entry = ctk.CTkEntry(form, width=100)
        self.timeout_entry.grid(row=1, column=1, padx=(0, 16), pady=(0, 16), sticky="ew")
        self.timeout_entry.insert(0, "1.0")

        self.scan_button = ctk.CTkButton(form, text="Scan Port", command=self.scan_selected_port)
        self.scan_button.grid(row=1, column=3, padx=(0, 16), pady=(0, 16), sticky="ew")

        self.output = ctk.CTkTextbox(self)
        self.output.grid(row=2, column=0, padx=24, pady=(12, 24), sticky="nsew")
        self.output.insert("1.0", "Enter a target and port, then click Scan Port.\n")
        self.output.configure(state="disabled")

    def write_output(self, message: str) -> None:
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.insert("1.0", message)
        self.output.configure(state="disabled")

    def scan_selected_port(self) -> None:
        target = self.target_entry.get().strip()
        port_text = self.port_entry.get().strip()
        timeout_text = self.timeout_entry.get().strip()

        try:
            port = int(port_text)
            timeout = float(timeout_text)
        except ValueError:
            self.write_output("Port must be an integer and timeout must be a number.\n")
            return

        result = scan_port(target, port, timeout)
        message = (
            f"Target: {target}\n"
            f"Port: {result['port']}\n"
            f"State: {result['state']}\n"
            f"Service: {result['service']}\n"
        )
        self.write_output(message)


if __name__ == "__main__":
    app = NetworkScannerApp()
    app.mainloop()