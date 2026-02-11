from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk

from cortexsec.api.contracts import AssessmentRequest
from cortexsec.engine.cli_engine import CliEngine


class CortexSecGuiApp:
    """Thin GUI wrapper that calls the same AssessmentService API as the CLI."""

    def __init__(self) -> None:
        self.engine = CliEngine()
        self.root = tk.Tk()
        self.root.title("CortexSec GUI Prototype")

        self.target_var = tk.StringVar(value="http://localhost:8080")
        self.mode_var = tk.StringVar(value="lab")
        self.provider_var = tk.StringVar(value="openai")
        self.external_tools_var = tk.BooleanVar(value=False)

        ttk.Label(self.root, text="Target").grid(row=0, column=0, sticky="w")
        ttk.Entry(self.root, textvariable=self.target_var, width=40).grid(row=0, column=1, padx=4, pady=4)

        ttk.Label(self.root, text="Mode").grid(row=1, column=0, sticky="w")
        ttk.Combobox(self.root, textvariable=self.mode_var, values=["lab", "authorized"], width=12).grid(
            row=1, column=1, sticky="w", padx=4, pady=4
        )

        ttk.Label(self.root, text="Provider").grid(row=2, column=0, sticky="w")
        ttk.Entry(self.root, textvariable=self.provider_var, width=20).grid(row=2, column=1, sticky="w", padx=4, pady=4)

        ttk.Checkbutton(self.root, text="Enable external tools", variable=self.external_tools_var).grid(
            row=3, column=1, sticky="w", padx=4, pady=4
        )

        ttk.Button(self.root, text="Run Assessment", command=self.run_assessment).grid(row=4, column=1, sticky="w", padx=4)

    def run_assessment(self) -> None:
        request = AssessmentRequest(
            target=self.target_var.get().strip(),
            mode=self.mode_var.get().strip(),
            provider=self.provider_var.get().strip(),
            enable_external_tools=self.external_tools_var.get(),
        )
        try:
            result = self.engine.run(request)
            messagebox.showinfo(
                "Assessment Complete",
                f"Status: {result.status}\nFindings: {result.findings_count}\nRisk: {result.risk_level}\nLog: {result.artifacts.get('log')}",
            )
        except Exception as exc:
            messagebox.showerror("Assessment Failed", str(exc))

    def start(self) -> None:
        self.root.mainloop()


if __name__ == "__main__":
    CortexSecGuiApp().start()
