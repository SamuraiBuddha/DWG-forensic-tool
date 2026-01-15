"""
DWG Forensic Tool - Simple GUI

A straightforward Tkinter-based graphical interface for forensic analysis.
"""

import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from pathlib import Path
from datetime import datetime

from dwg_forensic import __version__
from dwg_forensic.core.analyzer import ForensicAnalyzer
from dwg_forensic.output.pdf_report import generate_pdf_report
from dwg_forensic.output.expert_witness import generate_expert_witness_document
from dwg_forensic.output.json_export import JSONExporter

# LLM integration (optional)
try:
    from dwg_forensic.llm import OllamaClient, ForensicNarrator
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False
    OllamaClient = None
    ForensicNarrator = None


class ForensicGUI:
    """Main GUI application for DWG Forensic Tool."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"DWG Forensic Tool v{__version__}")
        self.root.geometry("1000x750")
        self.root.minsize(900, 650)

        # State
        self.current_file: Path | None = None
        self.current_analysis = None
        self.progress_log = None  # Will be set after UI creation
        self.analyzer = None  # Created per-analysis with callback

        # LLM State
        self.llm_enabled = tk.BooleanVar(value=False)
        self.llm_model = tk.StringVar(value="")
        self.llm_status = tk.StringVar(value="Not connected")
        self.ollama_client = None
        self.available_models: list[str] = []

        # Build UI
        self._create_menu()
        self._create_toolbar()
        self._create_main_content()
        self._create_status_bar()

        # Check LLM availability on startup
        if LLM_AVAILABLE:
            self.root.after(500, self._check_ollama_connection)

    def _create_menu(self):
        """Create menu bar."""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open DWG...", command=self.open_file, accelerator="Ctrl+O")
        file_menu.add_separator()
        file_menu.add_command(label="Export JSON...", command=self.export_json)
        file_menu.add_command(label="Generate PDF Report...", command=self.generate_pdf)
        file_menu.add_command(label="Generate Expert Witness Doc...", command=self.generate_expert)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)

        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)

        # Bind shortcuts
        self.root.bind("<Control-o>", lambda e: self.open_file())

    def _create_toolbar(self):
        """Create toolbar."""
        toolbar = ttk.Frame(self.root, padding=5)
        toolbar.pack(side=tk.TOP, fill=tk.X)

        ttk.Button(toolbar, text="Open File", command=self.open_file).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Analyze", command=self.run_analysis).pack(side=tk.LEFT, padx=2)
        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=5)
        ttk.Button(toolbar, text="PDF Report", command=self.generate_pdf).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Expert Witness", command=self.generate_expert).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Export JSON", command=self.export_json).pack(side=tk.LEFT, padx=2)

    def _create_main_content(self):
        """Create main content area."""
        # Main container with two panes
        main = ttk.Frame(self.root, padding=10)
        main.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        # Left side - File info and LLM settings
        left_panel = ttk.Frame(main, width=280)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        left_panel.pack_propagate(False)

        # File info section
        file_frame = ttk.LabelFrame(left_panel, text="File Information", padding=10)
        file_frame.pack(fill=tk.X, pady=(0, 10))

        self.file_label = ttk.Label(file_frame, text="No file selected", font=("", 10), wraplength=250)
        self.file_label.pack(anchor=tk.W)

        self.hash_label = ttk.Label(file_frame, text="SHA-256: --", font=("Consolas", 8), wraplength=250)
        self.hash_label.pack(anchor=tk.W)

        # LLM Settings section
        self._create_llm_panel(left_panel)

        # Right side - Results notebook (tabs)
        right_panel = ttk.Frame(main)
        right_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        notebook = ttk.Notebook(right_panel)
        notebook.pack(fill=tk.BOTH, expand=True)

        # Summary tab
        summary_frame = ttk.Frame(notebook, padding=10)
        notebook.add(summary_frame, text="Summary")
        self._create_summary_tab(summary_frame)

        # Details tab
        details_frame = ttk.Frame(notebook, padding=10)
        notebook.add(details_frame, text="Details")
        self._create_details_tab(details_frame)

        # Raw JSON tab
        json_frame = ttk.Frame(notebook, padding=10)
        notebook.add(json_frame, text="Raw JSON")
        self._create_json_tab(json_frame)

        # Progress Log tab
        progress_frame = ttk.Frame(notebook, padding=10)
        notebook.add(progress_frame, text="Progress Log")
        self._create_progress_tab(progress_frame)

        # Store notebook reference for tab switching
        self.notebook = notebook

    def _create_summary_tab(self, parent):
        """Create summary tab content."""
        # Risk assessment frame
        risk_frame = ttk.LabelFrame(parent, text="Risk Assessment", padding=10)
        risk_frame.pack(fill=tk.X, pady=(0, 10))

        self.risk_label = ttk.Label(risk_frame, text="--", font=("", 14, "bold"))
        self.risk_label.pack(anchor=tk.W)

        self.risk_details = ttk.Label(risk_frame, text="Run analysis to see results")
        self.risk_details.pack(anchor=tk.W)

        # Key findings frame
        findings_frame = ttk.LabelFrame(parent, text="Key Findings", padding=10)
        findings_frame.pack(fill=tk.BOTH, expand=True)

        # Create a grid for findings
        self.findings_tree = ttk.Treeview(
            findings_frame,
            columns=("status", "finding", "details"),
            show="headings",
            height=10
        )
        self.findings_tree.heading("status", text="Status")
        self.findings_tree.heading("finding", text="Finding")
        self.findings_tree.heading("details", text="Details")
        self.findings_tree.column("status", width=80, anchor=tk.CENTER)
        self.findings_tree.column("finding", width=200)
        self.findings_tree.column("details", width=400)

        scrollbar = ttk.Scrollbar(findings_frame, orient=tk.VERTICAL, command=self.findings_tree.yview)
        self.findings_tree.configure(yscrollcommand=scrollbar.set)

        self.findings_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def _create_details_tab(self, parent):
        """Create details tab content."""
        self.details_text = scrolledtext.ScrolledText(
            parent,
            wrap=tk.WORD,
            font=("Consolas", 10),
            state=tk.DISABLED
        )
        self.details_text.pack(fill=tk.BOTH, expand=True)

    def _create_json_tab(self, parent):
        """Create raw JSON tab content."""
        self.json_text = scrolledtext.ScrolledText(
            parent,
            wrap=tk.NONE,
            font=("Consolas", 9),
            state=tk.DISABLED
        )
        self.json_text.pack(fill=tk.BOTH, expand=True)

    def _create_progress_tab(self, parent):
        """Create progress log tab content."""
        # Header label
        ttk.Label(
            parent,
            text="Analysis Progress Log",
            font=("", 10, "bold")
        ).pack(anchor=tk.W, pady=(0, 5))

        # Progress log text widget
        self.progress_log = scrolledtext.ScrolledText(
            parent,
            wrap=tk.WORD,
            font=("Consolas", 9),
            state=tk.DISABLED,
            bg="#1e1e1e",
            fg="#d4d4d4",
            insertbackground="white"
        )
        self.progress_log.pack(fill=tk.BOTH, expand=True)

        # Configure tags for colored output
        self.progress_log.tag_config("step", foreground="#569cd6")
        self.progress_log.tag_config("ok", foreground="#4ec9b0")
        self.progress_log.tag_config("error", foreground="#f14c4c")
        self.progress_log.tag_config("warn", foreground="#dcdcaa")
        self.progress_log.tag_config("info", foreground="#9cdcfe")

        # Clear button
        ttk.Button(
            parent,
            text="Clear Log",
            command=self._clear_progress_log
        ).pack(anchor=tk.E, pady=(5, 0))

    def _clear_progress_log(self):
        """Clear the progress log."""
        if self.progress_log:
            self.progress_log.config(state=tk.NORMAL)
            self.progress_log.delete(1.0, tk.END)
            self.progress_log.config(state=tk.DISABLED)

    def _log_progress(self, step: str, status: str, message: str):
        """Log progress to the progress log widget (thread-safe)."""
        def update():
            if not self.progress_log:
                return

            self.progress_log.config(state=tk.NORMAL)

            # Format the log entry
            step_names = {
                "file_info": "File Info",
                "header": "DWG Header",
                "crc": "CRC Validation",
                "watermark": "TrustedDWG",
                "fingerprint": "CAD Detection",
                "timestamps": "Timestamps",
                "ntfs": "NTFS Timestamps",
                "sections": "Section Map",
                "drawing_vars": "Drawing Vars",
                "handles": "Handle Map",
                "anomalies": "Anomalies",
                "rules": "Tampering Rules",
                "tampering": "Indicators",
                "risk": "Risk Score",
            }
            step_name = step_names.get(step, step)

            if status == "start":
                self.progress_log.insert(tk.END, f"[....] {step_name}: ", "step")
                self.progress_log.insert(tk.END, f"{message}\n", "info")
            elif status == "complete":
                self.progress_log.insert(tk.END, f"[ OK ] {step_name}: ", "ok")
                self.progress_log.insert(tk.END, f"{message}\n", "info")
            elif status == "error":
                self.progress_log.insert(tk.END, f"[FAIL] {step_name}: ", "error")
                self.progress_log.insert(tk.END, f"{message}\n", "error")
            elif status == "skip":
                self.progress_log.insert(tk.END, f"[SKIP] {step_name}: ", "warn")
                self.progress_log.insert(tk.END, f"{message}\n", "warn")

            self.progress_log.see(tk.END)
            self.progress_log.config(state=tk.DISABLED)

        # Schedule update on main thread
        self.root.after(0, update)

    def _create_status_bar(self):
        """Create status bar."""
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(
            self.root,
            textvariable=self.status_var,
            relief=tk.SUNKEN,
            anchor=tk.W,
            padding=(5, 2)
        )
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def _create_llm_panel(self, parent):
        """Create LLM settings panel."""
        llm_frame = ttk.LabelFrame(parent, text="AI Narrative Generation", padding=10)
        llm_frame.pack(fill=tk.X, pady=(0, 10))

        if not LLM_AVAILABLE:
            ttk.Label(
                llm_frame,
                text="LLM module not available.\nInstall with: pip install -e .",
                foreground="gray"
            ).pack(anchor=tk.W)
            return

        # Enable checkbox
        enable_check = ttk.Checkbutton(
            llm_frame,
            text="Enable AI-powered narratives",
            variable=self.llm_enabled,
            command=self._on_llm_toggle
        )
        enable_check.pack(anchor=tk.W, pady=(0, 5))

        # Status indicator
        status_frame = ttk.Frame(llm_frame)
        status_frame.pack(fill=tk.X, pady=(0, 5))

        ttk.Label(status_frame, text="Ollama:").pack(side=tk.LEFT)
        self.llm_status_label = ttk.Label(
            status_frame,
            textvariable=self.llm_status,
            foreground="gray"
        )
        self.llm_status_label.pack(side=tk.LEFT, padx=(5, 0))

        # Model selection
        model_frame = ttk.Frame(llm_frame)
        model_frame.pack(fill=tk.X, pady=(5, 0))

        ttk.Label(model_frame, text="Model:").pack(side=tk.LEFT)
        self.model_combo = ttk.Combobox(
            model_frame,
            textvariable=self.llm_model,
            state="readonly",
            width=20
        )
        self.model_combo.pack(side=tk.LEFT, padx=(5, 0), fill=tk.X, expand=True)

        # Refresh button
        ttk.Button(
            llm_frame,
            text="Refresh Connection",
            command=self._check_ollama_connection
        ).pack(fill=tk.X, pady=(10, 0))

        # Info label
        ttk.Label(
            llm_frame,
            text="AI generates detailed explanations\nfor forensic findings using local LLM.",
            font=("", 8),
            foreground="gray",
            wraplength=240
        ).pack(anchor=tk.W, pady=(10, 0))

    def _check_ollama_connection(self):
        """Check Ollama connection and refresh available models."""
        if not LLM_AVAILABLE or not OllamaClient:
            self.llm_status.set("Module not available")
            return

        def check():
            try:
                self.ollama_client = OllamaClient()
                if self.ollama_client.is_available():
                    version = self.ollama_client.get_version() or "unknown"
                    models = self.ollama_client.list_models()
                    self.root.after(0, lambda: self._update_llm_status(True, version, models))
                else:
                    self.root.after(0, lambda: self._update_llm_status(False, None, []))
            except Exception as e:
                self.root.after(0, lambda: self._update_llm_status(False, None, []))

        thread = threading.Thread(target=check, daemon=True)
        thread.start()

    def _update_llm_status(self, connected: bool, version: str | None, models: list[str]):
        """Update LLM status in UI."""
        if connected:
            self.llm_status.set(f"Connected (v{version})")
            self.llm_status_label.config(foreground="green")
            self.available_models = models
            self.model_combo["values"] = models
            if models and not self.llm_model.get():
                # Auto-select first model
                self.llm_model.set(models[0])
        else:
            self.llm_status.set("Not running")
            self.llm_status_label.config(foreground="red")
            self.available_models = []
            self.model_combo["values"] = []

    def _on_llm_toggle(self):
        """Handle LLM enable/disable toggle."""
        if self.llm_enabled.get():
            if not self.available_models:
                messagebox.showwarning(
                    "Ollama Not Available",
                    "Ollama is not running or no models are installed.\n\n"
                    "1. Start Ollama\n"
                    "2. Install a model: ollama pull phi4\n"
                    "3. Click 'Refresh Connection'"
                )
                self.llm_enabled.set(False)

    def open_file(self):
        """Open a DWG file."""
        file_path = filedialog.askopenfilename(
            title="Select DWG File",
            filetypes=[
                ("DWG Files", "*.dwg"),
                ("All Files", "*.*")
            ]
        )
        if file_path:
            self.current_file = Path(file_path)
            self.file_label.config(text=f"File: {self.current_file.name}")
            self.hash_label.config(text="SHA-256: (analyzing...)")
            self.status_var.set(f"Loaded: {self.current_file.name}")
            self.run_analysis()

    def run_analysis(self):
        """Run forensic analysis on the current file."""
        if not self.current_file:
            messagebox.showwarning("No File", "Please open a DWG file first.")
            return

        self.status_var.set("Analyzing...")

        # Clear and show progress log
        self._clear_progress_log()
        self.notebook.select(3)  # Switch to Progress Log tab
        self.root.update()

        # Log start
        self._log_progress("analysis", "start", f"Starting analysis of {self.current_file.name}")

        # Create analyzer with progress callback
        analyzer = ForensicAnalyzer(progress_callback=self._log_progress)

        # Run analysis in background thread
        def analyze():
            try:
                self.current_analysis = analyzer.analyze(self.current_file)
                self._log_progress("analysis", "complete", "Analysis finished successfully")
                self.root.after(0, self._display_results)
            except Exception as e:
                error_msg = str(e)
                # Log error to progress log
                self._log_progress("analysis", "error", f"Analysis failed: {error_msg}")
                self.root.after(0, lambda msg=error_msg: self._show_error(msg))

        thread = threading.Thread(target=analyze, daemon=True)
        thread.start()

    def _display_results(self):
        """Display analysis results in the GUI."""
        if not self.current_analysis:
            return

        analysis = self.current_analysis

        # Update file info
        self.hash_label.config(text=f"SHA-256: {analysis.file_info.sha256}")

        # Update risk assessment
        risk = analysis.risk_assessment.overall_risk.value
        risk_colors = {
            "LOW": "green",
            "MEDIUM": "orange",
            "HIGH": "red",
            "CRITICAL": "darkred"
        }
        self.risk_label.config(
            text=f"Risk Level: {risk}",
            foreground=risk_colors.get(risk, "black")
        )

        factors_count = len(analysis.risk_assessment.factors)
        self.risk_details.config(text=f"Risk Factors: {factors_count}")

        # Update findings tree
        for item in self.findings_tree.get_children():
            self.findings_tree.delete(item)

        # CRC validation
        crc_status = "[OK]" if analysis.crc_validation.is_valid else "[FAIL]"
        self.findings_tree.insert("", tk.END, values=(
            crc_status,
            "CRC Validation",
            f"Stored: {analysis.crc_validation.header_crc_stored}, "
            f"Calculated: {analysis.crc_validation.header_crc_calculated}"
        ))

        # Watermark
        if analysis.trusted_dwg.watermark_present:
            wm_status = "[OK]" if analysis.trusted_dwg.watermark_valid else "[WARN]"
            wm_text = "Valid TrustedDWG watermark" if analysis.trusted_dwg.watermark_valid else "Invalid watermark"
        else:
            wm_status = "[WARN]"
            wm_text = "No TrustedDWG watermark found"
        self.findings_tree.insert("", tk.END, values=(wm_status, "TrustedDWG Watermark", wm_text))

        # Version
        self.findings_tree.insert("", tk.END, values=(
            "[OK]" if analysis.header_analysis.is_supported else "[WARN]",
            "DWG Version",
            f"{analysis.header_analysis.version_string} ({analysis.header_analysis.version_name})"
        ))

        # Anomalies
        for anomaly in analysis.anomalies:
            self.findings_tree.insert("", tk.END, values=(
                "[WARN]",
                f"Anomaly: {anomaly.anomaly_type.value}",
                anomaly.description
            ))

        # Tampering indicators
        for indicator in analysis.tampering_indicators:
            self.findings_tree.insert("", tk.END, values=(
                "[FAIL]",
                f"Tampering: {indicator.indicator_type.value}",
                indicator.description
            ))

        # Update details text
        self._update_details_text(analysis)

        # Update JSON text
        exporter = JSONExporter(indent=2)
        json_str = exporter.to_json(analysis)
        self.json_text.config(state=tk.NORMAL)
        self.json_text.delete("1.0", tk.END)
        self.json_text.insert(tk.END, json_str)
        self.json_text.config(state=tk.DISABLED)

        self.status_var.set(f"Analysis complete - Risk: {risk}")

    def _update_details_text(self, analysis):
        """Update the details text area."""
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete("1.0", tk.END)

        lines = [
            "=" * 60,
            "FORENSIC ANALYSIS REPORT",
            "=" * 60,
            "",
            "FILE INFORMATION",
            "-" * 40,
            f"Filename: {analysis.file_info.filename}",
            f"Size: {analysis.file_info.file_size_bytes:,} bytes",
            f"SHA-256: {analysis.file_info.sha256}",
            f"Analyzed: {analysis.file_info.intake_timestamp.isoformat()}",
            "",
            "HEADER ANALYSIS",
            "-" * 40,
            f"Version: {analysis.header_analysis.version_string}",
            f"Version Name: {analysis.header_analysis.version_name}",
            f"Maintenance Version: {analysis.header_analysis.maintenance_version}",
            f"Codepage: {analysis.header_analysis.codepage}",
            f"Supported: {'Yes' if analysis.header_analysis.is_supported else 'No'}",
            "",
            "CRC VALIDATION",
            "-" * 40,
            f"Stored CRC: {analysis.crc_validation.header_crc_stored}",
            f"Calculated CRC: {analysis.crc_validation.header_crc_calculated}",
            f"Valid: {'Yes' if analysis.crc_validation.is_valid else 'NO - POSSIBLE TAMPERING'}",
            "",
            "TRUSTEDDWG WATERMARK",
            "-" * 40,
            f"Present: {'Yes' if analysis.trusted_dwg.watermark_present else 'No'}",
            f"Valid: {'Yes' if analysis.trusted_dwg.watermark_valid else 'No'}",
        ]

        if analysis.trusted_dwg.watermark_text:
            lines.append(f"Text: {analysis.trusted_dwg.watermark_text[:50]}...")

        lines.extend([
            "",
            "RISK ASSESSMENT",
            "-" * 40,
            f"Overall Risk: {analysis.risk_assessment.overall_risk.value}",
            f"Recommendation: {analysis.risk_assessment.recommendation}",
        ])

        if analysis.risk_assessment.factors:
            lines.append("Risk Factors:")
            for factor in analysis.risk_assessment.factors:
                lines.append(f"  - {factor}")

        if analysis.anomalies:
            lines.extend([
                "",
                "ANOMALIES DETECTED",
                "-" * 40,
            ])
            for a in analysis.anomalies:
                lines.append(f"  [{a.severity.value}] {a.anomaly_type.value}: {a.description}")

        if analysis.tampering_indicators:
            lines.extend([
                "",
                "TAMPERING INDICATORS",
                "-" * 40,
            ])
            for t in analysis.tampering_indicators:
                lines.append(f"  [{t.confidence:.0%}] {t.indicator_type.value}: {t.description}")

        self.details_text.insert(tk.END, "\n".join(lines))
        self.details_text.config(state=tk.DISABLED)

    def _show_error(self, message: str):
        """Show error message."""
        messagebox.showerror("Analysis Error", message)
        self.status_var.set("Error during analysis")

    def export_json(self):
        """Export analysis results to JSON."""
        if not self.current_analysis:
            messagebox.showwarning("No Analysis", "Please run analysis first.")
            return

        file_path = filedialog.asksaveasfilename(
            title="Export JSON",
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json")],
            initialfile=f"{self.current_file.stem}_analysis.json"
        )
        if file_path:
            exporter = JSONExporter(indent=2)
            exporter.to_file(self.current_analysis, file_path)
            self.status_var.set(f"Exported: {Path(file_path).name}")
            messagebox.showinfo("Export Complete", f"JSON saved to:\n{file_path}")

    def generate_pdf(self):
        """Generate PDF forensic report."""
        if not self.current_analysis:
            messagebox.showwarning("No Analysis", "Please run analysis first.")
            return

        file_path = filedialog.asksaveasfilename(
            title="Save PDF Report",
            defaultextension=".pdf",
            filetypes=[("PDF Files", "*.pdf")],
            initialfile=f"{self.current_file.stem}_report.pdf"
        )
        if file_path:
            # Ask for case ID
            case_id = self._ask_string("Case ID", "Enter Case ID (optional):")

            # Check if LLM is enabled
            use_llm = self.llm_enabled.get() and self.llm_model.get()
            llm_model = self.llm_model.get() if use_llm else None

            if use_llm:
                self.status_var.set(f"Generating report with AI narration ({llm_model})...")
                self.root.update()

            try:
                generate_pdf_report(
                    analysis=self.current_analysis,
                    output_path=file_path,
                    case_id=case_id if case_id else None,
                    use_llm_narration=use_llm,
                    llm_model=llm_model,
                )

                llm_note = " (with AI narratives)" if use_llm else ""
                self.status_var.set(f"Generated: {Path(file_path).name}{llm_note}")
                messagebox.showinfo("Report Generated", f"PDF report saved to:\n{file_path}\n\n{'AI-powered narratives enabled' if use_llm else 'Standard narratives'}")
            except PermissionError:
                self.status_var.set("Error: File is in use")
                messagebox.showerror(
                    "Permission Denied",
                    f"Cannot write to:\n{file_path}\n\n"
                    "The file may be open in another application (PDF viewer).\n"
                    "Please close the file and try again."
                )
            except (TimeoutError, OSError, ConnectionError) as e:
                self.status_var.set("Error: LLM connection failed")
                messagebox.showerror(
                    "LLM Connection Error",
                    f"Failed to connect to Ollama for AI narration.\n\n"
                    f"Error: {e}\n\n"
                    "Please ensure Ollama is running, or disable LLM in Settings."
                )
            except Exception as e:
                self.status_var.set(f"Error: {type(e).__name__}")
                messagebox.showerror("Report Generation Failed", f"An error occurred:\n\n{e}")

    def generate_expert(self):
        """Generate expert witness document."""
        if not self.current_analysis:
            messagebox.showwarning("No Analysis", "Please run analysis first.")
            return

        file_path = filedialog.asksaveasfilename(
            title="Save Expert Witness Document",
            defaultextension=".pdf",
            filetypes=[("PDF Files", "*.pdf")],
            initialfile=f"{self.current_file.stem}_expert_witness.pdf"
        )
        if file_path:
            case_id = self._ask_string("Case ID", "Enter Case ID (optional):")
            expert_name = self._ask_string("Expert Name", "Enter Expert Name:", "Digital Forensics Expert")

            # Check if LLM is enabled
            use_llm = self.llm_enabled.get() and self.llm_model.get()
            llm_model = self.llm_model.get() if use_llm else None

            if use_llm:
                self.status_var.set(f"Generating expert witness document with AI analysis ({llm_model})...")
                self.root.update()

            try:
                generate_expert_witness_document(
                    analysis=self.current_analysis,
                    output_path=file_path,
                    case_id=case_id if case_id else None,
                    expert_name=expert_name if expert_name else "Digital Forensics Expert",
                    use_llm_narration=use_llm,
                    llm_model=llm_model,
                )

                llm_note = " (with AI analysis)" if use_llm else ""
                self.status_var.set(f"Generated: {Path(file_path).name}{llm_note}")
                messagebox.showinfo(
                    "Document Generated",
                    f"Expert witness document saved to:\n{file_path}\n\n"
                    f"{'AI-powered forensic analysis enabled' if use_llm else 'Standard analysis'}"
                )
            except PermissionError:
                self.status_var.set("Error: File is in use")
                messagebox.showerror(
                    "Permission Denied",
                    f"Cannot write to:\n{file_path}\n\n"
                    "The file may be open in another application (PDF viewer).\n"
                    "Please close the file and try again."
                )
            except (TimeoutError, OSError, ConnectionError) as e:
                self.status_var.set("Error: LLM connection failed")
                messagebox.showerror(
                    "LLM Connection Error",
                    f"Failed to connect to Ollama for AI analysis.\n\n"
                    f"Error: {e}\n\n"
                    "Please ensure Ollama is running, or disable LLM in Settings."
                )
            except Exception as e:
                self.status_var.set(f"Error: {type(e).__name__}")
                messagebox.showerror("Document Generation Failed", f"An error occurred:\n\n{e}")

    def _ask_string(self, title: str, prompt: str, default: str = "") -> str:
        """Show a simple string input dialog."""
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("350x120")
        dialog.transient(self.root)
        dialog.grab_set()

        ttk.Label(dialog, text=prompt, padding=10).pack()
        entry = ttk.Entry(dialog, width=40)
        entry.insert(0, default)
        entry.pack(padx=10)
        entry.focus()

        result = [default]

        def on_ok():
            result[0] = entry.get()
            dialog.destroy()

        def on_cancel():
            dialog.destroy()

        btn_frame = ttk.Frame(dialog, padding=10)
        btn_frame.pack()
        ttk.Button(btn_frame, text="OK", command=on_ok).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=on_cancel).pack(side=tk.LEFT, padx=5)

        entry.bind("<Return>", lambda e: on_ok())
        dialog.bind("<Escape>", lambda e: on_cancel())

        self.root.wait_window(dialog)
        return result[0]

    def show_about(self):
        """Show about dialog."""
        messagebox.showinfo(
            "About DWG Forensic Tool",
            f"DWG Forensic Tool v{__version__}\n\n"
            "Open-source forensic analysis toolkit for AutoCAD DWG files.\n\n"
            "Designed for litigation support, chain of custody documentation, "
            "and tampering detection.\n\n"
            "License: GPL v3\n"
            "https://github.com/SamuraiBuddha/DWG-forensic-tool"
        )


def main():
    """Launch the GUI application."""
    root = tk.Tk()

    # Set icon if available
    try:
        # You could add an icon file here
        pass
    except Exception:
        pass

    app = ForensicGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
