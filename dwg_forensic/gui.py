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


class ForensicGUI:
    """Main GUI application for DWG Forensic Tool."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"DWG Forensic Tool v{__version__}")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)

        # State
        self.current_file: Path | None = None
        self.current_analysis = None
        self.analyzer = ForensicAnalyzer()

        # Build UI
        self._create_menu()
        self._create_toolbar()
        self._create_main_content()
        self._create_status_bar()

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
        # Main container
        main = ttk.Frame(self.root, padding=10)
        main.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        # File info section
        file_frame = ttk.LabelFrame(main, text="File Information", padding=10)
        file_frame.pack(fill=tk.X, pady=(0, 10))

        self.file_label = ttk.Label(file_frame, text="No file selected", font=("", 10))
        self.file_label.pack(anchor=tk.W)

        self.hash_label = ttk.Label(file_frame, text="SHA-256: --", font=("Consolas", 9))
        self.hash_label.pack(anchor=tk.W)

        # Results notebook (tabs)
        notebook = ttk.Notebook(main)
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
        self.root.update()

        # Run analysis in background thread
        def analyze():
            try:
                self.current_analysis = self.analyzer.analyze(self.current_file)
                self.root.after(0, self._display_results)
            except Exception as e:
                error_msg = str(e)
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

            generate_pdf_report(
                analysis=self.current_analysis,
                output_path=file_path,
                case_id=case_id if case_id else None,
            )
            self.status_var.set(f"Generated: {Path(file_path).name}")
            messagebox.showinfo("Report Generated", f"PDF report saved to:\n{file_path}")

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

            generate_expert_witness_document(
                analysis=self.current_analysis,
                output_path=file_path,
                case_id=case_id if case_id else None,
                expert_name=expert_name if expert_name else "Digital Forensics Expert",
            )
            self.status_var.set(f"Generated: {Path(file_path).name}")
            messagebox.showinfo("Document Generated", f"Expert witness document saved to:\n{file_path}")

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
