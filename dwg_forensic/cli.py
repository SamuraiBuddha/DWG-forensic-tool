"""Command-line interface for DWG Forensic Tool."""

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from dwg_forensic import __version__
from dwg_forensic.core.analyzer import ForensicAnalyzer, analyze_tampering
from dwg_forensic.core.custody import CustodyChain, EventType, IntegrityError
from dwg_forensic.core.file_guard import FileGuard
from dwg_forensic.core.intake import FileIntake
from dwg_forensic.output.json_export import JSONExporter
from dwg_forensic.output.pdf_report import generate_pdf_report
from dwg_forensic.output.expert_witness import generate_expert_witness_document
from dwg_forensic.output.timeline import generate_timeline
from dwg_forensic.parsers import CRCValidator, HeaderParser
from dwg_forensic.utils.audit import AuditLogger, get_audit_logger
from dwg_forensic.utils.exceptions import DWGForensicError, IntakeError, UnsupportedVersionError

# Phase 3 imports
from dwg_forensic.analysis import TamperingRuleEngine, RiskScorer

console = Console()


def print_status(status: str, message: str) -> None:
    """Print a status message with consistent formatting.

    Args:
        status: Status indicator ([OK], [FAIL], [WARN], [INFO], [ERROR])
        message: Message to display
    """
    color_map = {
        "[OK]": "green",
        "[FAIL]": "red",
        "[WARN]": "yellow",
        "[INFO]": "blue",
        "[ERROR]": "red bold",
    }
    color = color_map.get(status, "white")
    console.print(f"[{color}]{status}[/{color}] {message}")


@click.group()
@click.version_option(version=__version__, prog_name="dwg-forensic")
def main():
    """DWG Forensic Tool - Forensic analysis toolkit for AutoCAD DWG files.

    Analyze DWG files for tampering detection, timestamp validation,
    and forensic documentation. Supports R18+ versions (AutoCAD 2010+).
    """
    pass


def _create_progress_callback(verbose: int):
    """Create a progress callback for the analyzer.

    Args:
        verbose: Verbosity level (0=quiet, 1=normal, 2+=detailed)

    Returns:
        Callback function for progress updates
    """
    # Step descriptions for critical steps (always shown)
    critical_steps = {
        "fingerprint": "CAD Application Detection",  # CRITICAL: determines all subsequent analysis
        "sections": "Deep Analysis: Section Map",
        "drawing_vars": "Deep Analysis: Drawing Variables",
        "handles": "Deep Analysis: Handle Gap Detection",
    }

    # All step descriptions (shown in verbose mode)
    all_steps = {
        "file_info": "File Information",
        "header": "DWG Header",
        "crc": "CRC Validation",
        "timestamps": "Embedded Timestamps",
        "ntfs": "NTFS Timestamps",
        "anomalies": "Anomaly Detection",
        "rules": "Tampering Rules",
        "tampering": "Tampering Indicators",
        "risk": "Risk Assessment",
        **critical_steps,
    }

    def callback(step: str, status: str, message: str) -> None:
        is_critical = step in critical_steps
        step_name = all_steps.get(step, step)

        # Always show critical steps (fingerprint, deep parsing); show others only in verbose mode
        should_show = is_critical or verbose >= 1

        if not should_show:
            return

        if status == "start":
            # Don't print start in non-verbose mode
            if verbose >= 2:
                console.print(f"  [dim][...] {step_name}[/dim]")
        elif status == "complete":
            console.print(f"  [green][OK][/green] {step_name}: {message}")
        elif status == "error":
            console.print(f"  [red][FAIL][/red] {step_name}: {message}")
        elif status == "skip":
            console.print(f"  [yellow][SKIP][/yellow] {step_name}: {message}")

    return callback


@main.command()
@click.argument("filepath", type=click.Path(exists=True))
@click.option("-o", "--output", help="Output file path for JSON report")
@click.option("-f", "--format", "output_format", type=click.Choice(["json", "table"]), default="table")
@click.option("-v", "--verbose", count=True, help="Verbosity level")
@click.option("--llm", is_flag=True, help="Enable LLM expert narrative generation")
@click.option("--llm-model", default="mistral", help="Ollama model for LLM narration")
def analyze(filepath: str, output: str, output_format: str, verbose: int, llm: bool, llm_model: str):
    """Perform full forensic analysis on a DWG file.

    FILEPATH is the path to the DWG file to analyze.
    """
    file_path = Path(filepath)
    console.print(Panel(f"[bold]DWG Forensic Analysis[/bold]\nFile: {file_path.name}", style="blue"))

    try:
        # Create progress callback for terminal display
        progress_callback = _create_progress_callback(verbose)
        analyzer = ForensicAnalyzer(
            progress_callback=progress_callback,
            use_llm=llm,
            llm_model=llm_model if llm else None,
        )
        result = analyzer.analyze(file_path)

        if output_format == "json" or output:
            exporter = JSONExporter(indent=2)
            json_output = exporter.to_json(result)

            if output:
                exporter.to_file(result, output)
                print_status("[OK]", f"Report saved to: {output}")
            else:
                console.print(json_output)
        else:
            # Table format output
            _print_analysis_table(result, verbose)

    except UnsupportedVersionError as e:
        print_status("[ERROR]", f"Unsupported version: {e.version}")
        console.print(f"  [dim]This tool only supports R18+ (AC1024, AC1027, AC1032)[/dim]")
        sys.exit(1)
    except DWGForensicError as e:
        print_status("[ERROR]", str(e))
        sys.exit(1)
    except Exception as e:
        print_status("[ERROR]", f"Unexpected error: {e}")
        if verbose > 0:
            console.print_exception()
        sys.exit(1)


def _print_analysis_table(result, verbose: int) -> None:
    """Print analysis results as formatted tables."""
    # File Info
    table = Table(title="File Information", show_header=True, header_style="bold")
    table.add_column("Property", style="cyan")
    table.add_column("Value")
    table.add_row("Filename", result.file_info.filename)
    table.add_row("SHA-256", result.file_info.sha256[:16] + "..." if not verbose else result.file_info.sha256)
    table.add_row("Size", f"{result.file_info.file_size_bytes:,} bytes")
    table.add_row("Analyzed", result.file_info.intake_timestamp.isoformat())
    console.print(table)
    console.print()

    # Header Analysis
    table = Table(title="Header Analysis", show_header=True, header_style="bold")
    table.add_column("Property", style="cyan")
    table.add_column("Value")
    table.add_row("Version", f"{result.header_analysis.version_string} ({result.header_analysis.version_name})")
    table.add_row("Maintenance Version", str(result.header_analysis.maintenance_version))
    table.add_row("Codepage", str(result.header_analysis.codepage))
    table.add_row("Supported", "[green][OK][/green]" if result.header_analysis.is_supported else "[red][X][/red]")
    console.print(table)
    console.print()

    # CRC Validation
    crc_status = "[green][OK][/green]" if result.crc_validation.is_valid else "[red][FAIL][/red]"
    table = Table(title="CRC Validation", show_header=True, header_style="bold")
    table.add_column("Property", style="cyan")
    table.add_column("Value")
    table.add_row("Status", crc_status)
    table.add_row("Stored CRC", result.crc_validation.header_crc_stored)
    table.add_row("Calculated CRC", result.crc_validation.header_crc_calculated)
    console.print(table)
    console.print()

    # Risk Assessment
    risk_colors = {
        "LOW": "green",
        "MEDIUM": "yellow",
        "HIGH": "red",
        "CRITICAL": "red bold",
    }
    risk_color = risk_colors.get(result.risk_assessment.overall_risk.value, "white")
    console.print(Panel(
        f"[{risk_color}]Risk Level: {result.risk_assessment.overall_risk.value}[/{risk_color}]\n\n"
        + "\n".join(result.risk_assessment.factors)
        + f"\n\n[dim]{result.risk_assessment.recommendation}[/dim]",
        title="Risk Assessment",
        style="bold",
    ))


@main.command(name="validate-crc")
@click.argument("filepath", type=click.Path(exists=True))
def validate_crc(filepath: str):
    """Validate CRC checksums in a DWG file.

    FILEPATH is the path to the DWG file to validate.
    """
    file_path = Path(filepath)
    console.print(f"[bold blue]CRC Validation:[/bold blue] {file_path.name}")

    try:
        validator = CRCValidator()
        result = validator.validate_header_crc(file_path)

        if result.is_valid:
            print_status("[OK]", "Header CRC is valid")
        else:
            print_status("[FAIL]", "Header CRC mismatch detected!")

        console.print(f"  Stored:     {result.header_crc_stored}")
        console.print(f"  Calculated: {result.header_crc_calculated}")

        sys.exit(0 if result.is_valid else 1)

    except DWGForensicError as e:
        print_status("[ERROR]", str(e))
        sys.exit(1)


@main.command()
@click.argument("filepath", type=click.Path(exists=True))
@click.option("-f", "--format", "output_format", type=click.Choice(["json", "table"]), default="table")
def metadata(filepath: str, output_format: str):
    """Extract metadata from a DWG file.

    FILEPATH is the path to the DWG file.
    """
    file_path = Path(filepath)
    console.print(f"[bold blue]Metadata:[/bold blue] {file_path.name}")

    try:
        parser = HeaderParser()
        result = parser.parse(file_path)

        if output_format == "json":
            import json
            console.print(json.dumps(result.model_dump(), indent=2))
        else:
            table = Table(show_header=True, header_style="bold")
            table.add_column("Property", style="cyan")
            table.add_column("Value")
            table.add_row("Version", f"{result.version_string} ({result.version_name})")
            table.add_row("Maintenance", str(result.maintenance_version))
            table.add_row("Preview Address", f"0x{result.preview_address:X}")
            table.add_row("Codepage", str(result.codepage))
            table.add_row("Supported", "Yes" if result.is_supported else "No")
            console.print(table)

    except UnsupportedVersionError as e:
        print_status("[ERROR]", f"Unsupported version: {e.version}")
        sys.exit(1)
    except DWGForensicError as e:
        print_status("[ERROR]", str(e))
        sys.exit(1)


@main.command()
@click.argument("filepath", type=click.Path(exists=True))
@click.option("--case-id", required=True, help="Case identifier")
@click.option("--examiner", required=True, help="Examiner name")
@click.option("--evidence-number", help="Evidence number (auto-generated if not provided)")
@click.option("--evidence-dir", type=click.Path(), default="./evidence", help="Evidence storage directory")
@click.option("--db-path", type=click.Path(), default="./evidence/custody.db", help="Database path")
@click.option("--notes", help="Intake notes")
def intake(filepath: str, case_id: str, examiner: str, evidence_number: str,
           evidence_dir: str, db_path: str, notes: str):
    """Intake a DWG file into evidence with chain of custody.

    FILEPATH is the path to the DWG file.

    This performs secure evidence intake including:
    - DWG format validation
    - Multi-hash calculation (SHA-256, SHA-1, MD5)
    - Copy to evidence directory with write-protection
    - Hash verification of copied file
    - Database record creation with chain of custody
    """
    file_path = Path(filepath)
    console.print(Panel(
        f"[bold]Evidence Intake[/bold]\n"
        f"File: {file_path.name}\n"
        f"Case: {case_id}\n"
        f"Examiner: {examiner}",
        style="blue"
    ))

    try:
        # Initialize intake handler
        intake_handler = FileIntake(
            evidence_dir=Path(evidence_dir),
            db_path=Path(db_path)
        )

        # Perform intake
        print_status("[INFO]", "Starting intake process...")
        evidence = intake_handler.intake(
            source_path=file_path,
            case_id=case_id,
            examiner=examiner,
            evidence_number=evidence_number,
            notes=notes,
        )

        # Log to audit logger
        audit_logger = get_audit_logger(Path(evidence_dir) / "logs")
        audit_logger.log_intake(
            evidence_id=evidence.id,
            case_id=case_id,
            examiner=examiner,
            filename=evidence.filename,
            sha256=evidence.sha256,
        )

        # Display results
        console.print()
        table = Table(title="Evidence Intake Complete", show_header=True, header_style="bold green")
        table.add_column("Property", style="cyan")
        table.add_column("Value")
        table.add_row("Evidence ID", evidence.id)
        table.add_row("Evidence Number", evidence.evidence_number)
        table.add_row("Filename", evidence.filename)
        table.add_row("Storage Path", evidence.file_path)
        table.add_row("SHA-256", evidence.sha256)
        table.add_row("SHA-1", evidence.sha1)
        table.add_row("MD5", evidence.md5)
        table.add_row("File Size", f"{evidence.file_size_bytes:,} bytes")
        table.add_row("Intake Time", evidence.intake_timestamp.isoformat())
        console.print(table)

        print_status("[OK]", "Evidence intake complete - chain of custody initiated")

    except IntakeError as e:
        print_status("[ERROR]", f"Intake failed: {e}")
        sys.exit(1)
    except DWGForensicError as e:
        print_status("[ERROR]", str(e))
        sys.exit(1)
    except Exception as e:
        print_status("[ERROR]", f"Unexpected error: {e}")
        sys.exit(1)


@main.command()
@click.argument("evidence-id")
@click.option("--db-path", type=click.Path(exists=True), default="./evidence/custody.db", help="Database path")
def verify(evidence_id: str, db_path: str):
    """Verify evidence file integrity.

    EVIDENCE-ID is the UUID of the evidence file to verify.

    Compares the current file hash against the stored hash from intake.
    """
    console.print(f"[bold blue]Integrity Verification:[/bold blue] {evidence_id[:16]}...")

    try:
        chain = CustodyChain(Path(db_path))
        is_valid, message = chain.verify_integrity(evidence_id)

        if is_valid:
            print_status("[OK]", message)
        else:
            print_status("[FAIL]", message)
            sys.exit(1)

    except ValueError as e:
        print_status("[ERROR]", str(e))
        sys.exit(1)
    except Exception as e:
        print_status("[ERROR]", f"Verification failed: {e}")
        sys.exit(1)


@main.command(name="custody-chain")
@click.argument("evidence-id")
@click.option("--db-path", type=click.Path(exists=True), default="./evidence/custody.db", help="Database path")
@click.option("-f", "--format", "output_format", type=click.Choice(["table", "json"]), default="table")
def custody_chain(evidence_id: str, db_path: str, output_format: str):
    """Display chain of custody for evidence.

    EVIDENCE-ID is the UUID of the evidence file.
    """
    console.print(f"[bold blue]Chain of Custody:[/bold blue] {evidence_id[:16]}...")

    try:
        chain = CustodyChain(Path(db_path))
        report = chain.generate_custody_report(evidence_id)

        if output_format == "json":
            console.print(json.dumps(report, indent=2, default=str))
        else:
            # Evidence info
            ev = report["evidence"]
            table = Table(title="Evidence Information", show_header=True, header_style="bold")
            table.add_column("Property", style="cyan")
            table.add_column("Value")
            table.add_row("ID", ev["id"])
            table.add_row("Filename", ev["filename"])
            table.add_row("Case ID", ev["case_id"])
            table.add_row("Evidence Number", ev["evidence_number"] or "N/A")
            table.add_row("SHA-256", ev["sha256"][:32] + "...")
            table.add_row("Size", f"{ev['file_size_bytes']:,} bytes")
            table.add_row("Intake", ev["intake_timestamp"])
            console.print(table)
            console.print()

            # Integrity status
            integrity = report["integrity_status"]
            status = "[OK]" if integrity["is_valid"] else "[FAIL]"
            print_status(status, integrity["message"])
            console.print()

            # Custody events
            table = Table(title=f"Custody Events ({report['total_events']})", show_header=True, header_style="bold")
            table.add_column("#", style="dim")
            table.add_column("Timestamp", style="cyan")
            table.add_column("Event")
            table.add_column("Examiner")
            table.add_column("Hash Verified")
            table.add_column("Description")

            for i, event in enumerate(report["chain"], 1):
                hash_status = "[OK]" if event["hash_verified"] else "-"
                table.add_row(
                    str(i),
                    event["timestamp"][:19],
                    event["event_type"],
                    event["examiner"],
                    hash_status,
                    event["description"][:50] + "..." if len(event["description"]) > 50 else event["description"]
                )

            console.print(table)

    except ValueError as e:
        print_status("[ERROR]", str(e))
        sys.exit(1)
    except Exception as e:
        print_status("[ERROR]", f"Failed to retrieve custody chain: {e}")
        sys.exit(1)


@main.command(name="log-event")
@click.argument("evidence-id")
@click.option("--event-type", required=True,
              type=click.Choice(["ACCESS", "ANALYSIS", "EXPORT", "TRANSFER", "VERIFICATION"]),
              help="Type of custody event")
@click.option("--examiner", required=True, help="Examiner name")
@click.option("--description", required=True, help="Event description")
@click.option("--db-path", type=click.Path(exists=True), default="./evidence/custody.db", help="Database path")
@click.option("--notes", help="Additional notes")
@click.option("--skip-verify", is_flag=True, help="Skip hash verification (not recommended)")
def log_event(evidence_id: str, event_type: str, examiner: str, description: str,
              db_path: str, notes: str, skip_verify: bool):
    """Log a custody event for evidence.

    EVIDENCE-ID is the UUID of the evidence file.
    """
    console.print(f"[bold blue]Logging Custody Event:[/bold blue] {event_type}")

    try:
        chain = CustodyChain(Path(db_path))
        event = chain.log_event(
            evidence_id=evidence_id,
            event_type=EventType[event_type],
            examiner=examiner,
            description=description,
            verify_hash=not skip_verify,
            notes=notes,
        )

        print_status("[OK]", f"Event logged: {event.id}")
        console.print(f"  Timestamp: {event.timestamp.isoformat()}")
        console.print(f"  Hash Verified: {event.hash_verified}")

    except IntegrityError as e:
        print_status("[FAIL]", f"Integrity check failed: {e}")
        sys.exit(1)
    except ValueError as e:
        print_status("[ERROR]", str(e))
        sys.exit(1)
    except Exception as e:
        print_status("[ERROR]", f"Failed to log event: {e}")
        sys.exit(1)


@main.command(name="protect")
@click.argument("filepath", type=click.Path(exists=True))
def protect_file(filepath: str):
    """Set write-protection on a file.

    FILEPATH is the path to the file to protect.
    """
    file_path = Path(filepath)
    console.print(f"[bold blue]Setting Write Protection:[/bold blue] {file_path.name}")

    try:
        guard = FileGuard()

        if guard.is_protected(file_path):
            print_status("[INFO]", "File is already write-protected")
            return

        guard.protect(file_path)
        print_status("[OK]", f"Write-protection set: {file_path}")

    except PermissionError as e:
        print_status("[ERROR]", str(e))
        sys.exit(1)
    except Exception as e:
        print_status("[ERROR]", f"Failed to protect file: {e}")
        sys.exit(1)


@main.command(name="check-protection")
@click.argument("filepath", type=click.Path(exists=True))
def check_protection(filepath: str):
    """Check write-protection status of a file.

    FILEPATH is the path to the file to check.
    """
    file_path = Path(filepath)
    console.print(f"[bold blue]Protection Status:[/bold blue] {file_path.name}")

    try:
        guard = FileGuard()
        is_protected, message = guard.verify_protection(file_path)

        if is_protected:
            print_status("[OK]", message)
        else:
            print_status("[WARN]", message)
            sys.exit(1)

    except Exception as e:
        print_status("[ERROR]", f"Check failed: {e}")
        sys.exit(1)


@main.command()
@click.argument("filepath", type=click.Path(exists=True))
@click.option("-o", "--output", help="Output file path for JSON report")
@click.option("-f", "--format", "output_format", type=click.Choice(["json", "table"]), default="table")
@click.option("--rules", type=click.Path(exists=True), help="Custom tampering rules file (YAML/JSON)")
@click.option("-v", "--verbose", count=True, help="Verbosity level")
def tampering(filepath: str, output: str, output_format: str, rules: str, verbose: int):
    """Perform focused tampering analysis on a DWG file.

    FILEPATH is the path to the DWG file to analyze.

    This command performs comprehensive tampering detection including:
    - 12 built-in tampering detection rules
    - Timestamp anomaly detection
    - Version consistency checks
    - Structural integrity analysis
    - Weighted risk scoring
    """
    file_path = Path(filepath)
    rules_path = Path(rules) if rules else None

    console.print(Panel(
        f"[bold]Tampering Analysis[/bold]\nFile: {file_path.name}",
        style="red"
    ))

    try:
        report = analyze_tampering(file_path, custom_rules_path=rules_path)

        if output_format == "json" or output:
            # JSON output
            report_dict = report.model_dump(mode="json")
            json_output = json.dumps(report_dict, indent=2, default=str)

            if output:
                with open(output, "w") as f:
                    f.write(json_output)
                print_status("[OK]", f"Report saved to: {output}")
            else:
                console.print(json_output)
        else:
            # Table format output
            _print_tampering_report(report, verbose)

    except DWGForensicError as e:
        print_status("[ERROR]", str(e))
        sys.exit(1)
    except Exception as e:
        print_status("[ERROR]", f"Tampering analysis failed: {e}")
        if verbose > 0:
            console.print_exception()
        sys.exit(1)


def _print_tampering_report(report, verbose: int) -> None:
    """Print tampering analysis report as formatted tables."""
    # Risk summary
    risk_colors = {
        "LOW": "green",
        "MEDIUM": "yellow",
        "HIGH": "red",
        "CRITICAL": "red bold",
    }
    risk_color = risk_colors.get(report.risk_level.value, "white")

    console.print(Panel(
        f"[{risk_color}]Risk Level: {report.risk_level.value}[/{risk_color}]\n"
        f"Risk Score: {report.risk_score}\n"
        f"Confidence: {report.confidence:.0%}",
        title="Risk Assessment",
        style="bold",
    ))
    console.print()

    # Summary counts
    table = Table(title="Analysis Summary", show_header=True, header_style="bold")
    table.add_column("Category", style="cyan")
    table.add_column("Count")
    table.add_column("Status")

    anomaly_status = "[green][OK][/green]" if report.anomaly_count == 0 else "[yellow][WARN][/yellow]"
    rule_status = "[green][OK][/green]" if report.rule_failures == 0 else "[red][FAIL][/red]"
    indicator_status = "[green][OK][/green]" if report.tampering_indicators == 0 else "[red][FAIL][/red]"

    table.add_row("Anomalies Detected", str(report.anomaly_count), anomaly_status)
    table.add_row("Rules Triggered", str(report.rule_failures), rule_status)
    table.add_row("Tampering Indicators", str(report.tampering_indicators), indicator_status)
    console.print(table)
    console.print()

    # CRC status
    table = Table(title="Integrity Checks", show_header=True, header_style="bold")
    table.add_column("Check", style="cyan")
    table.add_column("Status")

    if report.crc_valid is not None:
        crc_status = "[green][OK][/green]" if report.crc_valid else "[red][FAIL][/red]"
        table.add_row("CRC Validation", crc_status)
    else:
        table.add_row("CRC Validation", "[dim]N/A[/dim]")

    console.print(table)
    console.print()

    # Risk factors
    if report.factors:
        console.print("[bold]Risk Factors:[/bold]")
        for factor in report.factors:
            # Color-code the factor based on status marker
            if "[OK]" in factor:
                console.print(f"  [green]{factor}[/green]")
            elif "[FAIL]" in factor or "[CRITICAL]" in factor:
                console.print(f"  [red]{factor}[/red]")
            elif "[WARN]" in factor:
                console.print(f"  [yellow]{factor}[/yellow]")
            else:
                console.print(f"  {factor}")
        console.print()

    # Failed rules (if verbose or any exist)
    if report.failed_rules and (verbose > 0 or len(report.failed_rules) <= 5):
        table = Table(title="Triggered Rules", show_header=True, header_style="bold red")
        table.add_column("Rule ID", style="cyan")
        table.add_column("Severity")
        table.add_column("Description")

        for rule in report.failed_rules[:10]:  # Limit to 10
            severity = rule.get("severity", "WARNING")
            severity_color = "red" if severity == "CRITICAL" else "yellow"
            table.add_row(
                rule.get("rule_id", "unknown"),
                f"[{severity_color}]{severity}[/{severity_color}]",
                rule.get("message", "")[:50] + "..." if len(rule.get("message", "")) > 50 else rule.get("message", "")
            )

        console.print(table)
        console.print()

    # Anomalies (if verbose)
    if verbose > 0 and report.anomalies:
        table = Table(title="Detected Anomalies", show_header=True, header_style="bold yellow")
        table.add_column("Type", style="cyan")
        table.add_column("Severity")
        table.add_column("Description")

        for anomaly in report.anomalies[:10]:
            severity_color = risk_colors.get(anomaly.severity.value, "white")
            table.add_row(
                anomaly.anomaly_type.value,
                f"[{severity_color}]{anomaly.severity.value}[/{severity_color}]",
                anomaly.description[:50] + "..." if len(anomaly.description) > 50 else anomaly.description
            )

        console.print(table)
        console.print()

    # Recommendation
    console.print(Panel(
        f"[dim]{report.recommendation}[/dim]",
        title="Recommendation",
        style="blue",
    ))


@main.command(name="list-rules")
@click.option("--format", "output_format", type=click.Choice(["table", "json"]), default="table")
def list_rules(output_format: str):
    """List all built-in tampering detection rules.

    Displays the 12 built-in rules used for tampering detection.
    """
    console.print(Panel("[bold]Built-in Tampering Rules[/bold]", style="blue"))

    engine = TamperingRuleEngine()
    rules = engine.get_builtin_rules()

    if output_format == "json":
        rules_list = [
            {
                "id": r.rule_id,
                "name": r.name,
                "description": r.description,
                "severity": r.severity.value,
                "enabled": r.enabled,
            }
            for r in rules
        ]
        console.print(json.dumps(rules_list, indent=2))
    else:
        table = Table(show_header=True, header_style="bold")
        table.add_column("Rule ID", style="cyan")
        table.add_column("Name")
        table.add_column("Severity")
        table.add_column("Enabled")

        severity_colors = {
            "INFO": "blue",
            "WARNING": "yellow",
            "CRITICAL": "red",
        }

        for rule in rules:
            severity_color = severity_colors.get(rule.severity.value, "white")
            enabled = "[green][OK][/green]" if rule.enabled else "[dim]No[/dim]"
            table.add_row(
                rule.rule_id,
                rule.name,
                f"[{severity_color}]{rule.severity.value}[/{severity_color}]",
                enabled
            )

        console.print(table)
        console.print()
        console.print(f"[dim]Total: {len(rules)} built-in rules[/dim]")


@main.command()
@click.argument("file1", type=click.Path(exists=True))
@click.argument("file2", type=click.Path(exists=True))
@click.option("--report", help="Output report file path")
def compare(file1: str, file2: str, report: str):
    """Compare two DWG files for differences.

    FILE1 and FILE2 are the paths to the DWG files to compare.
    """
    console.print("[bold blue]Comparing:[/bold blue]")
    console.print(f"  File 1: {file1}")
    console.print(f"  File 2: {file2}")
    # TODO: Implement comparison in future phase
    console.print("[yellow]Compare module will be implemented in a future phase[/yellow]")


@main.command()
@click.argument("directory", type=click.Path(exists=True))
@click.option("--recursive", is_flag=True, help="Process subdirectories")
@click.option("--output-dir", help="Output directory for reports")
def batch(directory: str, recursive: bool, output_dir: str):
    """Batch analyze multiple DWG files in a directory.

    DIRECTORY is the path to the directory containing DWG files.
    """
    console.print(f"[bold blue]Batch Analysis:[/bold blue] {directory}")
    console.print(f"[dim]Recursive: {recursive}[/dim]")
    # TODO: Implement batch processing in Phase 3
    console.print("[yellow]Batch module will be implemented in Phase 3[/yellow]")


@main.command()
@click.argument("filepath", type=click.Path(exists=True))
@click.option("-o", "--output", required=True, help="Output PDF file path")
@click.option("--case-id", help="Case identifier for the report")
@click.option("--examiner", default="Digital Forensics Examiner", help="Examiner name")
@click.option("--organization", help="Organization name")
@click.option("--include-hex", is_flag=True, help="Include hex dump appendix")
@click.option("--llm/--no-llm", default=False, help="Enable LLM-enhanced narratives (requires Ollama)")
@click.option("--llm-model", default="phi4", help="Ollama model for LLM narration")
@click.option("-v", "--verbose", count=True, help="Verbosity level")
def report(filepath: str, output: str, case_id: str, examiner: str,
           organization: str, include_hex: bool, llm: bool, llm_model: str, verbose: int):
    """Generate a PDF forensic report for a DWG file.

    FILEPATH is the path to the DWG file to analyze.

    This command performs full forensic analysis and generates a
    litigation-ready PDF report including:
    - Cover page with file identification
    - Executive summary (non-technical)
    - Technical findings
    - Metadata analysis
    - Anomaly and tampering detection results
    - Hash attestation
    - Optional hex dump appendix

    Use --llm to enable AI-powered narrative generation using a local
    Ollama instance. This provides more detailed, context-aware explanations
    suitable for non-technical audiences. Requires Ollama to be running.
    """
    file_path = Path(filepath)
    output_path = Path(output)

    console.print(Panel(
        f"[bold]PDF Report Generation[/bold]\n"
        f"File: {file_path.name}\n"
        f"Output: {output_path}",
        style="blue"
    ))

    try:
        # Run analysis with progress callback
        print_status("[INFO]", "Running forensic analysis...")
        progress_callback = _create_progress_callback(verbose)
        analyzer = ForensicAnalyzer(
            progress_callback=progress_callback,
            use_llm=llm,
            llm_model=llm_model if llm else None,
        )
        result = analyzer.analyze(file_path)

        # Check LLM availability if requested (for PDF report generation)
        if llm:
            print_status("[INFO]", f"LLM narration enabled (model: {llm_model})")
            try:
                from dwg_forensic.llm import OllamaClient
                client = OllamaClient(model=llm_model)
                if not client.is_available():
                    print_status("[WARN]", "Ollama not available - falling back to static narratives")
                    llm = False
                elif not client.is_model_available(llm_model):
                    print_status("[WARN]", f"Model '{llm_model}' not installed - falling back to static narratives")
                    llm = False
            except ImportError:
                print_status("[WARN]", "LLM module not available - falling back to static narratives")
                llm = False

        # Generate report
        print_status("[INFO]", "Generating PDF report...")
        report_path = generate_pdf_report(
            analysis=result,
            output_path=output_path,
            case_id=case_id,
            examiner_name=examiner,
            company_name=organization,
            include_hex_dumps=include_hex,
            use_llm_narration=llm,
            llm_model=llm_model,
        )

        print_status("[OK]", f"Report generated: {report_path}")

        # Display summary
        table = Table(title="Report Summary", show_header=True, header_style="bold")
        table.add_column("Property", style="cyan")
        table.add_column("Value")
        table.add_row("File Analyzed", result.file_info.filename)
        table.add_row("Risk Level", result.risk_assessment.overall_risk.value)
        table.add_row("CRC Valid", "[OK]" if result.crc_validation.is_valid else "[FAIL]")
        table.add_row("Report Path", str(report_path))
        console.print(table)

    except UnsupportedVersionError as e:
        print_status("[ERROR]", f"Unsupported version: {e.version}")
        sys.exit(1)
    except DWGForensicError as e:
        print_status("[ERROR]", str(e))
        sys.exit(1)
    except Exception as e:
        print_status("[ERROR]", f"Report generation failed: {e}")
        if verbose > 0:
            console.print_exception()
        sys.exit(1)


@main.command(name="expert-witness")
@click.argument("filepath", type=click.Path(exists=True))
@click.option("-o", "--output", required=True, help="Output PDF file path")
@click.option("--case-id", help="Case identifier")
@click.option("--expert-name", default="Digital Forensics Expert", help="Expert witness name")
@click.option("--credentials", help="Expert credentials/certifications")
@click.option("--company", help="Company or organization name")
@click.option("--llm/--no-llm", default=False, help="Enable LLM-enhanced analysis (requires Ollama)")
@click.option("--llm-model", default="phi4", help="Ollama model for LLM analysis")
@click.option("-v", "--verbose", count=True, help="Verbosity level")
def expert_witness(filepath: str, output: str, case_id: str, expert_name: str,
                   credentials: str, company: str, llm: bool, llm_model: str, verbose: int):
    """Generate expert witness methodology documentation.

    FILEPATH is the path to the DWG file to analyze.

    This command generates professional documentation suitable for:
    - Court submission
    - Deposition support
    - Expert testimony preparation
    - Methodology documentation

    Implements FR-REPORT-003 from the PRD.
    """
    file_path = Path(filepath)
    output_path = Path(output)

    console.print(Panel(
        f"[bold]Expert Witness Document[/bold]\n"
        f"File: {file_path.name}\n"
        f"Expert: {expert_name}",
        style="blue"
    ))

    try:
        # Run analysis with progress callback
        print_status("[INFO]", "Running forensic analysis...")
        progress_callback = _create_progress_callback(verbose)
        analyzer = ForensicAnalyzer(
            progress_callback=progress_callback,
            use_llm=llm,
            llm_model=llm_model if llm else None,
            expert_name=expert_name,
        )
        result = analyzer.analyze(file_path)

        # Check LLM availability if requested (for expert witness doc generation)
        if llm:
            print_status("[INFO]", f"LLM analysis enabled (model: {llm_model})")
            try:
                from dwg_forensic.llm import OllamaClient, ForensicNarrator
                client = OllamaClient(model=llm_model)
                if not client.is_available():
                    print_status("[WARN]", "Ollama not available - falling back to static analysis")
                    llm = False
                elif not client.is_model_available(llm_model):
                    print_status("[WARN]", f"Model '{llm_model}' not installed - falling back to static analysis")
                    llm = False
                else:
                    print_status("[OK]", f"Ollama connected - model '{llm_model}' ready")
                    # Verify ForensicNarrator can be created
                    test_narrator = ForensicNarrator(model=llm_model, enabled=True)
                    if test_narrator.is_available():
                        print_status("[OK]", "ForensicNarrator initialized successfully")
                    else:
                        print_status("[WARN]", "ForensicNarrator not available - check logs")
                        llm = False
            except ImportError as e:
                print_status("[WARN]", f"LLM module not available: {e}")
                llm = False
            except Exception as e:
                print_status("[WARN]", f"LLM initialization failed: {e}")
                llm = False

        # Generate document
        if llm:
            print_status("[INFO]", f"Generating expert witness document with LLM analysis ({llm_model})...")
        else:
            print_status("[INFO]", "Generating expert witness document...")
        doc_path = generate_expert_witness_document(
            analysis=result,
            output_path=output_path,
            case_id=case_id,
            expert_name=expert_name,
            expert_credentials=credentials,
            company_name=company,
            use_llm_narration=llm,
            llm_model=llm_model,
        )

        print_status("[OK]", f"Document generated: {doc_path}")

        # Display info
        console.print()
        console.print("[bold]Document Contents:[/bold]")
        console.print("  [*] Methodology description")
        console.print("  [*] Tool information and dependencies")
        if llm:
            console.print("  [*] Comprehensive Forensic Analysis (LLM-generated)")
        console.print("  [*] Reproducibility instructions")
        console.print("  [*] Limitations statement")
        console.print("  [*] Opinion support framework")
        console.print("  [*] Expert attestation section")

    except UnsupportedVersionError as e:
        print_status("[ERROR]", f"Unsupported version: {e.version}")
        sys.exit(1)
    except DWGForensicError as e:
        print_status("[ERROR]", str(e))
        sys.exit(1)
    except Exception as e:
        print_status("[ERROR]", f"Document generation failed: {e}")
        if verbose > 0:
            console.print_exception()
        sys.exit(1)


@main.command()
@click.argument("filepath", type=click.Path(exists=True))
@click.option("-o", "--output", help="Output file path (for SVG format)")
@click.option("-f", "--format", "output_format", type=click.Choice(["ascii", "svg"]), default="ascii",
              help="Output format")
@click.option("-v", "--verbose", count=True, help="Verbosity level")
def timeline(filepath: str, output: str, output_format: str, verbose: int):
    """Generate a timeline visualization of file events.

    FILEPATH is the path to the DWG file to analyze.

    Extracts timestamp events from the file and generates a timeline
    visualization showing creation, modification, and analysis events.

    Supports ASCII (text) and SVG (graphical) output formats.
    """
    file_path = Path(filepath)
    output_path = Path(output) if output else None

    console.print(Panel(
        f"[bold]Timeline Visualization[/bold]\n"
        f"File: {file_path.name}\n"
        f"Format: {output_format.upper()}",
        style="blue"
    ))

    try:
        # Run analysis
        print_status("[INFO]", "Running forensic analysis...")
        analyzer = ForensicAnalyzer()
        result = analyzer.analyze(file_path)

        # Generate timeline
        print_status("[INFO]", "Generating timeline...")
        timeline_output = generate_timeline(
            analysis=result,
            output_path=output_path,
            format=output_format,
        )

        if output_format == "svg" and output_path:
            print_status("[OK]", f"SVG timeline saved: {output_path}")
        else:
            console.print()
            console.print(timeline_output)

    except UnsupportedVersionError as e:
        print_status("[ERROR]", f"Unsupported version: {e.version}")
        sys.exit(1)
    except DWGForensicError as e:
        print_status("[ERROR]", str(e))
        sys.exit(1)
    except Exception as e:
        print_status("[ERROR]", f"Timeline generation failed: {e}")
        if verbose > 0:
            console.print_exception()
        sys.exit(1)


@main.command()
def info():
    """Display tool information and supported versions."""
    console.print(Panel(
        f"[bold]DWG Forensic Tool v{__version__}[/bold]\n\n"
        "Forensic analysis toolkit for AutoCAD DWG files\n\n"
        "[bold]Supported DWG Versions:[/bold]\n"
        "  [->] AC1024: AutoCAD 2010-2012\n"
        "  [->] AC1027: AutoCAD 2013-2017\n"
        "  [->] AC1032: AutoCAD 2018+\n\n"
        "[bold]Phase 1 - Forensic Analysis:[/bold]\n"
        "  [*] Header parsing and version detection\n"
        "  [*] CRC32 integrity validation\n"
        "  [*] CAD application fingerprinting\n"
        "  [*] Risk assessment and anomaly detection\n"
        "  [*] JSON export for reporting\n\n"
        "[bold]Phase 2 - Chain of Custody:[/bold]\n"
        "  [*] Secure evidence intake with multi-hash verification\n"
        "  [*] Chain of custody tracking and event logging\n"
        "  [*] File write-protection management\n"
        "  [*] Forensic-grade audit logging\n"
        "  [*] Integrity verification at any time\n\n"
        "[bold]Phase 3 - Tampering Detection:[/bold]\n"
        "  [*] 12 built-in tampering detection rules\n"
        "  [*] Timestamp anomaly detection\n"
        "  [*] Version consistency checks\n"
        "  [*] Structural integrity analysis\n"
        "  [*] Custom rules via YAML/JSON\n"
        "  [*] Weighted risk scoring algorithm\n\n"
        "[bold]Phase 4 - Reporting:[/bold]\n"
        "  [*] Litigation-ready PDF forensic reports\n"
        "  [*] Executive summary generator\n"
        "  [*] Expert witness methodology documentation\n"
        "  [*] Timeline visualization (ASCII and SVG)\n"
        "  [*] Hex dump formatter for evidence\n"
        "  [*] Hash attestation and chain of custody\n\n"
        "[dim]Built for litigation support[/dim]",
        title="About",
        style="blue",
    ))


if __name__ == "__main__":
    main()
