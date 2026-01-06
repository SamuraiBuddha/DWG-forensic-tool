"""
DWG Forensic Tool - Timeline Visualization

Generates timeline visualizations for forensic reports showing
file creation, modification, and analysis events.
"""

from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple, Union

from dwg_forensic.models import ForensicAnalysis, DWGMetadata


class TimelineEvent:
    """Represents a single event on the timeline."""

    def __init__(
        self,
        timestamp: datetime,
        event_type: str,
        description: str,
        source: str = "analysis",
    ):
        """
        Initialize a timeline event.

        Args:
            timestamp: When the event occurred
            event_type: Type of event (created, modified, saved, analyzed)
            description: Human-readable description
            source: Source of the event data
        """
        self.timestamp = timestamp
        self.event_type = event_type
        self.description = description
        self.source = source

    def __lt__(self, other: "TimelineEvent") -> bool:
        return self.timestamp < other.timestamp


class TimelineGenerator:
    """
    Generates timeline visualizations from forensic analysis data.

    Supports:
    - SVG output for scalable graphics
    - Text-based ASCII timeline
    - Event extraction from analysis results
    """

    # Event type markers for ASCII timeline
    EVENT_MARKERS = {
        "created": "[+]",
        "modified": "[M]",
        "saved": "[S]",
        "analyzed": "[A]",
        "intake": "[I]",
        "other": "[*]",
    }

    def __init__(self, width: int = 800, height: int = 400):
        """
        Initialize the timeline generator.

        Args:
            width: SVG width in pixels
            height: SVG height in pixels
        """
        self.width = width
        self.height = height

    def extract_events(self, analysis: ForensicAnalysis) -> List[TimelineEvent]:
        """
        Extract timeline events from forensic analysis.

        Args:
            analysis: Forensic analysis results

        Returns:
            List of timeline events sorted chronologically
        """
        events = []

        # Analysis timestamp
        if analysis.analysis_timestamp:
            events.append(TimelineEvent(
                timestamp=analysis.analysis_timestamp,
                event_type="analyzed",
                description="Forensic analysis performed",
                source="analysis",
            ))

        # File intake timestamp
        if analysis.file_info and analysis.file_info.intake_timestamp:
            events.append(TimelineEvent(
                timestamp=analysis.file_info.intake_timestamp,
                event_type="intake",
                description="File received for analysis",
                source="intake",
            ))

        # Metadata timestamps
        if analysis.metadata:
            if analysis.metadata.created_date:
                events.append(TimelineEvent(
                    timestamp=analysis.metadata.created_date,
                    event_type="created",
                    description="File created (per metadata)",
                    source="dwg_metadata",
                ))

            if analysis.metadata.modified_date:
                events.append(TimelineEvent(
                    timestamp=analysis.metadata.modified_date,
                    event_type="modified",
                    description="File last modified (per metadata)",
                    source="dwg_metadata",
                ))

        # Sort by timestamp
        events.sort()

        return events

    def generate_ascii(
        self,
        events: List[TimelineEvent],
        title: str = "File Timeline",
    ) -> str:
        """
        Generate ASCII text timeline.

        Args:
            events: List of timeline events
            title: Title for the timeline

        Returns:
            ASCII timeline string
        """
        if not events:
            return f"{title}\n{'=' * len(title)}\n\nNo events to display."

        lines = [
            title,
            "=" * len(title),
            "",
        ]

        # Find date range for formatting
        for event in events:
            marker = self.EVENT_MARKERS.get(event.event_type, self.EVENT_MARKERS["other"])
            timestamp_str = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            lines.append(f"  {marker} {timestamp_str}  {event.description}")
            lines.append(f"      Source: {event.source}")
            lines.append("")

        # Add legend
        lines.extend([
            "Legend:",
            "  [+] Created    [M] Modified    [S] Saved",
            "  [A] Analyzed   [I] Intake      [*] Other",
        ])

        return "\n".join(lines)

    def generate_svg(
        self,
        events: List[TimelineEvent],
        title: str = "File Timeline",
    ) -> str:
        """
        Generate SVG timeline visualization.

        Args:
            events: List of timeline events
            title: Title for the timeline

        Returns:
            SVG string
        """
        if not events:
            return self._generate_empty_svg(title)

        # Calculate dimensions
        margin = 60
        timeline_y = self.height // 2
        usable_width = self.width - 2 * margin

        # Find time range
        min_time = min(e.timestamp for e in events)
        max_time = max(e.timestamp for e in events)
        time_range = (max_time - min_time).total_seconds()

        if time_range == 0:
            time_range = 1  # Prevent division by zero

        # Generate SVG
        svg_parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{self.width}" height="{self.height}">',
            '  <style>',
            '    .title { font: bold 18px sans-serif; }',
            '    .event-label { font: 12px sans-serif; }',
            '    .date-label { font: 10px monospace; fill: #666; }',
            '    .timeline { stroke: #333; stroke-width: 2; }',
            '    .event-marker { fill: #007ACC; }',
            '    .event-created { fill: #28A745; }',
            '    .event-modified { fill: #FFC107; }',
            '    .event-analyzed { fill: #17A2B8; }',
            '  </style>',
            '',
            f'  <!-- Title -->',
            f'  <text x="{self.width // 2}" y="30" text-anchor="middle" class="title">{title}</text>',
            '',
            f'  <!-- Timeline axis -->',
            f'  <line x1="{margin}" y1="{timeline_y}" x2="{self.width - margin}" y2="{timeline_y}" class="timeline"/>',
        ]

        # Add events
        event_colors = {
            "created": "event-created",
            "modified": "event-modified",
            "analyzed": "event-analyzed",
        }

        for i, event in enumerate(events):
            # Calculate x position
            time_offset = (event.timestamp - min_time).total_seconds()
            x = margin + (time_offset / time_range) * usable_width

            # Alternate y offset for labels to avoid overlap
            y_offset = 40 if i % 2 == 0 else -40
            label_y = timeline_y + y_offset

            color_class = event_colors.get(event.event_type, "event-marker")

            svg_parts.extend([
                f'  <!-- Event: {event.event_type} -->',
                f'  <circle cx="{x:.1f}" cy="{timeline_y}" r="8" class="{color_class}"/>',
                f'  <line x1="{x:.1f}" y1="{timeline_y}" x2="{x:.1f}" y2="{label_y}" stroke="#999" stroke-dasharray="2,2"/>',
                f'  <text x="{x:.1f}" y="{label_y + (15 if y_offset > 0 else -5)}" text-anchor="middle" class="event-label">{event.event_type.title()}</text>',
                f'  <text x="{x:.1f}" y="{label_y + (30 if y_offset > 0 else -20)}" text-anchor="middle" class="date-label">{event.timestamp.strftime("%Y-%m-%d")}</text>',
            ])

        # Add date range labels
        svg_parts.extend([
            f'  <!-- Date range -->',
            f'  <text x="{margin}" y="{timeline_y + 80}" class="date-label">{min_time.strftime("%Y-%m-%d %H:%M")}</text>',
            f'  <text x="{self.width - margin}" y="{timeline_y + 80}" text-anchor="end" class="date-label">{max_time.strftime("%Y-%m-%d %H:%M")}</text>',
        ])

        svg_parts.append('</svg>')

        return "\n".join(svg_parts)

    def _generate_empty_svg(self, title: str) -> str:
        """Generate an empty SVG with a message."""
        return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{self.width}" height="{self.height}">
  <text x="{self.width // 2}" y="30" text-anchor="middle" font-weight="bold">{title}</text>
  <text x="{self.width // 2}" y="{self.height // 2}" text-anchor="middle" fill="#666">No timeline events available</text>
</svg>'''

    def save_svg(
        self,
        events: List[TimelineEvent],
        output_path: Union[str, Path],
        title: str = "File Timeline",
    ) -> None:
        """
        Generate and save SVG timeline to file.

        Args:
            events: List of timeline events
            output_path: Path to save the SVG file
            title: Title for the timeline
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        svg_content = self.generate_svg(events, title)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(svg_content)


def generate_timeline(
    analysis: ForensicAnalysis,
    output_path: Optional[Union[str, Path]] = None,
    format: str = "ascii",
) -> str:
    """
    Convenience function to generate a timeline from analysis.

    Args:
        analysis: Forensic analysis results
        output_path: Optional path to save timeline (for SVG)
        format: Output format ('ascii' or 'svg')

    Returns:
        Timeline string (ASCII or SVG)
    """
    generator = TimelineGenerator()
    events = generator.extract_events(analysis)

    if format == "svg":
        result = generator.generate_svg(events, title=f"Timeline: {analysis.file_info.filename}")
        if output_path:
            generator.save_svg(events, output_path, title=f"Timeline: {analysis.file_info.filename}")
    else:
        result = generator.generate_ascii(events, title=f"Timeline: {analysis.file_info.filename}")

    return result
