"""
Phase 3: Litigation Graph Visualization Generator
Generates network visualization of all 1,040 documents and their relationships.

Author: CasparCode-002 Orchestrator
Generated: 2026-01-30
"""

import argparse
import json
import logging
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False


# ============================================================================
# LOGGING
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)


# ============================================================================
# COLOR SCHEMES
# ============================================================================

NODE_COLORS = {
    "Document": "#4A90D9",      # Blue
    "Party": "#E74C3C",         # Red
    "Location": "#27AE60",      # Green
    "Evidence": "#F39C12",      # Orange
    "Event": "#9B59B6",         # Purple
    "Claim": "#E91E63",         # Pink
    "Timeline": "#00BCD4",      # Cyan
}

EDGE_COLORS = {
    "REFERENCES": "#7F8C8D",
    "LOCATED_IN": "#27AE60",
    "CREATED": "#E74C3C",
    "MODIFIED": "#F39C12",
    "SUPPORTS_CLAIM": "#2ECC71",
    "CONTRADICTS_CLAIM": "#C0392B",
    "PARTY_INVOLVED_IN": "#9B59B6",
}

CATEGORY_COLORS = {
    "design_file": "#3498DB",
    "deposition": "#E74C3C",
    "forensic_report": "#9B59B6",
    "correspondence": "#F1C40F",
    "email": "#1ABC9C",
    "contract": "#E67E22",
    "permit": "#34495E",
    "other": "#95A5A6",
}


# ============================================================================
# VISUALIZATION GENERATOR
# ============================================================================

class LitigationGraphVisualizer:
    """
    Generates visualizations of the litigation knowledge graph.
    Supports both PNG output and ASCII fallback.
    """

    def __init__(self, backup_json_path: str):
        """
        Initialize with graph backup JSON.

        Args:
            backup_json_path: Path to neo4j_full_backup.json
        """
        self.backup_path = backup_json_path
        self.nodes: List[Dict[str, Any]] = []
        self.relationships: List[Dict[str, Any]] = []
        self.metadata: Dict[str, Any] = {}

        self._load_backup()

    def _load_backup(self):
        """Load graph data from JSON backup."""
        logger.info(f"[->] Loading graph backup from {self.backup_path}")

        try:
            with open(self.backup_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            self.nodes = data.get("nodes", [])
            self.relationships = data.get("relationships", [])
            self.metadata = data.get("metadata", {})

            logger.info(f"    [OK] Loaded {len(self.nodes)} nodes")
            logger.info(f"    [OK] Loaded {len(self.relationships)} relationships")

        except Exception as e:
            logger.error(f"[FAIL] Failed to load backup: {e}")
            raise

    def generate_statistics_summary(self) -> Dict[str, Any]:
        """Generate summary statistics of the graph."""
        stats = {
            "total_nodes": len(self.nodes),
            "total_relationships": len(self.relationships),
            "nodes_by_label": defaultdict(int),
            "relationships_by_type": defaultdict(int),
            "documents_by_category": defaultdict(int),
            "documents_by_file_type": defaultdict(int),
        }

        # Count nodes by label
        for node in self.nodes:
            for label in node.get("labels", []):
                stats["nodes_by_label"][label] += 1

            # Document-specific stats
            if "Document" in node.get("labels", []):
                props = node.get("properties", {})
                category = props.get("evidence_category", "unknown")
                file_type = props.get("file_type", "unknown")
                stats["documents_by_category"][category] += 1
                stats["documents_by_file_type"][file_type] += 1

        # Count relationships by type
        for rel in self.relationships:
            rel_type = rel.get("type", "UNKNOWN")
            stats["relationships_by_type"][rel_type] += 1

        # Convert defaultdicts to regular dicts
        stats["nodes_by_label"] = dict(stats["nodes_by_label"])
        stats["relationships_by_type"] = dict(stats["relationships_by_type"])
        stats["documents_by_category"] = dict(stats["documents_by_category"])
        stats["documents_by_file_type"] = dict(stats["documents_by_file_type"])

        return stats

    def generate_ascii_visualization(self) -> str:
        """Generate ASCII art visualization of graph structure."""
        stats = self.generate_statistics_summary()

        lines = []
        lines.append("=" * 70)
        lines.append("LITIGATION GRAPH VISUALIZATION (ASCII)")
        lines.append("Kara Murphy vs Danny Garcia")
        lines.append("=" * 70)
        lines.append("")

        # Overall stats
        lines.append(f"Total Nodes: {stats['total_nodes']}")
        lines.append(f"Total Relationships: {stats['total_relationships']}")
        lines.append("")

        # Node distribution
        lines.append("-" * 40)
        lines.append("NODES BY TYPE")
        lines.append("-" * 40)
        max_count = max(stats["nodes_by_label"].values()) if stats["nodes_by_label"] else 1
        for label, count in sorted(stats["nodes_by_label"].items(), key=lambda x: -x[1]):
            bar_len = int((count / max_count) * 30)
            bar = "#" * bar_len
            lines.append(f"  {label:15} [{bar:30}] {count:5}")
        lines.append("")

        # Relationship distribution
        lines.append("-" * 40)
        lines.append("RELATIONSHIPS BY TYPE")
        lines.append("-" * 40)
        max_rel = max(stats["relationships_by_type"].values()) if stats["relationships_by_type"] else 1
        for rel_type, count in sorted(stats["relationships_by_type"].items(), key=lambda x: -x[1]):
            bar_len = int((count / max_rel) * 25)
            bar = "=" * bar_len
            lines.append(f"  {rel_type:20} [{bar:25}] {count:5}")
        lines.append("")

        # Document categories
        lines.append("-" * 40)
        lines.append("DOCUMENTS BY CATEGORY")
        lines.append("-" * 40)
        max_cat = max(stats["documents_by_category"].values()) if stats["documents_by_category"] else 1
        for category, count in sorted(stats["documents_by_category"].items(), key=lambda x: -x[1]):
            bar_len = int((count / max_cat) * 25)
            bar = "*" * bar_len
            lines.append(f"  {category:20} [{bar:25}] {count:5}")
        lines.append("")

        # File types
        lines.append("-" * 40)
        lines.append("DOCUMENTS BY FILE TYPE")
        lines.append("-" * 40)
        max_ft = max(stats["documents_by_file_type"].values()) if stats["documents_by_file_type"] else 1
        for file_type, count in sorted(stats["documents_by_file_type"].items(), key=lambda x: -x[1]):
            bar_len = int((count / max_ft) * 25)
            bar = "+" * bar_len
            lines.append(f"  {file_type:10} [{bar:25}] {count:5}")
        lines.append("")

        # Graph structure diagram
        lines.append("-" * 40)
        lines.append("GRAPH STRUCTURE")
        lines.append("-" * 40)
        lines.append("")
        lines.append("                    [Party]")
        lines.append("                       ^")
        lines.append("                       |")
        lines.append("                   REFERENCES")
        lines.append("                       |")
        lines.append("    [Location] <---LOCATED_IN--- [Document] ---REFERENCES---> [Evidence]")
        lines.append("                                    |")
        lines.append("                                    |")
        lines.append("                             SUPPORTS_CLAIM")
        lines.append("                                    |")
        lines.append("                                    v")
        lines.append("                                 [Claim]")
        lines.append("")

        # Party connections summary
        lines.append("-" * 40)
        lines.append("PARTY CONNECTIONS")
        lines.append("-" * 40)

        party_refs = defaultdict(int)
        node_id_map = {n["id"]: n for n in self.nodes}

        for rel in self.relationships:
            if rel["type"] == "REFERENCES":
                target_node = node_id_map.get(rel["target"])
                if target_node and "Party" in target_node.get("labels", []):
                    party_name = target_node.get("properties", {}).get("name", "Unknown")
                    party_refs[party_name] += 1

        for party, count in sorted(party_refs.items(), key=lambda x: -x[1]):
            lines.append(f"  {party}: {count} document references")

        lines.append("")
        lines.append("=" * 70)
        lines.append(f"Generated: {datetime.utcnow().isoformat()}")
        lines.append("=" * 70)

        return "\n".join(lines)

    def generate_png_visualization(
        self,
        output_path: str,
        max_nodes: int = 500,
        figsize: tuple = (24, 18),
        dpi: int = 150
    ) -> bool:
        """
        Generate PNG network visualization.

        Args:
            output_path: Output PNG file path
            max_nodes: Maximum nodes to display (for performance)
            figsize: Figure size in inches
            dpi: DPI for output

        Returns:
            True if successful, False otherwise
        """
        if not NETWORKX_AVAILABLE:
            logger.warning("[WARN] NetworkX not available. Install with: pip install networkx")
            return False

        if not MATPLOTLIB_AVAILABLE:
            logger.warning("[WARN] Matplotlib not available. Install with: pip install matplotlib")
            return False

        logger.info(f"[->] Generating PNG visualization to {output_path}")

        # Build NetworkX graph
        G = nx.DiGraph()

        # Create node ID mapping
        node_id_map = {}
        for i, node in enumerate(self.nodes[:max_nodes]):
            node_id = node["id"]
            labels = node.get("labels", ["Unknown"])
            props = node.get("properties", {})

            # Get display name
            name = props.get("name") or props.get("file_name") or props.get("path", "")[:30]
            if len(name) > 25:
                name = name[:22] + "..."

            # Primary label
            primary_label = labels[0] if labels else "Unknown"

            # Get color
            color = NODE_COLORS.get(primary_label, "#95A5A6")

            # Category-based color for documents
            if primary_label == "Document":
                category = props.get("evidence_category", "other")
                color = CATEGORY_COLORS.get(category, "#4A90D9")

            G.add_node(
                node_id,
                label=name,
                node_type=primary_label,
                color=color,
            )
            node_id_map[node_id] = True

        # Add edges
        for rel in self.relationships:
            source = rel["source"]
            target = rel["target"]
            if source in node_id_map and target in node_id_map:
                rel_type = rel.get("type", "UNKNOWN")
                color = EDGE_COLORS.get(rel_type, "#7F8C8D")
                G.add_edge(source, target, rel_type=rel_type, color=color)

        logger.info(f"    Graph has {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

        # Create figure
        fig, ax = plt.subplots(figsize=figsize)

        # Calculate layout
        if G.number_of_nodes() > 100:
            # Use spring layout for large graphs
            pos = nx.spring_layout(G, k=2, iterations=50, seed=42)
        else:
            pos = nx.kamada_kawai_layout(G)

        # Get node colors and sizes
        node_colors = [G.nodes[n].get("color", "#95A5A6") for n in G.nodes()]
        node_sizes = []
        for n in G.nodes():
            node_type = G.nodes[n].get("node_type", "Unknown")
            if node_type == "Party":
                node_sizes.append(800)
            elif node_type == "Location":
                node_sizes.append(400)
            else:
                node_sizes.append(200)

        # Draw nodes
        nx.draw_networkx_nodes(
            G, pos, ax=ax,
            node_color=node_colors,
            node_size=node_sizes,
            alpha=0.8,
        )

        # Draw edges
        edge_colors = [G.edges[e].get("color", "#7F8C8D") for e in G.edges()]
        nx.draw_networkx_edges(
            G, pos, ax=ax,
            edge_color=edge_colors,
            alpha=0.4,
            arrows=True,
            arrowsize=8,
            width=0.5,
        )

        # Add labels for important nodes (Parties only for clarity)
        party_labels = {}
        for n in G.nodes():
            if G.nodes[n].get("node_type") == "Party":
                party_labels[n] = G.nodes[n].get("label", "")

        nx.draw_networkx_labels(
            G, pos, ax=ax,
            labels=party_labels,
            font_size=10,
            font_weight="bold",
        )

        # Create legend
        legend_patches = []
        for label, color in NODE_COLORS.items():
            patch = mpatches.Patch(color=color, label=label)
            legend_patches.append(patch)

        ax.legend(
            handles=legend_patches,
            loc="upper left",
            fontsize=10,
            title="Node Types"
        )

        # Title and styling
        ax.set_title(
            "Kara Murphy vs Danny Garcia - Litigation Knowledge Graph\n"
            f"{G.number_of_nodes()} Nodes, {G.number_of_edges()} Relationships",
            fontsize=16,
            fontweight="bold"
        )
        ax.axis("off")

        # Save
        plt.tight_layout()
        plt.savefig(output_path, dpi=dpi, bbox_inches="tight", facecolor="white")
        plt.close()

        logger.info(f"[OK] PNG visualization saved to {output_path}")
        return True


# ============================================================================
# MAIN
# ============================================================================

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Generate litigation graph visualization from Neo4j backup"
    )
    parser.add_argument(
        "--backup",
        required=True,
        help="Path to neo4j_full_backup.json"
    )
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Output directory"
    )
    parser.add_argument(
        "--max-nodes",
        type=int,
        default=500,
        help="Maximum nodes to display in PNG"
    )

    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Initialize visualizer
    visualizer = LitigationGraphVisualizer(args.backup)

    # Generate ASCII visualization
    ascii_viz = visualizer.generate_ascii_visualization()
    ascii_path = output_dir / "LITIGATION_GRAPH_FULL_VISUALIZATION.txt"
    with open(ascii_path, "w", encoding="utf-8") as f:
        f.write(ascii_viz)
    logger.info(f"[OK] ASCII visualization saved to {ascii_path}")

    # Generate PNG visualization
    png_path = output_dir / "LITIGATION_GRAPH_FULL_VISUALIZATION.png"
    if visualizer.generate_png_visualization(str(png_path), max_nodes=args.max_nodes):
        logger.info(f"[OK] PNG visualization saved to {png_path}")
    else:
        logger.info("[INFO] PNG visualization skipped (dependencies not available)")

    # Print statistics
    stats = visualizer.generate_statistics_summary()
    logger.info("\n" + "=" * 50)
    logger.info("GRAPH STATISTICS")
    logger.info("=" * 50)
    logger.info(f"Total Nodes: {stats['total_nodes']}")
    logger.info(f"Total Relationships: {stats['total_relationships']}")
    logger.info(f"Nodes by Label: {stats['nodes_by_label']}")
    logger.info(f"Documents by Category: {stats['documents_by_category']}")


if __name__ == "__main__":
    main()
