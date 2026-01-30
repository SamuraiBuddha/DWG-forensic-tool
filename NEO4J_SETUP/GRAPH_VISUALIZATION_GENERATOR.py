"""
Graph Visualization Generator
Kara Murphy vs Danny Garcia Litigation Case

This script generates visual representations of the Neo4j knowledge graph
for expert testimony, settlement negotiations, and litigation presentations.

Prerequisites:
- Neo4j instance running with initialized graph
- neo4j-driver installed: pip install neo4j
- matplotlib for visualization: pip install matplotlib
- networkx for graph layout: pip install networkx
- Pillow for image handling: pip install Pillow

Usage:
    python GRAPH_VISUALIZATION_GENERATOR.py --uri bolt://localhost:7687 --user neo4j --password your_password --output-dir ./visualizations
"""

import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

from neo4j import GraphDatabase

try:
    import matplotlib.pyplot as plt
    import networkx as nx
    VISUALIZATION_AVAILABLE = True
except ImportError:
    VISUALIZATION_AVAILABLE = False
    print("[WARN] Visualization libraries not installed. Install matplotlib and networkx.")


class GraphVisualizer:
    """Generates visualizations from Neo4j litigation knowledge graph."""

    def __init__(self, uri: str, user: str, password: str, output_dir: str):
        """
        Initialize Neo4j connection and output directory.

        Args:
            uri: Neo4j connection URI
            user: Username
            password: Password
            output_dir: Output directory for visualizations
        """
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        print(f"[OK] Connected to Neo4j at {uri}")
        print(f"[OK] Output directory: {self.output_dir.absolute()}")

    def close(self):
        """Close Neo4j connection."""
        self.driver.close()
        print("[OK] Connection closed")

    def _get_node_color(self, label: str) -> str:
        """
        Get color for node based on label.

        Args:
            label: Node label

        Returns:
            Hex color string
        """
        color_map = {
            "Party": "#FF6B6B",       # Red
            "Location": "#4ECDC4",     # Teal
            "Event": "#FFE66D",        # Yellow
            "Evidence": "#95E1D3",     # Mint
            "Timeline": "#C7CEEA",     # Lavender
            "Claim": "#FF6F91",        # Pink
            "Document": "#FFA07A",     # Light Salmon
        }
        return color_map.get(label, "#CCCCCC")

    def _get_edge_color(self, rel_type: str) -> str:
        """
        Get color for edge based on relationship type.

        Args:
            rel_type: Relationship type

        Returns:
            Hex color string
        """
        color_map = {
            "CREATED": "#2ECC71",           # Green
            "MODIFIED": "#F39C12",          # Orange
            "PARTY_INVOLVED_IN": "#3498DB", # Blue
            "LOCATED_IN": "#9B59B6",        # Purple
            "OCCURRED_ON": "#E74C3C",       # Red
            "SUPPORTS_CLAIM": "#27AE60",    # Dark Green
            "CONTRADICTS_CLAIM": "#C0392B", # Dark Red
            "REFERENCES": "#16A085",        # Dark Teal
            "DEPENDS_ON": "#8E44AD",        # Dark Purple
        }
        return color_map.get(rel_type, "#95A5A6")

    def generate_complete_case_graph(self, max_nodes: int = 100) -> str:
        """
        Generate visualization of complete case graph (limited nodes).

        Args:
            max_nodes: Maximum number of nodes to include

        Returns:
            Path to generated image file
        """
        if not VISUALIZATION_AVAILABLE:
            print("[FAIL] Visualization libraries not available")
            return ""

        print(f"\n[->] Generating complete case graph (max {max_nodes} nodes)...")

        with self.driver.session() as session:
            # Fetch all nodes and relationships
            result = session.run(
                f"""
                MATCH (n)
                WITH n LIMIT {max_nodes}
                MATCH (n)-[r]->(m)
                RETURN n, r, m
                """
            )

            G = nx.DiGraph()

            for record in result:
                node_from = record["n"]
                node_to = record["m"]
                relationship = record["r"]

                # Add nodes
                from_id = node_from.element_id
                to_id = node_to.element_id
                from_label = list(node_from.labels)[0]
                to_label = list(node_to.labels)[0]

                G.add_node(
                    from_id,
                    label=node_from.get("name", node_from.get("title", from_id[:8])),
                    node_type=from_label,
                )
                G.add_node(
                    to_id,
                    label=node_to.get("name", node_to.get("title", to_id[:8])),
                    node_type=to_label,
                )

                # Add edge
                G.add_edge(from_id, to_id, rel_type=relationship.type)

        # Create visualization
        plt.figure(figsize=(20, 16))
        pos = nx.spring_layout(G, k=2, iterations=50)

        # Draw nodes by type
        for node_type in set(nx.get_node_attributes(G, "node_type").values()):
            nodelist = [n for n, d in G.nodes(data=True) if d.get("node_type") == node_type]
            nx.draw_networkx_nodes(
                G,
                pos,
                nodelist=nodelist,
                node_color=self._get_node_color(node_type),
                node_size=1500,
                alpha=0.9,
                label=node_type,
            )

        # Draw edges by type
        for rel_type in set(nx.get_edge_attributes(G, "rel_type").values()):
            edgelist = [(u, v) for u, v, d in G.edges(data=True) if d.get("rel_type") == rel_type]
            nx.draw_networkx_edges(
                G,
                pos,
                edgelist=edgelist,
                edge_color=self._get_edge_color(rel_type),
                alpha=0.6,
                width=2,
                arrows=True,
                arrowsize=20,
            )

        # Draw labels
        labels = nx.get_node_attributes(G, "label")
        nx.draw_networkx_labels(G, pos, labels, font_size=8, font_weight="bold")

        plt.title("Kara Murphy vs Danny Garcia - Complete Case Graph", fontsize=18, fontweight="bold")
        plt.legend(loc="upper left", fontsize=12)
        plt.axis("off")
        plt.tight_layout()

        output_path = self.output_dir / "complete_case_graph.png"
        plt.savefig(output_path, dpi=300, bbox_inches="tight")
        plt.close()

        print(f"[OK] Saved: {output_path}")
        return str(output_path)

    def generate_evidence_timeline(self) -> str:
        """
        Generate timeline visualization of evidence creation/modification.

        Returns:
            Path to generated image file
        """
        if not VISUALIZATION_AVAILABLE:
            print("[FAIL] Visualization libraries not available")
            return ""

        print("\n[->] Generating evidence timeline...")

        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (ev:Evidence)
                OPTIONAL MATCH (p:Party)-[c:CREATED]->(ev)
                OPTIONAL MATCH (p2:Party)-[m:MODIFIED]->(ev)
                RETURN ev.name AS name,
                       c.created_date AS created_date,
                       m.modification_date AS modified_date,
                       p.name AS creator,
                       p2.name AS modifier
                ORDER BY created_date, modified_date
                """
            )

            events = []
            for record in result:
                if record["created_date"]:
                    events.append({
                        "name": record["name"],
                        "date": record["created_date"],
                        "action": "Created",
                        "party": record["creator"],
                    })
                if record["modified_date"]:
                    events.append({
                        "name": record["name"],
                        "date": record["modified_date"],
                        "action": "Modified",
                        "party": record["modifier"],
                    })

            # Sort by date
            events.sort(key=lambda x: x["date"] if x["date"] else datetime.min)

        # Create timeline visualization
        fig, ax = plt.subplots(figsize=(16, 10))

        y_positions = list(range(len(events)))
        colors = ["#2ECC71" if e["action"] == "Created" else "#F39C12" for e in events]

        ax.scatter(
            [e["date"] for e in events if e["date"]],
            [y_positions[i] for i, e in enumerate(events) if e["date"]],
            c=colors,
            s=200,
            alpha=0.7,
            edgecolors="black",
            linewidths=1.5,
        )

        # Add labels
        for i, event in enumerate(events):
            if event["date"]:
                label = f"{event['name']} ({event['action']})"
                if event["party"]:
                    label += f"\n by {event['party']}"
                ax.text(
                    event["date"],
                    i,
                    label,
                    fontsize=9,
                    ha="left",
                    va="center",
                    bbox=dict(boxstyle="round,pad=0.3", facecolor="white", alpha=0.7),
                )

        ax.set_xlabel("Date", fontsize=14, fontweight="bold")
        ax.set_ylabel("Event Index", fontsize=14, fontweight="bold")
        ax.set_title("Evidence Timeline - Creation and Modification Events", fontsize=16, fontweight="bold")
        ax.grid(True, alpha=0.3)

        plt.tight_layout()

        output_path = self.output_dir / "evidence_timeline.png"
        plt.savefig(output_path, dpi=300, bbox_inches="tight")
        plt.close()

        print(f"[OK] Saved: {output_path}")
        return str(output_path)

    def generate_claim_evidence_network(self) -> str:
        """
        Generate visualization of claims and supporting/contradicting evidence.

        Returns:
            Path to generated image file
        """
        if not VISUALIZATION_AVAILABLE:
            print("[FAIL] Visualization libraries not available")
            return ""

        print("\n[->] Generating claim-evidence network...")

        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (c:Claim)
                OPTIONAL MATCH (ev:Evidence)-[s:SUPPORTS_CLAIM]->(c)
                OPTIONAL MATCH (ev2:Evidence)-[con:CONTRADICTS_CLAIM]->(c)
                RETURN c.claim_text AS claim,
                       collect(DISTINCT {name: ev.name, strength: s.strength}) AS supporting,
                       collect(DISTINCT {name: ev2.name, strength: con.strength}) AS contradicting
                """
            )

            G = nx.DiGraph()

            for record in result:
                claim = record["claim"]
                G.add_node(claim, node_type="Claim")

                for evidence in record["supporting"]:
                    if evidence["name"]:
                        G.add_node(evidence["name"], node_type="Evidence")
                        G.add_edge(
                            evidence["name"],
                            claim,
                            rel_type="SUPPORTS_CLAIM",
                            strength=evidence.get("strength", "Moderate"),
                        )

                for evidence in record["contradicting"]:
                    if evidence["name"]:
                        G.add_node(evidence["name"], node_type="Evidence")
                        G.add_edge(
                            evidence["name"],
                            claim,
                            rel_type="CONTRADICTS_CLAIM",
                            strength=evidence.get("strength", "Moderate"),
                        )

        # Create visualization
        plt.figure(figsize=(18, 14))
        pos = nx.spring_layout(G, k=3, iterations=50)

        # Draw nodes
        claim_nodes = [n for n, d in G.nodes(data=True) if d.get("node_type") == "Claim"]
        evidence_nodes = [n for n, d in G.nodes(data=True) if d.get("node_type") == "Evidence"]

        nx.draw_networkx_nodes(
            G,
            pos,
            nodelist=claim_nodes,
            node_color="#FF6F91",
            node_size=3000,
            alpha=0.9,
            label="Claims",
        )
        nx.draw_networkx_nodes(
            G,
            pos,
            nodelist=evidence_nodes,
            node_color="#95E1D3",
            node_size=2000,
            alpha=0.9,
            label="Evidence",
        )

        # Draw edges
        supporting_edges = [(u, v) for u, v, d in G.edges(data=True) if d.get("rel_type") == "SUPPORTS_CLAIM"]
        contradicting_edges = [(u, v) for u, v, d in G.edges(data=True) if d.get("rel_type") == "CONTRADICTS_CLAIM"]

        nx.draw_networkx_edges(
            G,
            pos,
            edgelist=supporting_edges,
            edge_color="#27AE60",
            alpha=0.7,
            width=3,
            arrows=True,
            arrowsize=20,
            label="Supports",
        )
        nx.draw_networkx_edges(
            G,
            pos,
            edgelist=contradicting_edges,
            edge_color="#C0392B",
            alpha=0.7,
            width=3,
            arrows=True,
            arrowsize=20,
            label="Contradicts",
            style="dashed",
        )

        # Draw labels
        labels = {n: n[:30] + "..." if len(n) > 30 else n for n in G.nodes()}
        nx.draw_networkx_labels(G, pos, labels, font_size=8, font_weight="bold")

        plt.title("Claim-Evidence Network", fontsize=18, fontweight="bold")
        plt.legend(loc="upper left", fontsize=12)
        plt.axis("off")
        plt.tight_layout()

        output_path = self.output_dir / "claim_evidence_network.png"
        plt.savefig(output_path, dpi=300, bbox_inches="tight")
        plt.close()

        print(f"[OK] Saved: {output_path}")
        return str(output_path)

    def generate_party_activity_chart(self, party_name: str) -> str:
        """
        Generate bar chart of party activity (created/modified files, events involved).

        Args:
            party_name: Name of party to visualize

        Returns:
            Path to generated image file
        """
        if not VISUALIZATION_AVAILABLE:
            print("[FAIL] Visualization libraries not available")
            return ""

        print(f"\n[->] Generating activity chart for: {party_name}")

        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (p:Party {name: $party_name})
                OPTIONAL MATCH (p)-[c:CREATED]->(ev_created:Evidence)
                OPTIONAL MATCH (p)-[m:MODIFIED]->(ev_modified:Evidence)
                OPTIONAL MATCH (p)-[:PARTY_INVOLVED_IN]->(e:Event)
                RETURN count(DISTINCT ev_created) AS created,
                       count(DISTINCT ev_modified) AS modified,
                       count(DISTINCT e) AS events
                """,
                party_name=party_name,
            )

            record = result.single()
            if not record:
                print(f"[WARN] No data found for party: {party_name}")
                return ""

        # Create bar chart
        fig, ax = plt.subplots(figsize=(10, 6))

        categories = ["Files Created", "Files Modified", "Events Involved"]
        values = [record["created"], record["modified"], record["events"]]
        colors = ["#2ECC71", "#F39C12", "#3498DB"]

        bars = ax.bar(categories, values, color=colors, alpha=0.8, edgecolor="black", linewidth=1.5)

        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            ax.text(
                bar.get_x() + bar.get_width() / 2.0,
                height,
                f"{int(height)}",
                ha="center",
                va="bottom",
                fontsize=14,
                fontweight="bold",
            )

        ax.set_ylabel("Count", fontsize=14, fontweight="bold")
        ax.set_title(f"Activity Summary: {party_name}", fontsize=16, fontweight="bold")
        ax.grid(axis="y", alpha=0.3)

        plt.tight_layout()

        output_path = self.output_dir / f"party_activity_{party_name.replace(' ', '_')}.png"
        plt.savefig(output_path, dpi=300, bbox_inches="tight")
        plt.close()

        print(f"[OK] Saved: {output_path}")
        return str(output_path)

    def generate_all_visualizations(self):
        """Generate all available visualizations."""
        print("\n" + "=" * 60)
        print("Generating All Visualizations")
        print("=" * 60)

        self.generate_complete_case_graph(max_nodes=100)
        self.generate_evidence_timeline()
        self.generate_claim_evidence_network()
        self.generate_party_activity_chart("Andy Garcia")
        self.generate_party_activity_chart("Kara Murphy")
        self.generate_party_activity_chart("Danny Garcia")

        print("\n" + "=" * 60)
        print("[OK] All visualizations generated")
        print(f"[OK] Output directory: {self.output_dir.absolute()}")
        print("=" * 60)


def main():
    """Main execution."""
    parser = argparse.ArgumentParser(description="Generate visualizations from Neo4j litigation knowledge graph")
    parser.add_argument("--uri", default="bolt://localhost:7687", help="Neo4j URI")
    parser.add_argument("--user", default="neo4j", help="Neo4j username")
    parser.add_argument("--password", required=True, help="Neo4j password")
    parser.add_argument("--output-dir", default="./visualizations", help="Output directory for images")
    parser.add_argument("--mode", choices=["all", "case", "timeline", "claims", "party"], default="all",
                        help="Visualization mode")
    parser.add_argument("--party", help="Party name for party activity chart (required if mode=party)")
    args = parser.parse_args()

    visualizer = GraphVisualizer(args.uri, args.user, args.password, args.output_dir)

    try:
        if args.mode == "all":
            visualizer.generate_all_visualizations()
        elif args.mode == "case":
            visualizer.generate_complete_case_graph()
        elif args.mode == "timeline":
            visualizer.generate_evidence_timeline()
        elif args.mode == "claims":
            visualizer.generate_claim_evidence_network()
        elif args.mode == "party":
            if not args.party:
                print("[FAIL] --party required for mode=party")
            else:
                visualizer.generate_party_activity_chart(args.party)

    finally:
        visualizer.close()


if __name__ == "__main__":
    main()
