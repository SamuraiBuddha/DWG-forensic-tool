"""
Neo4j Utilities
Quick status checks, maintenance, and common operations for litigation knowledge graph.

Usage:
    python neo4j_utils.py --password your_password status
    python neo4j_utils.py --password your_password stats
    python neo4j_utils.py --password your_password export --output graph_export.json
    python neo4j_utils.py --password your_password clear --confirm
"""

import argparse
import json
from datetime import datetime
from typing import Any, Dict, List

from neo4j import GraphDatabase


class Neo4jUtils:
    """Utility functions for Neo4j litigation knowledge graph."""

    def __init__(self, uri: str, user: str, password: str):
        """
        Initialize Neo4j connection.

        Args:
            uri: Neo4j connection URI
            user: Username
            password: Password
        """
        try:
            self.driver = GraphDatabase.driver(uri, auth=(user, password))
            # Test connection
            with self.driver.session() as session:
                session.run("RETURN 1")
            print(f"[OK] Connected to Neo4j at {uri}")
        except Exception as e:
            print(f"[FAIL] Connection failed: {e}")
            raise

    def close(self):
        """Close Neo4j connection."""
        self.driver.close()
        print("[OK] Connection closed")

    def check_status(self):
        """Check Neo4j database status and graph health."""
        print("\n" + "=" * 60)
        print("Neo4j Database Status")
        print("=" * 60)

        with self.driver.session() as session:
            # Check connection
            try:
                result = session.run("CALL dbms.components() YIELD name, versions, edition")
                for record in result:
                    print(f"\n  Database: {record['name']}")
                    print(f"  Version: {record['versions'][0]}")
                    print(f"  Edition: {record['edition']}")
            except Exception as e:
                print(f"  [WARN] Could not retrieve version info: {e}")

            # Check constraints
            result = session.run("SHOW CONSTRAINTS")
            constraints = list(result)
            print(f"\n  Constraints: {len(constraints)}")
            for constraint in constraints[:5]:  # Show first 5
                print(f"    - {constraint.get('name', 'unnamed')}")
            if len(constraints) > 5:
                print(f"    ... and {len(constraints) - 5} more")

            # Check indexes
            result = session.run("SHOW INDEXES")
            indexes = list(result)
            print(f"\n  Indexes: {len(indexes)}")
            for index in indexes[:5]:  # Show first 5
                print(f"    - {index.get('name', 'unnamed')}")
            if len(indexes) > 5:
                print(f"    ... and {len(indexes) - 5} more")

        print("\n" + "=" * 60)
        print("[OK] Status check complete")
        print("=" * 60)

    def get_statistics(self):
        """Get comprehensive graph statistics."""
        print("\n" + "=" * 60)
        print("Graph Statistics")
        print("=" * 60)

        with self.driver.session() as session:
            # Node counts by label
            print("\n  Node Counts by Label:")
            result = session.run(
                """
                MATCH (n)
                RETURN labels(n)[0] AS label, count(n) AS count
                ORDER BY count DESC
                """
            )
            total_nodes = 0
            for record in result:
                count = record["count"]
                total_nodes += count
                print(f"    {record['label']}: {count}")

            print(f"\n  Total Nodes: {total_nodes}")

            # Relationship counts by type
            print("\n  Relationship Counts by Type:")
            result = session.run(
                """
                MATCH ()-[r]->()
                RETURN type(r) AS type, count(r) AS count
                ORDER BY count DESC
                """
            )
            total_rels = 0
            for record in result:
                count = record["count"]
                total_rels += count
                print(f"    {record['type']}: {count}")

            print(f"\n  Total Relationships: {total_rels}")

            # Evidence breakdown
            print("\n  Evidence Breakdown:")
            result = session.run(
                """
                MATCH (ev:Evidence)
                RETURN ev.evidence_type AS type, count(ev) AS count
                ORDER BY count DESC
                """
            )
            for record in result:
                print(f"    {record['type']}: {record['count']}")

            # Claim status breakdown
            print("\n  Claim Status Breakdown:")
            result = session.run(
                """
                MATCH (c:Claim)
                RETURN c.status AS status, c.severity AS severity, count(c) AS count
                ORDER BY severity DESC, status
                """
            )
            for record in result:
                print(f"    {record['severity']} - {record['status']}: {record['count']}")

            # Party activity summary
            print("\n  Party Activity Summary:")
            result = session.run(
                """
                MATCH (p:Party)
                OPTIONAL MATCH (p)-[:CREATED]->(ev_created)
                OPTIONAL MATCH (p)-[:MODIFIED]->(ev_modified)
                OPTIONAL MATCH (p)-[:PARTY_INVOLVED_IN]->(e)
                RETURN p.name AS party,
                       count(DISTINCT ev_created) AS created,
                       count(DISTINCT ev_modified) AS modified,
                       count(DISTINCT e) AS events
                ORDER BY (created + modified + events) DESC
                """
            )
            for record in result:
                print(f"    {record['party']}:")
                print(f"      Created: {record['created']}, Modified: {record['modified']}, Events: {record['events']}")

            # Timeline coverage
            print("\n  Timeline Coverage:")
            result = session.run(
                """
                MATCH (t:Timeline)
                OPTIONAL MATCH (e:Event)-[:OCCURRED_ON]->(t)
                RETURN t.name AS timeline,
                       t.start_date AS start,
                       t.end_date AS end,
                       count(e) AS event_count
                ORDER BY start
                """
            )
            for record in result:
                end = record["end"] if record["end"] else "ongoing"
                print(f"    {record['timeline']}: {record['start']} to {end} ({record['event_count']} events)")

        print("\n" + "=" * 60)
        print("[OK] Statistics generation complete")
        print("=" * 60)

    def export_graph(self, output_file: str):
        """
        Export entire graph to JSON.

        Args:
            output_file: Path to output JSON file
        """
        print(f"\n[->] Exporting graph to {output_file}...")

        export_data = {
            "metadata": {
                "export_timestamp": datetime.utcnow().isoformat(),
                "case": "Kara Murphy vs Danny Garcia",
            },
            "nodes": [],
            "relationships": [],
        }

        with self.driver.session() as session:
            # Export nodes
            result = session.run(
                """
                MATCH (n)
                RETURN elementId(n) AS id, labels(n) AS labels, properties(n) AS properties
                """
            )
            for record in result:
                export_data["nodes"].append({
                    "id": record["id"],
                    "labels": record["labels"],
                    "properties": dict(record["properties"]),
                })

            print(f"  [OK] Exported {len(export_data['nodes'])} nodes")

            # Export relationships
            result = session.run(
                """
                MATCH (source)-[r]->(target)
                RETURN elementId(source) AS source_id,
                       elementId(target) AS target_id,
                       type(r) AS type,
                       properties(r) AS properties
                """
            )
            for record in result:
                export_data["relationships"].append({
                    "source": record["source_id"],
                    "target": record["target_id"],
                    "type": record["type"],
                    "properties": dict(record["properties"]),
                })

            print(f"  [OK] Exported {len(export_data['relationships'])} relationships")

        # Write to file
        with open(output_file, "w") as f:
            json.dump(export_data, f, indent=2, default=str)

        print(f"[OK] Graph exported to {output_file}")

    def clear_graph(self, confirm: bool = False):
        """
        Clear entire graph (DESTRUCTIVE).

        Args:
            confirm: Must be True to proceed
        """
        if not confirm:
            print("[FAIL] Clear operation requires --confirm flag")
            return

        print("\n[WARN] This will DELETE ALL NODES AND RELATIONSHIPS")
        print("[WARN] This operation is IRREVERSIBLE")

        user_input = input("\nType 'DELETE EVERYTHING' to confirm: ")

        if user_input != "DELETE EVERYTHING":
            print("[OK] Operation cancelled")
            return

        print("\n[->] Clearing graph...")

        with self.driver.session() as session:
            # Delete all nodes and relationships
            result = session.run("MATCH (n) DETACH DELETE n RETURN count(n) AS deleted")
            deleted = result.single()["deleted"]

            print(f"[OK] Deleted {deleted} nodes and all relationships")

        print("[OK] Graph cleared")

    def validate_integrity(self):
        """Validate graph integrity and data quality."""
        print("\n" + "=" * 60)
        print("Graph Integrity Validation")
        print("=" * 60)

        issues = []

        with self.driver.session() as session:
            # Check for orphaned evidence (no location)
            result = session.run(
                """
                MATCH (ev:Evidence)
                WHERE NOT EXISTS {
                    MATCH (ev)-[:LOCATED_IN]->(:Location)
                }
                RETURN ev.name AS name
                """
            )
            orphaned = [record["name"] for record in result]
            if orphaned:
                issues.append(f"Orphaned evidence (no location): {len(orphaned)} files")
                print(f"\n  [WARN] {len(orphaned)} evidence nodes have no LOCATED_IN relationship")
                for name in orphaned[:5]:
                    print(f"    - {name}")

            # Check for evidence without creator
            result = session.run(
                """
                MATCH (ev:Evidence)
                WHERE NOT EXISTS {
                    MATCH (ev)<-[:CREATED]-(:Party)
                }
                RETURN ev.name AS name
                """
            )
            no_creator = [record["name"] for record in result]
            if no_creator:
                issues.append(f"Evidence without creator: {len(no_creator)} files")
                print(f"\n  [WARN] {len(no_creator)} evidence nodes have no CREATED relationship")
                for name in no_creator[:5]:
                    print(f"    - {name}")

            # Check for events without timeline
            result = session.run(
                """
                MATCH (e:Event)
                WHERE NOT EXISTS {
                    MATCH (e)-[:OCCURRED_ON]->(:Timeline)
                }
                RETURN e.name AS name
                """
            )
            no_timeline = [record["name"] for record in result]
            if no_timeline:
                issues.append(f"Events without timeline: {len(no_timeline)}")
                print(f"\n  [WARN] {len(no_timeline)} events have no OCCURRED_ON relationship")
                for name in no_timeline[:5]:
                    print(f"    - {name}")

            # Check for claims without evidence
            result = session.run(
                """
                MATCH (c:Claim)
                WHERE NOT EXISTS {
                    MATCH (c)<-[:SUPPORTS_CLAIM|CONTRADICTS_CLAIM]-(:Evidence)
                }
                RETURN c.claim_text AS claim
                """
            )
            no_evidence = [record["claim"] for record in result]
            if no_evidence:
                issues.append(f"Claims without evidence: {len(no_evidence)}")
                print(f"\n  [WARN] {len(no_evidence)} claims have no supporting/contradicting evidence")
                for claim in no_evidence:
                    print(f"    - {claim[:60]}...")

            # Check for duplicate SHA-256 hashes
            result = session.run(
                """
                MATCH (ev:Evidence)
                WHERE ev.sha256 IS NOT NULL
                WITH ev.sha256 AS hash, collect(ev.name) AS files
                WHERE size(files) > 1
                RETURN hash, files
                """
            )
            duplicates = list(result)
            if duplicates:
                issues.append(f"Duplicate SHA-256 hashes: {len(duplicates)}")
                print(f"\n  [WARN] {len(duplicates)} duplicate SHA-256 hashes found")
                for record in duplicates:
                    print(f"    - {record['hash'][:16]}...: {record['files']}")

        print("\n" + "=" * 60)
        if issues:
            print(f"[WARN] Found {len(issues)} integrity issues")
            for issue in issues:
                print(f"  - {issue}")
        else:
            print("[OK] No integrity issues found")
        print("=" * 60)

    def find_conflicts(self):
        """Find potential conflicts in evidence/claims."""
        print("\n" + "=" * 60)
        print("Conflict Detection")
        print("=" * 60)

        with self.driver.session() as session:
            # Find evidence that both supports AND contradicts same claim
            print("\n  Evidence with Contradictory Relationships:")
            result = session.run(
                """
                MATCH (ev:Evidence)-[:SUPPORTS_CLAIM]->(c:Claim)
                MATCH (ev)-[:CONTRADICTS_CLAIM]->(c)
                RETURN ev.name AS evidence, c.claim_text AS claim
                """
            )
            conflicts = list(result)
            if conflicts:
                for record in conflicts:
                    print(f"    [!] {record['evidence']} both supports AND contradicts:")
                    print(f"        {record['claim'][:60]}...")
            else:
                print("    [OK] No contradictory evidence relationships found")

            # Find temporal impossibilities (modification before creation)
            print("\n  Temporal Impossibilities:")
            result = session.run(
                """
                MATCH (p:Party)-[c:CREATED]->(ev:Evidence)
                MATCH (p2:Party)-[m:MODIFIED]->(ev)
                WHERE m.modification_date < c.created_date
                RETURN ev.name AS evidence,
                       c.created_date AS created,
                       m.modification_date AS modified
                """
            )
            temporal_issues = list(result)
            if temporal_issues:
                for record in temporal_issues:
                    print(f"    [!] {record['evidence']} modified before creation")
                    print(f"        Created: {record['created']}, Modified: {record['modified']}")
            else:
                print("    [OK] No temporal impossibilities found")

        print("\n" + "=" * 60)
        print("[OK] Conflict detection complete")
        print("=" * 60)


def main():
    """Main execution."""
    parser = argparse.ArgumentParser(description="Neo4j utility functions")
    parser.add_argument("--uri", default="bolt://localhost:7687", help="Neo4j URI")
    parser.add_argument("--user", default="neo4j", help="Neo4j username")
    parser.add_argument("--password", required=True, help="Neo4j password")

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Status command
    subparsers.add_parser("status", help="Check database status")

    # Stats command
    subparsers.add_parser("stats", help="Get graph statistics")

    # Export command
    export_parser = subparsers.add_parser("export", help="Export graph to JSON")
    export_parser.add_argument("--output", required=True, help="Output JSON file")

    # Clear command
    clear_parser = subparsers.add_parser("clear", help="Clear entire graph (DESTRUCTIVE)")
    clear_parser.add_argument("--confirm", action="store_true", help="Confirm deletion")

    # Validate command
    subparsers.add_parser("validate", help="Validate graph integrity")

    # Conflicts command
    subparsers.add_parser("conflicts", help="Find potential conflicts")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    utils = Neo4jUtils(args.uri, args.user, args.password)

    try:
        if args.command == "status":
            utils.check_status()
        elif args.command == "stats":
            utils.get_statistics()
        elif args.command == "export":
            utils.export_graph(args.output)
        elif args.command == "clear":
            utils.clear_graph(args.confirm)
        elif args.command == "validate":
            utils.validate_integrity()
        elif args.command == "conflicts":
            utils.find_conflicts()
    finally:
        utils.close()


if __name__ == "__main__":
    main()
