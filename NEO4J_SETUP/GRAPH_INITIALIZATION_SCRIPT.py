"""
Neo4j Graph Initialization Script
Kara Murphy vs Danny Garcia Litigation Case

This script loads initial nodes and relationships from forensic analysis
into the Neo4j knowledge graph.

Prerequisites:
- Neo4j instance running (default: bolt://localhost:7687)
- neo4j-driver installed: pip install neo4j

Usage:
    python GRAPH_INITIALIZATION_SCRIPT.py --uri bolt://localhost:7687 --user neo4j --password your_password
"""

import argparse
import uuid
from datetime import datetime
from typing import Any

from neo4j import GraphDatabase


class LitigationGraphInitializer:
    """Initializes Neo4j knowledge graph for litigation case."""

    def __init__(self, uri: str, user: str, password: str):
        """
        Initialize Neo4j connection.

        Args:
            uri: Neo4j connection URI (e.g., bolt://localhost:7687)
            user: Username
            password: Password
        """
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        print(f"[OK] Connected to Neo4j at {uri}")

    def close(self):
        """Close Neo4j connection."""
        self.driver.close()
        print("[OK] Connection closed")

    def _generate_uuid(self) -> str:
        """Generate UUID for node."""
        return str(uuid.uuid4())

    def _current_timestamp(self) -> datetime:
        """Get current timestamp."""
        return datetime.utcnow()

    def create_constraints_and_indexes(self):
        """Create all constraints and indexes defined in schema."""
        print("\n[->] Creating constraints and indexes...")

        with self.driver.session() as session:
            # Unique constraints
            constraints = [
                "CREATE CONSTRAINT party_uuid_unique IF NOT EXISTS FOR (p:Party) REQUIRE p.uuid IS UNIQUE",
                "CREATE CONSTRAINT location_uuid_unique IF NOT EXISTS FOR (l:Location) REQUIRE l.uuid IS UNIQUE",
                "CREATE CONSTRAINT event_uuid_unique IF NOT EXISTS FOR (e:Event) REQUIRE e.uuid IS UNIQUE",
                "CREATE CONSTRAINT evidence_uuid_unique IF NOT EXISTS FOR (ev:Evidence) REQUIRE ev.uuid IS UNIQUE",
                "CREATE CONSTRAINT timeline_uuid_unique IF NOT EXISTS FOR (t:Timeline) REQUIRE t.uuid IS UNIQUE",
                "CREATE CONSTRAINT claim_uuid_unique IF NOT EXISTS FOR (c:Claim) REQUIRE c.uuid IS UNIQUE",
                "CREATE CONSTRAINT document_uuid_unique IF NOT EXISTS FOR (d:Document) REQUIRE d.uuid IS UNIQUE",
                "CREATE CONSTRAINT evidence_sha256_unique IF NOT EXISTS FOR (ev:Evidence) REQUIRE ev.sha256 IS UNIQUE",
            ]

            # Performance indexes
            indexes = [
                "CREATE INDEX party_name_idx IF NOT EXISTS FOR (p:Party) ON (p.name)",
                "CREATE INDEX location_path_idx IF NOT EXISTS FOR (l:Location) ON (l.path)",
                "CREATE INDEX event_date_idx IF NOT EXISTS FOR (e:Event) ON (e.date)",
                "CREATE INDEX event_type_idx IF NOT EXISTS FOR (e:Event) ON (e.event_type)",
                "CREATE INDEX evidence_type_idx IF NOT EXISTS FOR (ev:Evidence) ON (ev.evidence_type)",
                "CREATE INDEX evidence_name_idx IF NOT EXISTS FOR (ev:Evidence) ON (ev.name)",
                "CREATE INDEX timeline_start_idx IF NOT EXISTS FOR (t:Timeline) ON (t.start_date)",
                "CREATE INDEX claim_type_idx IF NOT EXISTS FOR (c:Claim) ON (c.claim_type)",
                "CREATE INDEX claim_status_idx IF NOT EXISTS FOR (c:Claim) ON (c.status)",
                "CREATE INDEX document_type_idx IF NOT EXISTS FOR (d:Document) ON (d.document_type)",
                "CREATE INDEX document_date_idx IF NOT EXISTS FOR (d:Document) ON (d.date)",
            ]

            for constraint in constraints:
                session.run(constraint)
                print(f"  [OK] {constraint.split('FOR')[0].strip()}")

            for index in indexes:
                session.run(index)
                print(f"  [OK] {index.split('FOR')[0].strip()}")

        print("[OK] Constraints and indexes created")

    def load_parties(self):
        """Load initial Party nodes."""
        print("\n[->] Loading parties...")

        parties = [
            {
                "name": "Kara Murphy",
                "role": "Plaintiff",
                "entity_type": "Person",
                "uuid": self._generate_uuid(),
                "created_at": self._current_timestamp(),
            },
            {
                "name": "Danny Garcia",
                "role": "Defendant",
                "entity_type": "Person",
                "uuid": self._generate_uuid(),
                "created_at": self._current_timestamp(),
            },
            {
                "name": "Andy Garcia",
                "role": "Architect",
                "entity_type": "Person",
                "uuid": self._generate_uuid(),
                "created_at": self._current_timestamp(),
            },
            {
                "name": "ODA SDK",
                "role": "Software",
                "entity_type": "Software",
                "uuid": self._generate_uuid(),
                "created_at": self._current_timestamp(),
            },
        ]

        with self.driver.session() as session:
            for party in parties:
                session.run(
                    """
                    CREATE (p:Party {
                        name: $name,
                        role: $role,
                        entity_type: $entity_type,
                        uuid: $uuid,
                        created_at: datetime($created_at)
                    })
                    """,
                    **party,
                    created_at=party["created_at"].isoformat(),
                )
                print(f"  [OK] Created Party: {party['name']} ({party['role']})")

        print(f"[OK] Loaded {len(parties)} parties")

    def load_locations(self):
        """Load initial Location nodes."""
        print("\n[->] Loading locations...")

        locations = [
            {
                "path": "E:\\6075 English Oaks - Naples 2\\2021 Initial Permit\\",
                "location_type": "Directory",
                "description": "Initial permit phase directory",
                "uuid": self._generate_uuid(),
                "created_at": self._current_timestamp(),
            },
            {
                "path": "E:\\6075 English Oaks - Naples 2\\2022 Drawing Files\\",
                "location_type": "Directory",
                "description": "2022 drawing files directory",
                "uuid": self._generate_uuid(),
                "created_at": self._current_timestamp(),
            },
            {
                "path": "C:\\Users\\Andy\\Dropbox",
                "location_type": "Cloud",
                "description": "Andy Garcia's Dropbox sync folder",
                "uuid": self._generate_uuid(),
                "created_at": self._current_timestamp(),
            },
            {
                "path": "E:\\Dropbox",
                "location_type": "Cloud",
                "description": "Dropbox sync folder on E drive",
                "uuid": self._generate_uuid(),
                "created_at": self._current_timestamp(),
            },
            {
                "path": "6075 English Oaks Drive, Naples, FL",
                "location_type": "Physical",
                "description": "Property address",
                "uuid": self._generate_uuid(),
                "created_at": self._current_timestamp(),
            },
        ]

        with self.driver.session() as session:
            for location in locations:
                session.run(
                    """
                    CREATE (l:Location {
                        path: $path,
                        location_type: $location_type,
                        description: $description,
                        uuid: $uuid,
                        created_at: datetime($created_at)
                    })
                    """,
                    **location,
                    created_at=location["created_at"].isoformat(),
                )
                print(f"  [OK] Created Location: {location['path']}")

        print(f"[OK] Loaded {len(locations)} locations")

    def load_timelines(self):
        """Load initial Timeline nodes."""
        print("\n[->] Loading timelines...")

        timelines = [
            {
                "name": "2021 Initial Permit Phase",
                "start_date": "2021-01-01T00:00:00Z",
                "end_date": "2021-12-31T23:59:59Z",
                "description": "Initial permit application and design phase",
                "uuid": self._generate_uuid(),
                "created_at": self._current_timestamp(),
            },
            {
                "name": "2022 Construction Phase",
                "start_date": "2022-01-01T00:00:00Z",
                "end_date": "2022-12-31T23:59:59Z",
                "description": "Construction and drawing revision phase",
                "uuid": self._generate_uuid(),
                "created_at": self._current_timestamp(),
            },
            {
                "name": "2026 Forensic Analysis",
                "start_date": "2026-01-01T00:00:00Z",
                "end_date": None,
                "description": "Forensic investigation and litigation preparation",
                "uuid": self._generate_uuid(),
                "created_at": self._current_timestamp(),
            },
        ]

        with self.driver.session() as session:
            for timeline in timelines:
                query = """
                CREATE (t:Timeline {
                    name: $name,
                    start_date: datetime($start_date),
                    description: $description,
                    uuid: $uuid,
                    created_at: datetime($created_at)
                })
                """
                params = {**timeline, "created_at": timeline["created_at"].isoformat()}

                if timeline["end_date"]:
                    query = query.replace("created_at: datetime($created_at)",
                                          "end_date: datetime($end_date), created_at: datetime($created_at)")

                session.run(query, **params)
                print(f"  [OK] Created Timeline: {timeline['name']}")

        print(f"[OK] Loaded {len(timelines)} timelines")

    def load_evidence(self):
        """Load initial Evidence nodes."""
        print("\n[->] Loading evidence...")

        evidence_items = [
            {
                "name": "Lane.rvt",
                "evidence_type": "RVT",
                "file_path": "E:\\6075 English Oaks - Naples 2\\2021 Initial Permit\\Lane.rvt",
                "acquisition_date": "2026-01-30T00:00:00Z",
                "description": "Original Revit source file",
                "uuid": self._generate_uuid(),
                "created_at": self._current_timestamp(),
            },
            {
                "name": "Lane.0024.rvt",
                "evidence_type": "RVT",
                "file_path": "E:\\6075 English Oaks - Naples 2\\2021 Initial Permit\\Lane.0024.rvt",
                "acquisition_date": "2026-01-30T00:00:00Z",
                "description": "Revit backup file from 2021-09-21",
                "uuid": self._generate_uuid(),
                "created_at": self._current_timestamp(),
            },
            {
                "name": "FLOOR PLAN.dwg",
                "evidence_type": "DWG",
                "file_path": "E:\\6075 English Oaks - Naples 2\\2022 Drawing Files\\FLOOR PLAN.dwg",
                "acquisition_date": "2026-01-30T00:00:00Z",
                "description": "DWG floor plan (converted from Revit)",
                "uuid": self._generate_uuid(),
                "created_at": self._current_timestamp(),
            },
            {
                "name": "FOUNDATION PLAN.dwg",
                "evidence_type": "DWG",
                "file_path": "E:\\6075 English Oaks - Naples 2\\2022 Drawing Files\\FOUNDATION PLAN.dwg",
                "acquisition_date": "2026-01-30T00:00:00Z",
                "description": "DWG foundation plan",
                "uuid": self._generate_uuid(),
                "created_at": self._current_timestamp(),
            },
            # Add remaining DWG files here (total 11)
        ]

        with self.driver.session() as session:
            for evidence in evidence_items:
                session.run(
                    """
                    CREATE (ev:Evidence {
                        name: $name,
                        evidence_type: $evidence_type,
                        file_path: $file_path,
                        acquisition_date: datetime($acquisition_date),
                        description: $description,
                        uuid: $uuid,
                        created_at: datetime($created_at)
                    })
                    """,
                    **evidence,
                    created_at=evidence["created_at"].isoformat(),
                )
                print(f"  [OK] Created Evidence: {evidence['name']} ({evidence['evidence_type']})")

        print(f"[OK] Loaded {len(evidence_items)} evidence items")

    def load_events(self):
        """Load initial Event nodes."""
        print("\n[->] Loading events...")

        events = [
            {
                "name": "Lane.rvt created",
                "event_type": "FileModification",
                "date": "2021-02-24T00:00:00Z",
                "description": "Original Revit file creation",
                "significance": "High",
                "uuid": self._generate_uuid(),
                "created_at": self._current_timestamp(),
            },
            {
                "name": "Lane.0024.rvt created/modified",
                "event_type": "FileModification",
                "date": "2021-09-21T00:00:00Z",
                "description": "Revit backup file timestamp",
                "significance": "High",
                "uuid": self._generate_uuid(),
                "created_at": self._current_timestamp(),
            },
            {
                "name": "Batch DWG conversion",
                "event_type": "FileModification",
                "date": "2026-01-09T00:00:00Z",
                "description": "11 DWG files created/modified in batch operation",
                "significance": "Critical",
                "uuid": self._generate_uuid(),
                "created_at": self._current_timestamp(),
            },
            {
                "name": "Forensic analysis initiated",
                "event_type": "Litigation",
                "date": "2026-01-30T00:00:00Z",
                "description": "Forensic examination of DWG/RVT files",
                "significance": "Critical",
                "uuid": self._generate_uuid(),
                "created_at": self._current_timestamp(),
            },
        ]

        with self.driver.session() as session:
            for event in events:
                session.run(
                    """
                    CREATE (e:Event {
                        name: $name,
                        event_type: $event_type,
                        date: datetime($date),
                        description: $description,
                        significance: $significance,
                        uuid: $uuid,
                        created_at: datetime($created_at)
                    })
                    """,
                    **event,
                    created_at=event["created_at"].isoformat(),
                )
                print(f"  [OK] Created Event: {event['name']} ({event['date']})")

        print(f"[OK] Loaded {len(events)} events")

    def load_claims(self):
        """Load initial Claim nodes."""
        print("\n[->] Loading claims...")

        claims = [
            {
                "claim_text": "Amenities removed from design without authorization",
                "claim_type": "Fraud",
                "alleged_by": "Kara Murphy",
                "alleged_against": "Danny Garcia",
                "status": "Active",
                "severity": "Critical",
                "uuid": self._generate_uuid(),
                "created_at": self._current_timestamp(),
            },
            {
                "claim_text": "Build version anachronism indicates file alteration",
                "claim_type": "Fraud",
                "alleged_by": "Kara Murphy",
                "alleged_against": "Andy Garcia",
                "status": "Active",
                "severity": "Critical",
                "uuid": self._generate_uuid(),
                "created_at": self._current_timestamp(),
            },
            {
                "claim_text": "Timestamp manipulation detected in DWG files",
                "claim_type": "Fraud",
                "alleged_by": "Kara Murphy",
                "alleged_against": "Andy Garcia",
                "status": "Active",
                "severity": "Critical",
                "uuid": self._generate_uuid(),
                "created_at": self._current_timestamp(),
            },
            {
                "claim_text": "Deleted partition evidence suggests intentional data destruction",
                "claim_type": "Fraud",
                "alleged_by": "Kara Murphy",
                "alleged_against": "Andy Garcia",
                "status": "Active",
                "severity": "High",
                "uuid": self._generate_uuid(),
                "created_at": self._current_timestamp(),
            },
        ]

        with self.driver.session() as session:
            for claim in claims:
                session.run(
                    """
                    CREATE (c:Claim {
                        claim_text: $claim_text,
                        claim_type: $claim_type,
                        alleged_by: $alleged_by,
                        alleged_against: $alleged_against,
                        status: $status,
                        severity: $severity,
                        uuid: $uuid,
                        created_at: datetime($created_at)
                    })
                    """,
                    **claim,
                    created_at=claim["created_at"].isoformat(),
                )
                print(f"  [OK] Created Claim: {claim['claim_text'][:50]}...")

        print(f"[OK] Loaded {len(claims)} claims")

    def create_relationships(self):
        """Create relationships between nodes."""
        print("\n[->] Creating relationships...")

        with self.driver.session() as session:
            # Andy Garcia CREATED Lane.rvt
            session.run(
                """
                MATCH (p:Party {name: "Andy Garcia"})
                MATCH (ev:Evidence {name: "Lane.rvt"})
                CREATE (p)-[:CREATED {
                    created_date: datetime("2021-02-24T00:00:00Z"),
                    confidence: "Confirmed",
                    source: "File metadata",
                    created_at: datetime($created_at)
                }]->(ev)
                """,
                created_at=self._current_timestamp().isoformat(),
            )
            print("  [OK] Andy Garcia -[CREATED]-> Lane.rvt")

            # ODA SDK CREATED FLOOR PLAN.dwg
            session.run(
                """
                MATCH (p:Party {name: "ODA SDK"})
                MATCH (ev:Evidence {name: "FLOOR PLAN.dwg"})
                CREATE (p)-[:CREATED {
                    created_date: datetime("2026-01-09T00:00:00Z"),
                    confidence: "Confirmed",
                    source: "Forensic analysis - FINGERCODE field",
                    created_at: datetime($created_at)
                }]->(ev)
                """,
                created_at=self._current_timestamp().isoformat(),
            )
            print("  [OK] ODA SDK -[CREATED]-> FLOOR PLAN.dwg")

            # Andy Garcia PARTY_INVOLVED_IN Batch DWG conversion
            session.run(
                """
                MATCH (p:Party {name: "Andy Garcia"})
                MATCH (e:Event {name: "Batch DWG conversion"})
                CREATE (p)-[:PARTY_INVOLVED_IN {
                    role_in_event: "Author",
                    created_at: datetime($created_at)
                }]->(e)
                """,
                created_at=self._current_timestamp().isoformat(),
            )
            print("  [OK] Andy Garcia -[PARTY_INVOLVED_IN]-> Batch DWG conversion")

            # Lane.rvt LOCATED_IN 2021 Initial Permit directory
            session.run(
                """
                MATCH (ev:Evidence {name: "Lane.rvt"})
                MATCH (loc:Location {path: "E:\\\\6075 English Oaks - Naples 2\\\\2021 Initial Permit\\\\"})
                CREATE (ev)-[:LOCATED_IN {
                    discovered_date: datetime("2026-01-30T00:00:00Z"),
                    still_present: true,
                    created_at: datetime($created_at)
                }]->(loc)
                """,
                created_at=self._current_timestamp().isoformat(),
            )
            print("  [OK] Lane.rvt -[LOCATED_IN]-> 2021 Initial Permit directory")

            # Lane.rvt created OCCURRED_ON 2021 Initial Permit Phase
            session.run(
                """
                MATCH (e:Event {name: "Lane.rvt created"})
                MATCH (t:Timeline {name: "2021 Initial Permit Phase"})
                CREATE (e)-[:OCCURRED_ON {
                    created_at: datetime($created_at)
                }]->(t)
                """,
                created_at=self._current_timestamp().isoformat(),
            )
            print("  [OK] Lane.rvt created -[OCCURRED_ON]-> 2021 Initial Permit Phase")

            # Batch DWG conversion SUPPORTS_CLAIM Timestamp manipulation
            session.run(
                """
                MATCH (e:Event {name: "Batch DWG conversion"})
                MATCH (c:Claim {claim_text: "Timestamp manipulation detected in DWG files"})
                CREATE (e)-[:SUPPORTS_CLAIM {
                    strength: "Strong",
                    relevance: "All 11 DWG files created on same date (2026-01-09) suggests batch operation, not organic design workflow",
                    created_at: datetime($created_at)
                }]->(c)
                """,
                created_at=self._current_timestamp().isoformat(),
            )
            print("  [OK] Batch DWG conversion -[SUPPORTS_CLAIM]-> Timestamp manipulation")

            # Batch DWG conversion DEPENDS_ON Lane.rvt created
            session.run(
                """
                MATCH (e1:Event {name: "Batch DWG conversion"})
                MATCH (e2:Event {name: "Lane.rvt created"})
                CREATE (e1)-[:DEPENDS_ON {
                    dependency_type: "HappenedAfter",
                    created_at: datetime($created_at)
                }]->(e2)
                """,
                created_at=self._current_timestamp().isoformat(),
            )
            print("  [OK] Batch DWG conversion -[DEPENDS_ON]-> Lane.rvt created")

        print("[OK] Relationships created")

    def verify_graph(self):
        """Verify graph initialization by counting nodes and relationships."""
        print("\n[->] Verifying graph...")

        with self.driver.session() as session:
            # Count nodes
            result = session.run(
                """
                MATCH (n)
                RETURN labels(n)[0] AS label, count(n) AS count
                ORDER BY label
                """
            )
            print("\n  Node counts:")
            for record in result:
                print(f"    {record['label']}: {record['count']}")

            # Count relationships
            result = session.run(
                """
                MATCH ()-[r]->()
                RETURN type(r) AS type, count(r) AS count
                ORDER BY type
                """
            )
            print("\n  Relationship counts:")
            for record in result:
                print(f"    {record['type']}: {record['count']}")

        print("\n[OK] Graph verification complete")

    def initialize_full_graph(self):
        """Run complete graph initialization."""
        print("\n" + "=" * 60)
        print("Neo4j Litigation Knowledge Graph Initialization")
        print("Kara Murphy vs Danny Garcia")
        print("=" * 60)

        self.create_constraints_and_indexes()
        self.load_parties()
        self.load_locations()
        self.load_timelines()
        self.load_evidence()
        self.load_events()
        self.load_claims()
        self.create_relationships()
        self.verify_graph()

        print("\n" + "=" * 60)
        print("[OK] Graph initialization complete")
        print("=" * 60)


def main():
    """Main execution."""
    parser = argparse.ArgumentParser(description="Initialize Neo4j litigation knowledge graph")
    parser.add_argument("--uri", default="bolt://localhost:7687", help="Neo4j URI")
    parser.add_argument("--user", default="neo4j", help="Neo4j username")
    parser.add_argument("--password", required=True, help="Neo4j password")
    args = parser.parse_args()

    initializer = LitigationGraphInitializer(args.uri, args.user, args.password)

    try:
        initializer.initialize_full_graph()
    finally:
        initializer.close()


if __name__ == "__main__":
    main()
