"""
Direct Neo4j import script using the neo4j Python driver.
Imports all remaining documents in efficient batches.
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path

from neo4j import GraphDatabase

# Configuration - you may need to adjust these
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "")  # Set via environment or modify here

if not NEO4J_PASSWORD:
    print("[WARN] NEO4J_PASSWORD environment variable not set")
    print("Set it with: export NEO4J_PASSWORD=your_password")
    print("Or modify this script directly")
    sys.exit(1)

# Paths
SCRIPT_DIR = Path(__file__).parent
BATCH_RECORDS_FILE = SCRIPT_DIR / "batch_records.json"
OUTPUT_DIR = SCRIPT_DIR


def load_records():
    """Load all document records."""
    with open(BATCH_RECORDS_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)


def create_documents_batch(tx, docs):
    """Create documents in a batch transaction."""
    query = """
    UNWIND $docs AS doc
    CREATE (d:Document {
        uuid: doc.uuid,
        file_name: doc.file_name,
        file_path: doc.file_path,
        file_type: doc.file_type,
        evidence_category: doc.evidence_category,
        category: doc.category,
        subject: doc.subject,
        file_size_bytes: doc.file_size_bytes,
        confidence_score: doc.confidence_score,
        created_at: datetime()
    })
    WITH d, doc
    MATCH (l:Location {path: doc.location_path})
    CREATE (d)-[:LOCATED_IN {confidence: 95, created_at: datetime()}]->(l)
    RETURN count(d) AS count
    """
    result = tx.run(query, docs=docs)
    return result.single()["count"]


def create_party_references(tx, party_refs):
    """Create REFERENCES relationships to Party nodes."""
    query = """
    UNWIND $refs AS ref
    MATCH (d:Document {uuid: ref.doc_uuid})
    MATCH (p:Party {name: ref.party_name})
    CREATE (d)-[:REFERENCES {
        reference_type: 'Mentions',
        confidence: ref.confidence,
        created_at: datetime()
    }]->(p)
    RETURN count(*) AS count
    """
    result = tx.run(query, refs=party_refs)
    return result.single()["count"]


def count_documents(tx):
    """Count existing documents."""
    result = tx.run("MATCH (d:Document) RETURN count(d) AS count")
    return result.single()["count"]


def main():
    print("=" * 60)
    print("PHASE 3: DIRECT NEO4J IMPORT")
    print(f"Started: {datetime.now().isoformat()}")
    print("=" * 60)

    # Connect to Neo4j
    print(f"[->] Connecting to Neo4j at {NEO4J_URI}")
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

    try:
        with driver.session() as session:
            # Check existing count
            existing = session.execute_read(count_documents)
            print(f"[OK] Connected. Existing documents: {existing}")

            # Load records
            print("[->] Loading document records...")
            records = load_records()
            print(f"[OK] Loaded {len(records)} total records")

            # Skip already imported
            records_to_import = records[existing:]
            print(f"[->] Documents to import: {len(records_to_import)}")

            if not records_to_import:
                print("[OK] All documents already imported!")
                return

            # Process in batches of 100
            batch_size = 100
            total_created = 0
            num_batches = (len(records_to_import) + batch_size - 1) // batch_size

            for i in range(0, len(records_to_import), batch_size):
                batch_num = (i // batch_size) + 1
                batch = records_to_import[i:i+batch_size]

                # Simplify records for Cypher
                docs_for_cypher = []
                for r in batch:
                    docs_for_cypher.append({
                        "uuid": r["uuid"],
                        "file_name": r["file_name"],
                        "file_path": r["file_path"],
                        "file_type": r["file_type"],
                        "evidence_category": r["evidence_category"],
                        "category": r["category"],
                        "subject": r["subject"],
                        "file_size_bytes": r["file_size_bytes"],
                        "confidence_score": r["confidence_score"],
                        "location_path": r["location_path"],
                    })

                try:
                    count = session.execute_write(create_documents_batch, docs_for_cypher)
                    total_created += count
                    pct = (batch_num / num_batches) * 100
                    print(f"    Batch {batch_num}/{num_batches}: {count} docs ({pct:.1f}%)")
                except Exception as e:
                    print(f"    [FAIL] Batch {batch_num} error: {e}")

            print(f"\n[OK] Total documents created: {total_created}")

            # Verify final count
            final_count = session.execute_read(count_documents)
            print(f"[OK] Final document count: {final_count}")

            # Create party references
            print("\n[->] Creating party reference relationships...")
            party_refs = []
            for r in records:
                for party in r.get("parties", []):
                    party_refs.append({
                        "doc_uuid": r["uuid"],
                        "party_name": party,
                        "confidence": 75,
                    })

            if party_refs:
                # Process in batches
                ref_batch_size = 500
                total_refs = 0
                for i in range(0, len(party_refs), ref_batch_size):
                    batch = party_refs[i:i+ref_batch_size]
                    try:
                        count = session.execute_write(create_party_references, batch)
                        total_refs += count
                    except Exception as e:
                        print(f"    [WARN] Party ref batch error: {e}")

                print(f"[OK] Party references created: {total_refs}")

    finally:
        driver.close()
        print("[OK] Connection closed")

    print(f"\nCompleted: {datetime.now().isoformat()}")
    print("=" * 60)


if __name__ == "__main__":
    main()
