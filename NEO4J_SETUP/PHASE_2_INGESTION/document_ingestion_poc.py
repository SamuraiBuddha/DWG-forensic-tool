"""
Phase 2 Document Ingestion - Proof of Concept
Kara Murphy vs Danny Garcia Litigation Case

This enhanced pipeline ingests critical forensic evidence documents into Neo4j
with full schema validation, confidence scoring, and dual-tracking recovery.

Author: CasparCode-002 Orchestrator
Generated: 2026-01-30
Phase: Phase 2 POC (5 core documents) - Ready to scale to 1,040 documents
"""

import argparse
import hashlib
import json
import logging
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from neo4j import GraphDatabase


# Configure logging with dual-tracking
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler('NEO4J_INGESTION_LOG.txt'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class ForensicDocumentIngestionPipeline:
    """
    Enhanced document ingestion pipeline with:
    - Neo4j schema validation
    - Confidence scoring for relationships
    - Forensic evidence categorization
    - Dual-tracking recovery
    - Scalable CSV batch processing architecture
    """

    def __init__(self, uri: str, user: str, password: str):
        """
        Initialize Neo4j connection with validation.

        Args:
            uri: Neo4j connection URI
            user: Username
            password: Password
        """
        logger.info(f"Initializing connection to Neo4j at {uri}")
        try:
            self.driver = GraphDatabase.driver(uri, auth=(user, password))
            # Test connection
            with self.driver.session() as session:
                session.run("RETURN 1")
            logger.info("[OK] Connected to Neo4j successfully")
        except Exception as e:
            logger.error(f"[FAIL] Neo4j connection failed: {e}")
            raise

        self.stats = {
            "documents_created": 0,
            "relationships_created": 0,
            "validation_errors": 0,
            "start_time": datetime.utcnow(),
        }

    def close(self):
        """Close Neo4j connection and log final statistics."""
        duration = (datetime.utcnow() - self.stats["start_time"]).total_seconds()
        logger.info("=" * 60)
        logger.info("Ingestion Statistics:")
        logger.info(f"  Documents Created: {self.stats['documents_created']}")
        logger.info(f"  Relationships Created: {self.stats['relationships_created']}")
        logger.info(f"  Validation Errors: {self.stats['validation_errors']}")
        logger.info(f"  Duration: {duration:.2f} seconds")
        logger.info("=" * 60)
        self.driver.close()
        logger.info("[OK] Connection closed")

    def _generate_uuid(self) -> str:
        """Generate UUID for node."""
        return str(uuid.uuid4())

    def _current_timestamp(self) -> datetime:
        """Get current UTC timestamp."""
        return datetime.utcnow()

    def _calculate_file_hash(self, file_path: str) -> Optional[str]:
        """
        Calculate SHA-256 hash for file integrity verification.

        Args:
            file_path: Path to file

        Returns:
            SHA-256 hash or None if file not accessible
        """
        try:
            if os.path.exists(file_path):
                sha256_hash = hashlib.sha256()
                with open(file_path, "rb") as f:
                    for byte_block in iter(lambda: f.read(4096), b""):
                        sha256_hash.update(byte_block)
                return sha256_hash.hexdigest()
        except Exception as e:
            logger.warning(f"Could not calculate hash for {file_path}: {e}")
        return None

    def validate_schema_constraints(self) -> bool:
        """
        Validate that required Neo4j schema constraints exist.

        Returns:
            True if schema is ready, False otherwise
        """
        logger.info("[->] Validating Neo4j schema constraints")

        required_constraints = [
            "document_uuid_unique",
            "evidence_uuid_unique",
            "party_uuid_unique",
        ]

        with self.driver.session() as session:
            try:
                result = session.run("SHOW CONSTRAINTS")
                existing = [record.get("name") for record in result]

                missing = []
                for constraint in required_constraints:
                    if constraint not in existing:
                        missing.append(constraint)

                if missing:
                    logger.warning(f"[WARN] Missing constraints: {missing}")
                    logger.info("Run NEO4J_SCHEMA.txt initialization first")
                    return False

                logger.info(f"[OK] Schema validation passed ({len(existing)} constraints)")
                return True

            except Exception as e:
                logger.error(f"[FAIL] Schema validation error: {e}")
                return False

    def create_document_node(
        self,
        file_name: str,
        file_path: str,
        file_type: str,
        evidence_category: str,
        created_date: Optional[str] = None,
        modified_date: Optional[str] = None,
        file_size_bytes: Optional[int] = None,
        forensic_findings: Optional[str] = None,
        confidence_score: int = 50,
    ) -> str:
        """
        Create Document node with forensic metadata.

        Args:
            file_name: Document filename
            file_path: Full file path
            file_type: "RVT" | "DWG" | "PDF" | "MSG" | "XLSX" | "TXT"
            evidence_category: "design_file" | "deposition" | "forensic_report" | "email" | "permit"
            created_date: ISO datetime string
            modified_date: ISO datetime string
            file_size_bytes: File size in bytes
            forensic_findings: Summary of forensic analysis
            confidence_score: 0-100 (50=baseline, 75=strong, 95=definitive)

        Returns:
            UUID of created Document node
        """
        logger.info(f"[->] Creating Document node: {file_name}")

        doc_uuid = self._generate_uuid()

        # Calculate hash if file exists
        sha256_hash = self._calculate_file_hash(file_path) if os.path.exists(file_path) else None

        query = """
        CREATE (d:Document {
            uuid: $uuid,
            file_name: $file_name,
            file_path: $file_path,
            file_type: $file_type,
            evidence_category: $evidence_category,
            created_at: datetime($created_at),
            confidence_score: $confidence_score
        })
        """

        params = {
            "uuid": doc_uuid,
            "file_name": file_name,
            "file_path": file_path,
            "file_type": file_type,
            "evidence_category": evidence_category,
            "created_at": self._current_timestamp().isoformat(),
            "confidence_score": confidence_score,
        }

        # Add optional properties
        if created_date:
            query = query.replace(
                "confidence_score: $confidence_score",
                "created_date: datetime($created_date), confidence_score: $confidence_score"
            )
            params["created_date"] = created_date

        if modified_date:
            query = query.replace(
                "confidence_score: $confidence_score",
                "modified_date: datetime($modified_date), confidence_score: $confidence_score"
            )
            params["modified_date"] = modified_date

        if file_size_bytes:
            query = query.replace(
                "confidence_score: $confidence_score",
                "file_size_bytes: $file_size_bytes, confidence_score: $confidence_score"
            )
            params["file_size_bytes"] = file_size_bytes

        if forensic_findings:
            query = query.replace(
                "confidence_score: $confidence_score",
                "forensic_findings: $forensic_findings, confidence_score: $confidence_score"
            )
            params["forensic_findings"] = forensic_findings

        if sha256_hash:
            query = query.replace(
                "confidence_score: $confidence_score",
                "sha256: $sha256, confidence_score: $confidence_score"
            )
            params["sha256"] = sha256_hash

        try:
            with self.driver.session() as session:
                session.run(query, **params)
            self.stats["documents_created"] += 1
            logger.info(f"  [OK] Document node created (UUID: {doc_uuid[:8]}...)")
            return doc_uuid
        except Exception as e:
            logger.error(f"  [FAIL] Document creation failed: {e}")
            self.stats["validation_errors"] += 1
            raise

    def link_document_to_evidence(
        self,
        document_uuid: str,
        evidence_name: str,
        relationship_type: str = "REFERENCES",
        reference_type: str = "Analyzes",
        confidence: int = 75,
        context: Optional[str] = None,
    ):
        """
        Create relationship from Document to Evidence node.

        Args:
            document_uuid: UUID of Document node
            evidence_name: Name of Evidence node
            relationship_type: "REFERENCES" | "SUPPORTS_CLAIM" | "CONTRADICTS_CLAIM"
            reference_type: "Exhibits" | "Mentions" | "Analyzes" | "Cites"
            confidence: 0-100 confidence score
            context: Explanation of relationship
        """
        query = f"""
        MATCH (d:Document {{uuid: $document_uuid}})
        MATCH (ev:Evidence {{name: $evidence_name}})
        CREATE (d)-[:{relationship_type} {{
            reference_type: $reference_type,
            confidence: $confidence,
            created_at: datetime($created_at)
        }}]->(ev)
        """

        params = {
            "document_uuid": document_uuid,
            "evidence_name": evidence_name,
            "reference_type": reference_type,
            "confidence": confidence,
            "created_at": self._current_timestamp().isoformat(),
        }

        if context:
            query = query.replace(
                "created_at: datetime($created_at)",
                "context: $context, created_at: datetime($created_at)"
            )
            params["context"] = context

        try:
            with self.driver.session() as session:
                session.run(query, **params)
            self.stats["relationships_created"] += 1
            logger.info(f"  [OK] {document_uuid[:8]}... -[{relationship_type}]-> {evidence_name}")
        except Exception as e:
            logger.error(f"  [FAIL] Relationship creation failed: {e}")
            self.stats["validation_errors"] += 1

    def link_document_to_party(
        self,
        document_uuid: str,
        party_name: str,
        reference_type: str = "Mentions",
        confidence: int = 75,
    ):
        """
        Create REFERENCES relationship from Document to Party.

        Args:
            document_uuid: UUID of Document node
            party_name: Name of Party node
            reference_type: "Exhibits" | "Mentions" | "Analyzes" | "Cites"
            confidence: 0-100 confidence score
        """
        query = """
        MATCH (d:Document {uuid: $document_uuid})
        MATCH (p:Party {name: $party_name})
        CREATE (d)-[:REFERENCES {
            reference_type: $reference_type,
            confidence: $confidence,
            created_at: datetime($created_at)
        }]->(p)
        """

        params = {
            "document_uuid": document_uuid,
            "party_name": party_name,
            "reference_type": reference_type,
            "confidence": confidence,
            "created_at": self._current_timestamp().isoformat(),
        }

        try:
            with self.driver.session() as session:
                session.run(query, **params)
            self.stats["relationships_created"] += 1
            logger.info(f"  [OK] {document_uuid[:8]}... -[REFERENCES]-> {party_name}")
        except Exception as e:
            logger.error(f"  [FAIL] Relationship creation failed: {e}")
            self.stats["validation_errors"] += 1

    def link_document_to_location(
        self,
        document_uuid: str,
        location_path: str,
        discovered_date: Optional[str] = None,
        still_present: bool = True,
    ):
        """
        Create LOCATED_IN relationship from Document to Location.

        Args:
            document_uuid: UUID of Document node
            location_path: Path of Location node
            discovered_date: When document was discovered (ISO datetime)
            still_present: Whether document still exists at location
        """
        query = """
        MATCH (d:Document {uuid: $document_uuid})
        MATCH (loc:Location {path: $location_path})
        CREATE (d)-[:LOCATED_IN {
            still_present: $still_present,
            created_at: datetime($created_at)
        }]->(loc)
        """

        params = {
            "document_uuid": document_uuid,
            "location_path": location_path,
            "still_present": still_present,
            "created_at": self._current_timestamp().isoformat(),
        }

        if discovered_date:
            query = query.replace(
                "created_at: datetime($created_at)",
                "discovered_date: datetime($discovered_date), created_at: datetime($created_at)"
            )
            params["discovered_date"] = discovered_date

        try:
            with self.driver.session() as session:
                session.run(query, **params)
            self.stats["relationships_created"] += 1
            logger.info(f"  [OK] {document_uuid[:8]}... -[LOCATED_IN]-> {location_path}")
        except Exception as e:
            logger.error(f"  [FAIL] Relationship creation failed: {e}")
            self.stats["validation_errors"] += 1

    def export_graph_backup(self, output_file: str):
        """
        Export full Neo4j graph to JSON for recovery.

        Args:
            output_file: Path to output JSON file
        """
        logger.info(f"[->] Exporting graph backup to {output_file}")

        backup_data = {
            "metadata": {
                "export_timestamp": datetime.utcnow().isoformat(),
                "case": "Kara Murphy vs Danny Garcia",
                "phase": "Phase 2 POC Ingestion",
                "statistics": self.stats,
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
                backup_data["nodes"].append({
                    "id": record["id"],
                    "labels": record["labels"],
                    "properties": dict(record["properties"]),
                })

            logger.info(f"  [OK] Exported {len(backup_data['nodes'])} nodes")

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
                backup_data["relationships"].append({
                    "source": record["source_id"],
                    "target": record["target_id"],
                    "type": record["type"],
                    "properties": dict(record["properties"]),
                })

            logger.info(f"  [OK] Exported {len(backup_data['relationships'])} relationships")

        # Write to file
        with open(output_file, "w") as f:
            json.dump(backup_data, f, indent=2, default=str)

        logger.info(f"[OK] Graph backup exported to {output_file}")


# ========================================================================
# POC DATA: Known Case Evidence Documents
# ========================================================================

POC_DOCUMENTS = [
    {
        "file_name": "Lane.rvt",
        "file_path": r"E:\6075 English Oaks - Naples 2\2021 Initial Permit\Lane.rvt",
        "file_type": "RVT",
        "evidence_category": "design_file",
        "created_date": "2021-02-24T00:00:00Z",
        "modified_date": "2021-02-24T00:00:00Z",
        "file_size_bytes": 97628160,  # 93.16 MB
        "forensic_findings": "Primary design file with all amenities intact. Build 20210224. Definitive baseline evidence.",
        "confidence_score": 95,
        "links": {
            "evidence": ["Lane.rvt"],
            "parties": ["Andy Garcia"],
            "location": r"E:\6075 English Oaks - Naples 2\2021 Initial Permit",
        },
    },
    {
        "file_name": "Lane.0024.rvt",
        "file_path": r"E:\6075 English Oaks - Naples 2\2022 Drawing Files\Lane.0024.rvt",
        "file_type": "RVT",
        "evidence_category": "design_file",
        "created_date": "2021-09-21T00:00:00Z",
        "modified_date": "2021-09-21T00:00:00Z",
        "file_size_bytes": 97587200,  # 93.12 MB (40KB smaller)
        "forensic_findings": "Backup variant with build 20210921 (7 months NEWER than Lane.rvt). Forensically impossible. Evidence of intentional de-scoping.",
        "confidence_score": 95,
        "links": {
            "evidence": ["Lane.0024.rvt"],
            "parties": ["Andy Garcia"],
            "location": r"E:\6075 English Oaks - Naples 2\2022 Drawing Files",
        },
    },
    {
        "file_name": "6075 Enlgish Oaks AutoCAD 092021mls.dwg",
        "file_path": r"E:\6075 English Oaks - Naples 2\2022 Drawing Files\6075 Enlgish Oaks AutoCAD 092021mls.dwg",
        "file_type": "DWG",
        "evidence_category": "design_file",
        "created_date": "2021-09-21T00:00:00Z",
        "file_size_bytes": 9990144,  # 9.53 MB
        "forensic_findings": "Primary DWG with 100% timestamp destruction (TDCREATE/TDUPDATE missing). Spoliation of evidence. TAMPER-013 triggered.",
        "confidence_score": 95,
        "links": {
            "evidence": ["6075 Enlgish Oaks AutoCAD 092021mls.dwg"],
            "parties": ["Andy Garcia", "ODA SDK"],
            "location": r"E:\6075 English Oaks - Naples 2\2022 Drawing Files",
        },
    },
    {
        "file_name": "Forensic_Analysis_Lane_RVT_Phase_A.pdf",
        "file_path": r"E:\6075 English Oaks - Naples 2\FORENSIC_REPORTS\Phase_A_Analysis.pdf",
        "file_type": "PDF",
        "evidence_category": "forensic_report",
        "created_date": "2026-01-30T00:00:00Z",
        "forensic_findings": "Comprehensive forensic analysis of Lane.rvt build version anachronism. Definitive proof of file manipulation.",
        "confidence_score": 95,
        "links": {
            "evidence": ["Lane.rvt", "Lane.0024.rvt"],
            "parties": ["Expert Witness Name"],
            "location": r"E:\6075 English Oaks - Naples 2\FORENSIC_REPORTS",
        },
    },
    {
        "file_name": "Deposition_Andy_Garcia_2025_XX_XX.pdf",
        "file_path": r"E:\6075 English Oaks - Naples 2\DEPOSITIONS\Garcia_Deposition.pdf",
        "file_type": "PDF",
        "evidence_category": "deposition",
        "created_date": "2025-06-15T00:00:00Z",
        "forensic_findings": "Deposition transcript. Key testimony regarding file modification timeline.",
        "confidence_score": 75,
        "links": {
            "evidence": ["Lane.rvt", "Lane.0024.rvt"],
            "parties": ["Andy Garcia", "Kara Murphy", "Danny Garcia"],
            "location": r"E:\6075 English Oaks - Naples 2\DEPOSITIONS",
        },
    },
]


# ========================================================================
# POC EXECUTION
# ========================================================================

def execute_poc_ingestion(pipeline: ForensicDocumentIngestionPipeline):
    """
    Execute proof of concept ingestion with 5 core documents.

    Args:
        pipeline: Initialized ForensicDocumentIngestionPipeline
    """
    logger.info("=" * 60)
    logger.info("Phase 2 POC Document Ingestion")
    logger.info("=" * 60)

    # Validate schema
    if not pipeline.validate_schema_constraints():
        logger.error("[FAIL] Schema validation failed. Aborting ingestion.")
        return

    # Ingest POC documents
    for doc_data in POC_DOCUMENTS:
        logger.info(f"\n[->] Processing: {doc_data['file_name']}")

        # Create Document node
        doc_uuid = pipeline.create_document_node(
            file_name=doc_data["file_name"],
            file_path=doc_data["file_path"],
            file_type=doc_data["file_type"],
            evidence_category=doc_data["evidence_category"],
            created_date=doc_data.get("created_date"),
            modified_date=doc_data.get("modified_date"),
            file_size_bytes=doc_data.get("file_size_bytes"),
            forensic_findings=doc_data.get("forensic_findings"),
            confidence_score=doc_data["confidence_score"],
        )

        # Create relationships
        links = doc_data.get("links", {})

        # Link to Evidence nodes
        for evidence_name in links.get("evidence", []):
            pipeline.link_document_to_evidence(
                document_uuid=doc_uuid,
                evidence_name=evidence_name,
                confidence=doc_data["confidence_score"],
                context=doc_data.get("forensic_findings"),
            )

        # Link to Party nodes
        for party_name in links.get("parties", []):
            pipeline.link_document_to_party(
                document_uuid=doc_uuid,
                party_name=party_name,
                confidence=doc_data["confidence_score"],
            )

        # Link to Location node
        location_path = links.get("location")
        if location_path:
            pipeline.link_document_to_location(
                document_uuid=doc_uuid,
                location_path=location_path,
                discovered_date=doc_data.get("created_date"),
                still_present=True,
            )

    logger.info("\n" + "=" * 60)
    logger.info("[OK] POC ingestion complete")
    logger.info("=" * 60)


def main():
    """Main execution."""
    parser = argparse.ArgumentParser(
        description="Phase 2 Forensic Document Ingestion - Proof of Concept"
    )
    parser.add_argument("--uri", default="bolt://localhost:7687", help="Neo4j URI")
    parser.add_argument("--user", default="neo4j", help="Neo4j username")
    parser.add_argument("--password", required=True, help="Neo4j password")
    parser.add_argument(
        "--export-backup",
        default="NEO4J_PHASE2_POC_BACKUP.json",
        help="Output JSON backup file",
    )
    args = parser.parse_args()

    pipeline = ForensicDocumentIngestionPipeline(args.uri, args.user, args.password)

    try:
        # Execute POC ingestion
        execute_poc_ingestion(pipeline)

        # Export backup
        pipeline.export_graph_backup(args.export_backup)

    finally:
        pipeline.close()


if __name__ == "__main__":
    main()
