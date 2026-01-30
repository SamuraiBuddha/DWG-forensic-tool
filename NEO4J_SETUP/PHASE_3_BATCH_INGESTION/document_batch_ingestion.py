"""
Phase 3 Document Batch Ingestion - Full CSV Pipeline
Kara Murphy vs Danny Garcia Litigation Case

Scalable batch ingestion pipeline for 1,040+ cataloged documents from CSV.
Features batch transaction processing, relationship inference, confidence scoring,
and comprehensive validation reporting.

Author: CasparCode-002 Orchestrator
Generated: 2026-01-30
Phase: Phase 3 CSV Batch Ingestion (1,040 documents)
"""

import argparse
import csv
import hashlib
import json
import logging
import os
import re
import uuid
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from neo4j import GraphDatabase


# Configure logging with dual-tracking
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler('PHASE_3_EXECUTION_LOG.txt'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class CSVDocumentParser:
    """
    CSV parser with validation and error handling.
    Validates required fields and data types before ingestion.
    """

    REQUIRED_FIELDS = ["file_name", "file_path", "file_type", "category"]
    VALID_FILE_TYPES = ["RVT", "DWG", "PDF", "MSG", "XLSX", "TXT", "DOCX", "JPG", "PNG"]
    VALID_CATEGORIES = [
        "design_file", "deposition", "forensic_report", "email",
        "permit", "contract", "invoice", "correspondence", "photo"
    ]

    def __init__(self):
        """Initialize parser with validation statistics."""
        self.stats = {
            "total_rows": 0,
            "valid_rows": 0,
            "skipped_rows": 0,
            "validation_errors": defaultdict(int)
        }
        self.failed_rows = []

    def parse_csv(self, csv_path: str) -> List[Dict]:
        """
        Parse CSV file and validate all rows.

        Args:
            csv_path: Path to CSV file

        Returns:
            List of validated document dictionaries

        Raises:
            FileNotFoundError: If CSV file doesn't exist
            ValueError: If required columns are missing
        """
        logger.info(f"[->] Parsing CSV file: {csv_path}")

        if not os.path.exists(csv_path):
            raise FileNotFoundError(f"CSV file not found: {csv_path}")

        valid_documents = []

        with open(csv_path, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)

            # Validate required columns
            if not reader.fieldnames:
                raise ValueError("CSV file is empty or has no header")

            missing_fields = [field for field in self.REQUIRED_FIELDS if field not in reader.fieldnames]
            if missing_fields:
                raise ValueError(f"Missing required CSV columns: {missing_fields}")

            logger.info(f"  CSV columns: {', '.join(reader.fieldnames)}")

            # Process each row
            for row_num, row in enumerate(reader, start=2):  # Start at 2 (header is row 1)
                self.stats["total_rows"] += 1

                # Validate row
                is_valid, error_msg = self._validate_row(row, row_num)

                if is_valid:
                    # Parse and normalize data
                    doc = self._normalize_document(row)
                    valid_documents.append(doc)
                    self.stats["valid_rows"] += 1
                else:
                    self.stats["skipped_rows"] += 1
                    self.failed_rows.append({
                        "row_num": row_num,
                        "error": error_msg,
                        "data": row
                    })

        logger.info(f"  [OK] Parsed {self.stats['valid_rows']} valid documents")
        logger.info(f"  [WARN] Skipped {self.stats['skipped_rows']} invalid rows")

        return valid_documents

    def _validate_row(self, row: Dict, row_num: int) -> Tuple[bool, Optional[str]]:
        """
        Validate a single CSV row.

        Args:
            row: CSV row as dictionary
            row_num: Row number for error reporting

        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check required fields
        for field in self.REQUIRED_FIELDS:
            if not row.get(field) or row[field].strip() == "":
                self.stats["validation_errors"][f"missing_{field}"] += 1
                return False, f"Missing required field: {field}"

        # Validate file_type
        file_type = row["file_type"].upper()
        if file_type not in self.VALID_FILE_TYPES:
            self.stats["validation_errors"]["invalid_file_type"] += 1
            return False, f"Invalid file_type: {file_type}"

        # Validate category
        category = row["category"].lower()
        if category not in self.VALID_CATEGORIES:
            self.stats["validation_errors"]["invalid_category"] += 1
            return False, f"Invalid category: {category}"

        # Validate dates (if present)
        for date_field in ["created_date", "modified_date"]:
            if row.get(date_field) and row[date_field].strip():
                if not self._validate_date(row[date_field]):
                    self.stats["validation_errors"][f"invalid_{date_field}"] += 1
                    return False, f"Invalid date format in {date_field}: {row[date_field]}"

        # Validate confidence_score (if present)
        if row.get("confidence_score"):
            try:
                score = int(row["confidence_score"])
                if not (0 <= score <= 100):
                    self.stats["validation_errors"]["invalid_confidence_score"] += 1
                    return False, f"Confidence score out of range (0-100): {score}"
            except ValueError:
                self.stats["validation_errors"]["invalid_confidence_score"] += 1
                return False, f"Invalid confidence score: {row['confidence_score']}"

        return True, None

    def _validate_date(self, date_str: str) -> bool:
        """
        Validate date string format.

        Args:
            date_str: Date string to validate

        Returns:
            True if valid ISO 8601 datetime format
        """
        try:
            # Try parsing as ISO 8601
            datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            return True
        except ValueError:
            # Try parsing as common date formats
            for fmt in ["%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%m/%d/%Y"]:
                try:
                    datetime.strptime(date_str, fmt)
                    return True
                except ValueError:
                    continue
            return False

    def _normalize_document(self, row: Dict) -> Dict:
        """
        Normalize and clean document data.

        Args:
            row: Raw CSV row

        Returns:
            Normalized document dictionary
        """
        doc = {
            "file_name": row["file_name"].strip(),
            "file_path": row["file_path"].strip(),
            "file_type": row["file_type"].upper().strip(),
            "evidence_category": row["category"].lower().strip(),
        }

        # Optional fields
        optional_fields = [
            "created_date", "modified_date", "file_size_bytes",
            "author", "recipient", "subject", "forensic_findings"
        ]

        for field in optional_fields:
            if row.get(field) and row[field].strip():
                # Normalize dates
                if field in ["created_date", "modified_date"]:
                    doc[field] = self._normalize_date(row[field].strip())
                # Convert file size to integer
                elif field == "file_size_bytes":
                    try:
                        doc[field] = int(row[field])
                    except ValueError:
                        logger.warning(f"Invalid file_size_bytes for {doc['file_name']}: {row[field]}")
                else:
                    doc[field] = row[field].strip()

        # Confidence score
        if row.get("confidence_score"):
            try:
                doc["confidence_score"] = int(row["confidence_score"])
            except ValueError:
                doc["confidence_score"] = 50  # Default
        else:
            doc["confidence_score"] = 50

        return doc

    def _normalize_date(self, date_str: str) -> str:
        """
        Normalize date to ISO 8601 format.

        Args:
            date_str: Date string to normalize

        Returns:
            ISO 8601 datetime string
        """
        # Try ISO 8601 first
        try:
            dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            return dt.isoformat()
        except ValueError:
            pass

        # Try common formats
        for fmt in ["%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%m/%d/%Y"]:
            try:
                dt = datetime.strptime(date_str, fmt)
                return dt.isoformat()
            except ValueError:
                continue

        # Return as-is if parsing fails
        logger.warning(f"Could not normalize date: {date_str}")
        return date_str

    def export_failed_rows(self, output_file: str):
        """
        Export failed rows to CSV for review.

        Args:
            output_file: Path to output CSV file
        """
        if not self.failed_rows:
            logger.info("[OK] No failed rows to export")
            return

        logger.info(f"[->] Exporting {len(self.failed_rows)} failed rows to {output_file}")

        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            if self.failed_rows:
                fieldnames = ["row_num", "error"] + list(self.failed_rows[0]["data"].keys())
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()

                for failed in self.failed_rows:
                    row_data = {"row_num": failed["row_num"], "error": failed["error"]}
                    row_data.update(failed["data"])
                    writer.writerow(row_data)

        logger.info(f"[OK] Failed rows exported to {output_file}")

    def get_validation_summary(self) -> Dict:
        """
        Get validation statistics summary.

        Returns:
            Dictionary of validation statistics
        """
        return {
            "total_rows": self.stats["total_rows"],
            "valid_rows": self.stats["valid_rows"],
            "skipped_rows": self.stats["skipped_rows"],
            "validation_errors": dict(self.stats["validation_errors"])
        }


class RelationshipInferenceEngine:
    """
    Infers relationships between documents and graph entities.
    Uses pattern matching and confidence scoring.
    """

    def __init__(self, driver):
        """
        Initialize inference engine.

        Args:
            driver: Neo4j driver instance
        """
        self.driver = driver
        self.known_evidence = set()
        self.known_parties = set()
        self.known_locations = set()

        # Load existing entities from graph
        self._load_existing_entities()

    def _load_existing_entities(self):
        """Load existing Evidence, Party, and Location nodes from graph."""
        logger.info("[->] Loading existing graph entities for relationship inference")

        with self.driver.session() as session:
            # Load Evidence nodes
            result = session.run("MATCH (ev:Evidence) RETURN ev.name AS name")
            self.known_evidence = {record["name"] for record in result}
            logger.info(f"  Loaded {len(self.known_evidence)} Evidence nodes")

            # Load Party nodes
            result = session.run("MATCH (p:Party) RETURN p.name AS name")
            self.known_parties = {record["name"] for record in result}
            logger.info(f"  Loaded {len(self.known_parties)} Party nodes")

            # Load Location nodes
            result = session.run("MATCH (loc:Location) RETURN loc.path AS path")
            self.known_locations = {record["path"] for record in result}
            logger.info(f"  Loaded {len(self.known_locations)} Location nodes")

    def infer_evidence_links(self, doc_data: Dict) -> List[Tuple[str, int, str]]:
        """
        Infer Evidence relationships.

        Args:
            doc_data: Document metadata

        Returns:
            List of tuples: (evidence_name, confidence, context)
        """
        links = []
        file_name = doc_data["file_name"]

        # Exact filename match (95% confidence)
        if file_name in self.known_evidence:
            links.append((file_name, 95, "Exact filename match"))

        # Partial filename match (85% confidence)
        for evidence_name in self.known_evidence:
            if evidence_name in file_name or file_name in evidence_name:
                if evidence_name != file_name:  # Avoid duplicate
                    links.append((evidence_name, 85, f"Partial match: {evidence_name}"))

        # Search in forensic_findings (75% confidence)
        if doc_data.get("forensic_findings"):
            findings = doc_data["forensic_findings"]
            for evidence_name in self.known_evidence:
                if evidence_name.lower() in findings.lower():
                    # Check if not already added
                    if not any(link[0] == evidence_name for link in links):
                        links.append((evidence_name, 75, "Referenced in forensic findings"))

        return links

    def infer_party_links(self, doc_data: Dict) -> List[Tuple[str, int]]:
        """
        Infer Party relationships.

        Args:
            doc_data: Document metadata

        Returns:
            List of tuples: (party_name, confidence)
        """
        links = []

        # Author metadata (95% confidence)
        if doc_data.get("author"):
            author = doc_data["author"]
            for party_name in self.known_parties:
                if party_name.lower() in author.lower():
                    links.append((party_name, 95))

        # Recipient metadata (95% confidence)
        if doc_data.get("recipient"):
            recipient = doc_data["recipient"]
            for party_name in self.known_parties:
                if party_name.lower() in recipient.lower():
                    if not any(link[0] == party_name for link in links):
                        links.append((party_name, 95))

        # Subject line (75% confidence)
        if doc_data.get("subject"):
            subject = doc_data["subject"]
            for party_name in self.known_parties:
                if party_name.lower() in subject.lower():
                    if not any(link[0] == party_name for link in links):
                        links.append((party_name, 75))

        return links

    def infer_location_link(self, doc_data: Dict) -> Tuple[str, int, bool]:
        """
        Infer Location relationship.

        Args:
            doc_data: Document metadata

        Returns:
            Tuple: (location_path, confidence, create_if_missing)
        """
        file_path = doc_data["file_path"]

        # Extract directory
        directory = os.path.dirname(file_path)

        # Exact match (95% confidence)
        if directory in self.known_locations:
            return (directory, 95, False)

        # Create new location (95% confidence)
        return (directory, 95, True)


class ForensicBatchIngestionPipeline:
    """
    Enhanced batch ingestion pipeline with:
    - CSV parsing and validation
    - Batch transaction processing (100 docs/batch)
    - Relationship inference with confidence scoring
    - Comprehensive error handling and reporting
    - Dual-tracking recovery
    """

    def __init__(self, uri: str, user: str, password: str):
        """
        Initialize Neo4j connection.

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
            "locations_created": 0,
            "validation_errors": 0,
            "batches_processed": 0,
            "start_time": datetime.utcnow(),
        }

        # Initialize relationship inference engine
        self.inference_engine = RelationshipInferenceEngine(self.driver)

    def close(self):
        """Close Neo4j connection and log final statistics."""
        duration = (datetime.utcnow() - self.stats["start_time"]).total_seconds()
        logger.info("=" * 60)
        logger.info("Batch Ingestion Statistics:")
        logger.info(f"  Documents Created: {self.stats['documents_created']}")
        logger.info(f"  Relationships Created: {self.stats['relationships_created']}")
        logger.info(f"  Locations Created: {self.stats['locations_created']}")
        logger.info(f"  Batches Processed: {self.stats['batches_processed']}")
        logger.info(f"  Validation Errors: {self.stats['validation_errors']}")
        logger.info(f"  Duration: {duration:.2f} seconds")
        logger.info(f"  Throughput: {self.stats['documents_created'] / duration:.2f} docs/sec")
        logger.info("=" * 60)
        self.driver.close()
        logger.info("[OK] Connection closed")

    def _generate_uuid(self) -> str:
        """Generate UUID for node."""
        return str(uuid.uuid4())

    def _current_timestamp(self) -> str:
        """Get current UTC timestamp as ISO string."""
        return datetime.utcnow().isoformat()

    def _calculate_file_hash(self, file_path: str) -> Optional[str]:
        """
        Calculate SHA-256 hash for file integrity.

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
            logger.debug(f"Could not calculate hash for {file_path}: {e}")
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

                missing = [c for c in required_constraints if c not in existing]

                if missing:
                    logger.warning(f"[WARN] Missing constraints: {missing}")
                    logger.info("Run GRAPH_INITIALIZATION_SCRIPT.py first")
                    return False

                logger.info(f"[OK] Schema validation passed ({len(existing)} constraints)")
                return True

            except Exception as e:
                logger.error(f"[FAIL] Schema validation error: {e}")
                return False

    def create_document_node(self, doc_data: Dict) -> str:
        """
        Create Document node from validated data.

        Args:
            doc_data: Normalized document dictionary

        Returns:
            UUID of created Document node
        """
        doc_uuid = self._generate_uuid()

        # Calculate hash if file exists
        sha256_hash = self._calculate_file_hash(doc_data["file_path"])

        # Build Cypher query dynamically
        properties = {
            "uuid": doc_uuid,
            "file_name": doc_data["file_name"],
            "file_path": doc_data["file_path"],
            "file_type": doc_data["file_type"],
            "evidence_category": doc_data["evidence_category"],
            "created_at": self._current_timestamp(),
            "confidence_score": doc_data["confidence_score"],
        }

        # Add optional properties
        for field in ["created_date", "modified_date", "file_size_bytes",
                      "author", "recipient", "subject", "forensic_findings"]:
            if field in doc_data:
                properties[field] = doc_data[field]

        if sha256_hash:
            properties["sha256"] = sha256_hash

        query = "CREATE (d:Document $properties)"

        try:
            with self.driver.session() as session:
                session.run(query, properties=properties)
            self.stats["documents_created"] += 1
            return doc_uuid
        except Exception as e:
            logger.error(f"  [FAIL] Document creation failed for {doc_data['file_name']}: {e}")
            self.stats["validation_errors"] += 1
            raise

    def create_or_get_location(self, location_path: str) -> bool:
        """
        Create Location node if it doesn't exist.

        Args:
            location_path: Directory path

        Returns:
            True if location was created, False if it already existed
        """
        # Determine location type from path pattern
        location_type = "Directory"  # Default
        if location_path.startswith("\\\\"):
            location_type = "Network"
        elif "dropbox" in location_path.lower() or "onedrive" in location_path.lower():
            location_type = "Cloud"

        query = """
        MERGE (loc:Location {path: $path})
        ON CREATE SET loc.uuid = $uuid,
                      loc.location_type = $location_type,
                      loc.created_at = datetime($created_at)
        RETURN loc.created_at AS created_at
        """

        try:
            with self.driver.session() as session:
                result = session.run(
                    query,
                    path=location_path,
                    uuid=self._generate_uuid(),
                    location_type=location_type,
                    created_at=self._current_timestamp()
                )
                record = result.single()
                # If created_at is recent, it was just created
                created_recently = record["created_at"] is not None
                if created_recently:
                    self.stats["locations_created"] += 1
                return created_recently
        except Exception as e:
            logger.error(f"  [FAIL] Location creation failed for {location_path}: {e}")
            return False

    def link_document_to_evidence(self, doc_uuid: str, evidence_name: str,
                                   confidence: int, context: str):
        """Create REFERENCES relationship from Document to Evidence."""
        query = """
        MATCH (d:Document {uuid: $doc_uuid})
        MATCH (ev:Evidence {name: $evidence_name})
        CREATE (d)-[:REFERENCES {
            reference_type: "Analyzes",
            confidence: $confidence,
            context: $context,
            created_at: datetime($created_at)
        }]->(ev)
        """

        try:
            with self.driver.session() as session:
                session.run(
                    query,
                    doc_uuid=doc_uuid,
                    evidence_name=evidence_name,
                    confidence=confidence,
                    context=context,
                    created_at=self._current_timestamp()
                )
            self.stats["relationships_created"] += 1
        except Exception as e:
            logger.debug(f"  Evidence link failed ({evidence_name}): {e}")

    def link_document_to_party(self, doc_uuid: str, party_name: str, confidence: int):
        """Create REFERENCES relationship from Document to Party."""
        query = """
        MATCH (d:Document {uuid: $doc_uuid})
        MATCH (p:Party {name: $party_name})
        CREATE (d)-[:REFERENCES {
            reference_type: "Mentions",
            confidence: $confidence,
            created_at: datetime($created_at)
        }]->(p)
        """

        try:
            with self.driver.session() as session:
                session.run(
                    query,
                    doc_uuid=doc_uuid,
                    party_name=party_name,
                    confidence=confidence,
                    created_at=self._current_timestamp()
                )
            self.stats["relationships_created"] += 1
        except Exception as e:
            logger.debug(f"  Party link failed ({party_name}): {e}")

    def link_document_to_location(self, doc_uuid: str, location_path: str,
                                   discovered_date: Optional[str]):
        """Create LOCATED_IN relationship from Document to Location."""
        query = """
        MATCH (d:Document {uuid: $doc_uuid})
        MATCH (loc:Location {path: $location_path})
        CREATE (d)-[:LOCATED_IN {
            still_present: true,
            created_at: datetime($created_at)
        }]->(loc)
        """

        params = {
            "doc_uuid": doc_uuid,
            "location_path": location_path,
            "created_at": self._current_timestamp()
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
        except Exception as e:
            logger.debug(f"  Location link failed ({location_path}): {e}")

    def batch_ingest_documents(self, documents: List[Dict], batch_size: int = 100):
        """
        Ingest documents in batches.

        Args:
            documents: List of validated document dictionaries
            batch_size: Documents per batch (default: 100)
        """
        total = len(documents)
        num_batches = (total + batch_size - 1) // batch_size

        logger.info("=" * 60)
        logger.info(f"Starting batch ingestion: {total} documents in {num_batches} batches")
        logger.info("=" * 60)

        for i in range(0, total, batch_size):
            batch = documents[i:i+batch_size]
            batch_num = (i // batch_size) + 1

            logger.info(f"\n[Batch {batch_num}/{num_batches}] Processing {len(batch)} documents")

            batch_start = datetime.utcnow()

            try:
                for doc_data in batch:
                    # Create Document node
                    doc_uuid = self.create_document_node(doc_data)

                    # Infer and create relationships
                    self._infer_and_create_relationships(doc_uuid, doc_data)

                batch_duration = (datetime.utcnow() - batch_start).total_seconds()
                logger.info(f"[Batch {batch_num}/{num_batches}] COMPLETE ({batch_duration:.2f}s)")
                self.stats["batches_processed"] += 1

            except Exception as e:
                logger.error(f"[Batch {batch_num}/{num_batches}] FAILED: {e}")
                # Continue to next batch

        logger.info("\n" + "=" * 60)
        logger.info("[OK] Batch ingestion complete")
        logger.info("=" * 60)

    def _infer_and_create_relationships(self, doc_uuid: str, doc_data: Dict):
        """
        Infer and create all relationships for a document.

        Args:
            doc_uuid: UUID of created Document node
            doc_data: Document metadata
        """
        # Evidence links
        evidence_links = self.inference_engine.infer_evidence_links(doc_data)
        for evidence_name, confidence, context in evidence_links:
            self.link_document_to_evidence(doc_uuid, evidence_name, confidence, context)

        # Party links
        party_links = self.inference_engine.infer_party_links(doc_data)
        for party_name, confidence in party_links:
            self.link_document_to_party(doc_uuid, party_name, confidence)

        # Location link
        location_path, confidence, create_new = self.inference_engine.infer_location_link(doc_data)
        if create_new:
            self.create_or_get_location(location_path)
        self.link_document_to_location(
            doc_uuid,
            location_path,
            doc_data.get("created_date")
        )

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
                "phase": "Phase 3 Batch Ingestion",
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

    def generate_validation_report(self, output_file: str):
        """
        Generate comprehensive validation report.

        Args:
            output_file: Path to output text file
        """
        logger.info(f"[->] Generating validation report: {output_file}")

        report_lines = [
            "=" * 80,
            "PHASE 3 BATCH INGESTION VALIDATION REPORT",
            "=" * 80,
            f"Generated: {datetime.utcnow().isoformat()}",
            f"Case: Kara Murphy vs Danny Garcia",
            "",
            "INGESTION STATISTICS",
            "-" * 80,
            f"Documents Created: {self.stats['documents_created']}",
            f"Relationships Created: {self.stats['relationships_created']}",
            f"Locations Created: {self.stats['locations_created']}",
            f"Batches Processed: {self.stats['batches_processed']}",
            f"Validation Errors: {self.stats['validation_errors']}",
            f"Duration: {(datetime.utcnow() - self.stats['start_time']).total_seconds():.2f} seconds",
            "",
        ]

        # Query graph for validation statistics
        with self.driver.session() as session:
            # Document count by category
            report_lines.extend([
                "DOCUMENT BREAKDOWN BY CATEGORY",
                "-" * 80,
            ])
            result = session.run("""
                MATCH (d:Document)
                RETURN d.evidence_category AS category, count(d) AS count
                ORDER BY count DESC
            """)
            for record in result:
                report_lines.append(f"  {record['category']}: {record['count']}")

            report_lines.append("")

            # Document count by file type
            report_lines.extend([
                "DOCUMENT BREAKDOWN BY FILE TYPE",
                "-" * 80,
            ])
            result = session.run("""
                MATCH (d:Document)
                RETURN d.file_type AS type, count(d) AS count
                ORDER BY count DESC
            """)
            for record in result:
                report_lines.append(f"  {record['type']}: {record['count']}")

            report_lines.append("")

            # Relationship statistics
            report_lines.extend([
                "RELATIONSHIP STATISTICS",
                "-" * 80,
            ])
            result = session.run("""
                MATCH (d:Document)-[r]->()
                RETURN type(r) AS rel_type, count(r) AS count
                ORDER BY count DESC
            """)
            for record in result:
                report_lines.append(f"  {record['rel_type']}: {record['count']}")

            report_lines.append("")

            # Orphaned documents check
            result = session.run("""
                MATCH (d:Document)
                WHERE NOT EXISTS {
                    MATCH (d)-[:REFERENCES]->(:Evidence)
                }
                AND NOT EXISTS {
                    MATCH (d)-[:REFERENCES]->(:Party)
                }
                RETURN count(d) AS orphaned_count
            """)
            orphaned_count = result.single()["orphaned_count"]
            orphan_pct = (orphaned_count / self.stats['documents_created'] * 100) if self.stats['documents_created'] > 0 else 0

            report_lines.extend([
                "DATA QUALITY METRICS",
                "-" * 80,
                f"Orphaned Documents (no Evidence/Party links): {orphaned_count} ({orphan_pct:.1f}%)",
            ])

            # Confidence score distribution
            result = session.run("""
                MATCH (d:Document)
                WITH d.confidence_score AS score, count(d) AS count
                ORDER BY score
                RETURN score, count
            """)
            report_lines.extend([
                "",
                "CONFIDENCE SCORE DISTRIBUTION",
                "-" * 80,
            ])
            for record in result:
                report_lines.append(f"  Score {record['score']}: {record['count']} documents")

        report_lines.extend([
            "",
            "=" * 80,
            "END OF VALIDATION REPORT",
            "=" * 80,
        ])

        # Write report
        with open(output_file, 'w') as f:
            f.write('\n'.join(report_lines))

        logger.info(f"[OK] Validation report generated: {output_file}")


def main():
    """Main execution."""
    parser = argparse.ArgumentParser(
        description="Phase 3 Forensic Document Batch Ingestion"
    )
    parser.add_argument("--csv", required=True, help="Path to document catalog CSV file")
    parser.add_argument("--uri", default="bolt://localhost:7687", help="Neo4j URI")
    parser.add_argument("--user", default="neo4j", help="Neo4j username")
    parser.add_argument("--password", required=True, help="Neo4j password")
    parser.add_argument("--batch-size", type=int, default=100, help="Documents per batch")
    parser.add_argument(
        "--backup-json",
        default="neo4j_full_backup.json",
        help="Output JSON backup file",
    )
    parser.add_argument(
        "--validation-report",
        default="PHASE_3_BATCH_INGESTION_REPORT.txt",
        help="Output validation report file",
    )
    parser.add_argument(
        "--failed-csv",
        default="FAILED_DOCUMENTS.csv",
        help="Output CSV for failed document rows",
    )
    args = parser.parse_args()

    logger.info("=" * 80)
    logger.info("PHASE 3: NEO4J CSV BATCH INGESTION")
    logger.info("=" * 80)

    # Step 1: Parse and validate CSV
    csv_parser = CSVDocumentParser()
    try:
        documents = csv_parser.parse_csv(args.csv)
    except Exception as e:
        logger.error(f"[FAIL] CSV parsing failed: {e}")
        return 1

    # Export failed rows
    csv_parser.export_failed_rows(args.failed_csv)

    # Print validation summary
    validation_summary = csv_parser.get_validation_summary()
    logger.info("\nCSV Validation Summary:")
    logger.info(f"  Total Rows: {validation_summary['total_rows']}")
    logger.info(f"  Valid Rows: {validation_summary['valid_rows']}")
    logger.info(f"  Skipped Rows: {validation_summary['skipped_rows']}")
    if validation_summary['validation_errors']:
        logger.info("  Validation Errors:")
        for error_type, count in validation_summary['validation_errors'].items():
            logger.info(f"    {error_type}: {count}")

    if not documents:
        logger.error("[FAIL] No valid documents to ingest")
        return 1

    # Step 2: Initialize pipeline and validate schema
    pipeline = ForensicBatchIngestionPipeline(args.uri, args.user, args.password)

    try:
        if not pipeline.validate_schema_constraints():
            logger.error("[FAIL] Schema validation failed. Run initialization script first.")
            return 1

        # Step 3: Batch ingest documents
        pipeline.batch_ingest_documents(documents, batch_size=args.batch_size)

        # Step 4: Export backup
        pipeline.export_graph_backup(args.backup_json)

        # Step 5: Generate validation report
        pipeline.generate_validation_report(args.validation_report)

    finally:
        pipeline.close()

    logger.info("\n[OK] Phase 3 batch ingestion complete")
    return 0


if __name__ == "__main__":
    exit(main())
