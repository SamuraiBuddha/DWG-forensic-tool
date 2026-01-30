"""
Phase 3: CSV Batch Document Ingestion for Neo4j
Kara Murphy vs Danny Garcia Litigation Case

Scales Phase 2 POC to ingest all 1,040 cataloged documents from network CSV
into Neo4j knowledge graph with full entity extraction, relationship inference,
and confidence scoring.

Author: CasparCode-002 Orchestrator
Generated: 2026-01-30
Phase: Phase 3 Batch Ingestion (1,040 documents)
"""

import argparse
import csv
import hashlib
import json
import logging
import os
import re
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from neo4j import GraphDatabase
    from neo4j.exceptions import Neo4jError
except ImportError:
    print("[FAIL] neo4j package not installed. Run: pip install neo4j")
    sys.exit(1)


# ============================================================================
# CONFIGURATION
# ============================================================================

# Default CSV path (network location)
DEFAULT_CSV_PATH = (
    r"\\adam\DataPool\Projects\2026-001_Kara_Murphy_vs_Danny_Garcia"
    r"\DOCUMENT_CATALOG\6075_ENGLISH_OAKS_DOCUMENTS.csv"
)

# Batch processing configuration
BATCH_SIZE = 100  # Documents per transaction batch
MAX_RETRIES = 3   # Retry count for failed batches

# Known parties for relationship inference
KNOWN_PARTIES = {
    "Kara Murphy": {"role": "Plaintiff", "entity_type": "Person"},
    "Danny Garcia": {"role": "Defendant", "entity_type": "Person"},
    "Andy Garcia": {"role": "Architect", "entity_type": "Person"},
    "Caron": {"role": "Client", "entity_type": "Person"},
    "Beauchamp": {"role": "Client", "entity_type": "Person"},
    "Gansari": {"role": "Witness", "entity_type": "Person"},
    "ODA SDK": {"role": "Software", "entity_type": "Software"},
    "AutoCAD": {"role": "Software", "entity_type": "Software"},
    "BricsCAD": {"role": "Software", "entity_type": "Software"},
    "NanoCAD": {"role": "Software", "entity_type": "Software"},
    "JPEC": {"role": "Law Firm", "entity_type": "Organization"},
}

# Category to evidence type mapping
CATEGORY_TO_EVIDENCE_TYPE = {
    "Correspondence": "correspondence",
    "Design Files (DWG/CAD)": "design_file",
    "Deposition/Transcript": "deposition",
    "Other": "other",
    "Legal Documents": "legal",
    "Forensic Reports": "forensic_report",
    "Emails": "email",
    "Contracts": "contract",
    "Permits": "permit",
}

# Extension to file type mapping
EXTENSION_TO_FILE_TYPE = {
    "dwg": "DWG",
    "rvt": "RVT",
    "pdf": "PDF",
    "docx": "DOCX",
    "xlsx": "XLSX",
    "msg": "MSG",
    "txt": "TXT",
    "md": "MD",
    "zip": "ZIP",
    "rpctemp3": "TEMP",
    "eml": "EML",
    "jpg": "IMAGE",
    "jpeg": "IMAGE",
    "png": "IMAGE",
    "tiff": "IMAGE",
    "bmp": "IMAGE",
}


# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

def setup_logging(log_file: str) -> logging.Logger:
    """Configure logging with file and console output."""
    logger = logging.getLogger("Phase3BatchIngestion")
    logger.setLevel(logging.DEBUG)

    # Clear existing handlers
    logger.handlers.clear()

    # File handler (detailed)
    file_handler = logging.FileHandler(log_file, mode="w", encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_format = logging.Formatter(
        "[%(asctime)s] [%(levelname)-8s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S"
    )
    file_handler.setFormatter(file_format)
    logger.addHandler(file_handler)

    # Console handler (info and above)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_format = logging.Formatter("[%(levelname)s] %(message)s")
    console_handler.setFormatter(console_format)
    logger.addHandler(console_handler)

    return logger


# ============================================================================
# ENTITY EXTRACTION
# ============================================================================

class EntityExtractor:
    """
    Extracts entities (parties, locations, keywords) from document metadata
    with confidence scoring for relationship inference.
    """

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self._compiled_party_patterns: Dict[str, re.Pattern] = {}
        for party_name in KNOWN_PARTIES:
            # Create case-insensitive patterns
            pattern = re.compile(re.escape(party_name), re.IGNORECASE)
            self._compiled_party_patterns[party_name] = pattern

    def extract_parties_from_text(
        self, text: str, confidence_base: int = 75
    ) -> List[Dict[str, Any]]:
        """
        Extract party references from text with confidence scoring.

        Args:
            text: Text to search for party references
            confidence_base: Base confidence level (0-100)

        Returns:
            List of dicts with party_name, confidence, and match_context
        """
        parties_found = []
        for party_name, pattern in self._compiled_party_patterns.items():
            matches = pattern.findall(text)
            if matches:
                # Higher confidence for multiple matches
                confidence = min(confidence_base + (len(matches) * 5), 95)
                parties_found.append({
                    "party_name": party_name,
                    "confidence": confidence,
                    "match_count": len(matches),
                    "context": text[:100] if len(text) > 100 else text,
                })
        return parties_found

    def extract_location_from_path(self, file_path: str) -> Dict[str, Any]:
        """
        Extract location information from file path.

        Args:
            file_path: Full file path

        Returns:
            Dict with location details and confidence
        """
        path_parts = Path(file_path).parts
        folder_path = str(Path(file_path).parent)

        # Detect location type
        if file_path.startswith("\\\\") or file_path.startswith("//"):
            location_type = "Network"
        elif "cloud" in file_path.lower() or "dropbox" in file_path.lower():
            location_type = "Cloud"
        else:
            location_type = "Directory"

        # Extract project reference from path
        project_ref = None
        for part in path_parts:
            if "6075" in part or "English Oaks" in part:
                project_ref = "6075 English Oaks"
                break

        return {
            "path": folder_path,
            "location_type": location_type,
            "project_reference": project_ref,
            "depth": len(path_parts),
            "confidence": 95,  # High confidence for direct path extraction
        }

    def extract_keywords_from_subject(
        self, subject: str, category: str
    ) -> List[str]:
        """
        Extract relevant keywords from subject and category.

        Args:
            subject: Document subject text
            category: Document category

        Returns:
            List of extracted keywords
        """
        keywords = set()

        # Add category as keyword
        if category:
            keywords.add(category.lower().replace(" ", "_"))

        # Extract keywords from subject
        if subject:
            # Common litigation-relevant terms
            litigation_terms = [
                "deposition", "transcript", "exhibit", "evidence",
                "forensic", "analysis", "report", "contract",
                "agreement", "letter", "correspondence", "drawing",
                "permit", "approval", "email", "timeline",
            ]
            subject_lower = subject.lower()
            for term in litigation_terms:
                if term in subject_lower:
                    keywords.add(term)

        return list(keywords)

    def infer_evidence_category(
        self, category: str, extension: str, subject: str
    ) -> Tuple[str, int]:
        """
        Infer evidence category with confidence scoring.

        Args:
            category: CSV category field
            extension: File extension
            subject: Document subject

        Returns:
            Tuple of (evidence_category, confidence)
        """
        # Primary: Use CSV category
        if category in CATEGORY_TO_EVIDENCE_TYPE:
            return CATEGORY_TO_EVIDENCE_TYPE[category], 95

        # Secondary: Infer from extension
        ext_lower = extension.lower().strip(".")
        if ext_lower in ["dwg", "rvt", "dxf"]:
            return "design_file", 90
        elif ext_lower == "pdf":
            # Check subject for clues
            if "deposition" in subject.lower() or "transcript" in subject.lower():
                return "deposition", 85
            elif "forensic" in subject.lower() or "analysis" in subject.lower():
                return "forensic_report", 85
            return "document", 70
        elif ext_lower in ["msg", "eml"]:
            return "email", 90
        elif ext_lower in ["docx", "doc"]:
            if "engagement" in subject.lower() or "contract" in subject.lower():
                return "contract", 80
            return "correspondence", 70

        # Fallback
        return "other", 50


# ============================================================================
# BATCH INGESTION PIPELINE
# ============================================================================

class BatchDocumentIngestionPipeline:
    """
    Batch document ingestion pipeline for Neo4j with:
    - Transaction batching (100 documents per batch)
    - Error handling and retry logic
    - Progress tracking and statistics
    - Relationship inference with confidence scoring
    - Full graph backup export
    """

    def __init__(self, uri: str, user: str, password: str, logger: logging.Logger):
        """
        Initialize Neo4j connection.

        Args:
            uri: Neo4j connection URI
            user: Username
            password: Password
            logger: Logger instance
        """
        self.logger = logger
        self.logger.info(f"Initializing connection to Neo4j at {uri}")

        try:
            self.driver = GraphDatabase.driver(uri, auth=(user, password))
            # Test connection
            with self.driver.session() as session:
                result = session.run("RETURN 1 AS test")
                result.single()
            self.logger.info("[OK] Connected to Neo4j successfully")
        except Exception as e:
            self.logger.error(f"[FAIL] Neo4j connection failed: {e}")
            raise

        self.entity_extractor = EntityExtractor(logger)
        self.stats = {
            "start_time": datetime.utcnow(),
            "documents_processed": 0,
            "documents_created": 0,
            "documents_skipped": 0,
            "relationships_created": 0,
            "parties_created": 0,
            "locations_created": 0,
            "batches_completed": 0,
            "batches_failed": 0,
            "validation_errors": 0,
            "hash_calculations": 0,
        }
        self._created_parties: Set[str] = set()
        self._created_locations: Set[str] = set()

    def close(self) -> Dict[str, Any]:
        """Close connection and return final statistics."""
        duration = (datetime.utcnow() - self.stats["start_time"]).total_seconds()
        self.stats["duration_seconds"] = duration
        self.stats["end_time"] = datetime.utcnow().isoformat()
        self.stats["start_time"] = self.stats["start_time"].isoformat()

        self.logger.info("=" * 70)
        self.logger.info("INGESTION COMPLETE - Final Statistics")
        self.logger.info("=" * 70)
        self.logger.info(f"  Documents Processed: {self.stats['documents_processed']}")
        self.logger.info(f"  Documents Created:   {self.stats['documents_created']}")
        self.logger.info(f"  Documents Skipped:   {self.stats['documents_skipped']}")
        self.logger.info(f"  Relationships:       {self.stats['relationships_created']}")
        self.logger.info(f"  Parties Created:     {self.stats['parties_created']}")
        self.logger.info(f"  Locations Created:   {self.stats['locations_created']}")
        self.logger.info(f"  Batches Completed:   {self.stats['batches_completed']}")
        self.logger.info(f"  Batches Failed:      {self.stats['batches_failed']}")
        self.logger.info(f"  Validation Errors:   {self.stats['validation_errors']}")
        self.logger.info(f"  Duration:            {duration:.2f} seconds")
        self.logger.info("=" * 70)

        self.driver.close()
        self.logger.info("[OK] Connection closed")
        return self.stats

    def _generate_uuid(self) -> str:
        """Generate UUID for node."""
        return str(uuid.uuid4())

    def _calculate_file_hash(self, file_path: str) -> Optional[str]:
        """Calculate SHA-256 hash for file integrity."""
        try:
            # Convert Windows path to accessible format
            accessible_path = file_path.replace("\\", "/")
            if accessible_path.startswith("//"):
                pass  # Already Unix-style UNC
            elif accessible_path.startswith("/"):
                accessible_path = "/" + accessible_path

            if os.path.exists(accessible_path):
                sha256_hash = hashlib.sha256()
                with open(accessible_path, "rb") as f:
                    for byte_block in iter(lambda: f.read(65536), b""):
                        sha256_hash.update(byte_block)
                self.stats["hash_calculations"] += 1
                return sha256_hash.hexdigest()
        except Exception as e:
            self.logger.debug(f"Hash calculation failed for {file_path}: {e}")
        return None

    def validate_schema(self) -> bool:
        """Validate Neo4j schema constraints exist."""
        self.logger.info("[->] Validating Neo4j schema constraints")

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
                    self.logger.warning(f"[WARN] Missing constraints: {missing}")
                    self.logger.info("Run schema initialization before ingestion")
                    return False

                self.logger.info(f"[OK] Schema validation passed ({len(existing)} constraints)")
                return True
            except Exception as e:
                self.logger.error(f"[FAIL] Schema validation error: {e}")
                return False

    def ensure_party_exists(self, party_name: str) -> bool:
        """Ensure Party node exists, creating if necessary."""
        if party_name in self._created_parties:
            return True

        party_info = KNOWN_PARTIES.get(party_name, {
            "role": "Unknown",
            "entity_type": "Person"
        })

        query = """
        MERGE (p:Party {name: $name})
        ON CREATE SET
            p.uuid = $uuid,
            p.role = $role,
            p.entity_type = $entity_type,
            p.created_at = datetime($created_at)
        RETURN p.uuid AS uuid
        """

        try:
            with self.driver.session() as session:
                session.run(
                    query,
                    name=party_name,
                    uuid=self._generate_uuid(),
                    role=party_info["role"],
                    entity_type=party_info["entity_type"],
                    created_at=datetime.utcnow().isoformat(),
                )
            self._created_parties.add(party_name)
            self.stats["parties_created"] += 1
            self.logger.debug(f"[OK] Party node ensured: {party_name}")
            return True
        except Exception as e:
            self.logger.error(f"[FAIL] Party creation failed for {party_name}: {e}")
            return False

    def ensure_location_exists(self, location_path: str, location_type: str) -> bool:
        """Ensure Location node exists, creating if necessary."""
        if location_path in self._created_locations:
            return True

        query = """
        MERGE (l:Location {path: $path})
        ON CREATE SET
            l.uuid = $uuid,
            l.location_type = $location_type,
            l.created_at = datetime($created_at)
        RETURN l.uuid AS uuid
        """

        try:
            with self.driver.session() as session:
                session.run(
                    query,
                    path=location_path,
                    uuid=self._generate_uuid(),
                    location_type=location_type,
                    created_at=datetime.utcnow().isoformat(),
                )
            self._created_locations.add(location_path)
            self.stats["locations_created"] += 1
            self.logger.debug(f"[OK] Location node ensured: {location_path[:50]}...")
            return True
        except Exception as e:
            self.logger.error(f"[FAIL] Location creation failed: {e}")
            return False

    def _process_single_document(
        self, session, doc: Dict[str, Any]
    ) -> Optional[str]:
        """
        Process a single document within a transaction.

        Args:
            session: Neo4j session
            doc: Document metadata dict

        Returns:
            Document UUID if created, None if skipped/failed
        """
        file_path = doc.get("full_path", "")
        file_name = doc.get("file_name", "")
        extension = doc.get("extension", "")
        category = doc.get("category", "")
        subject = doc.get("subject", "")

        # Validate required fields
        if not file_path or not file_name:
            self.logger.warning(f"[SKIP] Missing required fields: {file_name}")
            self.stats["documents_skipped"] += 1
            return None

        # Extract entities
        evidence_category, category_confidence = (
            self.entity_extractor.infer_evidence_category(category, extension, subject)
        )
        file_type = EXTENSION_TO_FILE_TYPE.get(
            extension.lower().strip("."), "OTHER"
        )
        location_info = self.entity_extractor.extract_location_from_path(file_path)
        parties = self.entity_extractor.extract_parties_from_text(
            f"{file_path} {file_name} {subject}"
        )
        keywords = self.entity_extractor.extract_keywords_from_subject(
            subject, category
        )

        # Parse dates
        created_date = doc.get("created_date")
        modified_date = doc.get("modified_date")

        # Generate UUID
        doc_uuid = self._generate_uuid()

        # Calculate hash if file accessible
        sha256 = self._calculate_file_hash(file_path)

        # File size
        try:
            file_size = int(doc.get("file_size_bytes", 0))
        except (ValueError, TypeError):
            file_size = 0

        # Build document node query
        query = """
        CREATE (d:Document {
            uuid: $uuid,
            file_name: $file_name,
            file_path: $file_path,
            file_type: $file_type,
            extension: $extension,
            evidence_category: $evidence_category,
            category: $category,
            subject: $subject,
            file_size_bytes: $file_size_bytes,
            confidence_score: $confidence_score,
            keywords: $keywords,
            created_at: datetime($created_at)
        })
        """

        params: Dict[str, Any] = {
            "uuid": doc_uuid,
            "file_name": file_name,
            "file_path": file_path,
            "file_type": file_type,
            "extension": extension,
            "evidence_category": evidence_category,
            "category": category,
            "subject": subject,
            "file_size_bytes": file_size,
            "confidence_score": category_confidence,
            "keywords": keywords,
            "created_at": datetime.utcnow().isoformat(),
        }

        # Add optional properties
        if created_date:
            query = query.replace(
                "created_at: datetime($created_at)",
                "created_date: $created_date, created_at: datetime($created_at)"
            )
            params["created_date"] = created_date

        if modified_date:
            query = query.replace(
                "created_at: datetime($created_at)",
                "modified_date: $modified_date, created_at: datetime($created_at)"
            )
            params["modified_date"] = modified_date

        if sha256:
            query = query.replace(
                "created_at: datetime($created_at)",
                "sha256: $sha256, created_at: datetime($created_at)"
            )
            params["sha256"] = sha256

        # Create document node
        session.run(query, **params)
        self.stats["documents_created"] += 1

        # Create Location relationship
        self.ensure_location_exists(
            location_info["path"],
            location_info["location_type"]
        )
        location_query = """
        MATCH (d:Document {uuid: $doc_uuid})
        MATCH (l:Location {path: $location_path})
        CREATE (d)-[:LOCATED_IN {
            confidence: $confidence,
            created_at: datetime($created_at)
        }]->(l)
        """
        session.run(
            location_query,
            doc_uuid=doc_uuid,
            location_path=location_info["path"],
            confidence=location_info["confidence"],
            created_at=datetime.utcnow().isoformat(),
        )
        self.stats["relationships_created"] += 1

        # Create Party relationships
        for party_info in parties:
            party_name = party_info["party_name"]
            self.ensure_party_exists(party_name)
            party_query = """
            MATCH (d:Document {uuid: $doc_uuid})
            MATCH (p:Party {name: $party_name})
            CREATE (d)-[:REFERENCES {
                reference_type: 'Mentions',
                confidence: $confidence,
                match_count: $match_count,
                created_at: datetime($created_at)
            }]->(p)
            """
            session.run(
                party_query,
                doc_uuid=doc_uuid,
                party_name=party_name,
                confidence=party_info["confidence"],
                match_count=party_info["match_count"],
                created_at=datetime.utcnow().isoformat(),
            )
            self.stats["relationships_created"] += 1

        return doc_uuid

    def process_batch(
        self, documents: List[Dict[str, Any]], batch_num: int
    ) -> Tuple[int, int]:
        """
        Process a batch of documents in a single transaction.

        Args:
            documents: List of document dicts
            batch_num: Batch number for logging

        Returns:
            Tuple of (success_count, error_count)
        """
        success_count = 0
        error_count = 0

        self.logger.info(
            f"[->] Processing batch {batch_num} ({len(documents)} documents)"
        )

        def process_tx(tx):
            nonlocal success_count, error_count
            for doc in documents:
                try:
                    doc_uuid = self._process_single_document(tx, doc)
                    if doc_uuid:
                        success_count += 1
                    else:
                        error_count += 1
                except Exception as e:
                    self.logger.error(
                        f"[FAIL] Document processing error: {doc.get('file_name', 'unknown')}: {e}"
                    )
                    error_count += 1
                    self.stats["validation_errors"] += 1

        retries = 0
        while retries < MAX_RETRIES:
            try:
                with self.driver.session() as session:
                    session.execute_write(process_tx)
                self.stats["batches_completed"] += 1
                self.logger.info(
                    f"    [OK] Batch {batch_num} complete: {success_count} success, {error_count} errors"
                )
                return success_count, error_count
            except Neo4jError as e:
                retries += 1
                self.logger.warning(
                    f"[WARN] Batch {batch_num} failed (attempt {retries}/{MAX_RETRIES}): {e}"
                )
                if retries >= MAX_RETRIES:
                    self.stats["batches_failed"] += 1
                    self.logger.error(f"[FAIL] Batch {batch_num} failed after {MAX_RETRIES} retries")
                    return 0, len(documents)

        return success_count, error_count

    def ingest_from_csv(self, csv_path: str) -> Dict[str, Any]:
        """
        Ingest all documents from CSV file.

        Args:
            csv_path: Path to CSV file

        Returns:
            Ingestion statistics
        """
        self.logger.info("=" * 70)
        self.logger.info("PHASE 3: CSV BATCH DOCUMENT INGESTION")
        self.logger.info(f"Source: {csv_path}")
        self.logger.info("=" * 70)

        # Read CSV
        documents = []
        try:
            with open(csv_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                documents = list(reader)
            self.logger.info(f"[OK] Loaded {len(documents)} documents from CSV")
        except Exception as e:
            self.logger.error(f"[FAIL] CSV read error: {e}")
            return self.stats

        # Process in batches
        total_batches = (len(documents) + BATCH_SIZE - 1) // BATCH_SIZE
        self.logger.info(f"[->] Processing {total_batches} batches of {BATCH_SIZE} documents")

        for i in range(0, len(documents), BATCH_SIZE):
            batch_num = (i // BATCH_SIZE) + 1
            batch_docs = documents[i:i + BATCH_SIZE]
            self.stats["documents_processed"] += len(batch_docs)
            self.process_batch(batch_docs, batch_num)

            # Progress update every 5 batches
            if batch_num % 5 == 0:
                pct = (batch_num / total_batches) * 100
                self.logger.info(f"    Progress: {pct:.1f}% ({batch_num}/{total_batches} batches)")

        return self.stats

    def export_graph_backup(self, output_file: str):
        """Export full graph to JSON backup."""
        self.logger.info(f"[->] Exporting graph backup to {output_file}")

        backup_data = {
            "metadata": {
                "export_timestamp": datetime.utcnow().isoformat(),
                "case": "Kara Murphy vs Danny Garcia",
                "phase": "Phase 3 Batch Ingestion",
                "statistics": dict(self.stats),
            },
            "nodes": [],
            "relationships": [],
        }

        with self.driver.session() as session:
            # Export all nodes
            result = session.run("""
                MATCH (n)
                RETURN elementId(n) AS id, labels(n) AS labels, properties(n) AS properties
            """)
            for record in result:
                props = dict(record["properties"])
                # Convert datetime objects to strings
                for key, value in props.items():
                    if hasattr(value, "isoformat"):
                        props[key] = value.isoformat()
                backup_data["nodes"].append({
                    "id": record["id"],
                    "labels": record["labels"],
                    "properties": props,
                })
            self.logger.info(f"    [OK] Exported {len(backup_data['nodes'])} nodes")

            # Export all relationships
            result = session.run("""
                MATCH (s)-[r]->(t)
                RETURN elementId(s) AS source_id,
                       elementId(t) AS target_id,
                       type(r) AS type,
                       properties(r) AS properties
            """)
            for record in result:
                props = dict(record["properties"])
                for key, value in props.items():
                    if hasattr(value, "isoformat"):
                        props[key] = value.isoformat()
                backup_data["relationships"].append({
                    "source": record["source_id"],
                    "target": record["target_id"],
                    "type": record["type"],
                    "properties": props,
                })
            self.logger.info(
                f"    [OK] Exported {len(backup_data['relationships'])} relationships"
            )

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(backup_data, f, indent=2, default=str)

        self.logger.info(f"[OK] Graph backup exported to {output_file}")
        return backup_data

    def run_validation_queries(self) -> Dict[str, Any]:
        """Run validation queries and return results."""
        self.logger.info("[->] Running validation queries")

        validation_results = {}
        queries = {
            "total_documents": "MATCH (d:Document) RETURN count(d) AS count",
            "total_parties": "MATCH (p:Party) RETURN count(p) AS count",
            "total_locations": "MATCH (l:Location) RETURN count(l) AS count",
            "total_relationships": "MATCH ()-[r]->() RETURN count(r) AS count",
            "documents_with_hash": (
                "MATCH (d:Document) WHERE d.sha256 IS NOT NULL RETURN count(d) AS count"
            ),
            "orphan_documents": (
                "MATCH (d:Document) WHERE NOT (d)-[:LOCATED_IN]->() RETURN count(d) AS count"
            ),
            "relationships_by_type": (
                "MATCH ()-[r]->() RETURN type(r) AS type, count(r) AS count ORDER BY count DESC"
            ),
            "documents_by_category": (
                "MATCH (d:Document) RETURN d.evidence_category AS category, "
                "count(d) AS count ORDER BY count DESC"
            ),
            "documents_by_file_type": (
                "MATCH (d:Document) RETURN d.file_type AS type, count(d) AS count ORDER BY count DESC"
            ),
            "parties_with_references": (
                "MATCH (d:Document)-[r:REFERENCES]->(p:Party) "
                "RETURN p.name AS party, count(r) AS ref_count ORDER BY ref_count DESC"
            ),
        }

        with self.driver.session() as session:
            for name, query in queries.items():
                try:
                    result = session.run(query)
                    records = list(result)
                    if len(records) == 1 and "count" in records[0].keys():
                        validation_results[name] = records[0]["count"]
                    else:
                        validation_results[name] = [dict(r) for r in records]
                    self.logger.debug(f"    {name}: {validation_results[name]}")
                except Exception as e:
                    self.logger.error(f"[FAIL] Validation query {name} failed: {e}")
                    validation_results[name] = f"ERROR: {e}"

        # Check for issues
        orphans = validation_results.get("orphan_documents", 0)
        if orphans > 0:
            self.logger.warning(f"[WARN] Found {orphans} orphan documents without location")

        self.logger.info("[OK] Validation queries complete")
        return validation_results


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Main entry point for Phase 3 batch ingestion."""
    parser = argparse.ArgumentParser(
        description="Phase 3: CSV Batch Document Ingestion for Neo4j"
    )
    parser.add_argument(
        "--csv",
        default=DEFAULT_CSV_PATH,
        help="Path to CSV file with document catalog"
    )
    parser.add_argument("--uri", default="bolt://localhost:7687", help="Neo4j URI")
    parser.add_argument("--user", default="neo4j", help="Neo4j username")
    parser.add_argument("--password", required=True, help="Neo4j password")
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Output directory for reports and backups"
    )
    parser.add_argument(
        "--skip-validation",
        action="store_true",
        help="Skip schema validation"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse CSV without writing to Neo4j"
    )

    args = parser.parse_args()

    # Setup output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Setup logging
    log_file = output_dir / "PHASE_3_EXECUTION_LOG.txt"
    logger = setup_logging(str(log_file))

    logger.info("=" * 70)
    logger.info("PHASE 3: NEO4J CSV BATCH INGESTION")
    logger.info(f"CSV Source: {args.csv}")
    logger.info(f"Output Directory: {output_dir}")
    logger.info(f"Batch Size: {BATCH_SIZE}")
    logger.info("=" * 70)

    if args.dry_run:
        logger.info("[DRY-RUN] Parsing CSV without Neo4j writes")
        # Just parse and validate CSV
        try:
            with open(args.csv, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                documents = list(reader)
            logger.info(f"[OK] CSV contains {len(documents)} documents")
            logger.info("[OK] Dry run complete")
        except Exception as e:
            logger.error(f"[FAIL] CSV read error: {e}")
        return

    # Initialize pipeline
    pipeline = BatchDocumentIngestionPipeline(
        args.uri, args.user, args.password, logger
    )

    try:
        # Validate schema
        if not args.skip_validation:
            if not pipeline.validate_schema():
                logger.error("[FAIL] Schema validation failed. Run schema initialization first.")
                return

        # Ingest documents
        pipeline.ingest_from_csv(args.csv)

        # Run validation queries
        validation_results = pipeline.run_validation_queries()

        # Export graph backup
        backup_file = output_dir / "neo4j_full_backup.json"
        pipeline.export_graph_backup(str(backup_file))

        # Generate validation queries file
        validation_file = output_dir / "BATCH_INGESTION_VALIDATION_QUERIES.txt"
        with open(validation_file, "w", encoding="utf-8") as f:
            f.write("# Phase 3 Batch Ingestion Validation Queries\n")
            f.write(f"# Generated: {datetime.utcnow().isoformat()}\n")
            f.write("# Case: Kara Murphy vs Danny Garcia\n")
            f.write("=" * 70 + "\n\n")

            f.write("## VALIDATION RESULTS\n\n")
            for name, value in validation_results.items():
                f.write(f"### {name}\n")
                if isinstance(value, list):
                    for item in value:
                        f.write(f"  {item}\n")
                else:
                    f.write(f"  {value}\n")
                f.write("\n")

            f.write("\n## CYPHER QUERIES FOR MANUAL VALIDATION\n\n")
            f.write("// 1. Count all documents\n")
            f.write("MATCH (d:Document) RETURN count(d) AS total_documents;\n\n")
            f.write("// 2. Count orphan documents\n")
            f.write("MATCH (d:Document) WHERE NOT (d)-[:LOCATED_IN]->() RETURN count(d);\n\n")
            f.write("// 3. Documents by category\n")
            f.write("MATCH (d:Document) RETURN d.evidence_category, count(d) ORDER BY count(d) DESC;\n\n")
            f.write("// 4. Party reference counts\n")
            f.write("MATCH (d:Document)-[r:REFERENCES]->(p:Party) RETURN p.name, count(r) ORDER BY count(r) DESC;\n\n")
            f.write("// 5. Location distribution\n")
            f.write("MATCH (d:Document)-[:LOCATED_IN]->(l:Location) RETURN l.path, count(d) ORDER BY count(d) DESC LIMIT 10;\n\n")
            f.write("// 6. Documents with SHA-256 hashes\n")
            f.write("MATCH (d:Document) WHERE d.sha256 IS NOT NULL RETURN count(d) AS hashed_docs;\n\n")
            f.write("// 7. Schema constraints\n")
            f.write("SHOW CONSTRAINTS;\n\n")
            f.write("// 8. Relationship types and counts\n")
            f.write("MATCH ()-[r]->() RETURN type(r), count(r) ORDER BY count(r) DESC;\n\n")
            f.write("// 9. Design files only\n")
            f.write("MATCH (d:Document) WHERE d.evidence_category = 'design_file' RETURN d.file_name, d.file_type;\n\n")
            f.write("// 10. Depositions/Transcripts\n")
            f.write("MATCH (d:Document) WHERE d.evidence_category = 'deposition' RETURN d.file_name;\n\n")
            f.write("// 11. Documents referencing Danny Garcia\n")
            f.write("MATCH (d:Document)-[:REFERENCES]->(p:Party {name: 'Danny Garcia'}) RETURN d.file_name;\n\n")
            f.write("// 12. Documents referencing Kara Murphy\n")
            f.write("MATCH (d:Document)-[:REFERENCES]->(p:Party {name: 'Kara Murphy'}) RETURN d.file_name;\n\n")
            f.write("// 13. High confidence documents (>=90)\n")
            f.write("MATCH (d:Document) WHERE d.confidence_score >= 90 RETURN d.file_name, d.confidence_score;\n\n")
            f.write("// 14. Recently modified documents\n")
            f.write("MATCH (d:Document) WHERE d.modified_date >= '2026-01-01' RETURN d.file_name, d.modified_date ORDER BY d.modified_date DESC;\n\n")
            f.write("// 15. Full graph visualization query (nodes + relationships)\n")
            f.write("MATCH p=()-[r]->() RETURN p LIMIT 500;\n")

        logger.info(f"[OK] Validation queries saved to {validation_file}")

        # Generate ingestion report
        report_file = output_dir / "PHASE_3_BATCH_INGESTION_REPORT.txt"
        stats = pipeline.stats
        with open(report_file, "w", encoding="utf-8") as f:
            f.write("=" * 70 + "\n")
            f.write("PHASE 3: BATCH DOCUMENT INGESTION REPORT\n")
            f.write("Kara Murphy vs Danny Garcia Litigation Case\n")
            f.write("=" * 70 + "\n\n")

            f.write(f"Generated: {datetime.utcnow().isoformat()}\n")
            f.write(f"CSV Source: {args.csv}\n")
            f.write(f"Neo4j URI: {args.uri}\n\n")

            f.write("-" * 70 + "\n")
            f.write("INGESTION STATISTICS\n")
            f.write("-" * 70 + "\n\n")

            f.write(f"Documents Processed:    {stats.get('documents_processed', 0)}\n")
            f.write(f"Documents Created:      {stats.get('documents_created', 0)}\n")
            f.write(f"Documents Skipped:      {stats.get('documents_skipped', 0)}\n")
            f.write(f"Relationships Created:  {stats.get('relationships_created', 0)}\n")
            f.write(f"Parties Created:        {stats.get('parties_created', 0)}\n")
            f.write(f"Locations Created:      {stats.get('locations_created', 0)}\n")
            f.write(f"Batches Completed:      {stats.get('batches_completed', 0)}\n")
            f.write(f"Batches Failed:         {stats.get('batches_failed', 0)}\n")
            f.write(f"Validation Errors:      {stats.get('validation_errors', 0)}\n")
            f.write(f"Hash Calculations:      {stats.get('hash_calculations', 0)}\n\n")

            f.write("-" * 70 + "\n")
            f.write("VALIDATION RESULTS\n")
            f.write("-" * 70 + "\n\n")

            for name, value in validation_results.items():
                f.write(f"{name}: {value}\n")

            f.write("\n" + "-" * 70 + "\n")
            f.write("DELIVERABLES\n")
            f.write("-" * 70 + "\n\n")

            f.write(f"[OK] PHASE_3_BATCH_INGESTION_REPORT.txt (this file)\n")
            f.write(f"[OK] neo4j_full_backup.json\n")
            f.write(f"[OK] BATCH_INGESTION_VALIDATION_QUERIES.txt\n")
            f.write(f"[OK] PHASE_3_EXECUTION_LOG.txt\n")

            f.write("\n" + "=" * 70 + "\n")
            f.write("END OF REPORT\n")
            f.write("=" * 70 + "\n")

        logger.info(f"[OK] Ingestion report saved to {report_file}")

    finally:
        pipeline.close()


if __name__ == "__main__":
    main()
