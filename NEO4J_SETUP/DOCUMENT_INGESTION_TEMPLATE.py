"""
Document Ingestion Template
Kara Murphy vs Danny Garcia Litigation Case

This script provides templates for ingesting additional documents (PDFs, emails,
contracts, pleadings, depositions) into the Neo4j knowledge graph.

Prerequisites:
- Neo4j instance running with initialized graph
- neo4j-driver installed: pip install neo4j
- PyPDF2 for PDF text extraction: pip install PyPDF2
- python-docx for Word docs (optional): pip install python-docx

Usage:
    python DOCUMENT_INGESTION_TEMPLATE.py --uri bolt://localhost:7687 --user neo4j --password your_password --document-dir /path/to/documents
"""

import argparse
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from neo4j import GraphDatabase

try:
    import PyPDF2
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False
    print("[WARN] PyPDF2 not installed. PDF text extraction will be disabled.")


class DocumentIngestionPipeline:
    """Ingests legal documents into Neo4j knowledge graph."""

    def __init__(self, uri: str, user: str, password: str):
        """
        Initialize Neo4j connection.

        Args:
            uri: Neo4j connection URI
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

    def extract_pdf_text(self, pdf_path: str) -> Optional[str]:
        """
        Extract text from PDF file.

        Args:
            pdf_path: Path to PDF file

        Returns:
            Extracted text or None if extraction fails
        """
        if not PDF_AVAILABLE:
            return None

        try:
            with open(pdf_path, "rb") as file:
                pdf_reader = PyPDF2.PdfReader(file)
                text = ""
                for page in pdf_reader.pages:
                    text += page.extract_text() + "\n"
                return text.strip()
        except Exception as e:
            print(f"[WARN] Failed to extract text from {pdf_path}: {e}")
            return None

    def ingest_document(
        self,
        title: str,
        document_type: str,
        file_path: str,
        author: Optional[str] = None,
        recipient: Optional[str] = None,
        date: Optional[str] = None,
        summary: Optional[str] = None,
        extract_text: bool = True,
    ) -> str:
        """
        Ingest a single document into the graph.

        Args:
            title: Document title
            document_type: "Email" | "Contract" | "Report" | "Letter" | "Pleading" | "Deposition"
            file_path: Path to document file
            author: Author name (optional)
            recipient: Recipient name (optional)
            date: Document date in ISO format (optional)
            summary: Brief summary (optional)
            extract_text: Whether to extract full text from PDF (default: True)

        Returns:
            UUID of created Document node
        """
        print(f"\n[->] Ingesting document: {title}")

        # Extract text if PDF and extraction enabled
        full_text = None
        if extract_text and file_path.lower().endswith(".pdf"):
            full_text = self.extract_pdf_text(file_path)
            if full_text:
                print(f"  [OK] Extracted {len(full_text)} characters from PDF")

        doc_uuid = self._generate_uuid()

        with self.driver.session() as session:
            query = """
            CREATE (d:Document {
                title: $title,
                document_type: $document_type,
                file_path: $file_path,
                uuid: $uuid,
                created_at: datetime($created_at)
            })
            """

            params = {
                "title": title,
                "document_type": document_type,
                "file_path": file_path,
                "uuid": doc_uuid,
                "created_at": self._current_timestamp().isoformat(),
            }

            # Add optional fields
            if author:
                query = query.replace("created_at: datetime($created_at)",
                                      "author: $author, created_at: datetime($created_at)")
                params["author"] = author

            if recipient:
                query = query.replace("created_at: datetime($created_at)",
                                      "recipient: $recipient, created_at: datetime($created_at)")
                params["recipient"] = recipient

            if date:
                query = query.replace("created_at: datetime($created_at)",
                                      "date: datetime($date), created_at: datetime($created_at)")
                params["date"] = date

            if summary:
                query = query.replace("created_at: datetime($created_at)",
                                      "summary: $summary, created_at: datetime($created_at)")
                params["summary"] = summary

            if full_text:
                query = query.replace("created_at: datetime($created_at)",
                                      "full_text: $full_text, created_at: datetime($created_at)")
                params["full_text"] = full_text

            session.run(query, **params)
            print(f"  [OK] Created Document node (UUID: {doc_uuid})")

        return doc_uuid

    def link_document_to_evidence(
        self,
        document_uuid: str,
        evidence_name: str,
        reference_type: str = "Exhibits",
        page_number: Optional[int] = None,
        context: Optional[str] = None,
    ):
        """
        Create REFERENCES relationship from Document to Evidence.

        Args:
            document_uuid: UUID of Document node
            evidence_name: Name of Evidence node
            reference_type: "Exhibits" | "Mentions" | "Analyzes" | "Cites"
            page_number: Page where evidence is referenced (optional)
            context: Surrounding text context (optional)
        """
        with self.driver.session() as session:
            query = """
            MATCH (d:Document {uuid: $document_uuid})
            MATCH (ev:Evidence {name: $evidence_name})
            CREATE (d)-[:REFERENCES {
                reference_type: $reference_type,
                created_at: datetime($created_at)
            }]->(ev)
            """

            params = {
                "document_uuid": document_uuid,
                "evidence_name": evidence_name,
                "reference_type": reference_type,
                "created_at": self._current_timestamp().isoformat(),
            }

            if page_number:
                query = query.replace("created_at: datetime($created_at)",
                                      "page_number: $page_number, created_at: datetime($created_at)")
                params["page_number"] = page_number

            if context:
                query = query.replace("created_at: datetime($created_at)",
                                      "context: $context, created_at: datetime($created_at)")
                params["context"] = context

            session.run(query, **params)
            print(f"  [OK] {document_uuid[:8]}... -[REFERENCES]-> {evidence_name}")

    def link_document_to_party(
        self,
        document_uuid: str,
        party_name: str,
        reference_type: str = "Mentions",
        page_number: Optional[int] = None,
    ):
        """
        Create REFERENCES relationship from Document to Party.

        Args:
            document_uuid: UUID of Document node
            party_name: Name of Party node
            reference_type: "Exhibits" | "Mentions" | "Analyzes" | "Cites"
            page_number: Page where party is referenced (optional)
        """
        with self.driver.session() as session:
            query = """
            MATCH (d:Document {uuid: $document_uuid})
            MATCH (p:Party {name: $party_name})
            CREATE (d)-[:REFERENCES {
                reference_type: $reference_type,
                created_at: datetime($created_at)
            }]->(p)
            """

            params = {
                "document_uuid": document_uuid,
                "party_name": party_name,
                "reference_type": reference_type,
                "created_at": self._current_timestamp().isoformat(),
            }

            if page_number:
                query = query.replace("created_at: datetime($created_at)",
                                      "page_number: $page_number, created_at: datetime($created_at)")
                params["page_number"] = page_number

            session.run(query, **params)
            print(f"  [OK] {document_uuid[:8]}... -[REFERENCES]-> {party_name}")

    def link_document_to_claim(
        self,
        document_uuid: str,
        claim_text: str,
        relationship_type: str = "SUPPORTS_CLAIM",
        strength: str = "Moderate",
        relevance: Optional[str] = None,
    ):
        """
        Create SUPPORTS_CLAIM or CONTRADICTS_CLAIM relationship from Document to Claim.

        Args:
            document_uuid: UUID of Document node
            claim_text: Text of Claim node
            relationship_type: "SUPPORTS_CLAIM" | "CONTRADICTS_CLAIM"
            strength: "Strong" | "Moderate" | "Weak"
            relevance: Explanation of relevance (optional)
        """
        with self.driver.session() as session:
            query = f"""
            MATCH (d:Document {{uuid: $document_uuid}})
            MATCH (c:Claim {{claim_text: $claim_text}})
            CREATE (d)-[:{relationship_type} {{
                strength: $strength,
                created_at: datetime($created_at)
            }}]->(c)
            """

            params = {
                "document_uuid": document_uuid,
                "claim_text": claim_text,
                "strength": strength,
                "created_at": self._current_timestamp().isoformat(),
            }

            if relevance:
                query = query.replace("created_at: datetime($created_at)",
                                      "relevance: $relevance, created_at: datetime($created_at)")
                params["relevance"] = relevance

            session.run(query, **params)
            print(f"  [OK] {document_uuid[:8]}... -[{relationship_type}]-> Claim")

    def batch_ingest_directory(
        self,
        directory: str,
        document_type: str,
        file_extension: str = ".pdf",
    ):
        """
        Batch ingest all files with given extension from directory.

        Args:
            directory: Directory path
            document_type: Document type for all files
            file_extension: File extension to filter (default: .pdf)
        """
        print(f"\n[->] Batch ingesting from directory: {directory}")

        directory_path = Path(directory)
        if not directory_path.exists():
            print(f"[FAIL] Directory not found: {directory}")
            return

        files = list(directory_path.glob(f"*{file_extension}"))
        print(f"  [OK] Found {len(files)} files with extension {file_extension}")

        for file_path in files:
            title = file_path.stem  # Filename without extension
            self.ingest_document(
                title=title,
                document_type=document_type,
                file_path=str(file_path),
                extract_text=True,
            )

        print(f"[OK] Batch ingestion complete ({len(files)} files)")


# ============================================================================
# EXAMPLE USAGE TEMPLATES
# ============================================================================

def example_ingest_forensic_report(pipeline: DocumentIngestionPipeline):
    """Example: Ingest forensic analysis report."""
    doc_uuid = pipeline.ingest_document(
        title="Forensic Analysis Report - Lane.rvt",
        document_type="Report",
        file_path="X:/Projects/2026-001/Reports/Forensic_Analysis_Lane.pdf",
        author="Expert Witness Name",
        date="2026-01-30T00:00:00Z",
        summary="Comprehensive forensic analysis of Lane.rvt and derived DWG files",
        extract_text=True,
    )

    # Link to evidence
    pipeline.link_document_to_evidence(
        document_uuid=doc_uuid,
        evidence_name="Lane.rvt",
        reference_type="Analyzes",
        page_number=5,
        context="The Lane.rvt file exhibits signs of...",
    )

    # Link to claim
    pipeline.link_document_to_claim(
        document_uuid=doc_uuid,
        claim_text="Timestamp manipulation detected in DWG files",
        relationship_type="SUPPORTS_CLAIM",
        strength="Strong",
        relevance="Forensic analysis confirms timestamp inconsistencies",
    )


def example_ingest_contract(pipeline: DocumentIngestionPipeline):
    """Example: Ingest design agreement contract."""
    doc_uuid = pipeline.ingest_document(
        title="Design Agreement Contract - Murphy/Garcia",
        document_type="Contract",
        file_path="X:/Projects/2026-001/Contracts/Design_Agreement.pdf",
        author="Law Firm Name",
        date="2020-06-15T00:00:00Z",
        summary="Original design agreement between Kara Murphy and Andy Garcia",
        extract_text=True,
    )

    # Link to parties
    pipeline.link_document_to_party(doc_uuid, "Kara Murphy", "Mentions", page_number=1)
    pipeline.link_document_to_party(doc_uuid, "Andy Garcia", "Mentions", page_number=1)


def example_ingest_email(pipeline: DocumentIngestionPipeline):
    """Example: Ingest email correspondence."""
    doc_uuid = pipeline.ingest_document(
        title="Email: Design Changes Discussion - 2021-09-15",
        document_type="Email",
        file_path="X:/Projects/2026-001/Emails/2021-09-15_design_changes.eml",
        author="Kara Murphy",
        recipient="Andy Garcia",
        date="2021-09-15T14:32:00Z",
        summary="Email discussing requested changes to amenities",
        extract_text=False,  # .eml files need different parser
    )

    pipeline.link_document_to_party(doc_uuid, "Kara Murphy", "Mentions")
    pipeline.link_document_to_party(doc_uuid, "Andy Garcia", "Mentions")


def example_batch_ingest_depositions(pipeline: DocumentIngestionPipeline):
    """Example: Batch ingest deposition transcripts."""
    pipeline.batch_ingest_directory(
        directory="X:/Projects/2026-001/Depositions",
        document_type="Deposition",
        file_extension=".pdf",
    )


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Main execution."""
    parser = argparse.ArgumentParser(description="Ingest documents into Neo4j litigation knowledge graph")
    parser.add_argument("--uri", default="bolt://localhost:7687", help="Neo4j URI")
    parser.add_argument("--user", default="neo4j", help="Neo4j username")
    parser.add_argument("--password", required=True, help="Neo4j password")
    parser.add_argument("--document-dir", help="Directory containing documents to ingest (batch mode)")
    parser.add_argument("--document-type", default="Report", help="Document type for batch ingestion")
    parser.add_argument("--extension", default=".pdf", help="File extension for batch ingestion")
    args = parser.parse_args()

    pipeline = DocumentIngestionPipeline(args.uri, args.user, args.password)

    try:
        if args.document_dir:
            # Batch mode
            pipeline.batch_ingest_directory(
                directory=args.document_dir,
                document_type=args.document_type,
                file_extension=args.extension,
            )
        else:
            # Interactive mode - run examples
            print("\n" + "=" * 60)
            print("Document Ingestion Examples")
            print("=" * 60)

            print("\n[->] Running example: Forensic Report")
            example_ingest_forensic_report(pipeline)

            print("\n[->] Running example: Contract")
            example_ingest_contract(pipeline)

            print("\n[->] Running example: Email")
            example_ingest_email(pipeline)

            print("\n" + "=" * 60)
            print("[OK] Example ingestion complete")
            print("=" * 60)

    finally:
        pipeline.close()


if __name__ == "__main__":
    main()
