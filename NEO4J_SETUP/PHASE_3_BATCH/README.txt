================================================================================
PHASE 3: NEO4J CSV BATCH INGESTION
Kara Murphy vs Danny Garcia Litigation Case
================================================================================

OVERVIEW
--------
This phase scales the Phase 2 POC to ingest all 1,040 cataloged documents from
the network CSV into the Neo4j knowledge graph. It includes entity extraction,
relationship inference with confidence scoring, and full data validation.

SOURCE DATA
-----------
CSV Path: \\adam\DataPool\Projects\2026-001_Kara_Murphy_vs_Danny_Garcia\
          DOCUMENT_CATALOG\6075_ENGLISH_OAKS_DOCUMENTS.csv

Document Count: 1,040 HIGH relevance documents
Columns: full_path, file_name, file_type, extension, file_size_bytes,
         file_size_mb, created_date, modified_date, subject, category

PREREQUISITES
-------------
1. Neo4j 5.x running locally (bolt://localhost:7687)
2. Schema constraints initialized (run NEO4J_SETUP/GRAPH_INITIALIZATION_SCRIPT.py)
3. Python 3.10+ with packages:
   - neo4j (required)
   - networkx (optional, for PNG visualization)
   - matplotlib (optional, for PNG visualization)

QUICK START
-----------
# Option 1: Quick-start runner (recommended)
python run_phase3_ingestion.py --password <your_neo4j_password>

# Option 2: Direct execution
python batch_document_ingestion.py --password <neo4j_password> \
    --csv "\\adam\DataPool\...\6075_ENGLISH_OAKS_DOCUMENTS.csv" \
    --output-dir .

# Option 3: Dry run (parse CSV without Neo4j)
python batch_document_ingestion.py --password <neo4j_password> --dry-run

BATCH PROCESSING
----------------
- Batch Size: 100 documents per transaction
- Total Batches: 11 (1,040 documents / 100)
- Retry Logic: 3 attempts per failed batch
- Transaction Safety: Atomic commits per batch

ENTITY EXTRACTION
-----------------
1. PARTIES: Extracted from file paths, subjects, and filenames
   - Known parties: Kara Murphy, Danny Garcia, Andy Garcia, Caron, Beauchamp,
     Gansari, JPEC, ODA SDK, AutoCAD, BricsCAD, NanoCAD
   - Confidence: 75-95% based on match count and context

2. LOCATIONS: Derived from directory paths
   - Types: Network, Directory, Cloud
   - Project reference: "6075 English Oaks" keyword matching
   - Confidence: 95% (direct extraction)

3. EVIDENCE CATEGORIES: Inferred from category + extension + subject
   - design_file, deposition, forensic_report, correspondence, email,
     contract, permit, other
   - Confidence: 50-95% based on inference source

RELATIONSHIPS CREATED
---------------------
- Document -[:LOCATED_IN]-> Location (confidence: 95%)
- Document -[:REFERENCES]-> Party (confidence: 75-95%)

DELIVERABLES
------------
After successful execution, the following files will be in PHASE_3_BATCH/:

1. PHASE_3_BATCH_INGESTION_REPORT.txt
   - Complete audit of ingestion: documents processed, created, skipped
   - Relationship counts by type
   - Validation errors encountered
   - Duration and performance metrics

2. neo4j_full_backup.json
   - Complete graph export (all nodes + relationships)
   - Recovery-ready JSON format
   - Includes all properties and metadata

3. BATCH_INGESTION_VALIDATION_QUERIES.txt
   - 15 Cypher queries for data integrity verification
   - Results from automated validation
   - Manual verification queries

4. PHASE_3_EXECUTION_LOG.txt
   - Timestamped log of all operations
   - Debug-level detail for troubleshooting
   - Batch completion timestamps

5. LITIGATION_GRAPH_FULL_VISUALIZATION.txt
   - ASCII art graph statistics
   - Node distribution by type
   - Relationship distribution
   - Party connection summary

6. LITIGATION_GRAPH_FULL_VISUALIZATION.png (if dependencies available)
   - Network diagram of up to 500 nodes
   - Color-coded by node type and evidence category
   - Party nodes highlighted with labels

VALIDATION
----------
The ingestion performs automatic validation:

1. Schema Validation: Checks required constraints exist
2. Orphan Detection: Flags documents without LOCATED_IN relationships
3. Relationship Counts: Verifies expected relationship cardinality
4. Hash Verification: SHA-256 calculated for accessible files

Post-ingestion Cypher queries to run manually:

    // Count all documents
    MATCH (d:Document) RETURN count(d) AS total;

    // Find orphan documents
    MATCH (d:Document) WHERE NOT (d)-[:LOCATED_IN]->() RETURN d.file_name;

    // Verify party references
    MATCH (d:Document)-[r:REFERENCES]->(p:Party)
    RETURN p.name, count(r) AS refs ORDER BY refs DESC;

ERROR HANDLING
--------------
- Missing required fields (file_path, file_name): Document skipped with warning
- Neo4j transaction failures: Automatic retry (3 attempts)
- File hash calculation failures: Continues without hash (logs warning)
- Network path inaccessible: Continues with metadata-only (no hash)

PERFORMANCE NOTES
-----------------
Estimated runtime for 1,040 documents:
- With hash calculation: 10-15 minutes (network I/O dependent)
- Without hash calculation: 2-5 minutes (Neo4j write speed)

Factors affecting performance:
- Network latency to file shares
- Neo4j transaction commit speed
- File sizes for hash calculation

TROUBLESHOOTING
---------------
1. "Schema validation failed"
   - Run NEO4J_SETUP/GRAPH_INITIALIZATION_SCRIPT.py first
   - Or use --skip-validation flag

2. "CSV file not accessible"
   - Check network connectivity to \\adam\DataPool
   - Verify Windows credentials/SMB access
   - Try mapping network drive explicitly

3. "Connection refused"
   - Verify Neo4j is running on localhost:7687
   - Check Neo4j authentication credentials

4. "MemoryError during visualization"
   - Reduce --max-nodes parameter
   - Install networkx with: pip install networkx

================================================================================
Generated: 2026-01-30
Author: CasparCode-002 Orchestrator
================================================================================
