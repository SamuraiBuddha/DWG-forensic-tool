================================================================================
PHASE 3 BATCH INGESTION - README
================================================================================

Case: Kara Murphy vs Danny Garcia
Directory: NEO4J_SETUP/PHASE_3_BATCH_INGESTION
Version: 1.0
Date: 2026-01-30
Status: Template Ready - Pending Network CSV Access

================================================================================
PURPOSE
================================================================================

This directory contains the production-ready batch ingestion pipeline for
importing 1,040 cataloged documents from CSV into the Neo4j litigation
knowledge graph.

Target Dataset: \\adam\DataPool\Projects\2026-001_Kara_Murphy_vs_Danny_Garcia\
                DOCUMENT_CATALOG\6075_ENGLISH_OAKS_DOCUMENTS.csv

Current Status: Network CSV not accessible - Template validated with
                100-document sample


================================================================================
DIRECTORY CONTENTS
================================================================================

CORE IMPLEMENTATION
------------------------------------------------------------
document_batch_ingestion.py         Main batch ingestion script (1,050 lines)
                                     - CSVDocumentParser (validation)
                                     - RelationshipInferenceEngine (inference)
                                     - ForensicBatchIngestionPipeline (ingestion)

SAMPLE DATA
------------------------------------------------------------
sample_100_documents.csv             Demonstration CSV (100 documents)
                                     - All file types (RVT, DWG, PDF, MSG, etc.)
                                     - All categories (design, deposition, etc.)
                                     - 5+ year date range (2020-2025)

DOCUMENTATION
------------------------------------------------------------
README.txt                           This file - directory overview

QUICK_START_EXECUTION_GUIDE.txt      Step-by-step execution instructions
                                     - Prerequisites checklist
                                     - 8-step execution workflow
                                     - Troubleshooting guide
                                     - Rollback procedure

BATCH_INGESTION_VALIDATION_QUERIES.txt  Validation query suite (80+ queries)
                                         - 15 validation categories
                                         - Smoke test suite
                                         - Litigation-specific queries

PHASE_3_COMPLETION_SUMMARY.txt       Comprehensive implementation report
                                     - Architecture decisions
                                     - Performance projections
                                     - Risk assessment
                                     - Deployment checklist


RUNTIME OUTPUTS (Generated on Execution)
------------------------------------------------------------
PHASE_3_EXECUTION_LOG.txt            Timestamped execution log (INFO/WARN/ERROR)
PHASE_3_BATCH_INGESTION_REPORT.txt   Validation report (auto-generated)
neo4j_full_backup.json               Complete graph export (recovery backup)
FAILED_DOCUMENTS.csv                 Invalid CSV rows (if any)


================================================================================
QUICK START
================================================================================

Step 1: Verify Prerequisites
------------------------------------------------------------
- Neo4j running at bolt://localhost:7687
- Phase 1 & 2 complete (schema initialized, POC ingestion done)
- Python 3.10+ with neo4j package installed
- Document CSV accessible

Step 2: Test Run with Sample Data
------------------------------------------------------------
python document_batch_ingestion.py \
  --csv sample_100_documents.csv \
  --password YOUR_NEO4J_PASSWORD

Expected: 100 documents ingested in ~10 seconds

Step 3: Validate Results
------------------------------------------------------------
# Open Neo4j Browser: http://localhost:7474
MATCH (d:Document) RETURN count(d) AS total_documents;
# Expected: 100+ documents (includes Phase 2 POC)

Step 4: Run Validation Queries
------------------------------------------------------------
# Open BATCH_INGESTION_VALIDATION_QUERIES.txt
# Execute smoke test queries in Neo4j Browser
# Verify all tests pass

Step 5: Full Ingestion (When Network Available)
------------------------------------------------------------
python document_batch_ingestion.py \
  --csv "\\\\adam\\DataPool\\Projects\\2026-001_Kara_Murphy_vs_Danny_Garcia\\DOCUMENT_CATALOG\\6075_ENGLISH_OAKS_DOCUMENTS.csv" \
  --password YOUR_NEO4J_PASSWORD

Expected: 1,040 documents ingested in 5-15 minutes

Step 6: Review Reports
------------------------------------------------------------
cat PHASE_3_BATCH_INGESTION_REPORT.txt
cat PHASE_3_EXECUTION_LOG.txt


================================================================================
FILE DESCRIPTIONS
================================================================================

document_batch_ingestion.py
------------------------------------------------------------
Main ingestion script with three core classes:

1. CSVDocumentParser
   - Parses CSV file with validation
   - Checks required fields: file_name, file_path, file_type, category
   - Validates data types and date formats
   - Exports failed rows to CSV

2. RelationshipInferenceEngine
   - Infers Evidence relationships (95% confidence)
   - Infers Party relationships (75-95% confidence)
   - Infers Location relationships (95% confidence)
   - Loads existing graph entities for pattern matching

3. ForensicBatchIngestionPipeline
   - Batch transaction processing (100 docs/batch)
   - Document node creation with all properties
   - Relationship creation (REFERENCES, LOCATED_IN)
   - Location auto-creation (MERGE pattern)
   - SHA-256 hash calculation for file integrity
   - Graph backup export (JSON)
   - Validation report generation

Usage:
  python document_batch_ingestion.py \
    --csv PATH_TO_CSV \
    --password NEO4J_PASSWORD \
    [--uri bolt://localhost:7687] \
    [--user neo4j] \
    [--batch-size 100] \
    [--backup-json neo4j_full_backup.json] \
    [--validation-report REPORT.txt] \
    [--failed-csv FAILED.csv]


sample_100_documents.csv
------------------------------------------------------------
Demonstration CSV with 100 diverse documents:

Columns:
- file_name: Document filename (required)
- file_path: Full file path (required)
- file_type: RVT, DWG, PDF, MSG, XLSX, DOCX, JPG, etc. (required)
- category: design_file, deposition, forensic_report, email, etc. (required)
- created_date: ISO 8601 datetime (optional)
- modified_date: ISO 8601 datetime (optional)
- file_size_bytes: Integer (optional)
- author: String (optional, for party inference)
- subject: String (optional, for context)
- confidence_score: 0-100 (optional, defaults to 50)

Document Types:
- 3 design files (RVT, DWG)
- 10 forensic reports
- 3 depositions
- 15 emails
- 12 permits
- 8 contracts
- 6 invoices
- 8 photos
- 35 supporting documents


QUICK_START_EXECUTION_GUIDE.txt
------------------------------------------------------------
Comprehensive execution guide with:

- Prerequisites: Phase 1/2, Neo4j, Python, CSV
- 8-step workflow: Verify, validate, test, ingest, report
- Command reference: All CLI options with examples
- Troubleshooting: 10 common issues with solutions
- Rollback: 5-step recovery procedure
- Success criteria: 10 validation checkpoints
- Next steps: Post-ingestion actions

Target Audience: User executing ingestion for first time


BATCH_INGESTION_VALIDATION_QUERIES.txt
------------------------------------------------------------
Neo4j validation query suite with 80+ queries:

Categories:
1. Document count validation (total, by category, by type)
2. Relationship validation (total, by type, coverage)
3. Data quality checks (orphaned, duplicates, missing)
4. Confidence score analysis (distribution, averages)
5. Timeline validation (date ranges, anachronisms)
6. Evidence correlation (document-evidence links)
7. Party analysis (document-party relationships)
8. Location analysis (document distribution)
9. Forensic category analysis (category-specific)
10. Graph integrity validation (constraints, indexes)
11. Performance validation (query profiling)
12. Export validation (JSON export)
13. Smoke test suite (5 quick tests)
14. Litigation-specific queries (critical evidence)
15. Data completeness report (property coverage)

Usage: Copy queries into Neo4j Browser and execute


PHASE_3_COMPLETION_SUMMARY.txt
------------------------------------------------------------
Comprehensive implementation report:

Contents:
- Executive summary
- Deliverables breakdown (5 files)
- Implementation details (CSV parsing, inference, batching)
- Architecture decisions (6 key decisions explained)
- Performance projections (throughput, memory, disk)
- Risk assessment (6 risks identified and mitigated)
- Quality assurance validation (code, testing, docs, security)
- Deployment readiness checklist (90% complete)
- Final deliverables summary

Target Audience: Technical stakeholders, future maintainers


================================================================================
WORKFLOW
================================================================================

Normal Execution Flow:
------------------------------------------------------------
1. User runs document_batch_ingestion.py with CSV path and password
2. Script connects to Neo4j and validates schema constraints
3. CSVDocumentParser reads and validates all CSV rows
4. Invalid rows logged and exported to FAILED_DOCUMENTS.csv
5. Valid documents split into batches of 100
6. For each batch:
   a. Create Document nodes with all properties
   b. Infer Evidence/Party/Location relationships
   c. Create or get Location nodes (MERGE)
   d. Create relationship edges (REFERENCES, LOCATED_IN)
   e. Commit batch transaction
   f. Log batch completion
7. After all batches complete:
   a. Export graph backup to JSON
   b. Generate validation report
   c. Log final statistics
8. User runs validation queries to verify results
9. User reviews reports and failed documents


Error Handling Flow:
------------------------------------------------------------
1. CSV file not found -> Exit with error message
2. Neo4j connection failed -> Exit with error message
3. Schema constraints missing -> Exit with error message
4. Invalid CSV row -> Skip row, log warning, continue
5. Document creation failed -> Log error, continue
6. Relationship creation failed -> Log debug, continue (orphaned doc)
7. Batch processing failed -> Log error, continue to next batch
8. Graph export failed -> Log error, but ingestion still succeeded


================================================================================
EXPECTED OUTPUTS
================================================================================

After Successful Ingestion:
------------------------------------------------------------

Neo4j Database:
- 1,000+ Document nodes (1,040 from CSV + Phase 2 POC)
- 30-50 new Location nodes (auto-created from paths)
- 3,000+ new relationships:
  * 1,000+ Document->Evidence (REFERENCES)
  * 500+ Document->Party (REFERENCES)
  * 1,040 Document->Location (LOCATED_IN)

PHASE_3_EXECUTION_LOG.txt:
- Connection established message
- Schema validation passed message
- CSV parsing statistics (1,040 total, X valid, Y skipped)
- Batch processing logs (11 batches)
- Final statistics:
  * Documents Created: 1,040
  * Relationships Created: 3,000+
  * Batches Processed: 11
  * Duration: 5-15 minutes
  * Throughput: 50-200 docs/sec

PHASE_3_BATCH_INGESTION_REPORT.txt:
- Ingestion statistics summary
- Document breakdown by category (9 categories)
- Document breakdown by file type (9 types)
- Relationship statistics (by type)
- Orphaned documents count (<10%)
- Confidence score distribution
- Data quality metrics

neo4j_full_backup.json:
- File size: 20-100 MB
- Contains all nodes and relationships
- Recovery backup in human-readable JSON

FAILED_DOCUMENTS.csv:
- Header row only (if no failures)
- Or invalid rows with error messages (if failures occurred)


================================================================================
TROUBLESHOOTING
================================================================================

Issue: Script exits with "Schema validation failed"
Solution: Run Phase 1 initialization: python GRAPH_INITIALIZATION_SCRIPT.py

Issue: High number of orphaned documents (>20%)
Solution: Verify Evidence and Party nodes exist. Check CSV data quality.

Issue: CSV parsing errors (many skipped rows)
Solution: Review FAILED_DOCUMENTS.csv for patterns. Fix CSV data and re-run.

Issue: Slow performance (<10 docs/sec)
Solution: Increase batch size (--batch-size 200). Check Neo4j heap size.

Issue: Connection timeout errors
Solution: Verify Neo4j is running. Check firewall allows port 7687.

Full troubleshooting guide: See QUICK_START_EXECUTION_GUIDE.txt Section 8


================================================================================
MAINTENANCE
================================================================================

To Update Validation Rules:
------------------------------------------------------------
Edit CSVDocumentParser class in document_batch_ingestion.py:
- VALID_FILE_TYPES list (line ~40)
- VALID_CATEGORIES list (line ~45)
- _validate_row() method (line ~120)

To Update Relationship Inference:
------------------------------------------------------------
Edit RelationshipInferenceEngine class in document_batch_ingestion.py:
- infer_evidence_links() method (line ~450)
- infer_party_links() method (line ~480)
- infer_location_link() method (line ~510)

To Add New Validation Queries:
------------------------------------------------------------
Edit BATCH_INGESTION_VALIDATION_QUERIES.txt:
- Add new query under appropriate category
- Document expected results
- Update section index at top of file

To Modify Batch Size:
------------------------------------------------------------
Change default in CLI argument parser (line ~1010):
  parser.add_argument("--batch-size", type=int, default=100)
Or specify via CLI:
  --batch-size 200


================================================================================
PERFORMANCE TUNING
================================================================================

If Ingestion is Slow:
------------------------------------------------------------
1. Increase batch size (--batch-size 200)
2. Increase Neo4j heap size (dbms.memory.heap.max_size=4G)
3. Disable relationship inference temporarily
4. Use faster storage (local SSD vs network)
5. Reduce logging verbosity

If Memory Usage is High:
------------------------------------------------------------
1. Decrease batch size (--batch-size 50)
2. Process CSV in chunks (split large CSV)
3. Increase system swap space
4. Close other applications

If Validation is Slow:
------------------------------------------------------------
1. Run smoke tests only (skip full validation)
2. Create additional indexes on Document properties
3. Use PROFILE to identify slow queries
4. Add LIMIT to queries during testing


================================================================================
NEXT STEPS
================================================================================

After Successful Phase 3 Ingestion:
------------------------------------------------------------

1. Generate Litigation Graph Visualization
   cd NEO4J_SETUP
   python GRAPH_VISUALIZATION_GENERATOR.py --output LITIGATION_GRAPH_FULL.png

2. Run Advanced Forensic Queries
   - Open BATCH_INGESTION_VALIDATION_QUERIES.txt Section 14
   - Execute litigation-specific queries in Neo4j Browser
   - Document findings

3. Identify Key Evidence Clusters
   - Use community detection algorithms
   - Find densely connected document groups
   - Correlate with case timeline

4. Create Timeline Visualization
   - Plot document creation dates
   - Identify critical periods (September 2021)
   - Overlay with case events

5. Update Case Documentation
   - Document key findings in litigation notes
   - Share graph insights with legal team
   - Prepare expert witness materials


================================================================================
SUPPORT & CONTACT
================================================================================

Phase Owner: CasparCode-002 Orchestrator
Generated: 2026-01-30
Status: Template Ready - Pending Network CSV Access

Documentation Files:
- README.txt (this file)
- QUICK_START_EXECUTION_GUIDE.txt (execution workflow)
- BATCH_INGESTION_VALIDATION_QUERIES.txt (validation suite)
- PHASE_3_COMPLETION_SUMMARY.txt (implementation report)

Related Files:
- ../PHASE_2_INGESTION/ (Phase 2 POC implementation)
- ../GRAPH_INITIALIZATION_SCRIPT.py (Phase 1 schema setup)
- ../neo4j_utils.py (utility functions)

Next Action:
When network CSV becomes available at:
\\adam\DataPool\Projects\2026-001_Kara_Murphy_vs_Danny_Garcia\DOCUMENT_CATALOG\

Execute full ingestion per QUICK_START_EXECUTION_GUIDE.txt Step 6


================================================================================
VERSION HISTORY
================================================================================

Version 1.0 (2026-01-30)
- Initial implementation complete
- 100-document sample CSV created
- Full validation suite implemented
- Documentation complete
- Ready for deployment


================================================================================
END OF README
================================================================================

For detailed execution instructions, see QUICK_START_EXECUTION_GUIDE.txt
For validation procedures, see BATCH_INGESTION_VALIDATION_QUERIES.txt
For architecture details, see PHASE_3_COMPLETION_SUMMARY.txt
