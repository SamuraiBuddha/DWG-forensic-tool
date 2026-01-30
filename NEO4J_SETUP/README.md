# Neo4j Knowledge Graph Setup
## Kara Murphy vs Danny Garcia Litigation Case

This directory contains all files necessary to initialize and query a Neo4j knowledge graph for the litigation case. The graph enables rapid querying of evidence, temporal relationships, party interactions, and claim analysis.

---

## Contents

1. **NEO4J_SCHEMA.txt** - Complete graph schema documentation
   - 7 node types (Party, Location, Event, Evidence, Timeline, Claim, Document)
   - 9 relationship types
   - Constraints and indexes
   - Data governance guidelines

2. **NEO4J_CYPHER_QUERIES.txt** - Pre-built Cypher query templates
   - Evidence timeline queries
   - Party relationship queries
   - Claim analysis queries
   - Document reference queries
   - Location-based queries
   - Temporal dependency queries
   - Forensic-specific queries
   - Deposition prep queries
   - Settlement negotiation queries
   - Graph visualization queries

3. **GRAPH_INITIALIZATION_SCRIPT.py** - Python script to load initial nodes/relationships
   - Creates constraints and indexes
   - Loads 4 parties (Kara Murphy, Danny Garcia, Andy Garcia, ODA SDK)
   - Loads 5 locations (directories, cloud storage, physical address)
   - Loads 3 timelines (2021 permit phase, 2022 construction, 2026 forensic)
   - Loads evidence files (RVT, DWG)
   - Loads 4 events (file creations, batch conversion, forensic analysis)
   - Loads 4 fraud claims
   - Creates initial relationships

4. **DOCUMENT_INGESTION_TEMPLATE.py** - Template for loading additional documents
   - PDF text extraction
   - Batch ingestion from directories
   - Linking documents to evidence/parties/claims
   - Example templates for forensic reports, contracts, emails

5. **GRAPH_VISUALIZATION_GENERATOR.py** - Generate visual graphs for expert testimony
   - Complete case graph visualization
   - Evidence timeline chart
   - Claim-evidence network
   - Party activity charts
   - Export as PNG images (300 DPI for presentations)

6. **README.md** - This file

---

## Prerequisites

### Neo4j Installation

**Option 1: Neo4j Desktop (Recommended)**
1. Download from: https://neo4j.com/download/
2. Install and create a new database
3. Set password for `neo4j` user
4. Start the database (default URI: `bolt://localhost:7687`)

**Option 2: Neo4j Docker**
```bash
docker run -d \
  --name neo4j-litigation \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/your_password \
  neo4j:latest
```

### Python Dependencies

```bash
pip install neo4j PyPDF2 matplotlib networkx
```

---

## Quick Start

### Step 1: Initialize the Graph

Run the initialization script to create the base knowledge graph:

```bash
python GRAPH_INITIALIZATION_SCRIPT.py --password your_neo4j_password
```

This will:
- Create all constraints and indexes
- Load initial parties, locations, timelines, evidence, events, claims
- Create relationships between entities
- Verify graph structure

### Step 2: Query the Graph

Open Neo4j Browser (http://localhost:7474) and run example queries from `NEO4J_CYPHER_QUERIES.txt`.

**Example: Show all evidence chronologically**
```cypher
MATCH (ev:Evidence)
OPTIONAL MATCH (ev)<-[c:CREATED]-(creator:Party)
OPTIONAL MATCH (ev)-[:LOCATED_IN]->(loc:Location)
RETURN ev.name AS Evidence,
       ev.evidence_type AS Type,
       c.created_date AS CreatedDate,
       creator.name AS Creator,
       loc.path AS Location
ORDER BY c.created_date ASC;
```

**Example: Evidence supporting fraud claims**
```cypher
MATCH (c:Claim {claim_type: "Fraud"})
OPTIONAL MATCH (ev:Evidence)-[s:SUPPORTS_CLAIM]->(c)
RETURN c.claim_text AS Claim,
       collect({evidence: ev.name, strength: s.strength}) AS SupportingEvidence;
```

### Step 3: Ingest Additional Documents

Use the document ingestion template to load PDFs, emails, contracts:

```bash
# Single document example (edit script to customize)
python DOCUMENT_INGESTION_TEMPLATE.py --password your_neo4j_password

# Batch ingestion from directory
python DOCUMENT_INGESTION_TEMPLATE.py \
  --password your_neo4j_password \
  --document-dir "X:/Projects/2026-001/Reports" \
  --document-type Report \
  --extension .pdf
```

### Step 4: Generate Visualizations

Create visual graphs for expert witness presentations:

```bash
# Generate all visualizations
python GRAPH_VISUALIZATION_GENERATOR.py \
  --password your_neo4j_password \
  --output-dir ./visualizations

# Generate specific visualization
python GRAPH_VISUALIZATION_GENERATOR.py \
  --password your_neo4j_password \
  --mode timeline \
  --output-dir ./visualizations
```

---

## Common Use Cases

### Deposition Preparation

**Query: Complete profile for witness**
```cypher
MATCH (p:Party {name: "Andy Garcia"})
OPTIONAL MATCH (p)-[c:CREATED]->(ev:Evidence)
OPTIONAL MATCH (p)-[m:MODIFIED]->(ev2:Evidence)
OPTIONAL MATCH (p)-[:PARTY_INVOLVED_IN]->(e:Event)
RETURN p.name AS Witness,
       collect(DISTINCT {file: ev.name, date: c.created_date}) AS CreatedFiles,
       collect(DISTINCT {file: ev2.name, date: m.modification_date}) AS ModifiedFiles,
       collect(DISTINCT e.name) AS Events;
```

### Settlement Negotiations

**Query: Strength of case summary**
```cypher
MATCH (c:Claim {alleged_by: "Kara Murphy"})
OPTIONAL MATCH (ev:Evidence)-[s:SUPPORTS_CLAIM]->(c)
OPTIONAL MATCH (ev2:Evidence)-[con:CONTRADICTS_CLAIM]->(c)
RETURN c.claim_text AS Claim,
       count(DISTINCT ev) AS SupportingEvidence,
       count(DISTINCT ev2) AS ContradictingEvidence;
```

### Expert Testimony

**Query: Smoking gun evidence**
```cypher
MATCH (c:Claim)<-[s:SUPPORTS_CLAIM]-(ev:Evidence)
WHERE s.strength = "Strong"
AND NOT EXISTS {
    MATCH (ev)-[:CONTRADICTS_CLAIM]->(c)
}
RETURN c.claim_text AS Claim,
       collect(ev.name) AS SmokingGunEvidence;
```

---

## Graph Schema Overview

```
[Party] --CREATED--> [Evidence] --LOCATED_IN--> [Location]
  |                     |
  +--MODIFIED--> [Evidence]
  |                     |
  +--PARTY_INVOLVED_IN--> [Event] --OCCURRED_ON--> [Timeline]
                          |
                          +--DEPENDS_ON--> [Event]

[Evidence] --SUPPORTS_CLAIM--> [Claim]
           --CONTRADICTS_CLAIM--> [Claim]

[Document] --REFERENCES--> [Evidence | Party | Event | Claim]
           --SUPPORTS_CLAIM--> [Claim]
```

---

## Data Integrity

### Chain of Custody

All Evidence nodes include `chain_of_custody` JSON documenting:
- Acquisition timestamp
- Acquiring party
- Transfer events
- Hash verification (SHA-256)

### Temporal Validation

Event dates are validated against external sources before ingestion. Use `date` properties with ISO 8601 format: `YYYY-MM-DDTHH:MM:SSZ`

### Access Controls

This graph contains attorney work product and privileged communications. Enforce access controls at the Neo4j authentication layer:

```cypher
// Create read-only user for litigation team
CREATE USER litigation_team SET PASSWORD 'secure_password' CHANGE NOT REQUIRED;
GRANT TRAVERSE ON GRAPH * NODES * TO litigation_team;
GRANT READ {*} ON GRAPH * NODES * TO litigation_team;
```

---

## Troubleshooting

### Connection Issues

**Error: "Unable to connect to Neo4j"**
- Verify Neo4j is running: Check Neo4j Desktop or `docker ps`
- Verify URI: Default is `bolt://localhost:7687`
- Check firewall settings

### Query Performance

**Slow queries**
- Verify indexes are created (run initialization script)
- Use `EXPLAIN` prefix to analyze query plan
- Add `LIMIT` to large result sets

### Visualization Issues

**Error: "Visualization libraries not available"**
```bash
pip install matplotlib networkx Pillow
```

---

## Advanced Features

### Custom Rules Integration

Load custom tampering rules from the DWG forensic tool:

```cypher
// Create Rule nodes
CREATE (r:Rule {
    rule_id: "TAMPER-013",
    name: "TDINDWG timestamp older than version",
    severity: "Critical"
});

// Link to evidence
MATCH (ev:Evidence {name: "FLOOR PLAN.dwg"})
MATCH (r:Rule {rule_id: "TAMPER-013"})
CREATE (ev)-[:TRIGGERED_RULE {
    timestamp: datetime(),
    details: "TDINDWG: 2021-02-24, Version: AC1032 (2018+)"
}]->(r);
```

### Temporal Queries

Find suspicious time gaps in file modifications:

```cypher
MATCH (e1:Event), (e2:Event)
WHERE e1.date < e2.date
  AND e1.event_type = "FileModification"
  AND e2.event_type = "FileModification"
  AND duration.between(e1.date, e2.date).days > 30
RETURN e1.name AS Event1,
       e1.date AS Date1,
       e2.name AS Event2,
       e2.date AS Date2,
       duration.between(e1.date, e2.date).days AS GapInDays
ORDER BY GapInDays DESC;
```

### Graph Algorithms

Use Neo4j Graph Data Science library for advanced analytics:

```cypher
// Find shortest path between parties
MATCH path = shortestPath(
    (p1:Party {name: "Kara Murphy"})-[*]-(p2:Party {name: "Andy Garcia"})
)
RETURN path;

// Centrality analysis - find most connected evidence
CALL gds.degree.stream({
    nodeProjection: "Evidence",
    relationshipProjection: {
        SUPPORTS_CLAIM: {type: "SUPPORTS_CLAIM"},
        CONTRADICTS_CLAIM: {type: "CONTRADICTS_CLAIM"}
    }
})
YIELD nodeId, score
RETURN gds.util.asNode(nodeId).name AS Evidence, score
ORDER BY score DESC LIMIT 10;
```

---

## Export and Backup

### Export Graph to JSON

```bash
# Using Neo4j APOC procedures
CALL apoc.export.json.all("litigation_graph.json", {useTypes: true});
```

### Backup Database

```bash
# Neo4j Desktop: Tools -> Backup
# Docker:
docker exec neo4j-litigation neo4j-admin dump --to=/backups/litigation_$(date +%Y%m%d).dump
```

---

## Support

For issues or questions:
1. Check `NEO4J_CYPHER_QUERIES.txt` for query templates
2. Review `NEO4J_SCHEMA.txt` for schema details
3. Consult Neo4j documentation: https://neo4j.com/docs/

---

**CONFIDENTIAL**: This knowledge graph contains attorney work product and privileged communications. Unauthorized access or disclosure is prohibited.
