# Neo4j Quick Reference Guide
## Kara Murphy vs Danny Garcia Litigation Case

---

## 1-Minute Setup

```bash
# Install dependencies
pip install neo4j PyPDF2 matplotlib networkx

# Initialize graph
python GRAPH_INITIALIZATION_SCRIPT.py --password your_password

# Check status
python neo4j_utils.py --password your_password stats
```

---

## Common Queries (Copy-Paste Ready)

### Show All Evidence Timeline
```cypher
MATCH (ev:Evidence)
OPTIONAL MATCH (ev)<-[c:CREATED]-(creator:Party)
RETURN ev.name, c.created_date, creator.name
ORDER BY c.created_date;
```

### Evidence Supporting Fraud Claims
```cypher
MATCH (c:Claim {claim_type: "Fraud"})
MATCH (ev:Evidence)-[s:SUPPORTS_CLAIM]->(c)
RETURN c.claim_text, collect(ev.name) AS evidence
ORDER BY c.severity DESC;
```

### Andy Garcia's Activity
```cypher
MATCH (p:Party {name: "Andy Garcia"})
OPTIONAL MATCH (p)-[:CREATED]->(ev1)
OPTIONAL MATCH (p)-[:MODIFIED]->(ev2)
OPTIONAL MATCH (p)-[:PARTY_INVOLVED_IN]->(e)
RETURN count(ev1) AS created,
       count(ev2) AS modified,
       count(e) AS events;
```

### Files at Specific Location
```cypher
MATCH (loc:Location)
WHERE loc.path CONTAINS "2021 Initial Permit"
MATCH (ev:Evidence)-[:LOCATED_IN]->(loc)
RETURN ev.name, ev.evidence_type;
```

### Batch Operations on 2026-01-09
```cypher
MATCH (e:Event {event_type: "FileModification"})
WHERE e.date >= datetime("2026-01-09T00:00:00Z")
  AND e.date <= datetime("2026-01-09T23:59:59Z")
RETURN e.name, e.date;
```

---

## Python Commands Cheat Sheet

### Initialization
```bash
python GRAPH_INITIALIZATION_SCRIPT.py --password PASSWORD
```

### Document Ingestion
```bash
# Single document (edit script first)
python DOCUMENT_INGESTION_TEMPLATE.py --password PASSWORD

# Batch from directory
python DOCUMENT_INGESTION_TEMPLATE.py \
  --password PASSWORD \
  --document-dir ./documents \
  --document-type Report \
  --extension .pdf
```

### Visualizations
```bash
# All visualizations
python GRAPH_VISUALIZATION_GENERATOR.py --password PASSWORD --output-dir ./viz

# Specific visualization
python GRAPH_VISUALIZATION_GENERATOR.py --password PASSWORD --mode timeline
```

### Utilities
```bash
# Database status
python neo4j_utils.py --password PASSWORD status

# Graph statistics
python neo4j_utils.py --password PASSWORD stats

# Export to JSON
python neo4j_utils.py --password PASSWORD export --output graph.json

# Validate integrity
python neo4j_utils.py --password PASSWORD validate

# Find conflicts
python neo4j_utils.py --password PASSWORD conflicts
```

---

## Neo4j Browser Shortcuts

**Open Browser**: http://localhost:7474

**Useful Commands**:
```cypher
// Show all node labels
CALL db.labels();

// Show all relationship types
CALL db.relationshipTypes();

// Count all nodes
MATCH (n) RETURN count(n);

// Show graph schema
CALL db.schema.visualization();

// Clear result cache
:clear;
```

---

## Node Properties Quick Reference

### Party
- `name` (String): Full name
- `role` (String): Plaintiff | Defendant | Architect | Software
- `entity_type` (String): Person | Organization | Software
- `uuid` (String): Unique identifier

### Evidence
- `name` (String): Filename
- `evidence_type` (String): DWG | RVT | Email | Contract | Photo
- `file_path` (String): Full path
- `sha256` (String): Hash
- `acquisition_date` (Datetime): When collected
- `uuid` (String): Unique identifier

### Event
- `name` (String): Event description
- `event_type` (String): Meeting | Approval | FileModification | Litigation
- `date` (Datetime): When occurred
- `significance` (String): Critical | High | Medium | Low
- `uuid` (String): Unique identifier

### Claim
- `claim_text` (String): Full claim statement
- `claim_type` (String): Fraud | ContractViolation | Negligence
- `alleged_by` (String): Party name
- `alleged_against` (String): Party name
- `status` (String): Active | Dismissed | Proven | Disproven
- `severity` (String): Critical | High | Medium | Low
- `uuid` (String): Unique identifier

---

## Relationship Types Quick Reference

### CREATED
`(Party) -[CREATED]-> (Evidence)`
- Properties: `created_date`, `confidence`, `source`

### MODIFIED
`(Party) -[MODIFIED]-> (Evidence)`
- Properties: `modification_date`, `modification_type`, `confidence`

### SUPPORTS_CLAIM
`(Evidence | Document | Event) -[SUPPORTS_CLAIM]-> (Claim)`
- Properties: `strength` (Strong | Moderate | Weak), `relevance`

### CONTRADICTS_CLAIM
`(Evidence | Document | Event) -[CONTRADICTS_CLAIM]-> (Claim)`
- Properties: `strength` (Strong | Moderate | Weak), `relevance`

### LOCATED_IN
`(Evidence) -[LOCATED_IN]-> (Location)`
- Properties: `discovered_date`, `still_present`

### PARTY_INVOLVED_IN
`(Party) -[PARTY_INVOLVED_IN]-> (Event)`
- Properties: `role_in_event`

### OCCURRED_ON
`(Event) -[OCCURRED_ON]-> (Timeline)`

### REFERENCES
`(Document) -[REFERENCES]-> (Evidence | Party | Event | Claim)`
- Properties: `reference_type`, `page_number`, `context`

### DEPENDS_ON
`(Event) -[DEPENDS_ON]-> (Event)`
- Properties: `dependency_type` (HappenedAfter | CausedBy | EnabledBy)

---

## Troubleshooting

### Can't Connect
1. Check Neo4j is running: Neo4j Desktop or `docker ps`
2. Verify password is correct
3. Default URI: `bolt://localhost:7687`

### Query Too Slow
1. Add `LIMIT 100` to query
2. Use `EXPLAIN` prefix to see query plan
3. Verify indexes exist: `SHOW INDEXES;`

### Visualization Fails
```bash
pip install matplotlib networkx Pillow
```

### Import Errors
```bash
pip install neo4j PyPDF2
```

---

## Example Workflows

### Deposition Prep for Andy Garcia
```bash
# 1. Get complete profile
python neo4j_utils.py --password PASSWORD stats

# 2. Query activity in Neo4j Browser
MATCH (p:Party {name: "Andy Garcia"})
OPTIONAL MATCH (p)-[r]->(target)
RETURN type(r), labels(target)[0], target.name, r;

# 3. Generate activity chart
python GRAPH_VISUALIZATION_GENERATOR.py \
  --password PASSWORD \
  --mode party \
  --party "Andy Garcia"
```

### Settlement Negotiation Prep
```bash
# 1. Get claim strength
MATCH (c:Claim {alleged_by: "Kara Murphy"})
MATCH (ev:Evidence)-[s:SUPPORTS_CLAIM]->(c)
RETURN c.claim_text, count(ev) AS support_count
ORDER BY support_count DESC;

# 2. Find smoking guns
MATCH (c:Claim)<-[s:SUPPORTS_CLAIM {strength: "Strong"}]-(ev:Evidence)
WHERE NOT EXISTS { MATCH (ev)-[:CONTRADICTS_CLAIM]->(c) }
RETURN c.claim_text, collect(ev.name);

# 3. Generate visualization
python GRAPH_VISUALIZATION_GENERATOR.py \
  --password PASSWORD \
  --mode claims
```

### Expert Testimony Prep
```bash
# 1. Export timeline
python GRAPH_VISUALIZATION_GENERATOR.py \
  --password PASSWORD \
  --mode timeline

# 2. Export complete graph
python neo4j_utils.py \
  --password PASSWORD \
  export --output expert_testimony_graph.json

# 3. Validate integrity
python neo4j_utils.py --password PASSWORD validate
```

---

## File Locations

**All scripts**: `NEO4J_SETUP/`
- `GRAPH_INITIALIZATION_SCRIPT.py` - Initial setup
- `DOCUMENT_INGESTION_TEMPLATE.py` - Add documents
- `GRAPH_VISUALIZATION_GENERATOR.py` - Create images
- `neo4j_utils.py` - Maintenance utilities
- `NEO4J_SCHEMA.txt` - Schema documentation
- `NEO4J_CYPHER_QUERIES.txt` - Full query library

**Documentation**:
- `README.md` - Comprehensive guide
- `QUICK_REFERENCE.md` - This file

**Outputs**:
- `visualizations/` - Generated graphs (PNG)
- `*.json` - Exported graph data

---

## Security Notes

- Change default Neo4j password immediately
- Restrict database access to litigation team only
- Evidence contains attorney work product (privileged)
- Export files to encrypted storage
- Use VPN when accessing remotely

---

## Support Resources

- Neo4j Browser: http://localhost:7474
- Neo4j Docs: https://neo4j.com/docs/
- Cypher Manual: https://neo4j.com/docs/cypher-manual/
- Graph Data Science: https://neo4j.com/docs/graph-data-science/

---

**Last Updated**: 2026-01-30
**Case**: Kara Murphy vs Danny Garcia
**Confidential**: Attorney Work Product
