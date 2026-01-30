# Neo4j Knowledge Graph - Installation Guide
## Kara Murphy vs Danny Garcia Litigation Case

This guide walks you through complete setup from scratch to a fully operational knowledge graph.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Neo4j Installation](#neo4j-installation)
3. [Python Environment Setup](#python-environment-setup)
4. [Graph Initialization](#graph-initialization)
5. [Verification](#verification)
6. [Next Steps](#next-steps)
7. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements
- **Operating System**: Windows 10/11, macOS, or Linux
- **RAM**: Minimum 4GB (8GB recommended for large graphs)
- **Disk Space**: 2GB for Neo4j + graph data
- **Python**: 3.8 or higher

### Required Software
- Neo4j Database (Community or Enterprise Edition)
- Python 3.8+
- pip (Python package manager)

---

## Neo4j Installation

### Option 1: Neo4j Desktop (Recommended for Litigation Team)

Neo4j Desktop provides a user-friendly GUI for managing databases.

**Step 1: Download**
1. Go to: https://neo4j.com/download/
2. Select "Neo4j Desktop"
3. Fill out form and download installer
4. Run installer and follow prompts

**Step 2: Create Database**
1. Launch Neo4j Desktop
2. Click "New Project" (name it "Kara Murphy vs Danny Garcia")
3. Click "Add Database" -> "Create Local Database"
4. Set database name: "litigation-kg"
5. Set password (IMPORTANT: Remember this password)
6. Click "Create"

**Step 3: Start Database**
1. Click "Start" button next to "litigation-kg"
2. Wait for status to show "Active"
3. Note the connection details:
   - **Bolt URL**: bolt://localhost:7687
   - **HTTP URL**: http://localhost:7474
   - **Username**: neo4j
   - **Password**: (your password)

**Step 4: Open Neo4j Browser**
1. Click "Open" button
2. Browser opens at http://localhost:7474
3. Login with username: `neo4j`, password: (your password)

### Option 2: Neo4j Docker (For Technical Users)

If you prefer Docker:

```bash
# Pull Neo4j image
docker pull neo4j:latest

# Run Neo4j container
docker run -d \
  --name neo4j-litigation \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/your_secure_password \
  -v $HOME/neo4j/data:/data \
  -v $HOME/neo4j/logs:/logs \
  neo4j:latest

# Check container is running
docker ps | grep neo4j-litigation

# View logs
docker logs neo4j-litigation
```

Access Neo4j Browser at: http://localhost:7474

### Option 3: Neo4j Community Server (Linux/Server Deployment)

```bash
# Ubuntu/Debian
wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
echo 'deb https://debian.neo4j.com stable latest' | sudo tee -a /etc/apt/sources.list.d/neo4j.list
sudo apt-get update
sudo apt-get install neo4j

# Set password
sudo neo4j-admin set-initial-password your_secure_password

# Start Neo4j
sudo systemctl start neo4j
sudo systemctl enable neo4j

# Check status
sudo systemctl status neo4j
```

---

## Python Environment Setup

### Step 1: Verify Python Installation

```bash
python --version
# Should show: Python 3.8.x or higher

# If not installed, download from: https://www.python.org/downloads/
```

### Step 2: Create Virtual Environment (Optional but Recommended)

```bash
# Navigate to NEO4J_SETUP directory
cd C:\Users\JordanEhrig\Documents\GitHub\DWG-forensic-tool\NEO4J_SETUP

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate
```

### Step 3: Install Python Dependencies

```bash
# Core dependency (required)
pip install neo4j

# Document ingestion (optional, for PDF parsing)
pip install PyPDF2

# Visualization (optional, for graph images)
pip install matplotlib networkx Pillow

# Install all at once
pip install neo4j PyPDF2 matplotlib networkx Pillow
```

### Step 4: Verify Installation

```bash
python -c "import neo4j; print('Neo4j driver version:', neo4j.__version__)"
python -c "import PyPDF2; print('PyPDF2 installed')"
python -c "import matplotlib; print('Matplotlib installed')"
python -c "import networkx; print('NetworkX installed')"
```

---

## Graph Initialization

### Step 1: Test Connection

```bash
# Test Neo4j connection
python neo4j_utils.py --password your_password status
```

Expected output:
```
[OK] Connected to Neo4j at bolt://localhost:7687
==============================
Neo4j Database Status
==============================
  Database: neo4j
  Version: 5.x.x
  Edition: community
...
```

If you see errors, verify:
- Neo4j is running (check Neo4j Desktop or `docker ps`)
- Password is correct
- Port 7687 is not blocked by firewall

### Step 2: Initialize Graph Schema

```bash
# Run initialization script
python GRAPH_INITIALIZATION_SCRIPT.py --password your_password
```

This script will:
1. Create all constraints and indexes (8 unique constraints, 11 indexes)
2. Load 4 parties (Kara Murphy, Danny Garcia, Andy Garcia, ODA SDK)
3. Load 5 locations (directories, cloud storage, physical address)
4. Load 3 timelines (2021 permit, 2022 construction, 2026 forensic)
5. Load evidence files (Lane.rvt, DWG files)
6. Load 4 events (file creations, batch conversion, forensic analysis)
7. Load 4 fraud claims
8. Create relationships between entities
9. Verify graph structure

Expected output:
```
[->] Creating constraints and indexes...
  [OK] CREATE CONSTRAINT party_uuid_unique
  ...
[->] Loading parties...
  [OK] Created Party: Kara Murphy (Plaintiff)
  ...
[->] Creating relationships...
  [OK] Andy Garcia -[CREATED]-> Lane.rvt
  ...
[OK] Graph initialization complete
```

### Step 3: Verify Graph Contents

```bash
# Get statistics
python neo4j_utils.py --password your_password stats
```

Expected node counts:
- Party: 4
- Location: 5
- Timeline: 3
- Evidence: 4+ (depending on how many files you added)
- Event: 4
- Claim: 4

Expected relationship counts:
- CREATED: 2+
- PARTY_INVOLVED_IN: 1+
- LOCATED_IN: 1+
- OCCURRED_ON: 1+
- SUPPORTS_CLAIM: 1+
- DEPENDS_ON: 1+

---

## Verification

### Test 1: Query Evidence Timeline

Open Neo4j Browser (http://localhost:7474) and run:

```cypher
MATCH (ev:Evidence)
OPTIONAL MATCH (ev)<-[c:CREATED]-(creator:Party)
RETURN ev.name AS Evidence, c.created_date AS Created, creator.name AS Creator
ORDER BY c.created_date;
```

Expected: List of evidence files with creation dates and creators.

### Test 2: Query Claim Support

```cypher
MATCH (c:Claim {claim_type: "Fraud"})
OPTIONAL MATCH (ev:Evidence)-[s:SUPPORTS_CLAIM]->(c)
RETURN c.claim_text AS Claim, collect(ev.name) AS SupportingEvidence;
```

Expected: Fraud claims with associated evidence.

### Test 3: Generate Visualization

```bash
# Create output directory
mkdir visualizations

# Generate timeline visualization
python GRAPH_VISUALIZATION_GENERATOR.py \
  --password your_password \
  --mode timeline \
  --output-dir ./visualizations
```

Expected: PNG file in `visualizations/evidence_timeline.png`

### Test 4: Validate Graph Integrity

```bash
python neo4j_utils.py --password your_password validate
```

Expected: No critical integrity issues (some warnings about missing relationships are normal for initial graph).

---

## Next Steps

### 1. Load Additional Documents

```bash
# Create directory for case documents
mkdir case_documents

# Copy PDFs to directory, then:
python DOCUMENT_INGESTION_TEMPLATE.py \
  --password your_password \
  --document-dir ./case_documents \
  --document-type Report
```

### 2. Generate All Visualizations

```bash
python GRAPH_VISUALIZATION_GENERATOR.py \
  --password your_password \
  --output-dir ./visualizations
```

### 3. Explore Query Templates

Open `NEO4J_CYPHER_QUERIES.txt` and try example queries in Neo4j Browser.

### 4. Add Custom Entities

Edit `GRAPH_INITIALIZATION_SCRIPT.py` to add:
- Additional parties (expert witnesses, opposing counsel, etc.)
- More evidence files
- Email correspondence
- Deposition transcripts
- Court filings

Rerun the script to add new entities.

### 5. Set Up Access Controls

In Neo4j Browser:

```cypher
// Create read-only user for litigation team
CREATE USER litigation_team SET PASSWORD 'secure_password' CHANGE NOT REQUIRED;
GRANT TRAVERSE ON GRAPH * NODES * TO litigation_team;
GRANT READ {*} ON GRAPH * NODES * TO litigation_team;

// Create admin user for case lead
CREATE USER case_admin SET PASSWORD 'admin_password' CHANGE NOT REQUIRED;
GRANT ALL DATABASE PRIVILEGES ON DATABASE * TO case_admin;
```

---

## Troubleshooting

### Issue: "Connection refused" error

**Cause**: Neo4j is not running or port is blocked.

**Solution**:
1. Check Neo4j Desktop shows "Active" status
2. For Docker: `docker ps | grep neo4j`
3. Check firewall allows port 7687
4. Try: `telnet localhost 7687`

### Issue: "Authentication failed"

**Cause**: Incorrect password.

**Solution**:
1. Verify password in Neo4j Desktop settings
2. For Docker: Check `-e NEO4J_AUTH=neo4j/password` in docker run command
3. Reset password in Neo4j Desktop: Database Settings -> Reset Password

### Issue: "ModuleNotFoundError: No module named 'neo4j'"

**Cause**: Python driver not installed.

**Solution**:
```bash
pip install neo4j
# If using virtual environment, make sure it's activated
```

### Issue: "Constraint already exists" during initialization

**Cause**: Script was run multiple times.

**Solution**:
```bash
# Either:
# 1. Clear graph and reinitialize
python neo4j_utils.py --password your_password clear --confirm

# 2. Or ignore the errors (script will continue)
```

### Issue: Visualizations fail with "module not found"

**Cause**: Visualization libraries not installed.

**Solution**:
```bash
pip install matplotlib networkx Pillow
```

### Issue: PyPDF2 extraction fails

**Cause**: Some PDFs are encrypted or image-based.

**Solution**:
1. Use Adobe Acrobat to remove encryption
2. Use OCR for image-based PDFs
3. Manually enter document metadata instead

### Issue: Graph is empty after initialization

**Cause**: Script failed silently or database connection issue.

**Solution**:
1. Check script output for errors
2. Verify with: `python neo4j_utils.py --password your_password stats`
3. Check Neo4j logs in Neo4j Desktop: Database -> Logs

---

## Performance Optimization

### For Large Graphs (1000+ nodes)

1. **Increase Neo4j Memory**:
   - Neo4j Desktop: Database Settings -> Memory -> Increase heap size to 2GB
   - Docker: Add `-e NEO4J_dbms_memory_heap_max__size=2G`

2. **Use Query Limits**:
   ```cypher
   MATCH (n) RETURN n LIMIT 100;
   ```

3. **Create Additional Indexes**:
   ```cypher
   CREATE INDEX evidence_acquisition_idx IF NOT EXISTS
   FOR (ev:Evidence) ON (ev.acquisition_date);
   ```

4. **Monitor Query Performance**:
   ```cypher
   PROFILE MATCH (ev:Evidence) RETURN ev;
   ```

---

## Backup and Recovery

### Backup Graph

```bash
# Export to JSON
python neo4j_utils.py --password your_password export --output backup_$(date +%Y%m%d).json

# Neo4j Desktop: Tools -> Backup
# Docker:
docker exec neo4j-litigation neo4j-admin dump --to=/backups/litigation.dump
```

### Restore Graph

```bash
# From JSON export (requires custom script)
# From Neo4j dump:
docker exec neo4j-litigation neo4j-admin load --from=/backups/litigation.dump --force
```

---

## Security Checklist

- [ ] Changed default Neo4j password
- [ ] Enabled Neo4j authentication
- [ ] Created role-based access users
- [ ] Restricted network access to port 7687
- [ ] Enabled SSL/TLS for production deployment
- [ ] Configured backup schedule
- [ ] Documented password in secure location (password manager)
- [ ] Set up VPN for remote access
- [ ] Encrypted export files
- [ ] Reviewed Neo4j security guide: https://neo4j.com/docs/operations-manual/current/security/

---

## Support Contacts

**Technical Issues**:
- Neo4j Community: https://community.neo4j.com/
- Neo4j Documentation: https://neo4j.com/docs/

**Case-Specific Questions**:
- Review `README.md` for comprehensive documentation
- Review `QUICK_REFERENCE.md` for common queries
- Review `NEO4J_CYPHER_QUERIES.txt` for query templates

---

## Installation Summary Checklist

- [ ] Neo4j installed and running
- [ ] Python 3.8+ installed
- [ ] Python dependencies installed (`neo4j`, `PyPDF2`, `matplotlib`, `networkx`)
- [ ] Connection test successful (`neo4j_utils.py status`)
- [ ] Graph initialized (`GRAPH_INITIALIZATION_SCRIPT.py`)
- [ ] Statistics verified (`neo4j_utils.py stats`)
- [ ] Test queries executed in Neo4j Browser
- [ ] Visualizations generated
- [ ] Backup created
- [ ] Access controls configured
- [ ] Documentation reviewed

---

**Congratulations!** Your Neo4j knowledge graph is now operational.

Next: Review `QUICK_REFERENCE.md` for common queries and workflows.

---

**Last Updated**: 2026-01-30
**Case**: Kara Murphy vs Danny Garcia
**Confidential**: Attorney Work Product
