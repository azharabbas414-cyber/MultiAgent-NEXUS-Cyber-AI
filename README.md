# NEXUS Cyber AI

**NEXUS = Network EXpert Unified Security**

## Milestone 2 — Data Sources & Data Inspection

This milestone extends the fresh Milestone 1 foundation with a Streamlit-based data layer.

### Current capabilities

- Local CSV upload
- Local Excel upload
- Local JSON upload
- Public direct URL loading
- Public Google Drive file loading
- Automatic file-format detection
- Security-field detection
- Common security-column standardization
- Data-quality inspection
- Security dataset confidence indicator
- Dataset preview
- Built-in sample-data test

### Supported security-field normalization

Examples:

```text
src_ip / source_address / SourceIP
        ↓
    source_ip

username / usr / User
        ↓
       user

hostname / host / Host_Name
        ↓
      asset

priority / alert_severity
        ↓
     severity
```

### Google Sheets

Google Sheets is intentionally **not implemented in Milestone 2**. It will be added after the current data-source flow is validated.

### Run

```bash
pip install -r requirements.txt
streamlit run app.py
```

### Safety

No live network/device integration is present. Data processing is read-only and intended for synthetic/demo security data.
