"""NEXUS Cyber AI configuration."""

APP_NAME = "NEXUS Cyber AI"
APP_FULL_NAME = "Network EXpert Unified Security"
GROK_API_KEY_ENV = "GROK_API_KEY"

SAMPLE_DATA_PATH = "data/sample_data/security_data.csv"
KNOWLEDGE_PATH = "knowledge"

SUPPORTED_EXTENSIONS = [".csv", ".xlsx", ".xls", ".json"]
SECURITY_FIELDS = [
    "timestamp", "event_id", "event_type", "source_ip", "destination_ip",
    "user", "asset", "severity", "action", "indicator", "threat_type",
    "business_service", "business_criticality", "incident_id"
]
