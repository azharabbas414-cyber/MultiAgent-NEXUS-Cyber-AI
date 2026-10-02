"""NEXUS Cyber AI configuration."""

APP_NAME = "NEXUS Cyber AI"
APP_FULL_NAME = "Network EXpert Unified Security"
GROK_API_KEY_ENV = "GROK_API_KEY"
GROQ_API_KEY_ENV = "GROQ_API_KEY"
GROK_MODEL_ENV = "GROK_MODEL"
GROK_BASE_URL_ENV = "GROK_BASE_URL"
DEFAULT_GROK_MODEL = "openai/gpt-oss-120b"
DEFAULT_GROK_BASE_URL = "https://api.groq.com/openai/v1"

SAMPLE_DATA_PATH = "data/sample_data/security_data.csv"
KNOWLEDGE_PATH = "knowledge"

SUPPORTED_EXTENSIONS = [".csv", ".xlsx", ".xls", ".json", ".pcap", ".pcapng", ".cap"]
SECURITY_FIELDS = [
    "timestamp", "event_id", "event_type", "source_ip", "destination_ip",
    "user", "asset", "severity", "action", "indicator", "threat_type",
    "business_service", "business_criticality", "incident_id"
]
