# NEXUS Cyber AI

Network EXpert Unified Security — a human-controlled, read-only multi-agent SOC analysis platform.

## AI providers

NEXUS supports interchangeable AI backends without changing the five SOC agents:

- **Groq** — cloud API; existing provider.
- **Gemini** — Google Gemini API through its OpenAI-compatible endpoint. Google documents this compatibility layer officially. The default NEXUS model is `gemini-3.1-flash-lite`; free-tier availability and quotas are subject to Google's current limits.
- **Ollama** — local OpenAI-compatible API. No cloud API key is required; the model runs on your own machine/server.

The Streamlit **SOC Investigation** page has an **AI Provider** selector. You can also set `AI_PROVIDER` in Streamlit Secrets.

### Gemini Streamlit Secrets

```toml
AI_PROVIDER = "gemini"
GEMINI_API_KEY = "your_gemini_api_key"
GEMINI_MODEL = "gemini-3.1-flash-lite"
GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai/"
```

### Groq Streamlit Secrets

```toml
AI_PROVIDER = "groq"
GROK_API_KEY = "your_groq_api_key"
GROK_MODEL = "openai/gpt-oss-120b"
GROK_BASE_URL = "https://api.groq.com/openai/v1"
```

### Ollama local configuration

```toml
AI_PROVIDER = "ollama"
OLLAMA_MODEL = "llama3.2:3b"
OLLAMA_BASE_URL = "http://localhost:11434/v1"
OLLAMA_API_KEY = "ollama"
```

Ollama must be running where NEXUS is running. It is generally not usable from Streamlit Community Cloud when Ollama is only running on your local PC because the cloud app cannot reach `localhost` on your computer.

## Safety boundary

NEXUS only analyzes supplied/synthetic data and prepares recommendations/reports. It does not SSH to production devices, change firewalls/routers/endpoints, delete accounts, block traffic, or execute consequential response actions.


## PCAP Malware & Artifact Analysis

NEXUS performs safe, offline-first artifact analysis when a PCAP is uploaded. It looks for common executable/archive/document signatures in TCP payloads, calculates SHA-256 hashes, and displays evidence without executing recovered content.

For optional exact hash-based threat labels, configure the Streamlit secret:

```toml
VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
```

Only the SHA-256 hash is sent for the optional reputation lookup; the recovered file itself is not uploaded by NEXUS. If the hash is not known, the application reports that the malware family/name is unconfirmed rather than guessing.

This feature is intentionally evidence-driven: an executable artifact is not automatically treated as malware.
