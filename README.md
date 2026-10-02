# NEXUS Cyber AI

**NEXUS = Network EXpert Unified Security**

## Milestone 4 — Multi-Agent SOC Workflow

Milestone 4 connects the five CrewAI agents into a structured, sequential investigation flow:

1. SOC Orchestrator
2. Security Analysis
3. Threat Intelligence
4. Risk & Business
5. Response & Automation

The Streamlit UI shows the current agent, status, progress and handoffs while the workflow runs.

## Model configuration

The workflow uses an OpenAI-compatible endpoint and defaults to Groq's `openai/gpt-oss-120b` model. CrewAI's current documentation supports custom OpenAI-compatible endpoints through `custom_openai=True` and `base_url`.

Streamlit Secrets:

```toml
GROK_API_KEY = "your_groq_api_key"
```

Optional:

```toml
GROK_MODEL = "openai/gpt-oss-120b"

Note: the workflow internally compensates for CrewAI custom_openai prefix handling so Groq receives the exact model ID `openai/gpt-oss-120b`.
GROK_BASE_URL = "https://api.groq.com/openai/v1"
```

## Safety boundary

NEXUS is read-only and human-controlled. Agents do not directly:
- SSH to production devices
- change firewall/router configuration
- modify production endpoints
- delete accounts
- automatically block indicators
- execute irreversible response actions

The Response & Automation Agent only prepares response artifacts for human review.

## Run

```bash
python3 -m pip install -r requirements.txt
python3 -m streamlit run app.py
```


### Streamlit/CrewAI execution note
The Streamlit SOC Investigation page runs the CrewAI Flow in a background worker and polls a thread-safe job registry stored in a separate imported module. This is important because Streamlit reruns `app.py`, which would otherwise recreate module-level job state. Streamlit secrets are read on the UI thread and passed into the worker; the worker never calls Streamlit APIs.


Milestone 4 v4: bounded inter-agent context and reduced output token budget to stay within Groq TPM limits.


## Milestone 5 — SOC Dashboard

Milestone 5 adds the operational Streamlit SOC experience on top of the verified Milestone 4 workflow:

- SOC Dashboard with security-event, incident, severity and asset KPIs
- Severity and event-type visualizations
- Data Inspector incident summary with evidence-oriented dataset inspection
- AI SOC Command Center replacing the old static agent-definition page
- Live agent status and latest investigation outputs
- Existing Data Sources, Data Inspector and SOC Investigation preserved
- Separate Incidents page removed to avoid duplicating SOC Investigation
- Human approval remains required for consequential response actions

No production network/device/endpoint changes are executed by NEXUS.


### PCAP investigation
NEXUS can ingest PCAP/PCAPNG packet data. During AI investigation, packet rows are reduced to deterministic network-intelligence summaries and representative evidence before being passed to the five agents. This avoids sending thousands of raw packet rows into every agent prompt.
