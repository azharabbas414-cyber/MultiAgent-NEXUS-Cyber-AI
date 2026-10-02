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
The Streamlit SOC Investigation page runs the CrewAI Flow in a background worker and polls a thread-safe job registry. The worker never calls Streamlit APIs, preventing `NoSessionContext` errors caused by UI calls from CrewAI execution contexts.
