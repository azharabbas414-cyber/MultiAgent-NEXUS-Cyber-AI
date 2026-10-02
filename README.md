# NEXUS Cyber AI

**NEXUS = Network EXpert Unified Security**

NEXUS Cyber AI is a multi-agent AI cybersecurity and SOC automation platform designed for safe, human-controlled security analysis and workflow automation.

## Milestone 1 — Project Foundation + Sample Data

This is the **fresh official project base**. The project intentionally starts with a simple structure so later functionality can be added without unnecessary complexity.

### Project structure

```text
NEXUS-Cyber-AI/
│
├── app.py
├── agents.py
├── workflow.py
├── data_loader.py
├── config.py
├── requirements.txt
├── README.md
├── .gitignore
│
├── data/
│   └── sample_data/
│       └── security_data.csv
│
└── knowledge/
    ├── incident_response.md
    ├── severity_policy.md
    ├── threat_intelligence.md
    └── business_risk.md
```

## Safety design

NEXUS is designed for human-controlled cybersecurity automation.

The planned system will:
- analyze security data
- correlate events
- investigate indicators
- use local knowledge
- assess business impact
- prepare reports and response recommendations
- request human approval before response actions

The planned system will **not** directly:
- SSH to production devices
- change firewall/router configuration
- delete accounts
- isolate production endpoints
- remove malware from live systems
- automatically block indicators in production

## Run locally

Install dependencies:

```bash
pip install -r requirements.txt
```

Start Streamlit:

```bash
streamlit run app.py
```

## API key

The API key will be introduced in a later milestone. Never commit a real API key to GitHub.

For local development, a future `.env` file will use:

```env
GROK_API_KEY=your_key_here
```

## Milestone roadmap

1. Project Foundation + Sample Data — **current**
2. Data Sources / Data Loader
3. Five AI Agents
4. CrewAI Workflow
5. Streamlit Dashboard
6. Testing and end-to-end scenarios
7. GitHub and Streamlit Community Cloud deployment
