# NEXUS Cyber AI

**NEXUS = Network EXpert Unified Security**

## Milestone 3 — Five AI Agents

Milestone 3 adds the five CrewAI agent definitions while keeping workflow execution disabled until Milestone 4.

### Five agents

1. **SOC Orchestrator Agent** — coordinates investigations, delegation, handoffs and approvals.
2. **Security Analysis Agent** — analyzes and correlates security events.
3. **Threat Intelligence Agent** — investigates indicators and threat context.
4. **Risk & Business Agent** — maps findings to business impact.
5. **Response & Automation Agent** — prepares response artifacts and recommendations.

### Safety boundary

Agents do not directly:
- SSH to production devices
- change firewall/router configuration
- modify production endpoints
- delete accounts
- automatically block indicators
- execute irreversible response actions

The workflow will remain human-controlled.

### UI requirement

The final multi-agent UI will show:
- all five agents
- current status of each agent
- currently working agent
- workflow handoffs
- task/progress information
- human approval state

The live working-agent panel is connected in Milestone 4 when the actual CrewAI workflow is introduced.

### Run

```bash
pip install -r requirements.txt
streamlit run app.py
```
