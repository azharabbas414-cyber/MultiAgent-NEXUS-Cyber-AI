"""NEXUS Cyber AI — Milestone 4 multi-agent SOC workflow.

The workflow is deliberately structured and human-controlled:
1. Investigation Coordinator
2. Security Analysis
3. Threat Intelligence
4. Risk & Business
5. Response & Automation

No agent performs a live network or endpoint action. The final stage only
prepares response artifacts for human approval.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable

from crewai import Crew, LLM, Process, Task
from crewai.flow.flow import Flow, listen, start
from pydantic import BaseModel, Field

from agents import build_agents


StatusCallback = Callable[[str, str, str], None]


class NexusWorkflowState(BaseModel):
    incident_id: str = ""
    incident_context: str = ""
    knowledge_context: str = ""
    orchestrator_result: str = ""
    security_result: str = ""
    threat_result: str = ""
    risk_result: str = ""
    response_result: str = ""
    final_report: str = ""
    statuses: dict[str, str] = Field(default_factory=dict)
    completed_steps: int = 0
    total_steps: int = 5


def build_llm(config: dict[str, str] | None = None) -> LLM:
    """Build an OpenAI-compatible LLM. Secrets are supplied by the UI thread."""
    config = config or {}
    api_key = config.get("api_key") or os.getenv("GROK_API_KEY") or os.getenv("GROQ_API_KEY")
    if not api_key:
        raise ValueError(
            "GROK_API_KEY is not configured. Add it to Streamlit Secrets "
            "before running the AI workflow."
        )
    model = config.get("model") or os.getenv("GROK_MODEL", "openai/gpt-oss-120b")
    base_url = config.get("base_url") or os.getenv("GROK_BASE_URL", "https://api.groq.com/openai/v1")

    # CrewAI's custom_openai mode strips one leading ``openai/`` prefix
    # before sending the request. Groq's GPT-OSS model ID itself requires
    # that prefix, so preserve it on the wire by adding one extra prefix.
    # This turns ``openai/gpt-oss-120b`` into ``openai/openai/gpt-oss-120b``
    # for CrewAI, which then sends the required ``openai/gpt-oss-120b``.
    if "api.groq.com/openai/v1" in base_url and model == "openai/gpt-oss-120b":
        model = "openai/openai/gpt-oss-120b"
    elif "api.groq.com/openai/v1" in base_url and model == "gpt-oss-120b":
        model = "openai/openai/gpt-oss-120b"

    return LLM(
        model=model,
        custom_openai=True,
        base_url=base_url,
        api_key=api_key,
        temperature=0.1,
        max_tokens=1200,
    )


def _text(value: Any) -> str:
    """Convert CrewAI output to clean text."""
    if value is None:
        return ""
    if hasattr(value, "raw"):
        return str(value.raw)
    return str(value)


def _clip(value: Any, max_chars: int = 2400) -> str:
    """Bound text passed between agents so Groq TPM limits are not exceeded."""
    text = _text(value)
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n[Context truncated for token-budget safety.]"


def _run_single_agent(agent: Any, description: str, expected_output: str, llm: LLM) -> str:
    """Run one specialist as a small Crew so each handoff is explicit."""
    task = Task(
        description=description,
        expected_output=expected_output,
        agent=agent,
    )
    crew = Crew(
        agents=[agent],
        tasks=[task],
        process=Process.sequential,
        verbose=True,
    )
    return _text(crew.kickoff())


def _knowledge_context() -> str:
    base = Path(__file__).resolve().parent / "knowledge"
    parts: list[str] = []
    for filename in [
        "incident_response.md",
        "severity_policy.md",
        "threat_intelligence.md",
        "business_risk.md",
    ]:
        path = base / filename
        if path.exists():
            parts.append(f"\n### {filename}\n{path.read_text(encoding='utf-8')}\n")
    return _clip("\n".join(parts), 3000)


def _dataset_context(df: Any, incident_id: str) -> str:
    """Create a bounded evidence payload for the selected incident."""
    if df is None or len(df) == 0:
        return "No security dataset was supplied."

    work = df.copy()
    if "incident_id" in work.columns and incident_id:
        filtered = work[work["incident_id"].astype(str) == str(incident_id)]
        if len(filtered) > 0:
            work = filtered

    # Keep prompts bounded while preserving all columns needed for analysis.
    work = work.head(100)
    records = work.where(work.notna(), None).to_dict(orient="records")
    return _clip(json.dumps(records, indent=2, default=str), 3000)


class NexusSOCFlow(Flow[NexusWorkflowState]):
    """Deterministic, auditable five-stage SOC flow."""

    def __init__(
        self,
        *,
        incident_id: str,
        incident_context: str,
        status_callback: StatusCallback | None = None,
        llm_config: dict[str, str] | None = None,
    ) -> None:
        super().__init__()
        self.status_callback = status_callback
        self.llm_config = llm_config or {}
        self.state.incident_id = incident_id
        self.state.incident_context = incident_context
        self.state.knowledge_context = _knowledge_context()
        self.state.statuses = {
            "Investigation Coordinator Agent": "Waiting",
            "Security Analysis Agent": "Waiting",
            "Threat Intelligence Agent": "Waiting",
            "Risk & Business Agent": "Waiting",
            "Response & Automation Agent": "Waiting",
        }

    def _status(self, agent_name: str, status: str, detail: str = "") -> None:
        self.state.statuses[agent_name] = status
        if self.status_callback:
            self.status_callback(agent_name, status, detail)

    @start()
    def orchestrate(self) -> str:
        agent_name = "Investigation Coordinator Agent"
        self._status(agent_name, "WORKING", "Understanding the incident and planning the investigation")
        self._llm = build_llm(self.llm_config)
        agents = build_agents(self._llm)
        self._agents = agents
        result = _run_single_agent(
            agents["orchestrator"],
            f"""
You are the Investigation Coordinator for NEXUS Cyber AI.

Incident ID: {self.state.incident_id}
Security evidence:
{_clip(self.state.incident_context, 2200)}

Local NEXUS knowledge:
{_clip(self.state.knowledge_context, 2200)}

Create a concise investigation plan for the next four specialist stages.
Identify the key questions, evidence that must be checked, and expected handoffs.
Do not invent facts and do not perform any response action.
""",
            "A concise investigation plan with evidence-based questions and four specialist handoffs.",
            self._llm,
        )
        self.state.orchestrator_result = result
        self.state.completed_steps = 1
        self._status(agent_name, "Completed", "Investigation plan created")
        return result

    @listen(orchestrate)
    def security_analysis(self, orchestrator_result: str) -> str:
        agent_name = "Security Analysis Agent"
        self._status(agent_name, "WORKING", "Correlating events and reconstructing the incident timeline")
        result = _run_single_agent(
            self._agents["security_analysis"],
            f"""
Analyze the selected cybersecurity incident using ONLY the supplied evidence.

Incident ID: {self.state.incident_id}
Evidence:
{_clip(self.state.incident_context, 2200)}

Investigation Coordinator plan:
{_clip(orchestrator_result, 2200)}

Produce:
1. Observed facts
2. Event/timeline correlation
3. Suspicious indicators or behaviors
4. Gaps/uncertainties
5. Technical conclusion

Do not claim an IOC is malicious unless the evidence supports that conclusion.
""",
            "A structured technical analysis separating observed evidence, inference, uncertainty, and conclusion.",
            self._llm,
        )
        self.state.security_result = result
        self.state.completed_steps = 2
        self._status(agent_name, "Completed", "Technical analysis completed")
        return result

    @listen(security_analysis)
    def threat_intelligence(self, security_result: str) -> str:
        agent_name = "Threat Intelligence Agent"
        self._status(agent_name, "WORKING", "Checking indicators against local threat knowledge")
        result = _run_single_agent(
            self._agents["threat_intelligence"],
            f"""
Investigate the indicators found in this incident using the supplied local knowledge.

Incident ID: {self.state.incident_id}
Evidence:
{_clip(self.state.incident_context, 2200)}

Security Analysis:
{_clip(security_result, 2200)}

Local threat intelligence knowledge:
{_clip(self.state.knowledge_context, 2200)}

For each relevant indicator, state whether it is:
- supported by local knowledge,
- unsupported/unknown, or
- contradicted by the available evidence.

Do not invent external reputation data. A knowledge match is supporting evidence,
not automatic proof of compromise.
""",
            "Indicator-by-indicator threat context with evidence and confidence/uncertainty.",
            self._llm,
        )
        self.state.threat_result = result
        self.state.completed_steps = 3
        self._status(agent_name, "Completed", "Threat context completed")
        return result

    @listen(threat_intelligence)
    def risk_business(self, threat_result: str) -> str:
        agent_name = "Risk & Business Agent"
        self._status(agent_name, "WORKING", "Mapping findings to asset and business impact")
        result = _run_single_agent(
            self._agents["risk_business"],
            f"""
Assess the technical findings from a business-risk perspective.

Incident ID: {self.state.incident_id}
Evidence:
{_clip(self.state.incident_context, 2200)}

Security Analysis:
{_clip(self.state.security_result, 2200)}

Threat Intelligence:
{_clip(threat_result, 2200)}

Relevant business-risk knowledge:
{_clip(self.state.knowledge_context, 2200)}

Produce:
1. Affected assets/services
2. Business criticality observed in the data
3. Potential operational/customer impact
4. Risk factors and uncertainty
5. Evidence-based severity rationale

Do not invent business impact that is not supported by the evidence.
""",
            "A structured business-impact assessment tied to observed assets, services, criticality and evidence.",
            self._llm,
        )
        self.state.risk_result = result
        self.state.completed_steps = 4
        self._status(agent_name, "Completed", "Business impact assessment completed")
        return result

    @listen(risk_business)
    def response_automation(self, risk_result: str) -> str:
        agent_name = "Response & Automation Agent"
        self._status(agent_name, "WORKING", "Preparing response artifacts for human approval")
        result = _run_single_agent(
            self._agents["response_automation"],
            f"""
Prepare safe SOC response artifacts. HUMAN APPROVAL IS REQUIRED.

Incident ID: {self.state.incident_id}
Evidence:
{_clip(self.state.incident_context, 2200)}

Security Analysis:
{_clip(self.state.security_result, 2200)}

Threat Intelligence:
{_clip(self.state.threat_result, 2200)}

Risk & Business:
{risk_result}

Local incident-response knowledge:
{_clip(self.state.knowledge_context, 2200)}

Produce:
1. Recommended investigation follow-ups
2. Suggested containment options for a human to review
3. Draft incident ticket summary
4. Draft management/escalation summary
5. Approval checklist

NEVER execute, simulate execution, or claim that you changed a router, firewall,
endpoint, account, SIEM rule, or other production system.
""",
            "A human-reviewable response plan, ticket draft, escalation summary and approval checklist.",
            self._llm,
        )
        self.state.response_result = result
        self.state.completed_steps = 5
        self.state.final_report = result
        self._status(agent_name, "Completed", "Response artifacts prepared; awaiting human approval")
        return result


def run_workflow(
    df: Any,
    incident_id: str,
    status_callback: StatusCallback | None = None,
    llm_config: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Run the NEXUS five-agent investigation and return all stage outputs."""
    context = _dataset_context(df, incident_id)
    flow = NexusSOCFlow(
        incident_id=incident_id,
        incident_context=context,
        status_callback=status_callback,
        llm_config=llm_config,
    )
    flow.kickoff()
    state = flow.state
    return {
        "incident_id": state.incident_id,
        "statuses": dict(state.statuses),
        "completed_steps": state.completed_steps,
        "total_steps": state.total_steps,
        "orchestrator": state.orchestrator_result,
        "security_analysis": state.security_result,
        "threat_intelligence": state.threat_result,
        "risk_business": state.risk_result,
        "response_automation": state.response_result,
        "final_report": state.final_report,
    }
