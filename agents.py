"""
NEXUS Cyber AI — Five AI Agent definitions.

Milestone 3:
- Defines the five CrewAI agents.
- Keeps each agent's role and boundaries explicit.
- Does not execute a workflow yet.
- The LLM is injected by the workflow layer later, so importing this file
  does not make an API call.
"""

from __future__ import annotations

from typing import Any

from crewai import Agent


AGENT_NAMES = [
    "SOC Orchestrator Agent",
    "Security Analysis Agent",
    "Threat Intelligence Agent",
    "Risk & Business Agent",
    "Response & Automation Agent",
]


def build_agents(llm: Any = None) -> dict[str, Agent]:
    """
    Build the five NEXUS agents.

    `llm` is optional so the project can define/test agent roles without
    contacting an external model. The workflow milestone will inject the
    configured LLM.
    """
    common = {"llm": llm} if llm is not None else {}

    orchestrator = Agent(
        role="SOC Orchestrator",
        goal=(
            "Coordinate cybersecurity investigations, understand the user's "
            "request, delegate work to the correct specialist agents, track "
            "workflow state, and ensure human approval is required before "
            "any consequential response action."
        ),
        backstory=(
            "You are the central coordinator of NEXUS Cyber AI. You do not "
            "perform specialist analysis when another agent is responsible. "
            "You organize evidence, handoffs, approvals, and final outputs."
        ),
        verbose=True,
        allow_delegation=True,
        **common,
    )

    security_analysis = Agent(
        role="Security Analysis Specialist",
        goal=(
            "Analyze security datasets, correlate events, identify suspicious "
            "patterns, reconstruct timelines, and produce evidence-based "
            "technical findings."
        ),
        backstory=(
            "You are an experienced SOC analyst. You work with authentication, "
            "firewall, IDS/IPS, endpoint, DNS, proxy, VPN, and network-security "
            "events. You distinguish observed evidence from assumptions."
        ),
        verbose=True,
        allow_delegation=False,
        **common,
    )

    threat_intelligence = Agent(
        role="Threat Intelligence Specialist",
        goal=(
            "Investigate IP addresses, domains, URLs, hashes, users, and other "
            "indicators using the available local knowledge and supplied data, "
            "then provide contextual threat findings with evidence and confidence."
        ),
        backstory=(
            "You are a threat-intelligence analyst. You correlate indicators "
            "with security events and local threat knowledge. A match is "
            "supporting evidence, not automatic proof of compromise."
        ),
        verbose=True,
        allow_delegation=False,
        **common,
    )

    risk_business = Agent(
        role="Risk & Business Impact Specialist",
        goal=(
            "Translate technical security findings into business impact by "
            "considering affected assets, services, criticality, exposure, "
            "customers, operations, and potential disruption."
        ),
        backstory=(
            "You bridge the SOC and business teams. You explain why a technical "
            "event matters to the organization and clearly separate evidence "
            "from risk interpretation."
        ),
        verbose=True,
        allow_delegation=False,
        **common,
    )

    response_automation = Agent(
        role="Response & Automation Specialist",
        goal=(
            "Prepare incident reports, investigation checklists, containment "
            "recommendations, tickets, escalation requests, management summaries, "
            "and other response artifacts while requiring human approval before "
            "consequential actions."
        ),
        backstory=(
            "You prepare safe, actionable SOC outputs. You never directly "
            "change production devices, firewalls, endpoints, accounts, or "
            "other live systems."
        ),
        verbose=True,
        allow_delegation=False,
        **common,
    )

    return {
        "orchestrator": orchestrator,
        "security_analysis": security_analysis,
        "threat_intelligence": threat_intelligence,
        "risk_business": risk_business,
        "response_automation": response_automation,
    }


def agent_status_template() -> list[dict[str, str]]:
    """Initial UI status model for the future live workflow panel."""
    return [
        {"name": name, "status": "Waiting"} for name in AGENT_NAMES
    ]
