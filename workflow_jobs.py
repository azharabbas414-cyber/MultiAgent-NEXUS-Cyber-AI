"""Thread-safe workflow job registry kept outside the Streamlit script module.

Streamlit reruns the app script; module-level globals in app.py are recreated on
each rerun. This module remains cached by Python, so background workflow state
survives Streamlit reruns while the UI polls it.
"""
from __future__ import annotations

import threading
import uuid
from typing import Any

from workflow import run_workflow
from agents import AGENT_NAMES

_JOBS: dict[str, dict[str, Any]] = {}
_LOCK = threading.Lock()


def create_job(df: Any, incident_id: str, llm_config: dict[str, str]) -> str:
    job_id = uuid.uuid4().hex
    with _LOCK:
        _JOBS[job_id] = {
            "status": "running",
            "current_agent": "",
            "detail": "Starting investigation",
            "completed_steps": 0,
            "total_steps": 5,
            "statuses": {name: "Waiting" for name in AGENT_NAMES},
            "result": None,
            "error": None,
        }

    def update_status(agent_name: str, status: str, detail: str) -> None:
        with _LOCK:
            job = _JOBS.get(job_id)
            if not job:
                return
            job["statuses"][agent_name] = status
            job["detail"] = detail
            if status == "WORKING":
                job["current_agent"] = agent_name
            elif status == "Completed" and job["current_agent"] == agent_name:
                job["current_agent"] = ""
            if status == "Completed":
                order = {name: i + 1 for i, name in enumerate(AGENT_NAMES)}
                job["completed_steps"] = max(job["completed_steps"], order.get(agent_name, 0))

    def worker() -> None:
        try:
            if not llm_config.get("api_key"):
                raise ValueError(
                    "GROK_API_KEY is not configured in Streamlit Secrets. "
                    "Add GROK_API_KEY before starting the AI investigation."
                )
            result = run_workflow(df, incident_id, update_status, llm_config=llm_config)
            with _LOCK:
                job = _JOBS.get(job_id)
                if job:
                    job["result"] = result
                    job["status"] = "completed"
                    job["completed_steps"] = 5
                    job["current_agent"] = ""
                    job["detail"] = "Investigation complete"
                    job["statuses"] = result.get("statuses", job["statuses"])
        except Exception as exc:
            with _LOCK:
                job = _JOBS.get(job_id)
                if job:
                    job["status"] = "failed"
                    job["error"] = f"{type(exc).__name__}: {exc}"
                    job["detail"] = "Workflow failed"

    thread = threading.Thread(target=worker, name=f"nexus-workflow-{job_id[:8]}", daemon=True)
    thread.start()
    return job_id


def get_snapshot(job_id: str | None) -> dict[str, Any] | None:
    if not job_id:
        return None
    with _LOCK:
        job = _JOBS.get(job_id)
        if job is None:
            return None
        return {
            "status": job["status"],
            "current_agent": job["current_agent"],
            "detail": job["detail"],
            "completed_steps": job["completed_steps"],
            "total_steps": job["total_steps"],
            "statuses": dict(job["statuses"]),
            "result": job["result"],
            "error": job["error"],
        }
