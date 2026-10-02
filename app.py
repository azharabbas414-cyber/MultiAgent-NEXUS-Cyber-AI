import time
from pathlib import Path

import pandas as pd
import streamlit as st

from config import APP_NAME, APP_FULL_NAME, SAMPLE_DATA_PATH
from data_loader import load_uploaded_file, load_from_url, prepare_dataset
from agents import AGENT_NAMES, agent_status_template
from workflow_jobs import create_job, get_snapshot

st.set_page_config(page_title=APP_NAME, page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

# -----------------------------
# Styling
# -----------------------------
st.markdown(
    """
    <style>
    .block-container {padding-top: 1.2rem; padding-bottom: 2rem;}
    .nexus-title {font-size: 2.1rem; font-weight: 750; margin-bottom: 0.1rem;}
    .nexus-subtitle {color: #667085; margin-bottom: 1.1rem;}
    .section-title {font-size: 1.35rem; font-weight: 700; margin-top: .4rem; margin-bottom: .7rem;}
    .status-card {border: 1px solid #e6e8ec; border-radius: 12px; padding: 14px 16px; background: #ffffff;}
    .status-label {font-size: .82rem; color: #667085; margin-bottom: 3px;}
    .status-value {font-size: 1.25rem; font-weight: 700;}
    .agent-current {border-left: 5px solid #3b82f6; background: #eff6ff; padding: 12px 15px; border-radius: 8px;}
    .small-muted {font-size: .84rem; color: #667085;}
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown('<div class="nexus-title">🛡️ NEXUS Cyber AI</div>', unsafe_allow_html=True)
st.markdown(f'<div class="nexus-subtitle">{APP_FULL_NAME} · Human-controlled AI SOC</div>', unsafe_allow_html=True)

# -----------------------------
# Session state
# -----------------------------
def init_state():
    defaults = {
        "dataset": None,
        "dataset_name": None,
        "inspection": None,
        "source_type": None,
        "workflow_result": None,
        "workflow_job_id": None,
        "page": "SOC Dashboard",
        "selected_incident": None,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

init_state()

with st.sidebar:
    st.header("Navigation")
    page = st.radio(
        "Select module",
        ["SOC Dashboard", "Data Sources", "Data Inspector", "AI SOC Command Center", "SOC Investigation"],
        key="page",
    )
    st.divider()
    st.caption("NEXUS safety boundary")
    st.caption("AI analyzes, correlates and recommends. Humans approve consequential actions. No production changes are executed.")


def load_sample_for_dashboard() -> pd.DataFrame:
    df = pd.read_csv(SAMPLE_DATA_PATH)
    standardized, _ = prepare_dataset(df)
    return standardized


def get_dashboard_df() -> pd.DataFrame | None:
    if st.session_state.dataset is not None:
        return st.session_state.dataset
    try:
        return load_sample_for_dashboard()
    except Exception:
        return None


def severity_counts(df: pd.DataFrame) -> pd.DataFrame:
    if "severity" not in df.columns:
        return pd.DataFrame()
    order = ["critical", "high", "medium", "low", "info"]
    counts = df["severity"].astype(str).str.lower().value_counts()
    return counts.reindex(order).fillna(0).astype(int).to_frame("Events")


def agent_monitor(job_id: str | None):
    snapshot = get_snapshot(job_id) if job_id else None
    st.markdown('<div class="section-title">🤖 AI Agent Command Center</div>', unsafe_allow_html=True)
    if not snapshot:
        st.info("No investigation is currently running. Start an investigation from **SOC Investigation** to see live agent activity here.")
        cols = st.columns(5)
        for col, name in zip(cols, AGENT_NAMES):
            col.markdown(f"**{name.replace(' Agent','')}**")
            col.caption("Waiting")
        return snapshot

    cols = st.columns(5)
    for col, name in zip(cols, AGENT_NAMES):
        status = snapshot["statuses"].get(name, "Waiting")
        icon = "▶️" if status == "WORKING" else ("✅" if status == "Completed" else "⏳")
        col.markdown(f"**{name.replace(' Agent','')}**")
        col.caption(f"{icon} {status}")
    if snapshot["status"] == "running":
        current = snapshot["current_agent"] or "Preparing workflow"
        st.markdown(f'<div class="agent-current">🔵 <b>Current agent:</b> {current}<br><span class="small-muted">{snapshot["detail"]}</span></div>', unsafe_allow_html=True)
    elif snapshot["status"] == "completed":
        st.success("🏁 Investigation complete — 5/5 agents completed.")
    elif snapshot["status"] == "failed":
        st.error(f"Workflow failed: {snapshot['error']}")
    return snapshot

# -----------------------------
# SOC Dashboard
# -----------------------------
if page == "SOC Dashboard":
    st.subheader("🏠 SOC Dashboard")
    st.caption("Executive security overview of the currently loaded security dataset. The built-in synthetic dataset is shown when no custom dataset has been loaded.")

    df = get_dashboard_df()
    if df is None or df.empty:
        st.warning("No security dataset is available. Go to Data Sources to load one.")
    else:
        source_label = st.session_state.dataset_name or "Built-in synthetic dataset"
        st.caption(f"Data: **{source_label}** · {len(df):,} events")

        incidents = int(df["incident_id"].nunique()) if "incident_id" in df.columns else 0
        critical = int((df["severity"].astype(str).str.lower() == "critical").sum()) if "severity" in df.columns else 0
        high = int((df["severity"].astype(str).str.lower() == "high").sum()) if "severity" in df.columns else 0
        assets = int(df["asset"].nunique()) if "asset" in df.columns else 0

        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Security Events", f"{len(df):,}")
        c2.metric("Incidents", f"{incidents:,}")
        c3.metric("Critical Events", f"{critical:,}")
        c4.metric("High Events", f"{high:,}")
        c5.metric("Affected Assets", f"{assets:,}")

        st.divider()
        left, right = st.columns(2)
        with left:
            st.markdown('<div class="section-title">Severity Distribution</div>', unsafe_allow_html=True)
            sev = severity_counts(df)
            if not sev.empty:
                st.bar_chart(sev, horizontal=True, use_container_width=True)
        with right:
            st.markdown('<div class="section-title">Event Types</div>', unsafe_allow_html=True)
            if "event_type" in df.columns:
                et = df["event_type"].astype(str).value_counts().head(8).to_frame("Events")
                st.bar_chart(et, horizontal=True, use_container_width=True)

        st.divider()
        left, right = st.columns(2)
        with left:
            st.markdown('<div class="section-title">Top Affected Assets</div>', unsafe_allow_html=True)
            if "asset" in df.columns:
                assets_df = df["asset"].astype(str).value_counts().head(8).rename_axis("Asset").reset_index(name="Events")
                st.dataframe(assets_df, use_container_width=True, hide_index=True)
        with right:
            st.markdown('<div class="section-title">Incident Overview</div>', unsafe_allow_html=True)
            if "incident_id" in df.columns:
                inc = df.groupby("incident_id").agg(
                    Events=("event_id", "count"),
                    Highest_Severity=("severity", lambda s: ", ".join(pd.unique(s.astype(str))[:3])),
                    Assets=("asset", lambda s: ", ".join(pd.unique(s.astype(str))[:3])),
                ).reset_index().sort_values("Events", ascending=False)
                st.dataframe(inc.head(10), use_container_width=True, hide_index=True)

        st.divider()
        agent_monitor(st.session_state.workflow_job_id)

# -----------------------------
# Data Sources
# -----------------------------
elif page == "Data Sources":
    st.subheader("📥 Load Security Data")
    st.write("NEXUS can load CSV, Excel and JSON datasets.")

    source = st.radio("Data source", ["Local File", "Direct URL", "Google Drive"], horizontal=True)

    if source == "Local File":
        uploaded = st.file_uploader("Upload a CSV, Excel or JSON file", type=["csv", "xlsx", "xls", "json"])
        if uploaded is not None and st.button("Load & Inspect File", type="primary"):
            try:
                df = load_uploaded_file(uploaded)
                standardized, report = prepare_dataset(df)
                st.session_state.dataset = standardized
                st.session_state.dataset_name = uploaded.name
                st.session_state.inspection = report
                st.session_state.source_type = "Local File"
                st.success(f"Loaded {uploaded.name} successfully.")
            except Exception as exc:
                st.error(f"Could not load the file: {exc}")

    elif source == "Direct URL":
        url = st.text_input("Public file URL", placeholder="https://example.com/security_data.csv")
        if st.button("Load & Inspect URL", type="primary"):
            if not url.strip():
                st.warning("Enter a URL first.")
            else:
                try:
                    df, filename = load_from_url(url)
                    standardized, report = prepare_dataset(df)
                    st.session_state.dataset = standardized
                    st.session_state.dataset_name = filename
                    st.session_state.inspection = report
                    st.session_state.source_type = "Direct URL"
                    st.success(f"Loaded {filename} successfully.")
                except Exception as exc:
                    st.error(f"Could not load the URL: {exc}")

    else:
        drive_url = st.text_input("Public Google Drive file link", placeholder="https://drive.google.com/file/d/...")
        if st.button("Load & Inspect Google Drive File", type="primary"):
            if not drive_url.strip():
                st.warning("Enter a Google Drive link first.")
            else:
                try:
                    df, filename = load_from_url(drive_url)
                    standardized, report = prepare_dataset(df)
                    st.session_state.dataset = standardized
                    st.session_state.dataset_name = filename
                    st.session_state.inspection = report
                    st.session_state.source_type = "Google Drive"
                    st.success(f"Loaded {filename} successfully.")
                except Exception as exc:
                    st.error(f"Could not load the Google Drive file: {exc}")

    st.divider()
    st.subheader("🧪 Quick Test")
    if st.button("Load NEXUS Sample Security Dataset"):
        try:
            df = pd.read_csv(SAMPLE_DATA_PATH)
            standardized, report = prepare_dataset(df)
            st.session_state.dataset = standardized
            st.session_state.dataset_name = "security_data.csv"
            st.session_state.inspection = report
            st.session_state.source_type = "Built-in Sample"
            st.success("NEXUS sample dataset loaded successfully.")
        except Exception as exc:
            st.error(f"Could not load sample data: {exc}")

# -----------------------------
# Data Inspector
# -----------------------------
elif page == "Data Inspector":
    st.subheader("🔎 Dataset Inspector")
    if st.session_state.dataset is None:
        st.info("Load a dataset from Data Sources first.")
    else:
        df = st.session_state.dataset
        report = st.session_state.inspection
        st.markdown(f"**File:** `{st.session_state.dataset_name}`  \n**Source:** `{st.session_state.source_type}`")
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Rows", report["rows"])
        c2.metric("Columns", report["columns"])
        c3.metric("Missing Cells", report["missing_cells"])
        c4.metric("Duplicate Rows", report["duplicate_rows"])
        st.divider()
        st.subheader("Security Dataset Detection")
        if report["security_dataset"]:
            st.success(f"🟢 Security dataset detected — confidence {report['security_confidence']}%")
        else:
            st.warning(f"🟡 Dataset does not strongly match the NEXUS security schema — confidence {report['security_confidence']}%")
        detected = report["detected_security_fields"]
        st.write("**Detected security fields:**")
        st.write(", ".join(detected) if detected else "None")
        st.divider()
        st.subheader("Data Quality")
        q1, q2, q3 = st.columns(3)
        if report["invalid_ips"] == 0:
            q1.success("✅ Invalid IPs: 0")
        else:
            q1.error(f"❌ Invalid IPs: {report['invalid_ips']}")
        if report["invalid_timestamps"] == 0:
            q2.success("✅ Invalid timestamps: 0")
        else:
            q2.error(f"❌ Invalid timestamps: {report['invalid_timestamps']}")
        if report["duplicate_rows"] == 0:
            q3.success("✅ Duplicate rows: 0")
        else:
            q3.warning(f"⚠ Duplicate rows: {report['duplicate_rows']}")
        st.divider()
        st.subheader("Standardized Column Mapping")
        if report["column_mapping"]:
            mapping_df = pd.DataFrame([{"Original Column": k, "NEXUS Column": v} for k, v in report["column_mapping"].items()])
            st.dataframe(mapping_df, use_container_width=True)
        else:
            st.info("No column renaming was required.")
        st.subheader("Incident Summary")
        if "incident_id" in df.columns:
            incident_summary = df.groupby("incident_id").agg(
                Events=("event_id", "count"),
                Highest_Severity=("severity", lambda s: "critical" if "critical" in s.astype(str).str.lower().values else ("high" if "high" in s.astype(str).str.lower().values else ("medium" if "medium" in s.astype(str).str.lower().values else str(s.iloc[0])))),
                Assets=("asset", lambda s: ", ".join(pd.unique(s.astype(str))[:3])) if "asset" in df.columns else ("event_id", "count"),
                Users=("user", lambda s: ", ".join(pd.unique(s.astype(str))[:3])) if "user" in df.columns else ("event_id", "count"),
                Services=("business_service", lambda s: ", ".join(pd.unique(s.astype(str))[:3])) if "business_service" in df.columns else ("event_id", "count"),
            ).reset_index()
            st.dataframe(incident_summary.sort_values("Events", ascending=False), use_container_width=True, hide_index=True)
            st.caption("Use SOC Investigation to select an incident and run the five-agent AI investigation. This section is for inspection only.")
        else:
            st.info("No incident_id field is available in this dataset.")
        st.divider()
        st.subheader("Dataset Preview")
        st.dataframe(df.head(50), use_container_width=True)
        if report["security_dataset"] and report["invalid_ips"] == 0 and report["invalid_timestamps"] == 0:
            st.success("🟢 READY FOR AI ANALYSIS")
        else:
            st.warning("🟡 REVIEW DATA QUALITY BEFORE AI ANALYSIS")

# -----------------------------
# AI SOC Command Center
# -----------------------------
elif page == "AI SOC Command Center":
    st.subheader("🤖 AI SOC Command Center")
    st.caption("Operational view of the NEXUS multi-agent system. This replaces the old static agent-definition screen with live workflow context.")

    snapshot = agent_monitor(st.session_state.workflow_job_id)
    st.divider()
    st.markdown('<div class="section-title">Agent Roles</div>', unsafe_allow_html=True)
    descriptions = {
        "SOC Orchestrator Agent": "Coordinates the investigation, delegates stages and tracks handoffs.",
        "Security Analysis Agent": "Correlates events, reconstructs timelines and identifies suspicious activity.",
        "Threat Intelligence Agent": "Investigates indicators using the available NEXUS knowledge base.",
        "Risk & Business Agent": "Maps findings to asset, service and business impact.",
        "Response & Automation Agent": "Prepares response plans, reports and escalation artifacts for human approval.",
    }
    cols = st.columns(5)
    for col, name in zip(cols, AGENT_NAMES):
        col.markdown(f"**{name.replace(' Agent','')}**")
        col.caption(descriptions[name])

    if snapshot and snapshot.get("result"):
        st.divider()
        st.markdown('<div class="section-title">Latest Investigation Outputs</div>', unsafe_allow_html=True)
        result = snapshot["result"]
        tabs = st.tabs(["Orchestrator", "Security", "Threat Intel", "Risk & Business", "Response"])
        outputs = [result["orchestrator"], result["security_analysis"], result["threat_intelligence"], result["risk_business"], result["response_automation"]]
        for tab, output in zip(tabs, outputs):
            with tab:
                st.markdown(output)

# -----------------------------
# SOC Investigation
# -----------------------------
else:
    st.subheader("🧠 SOC Investigation")
    st.caption("Run a human-controlled, read-only analysis workflow. No production changes are executed.")

    if st.session_state.dataset is None:
        st.warning("Load a security dataset first from **Data Sources**.")
    else:
        df = st.session_state.dataset
        incident_values = [str(x) for x in df["incident_id"].dropna().unique().tolist()] if "incident_id" in df.columns else []
        if not incident_values:
            incident_values = ["Dataset-wide investigation"]

        default_index = 0
        if st.session_state.selected_incident in incident_values:
            default_index = incident_values.index(st.session_state.selected_incident)
        incident_id = st.selectbox("Select incident", incident_values, index=default_index)
        st.session_state.selected_incident = incident_id
        evidence_count = len(df[df["incident_id"].astype(str) == incident_id]) if "incident_id" in df.columns and incident_id != "Dataset-wide investigation" else len(df)
        st.write(f"**Evidence rows available:** {evidence_count}")

        st.divider()
        st.subheader("Live Agent Workflow")
        job_id = st.session_state.workflow_job_id
        snapshot = get_snapshot(job_id) if job_id else None

        llm_config = {
            "api_key": str(st.secrets.get("GROK_API_KEY", "")) or str(st.secrets.get("GROQ_API_KEY", "")),
            "model": str(st.secrets.get("GROK_MODEL", "openai/gpt-oss-120b")),
            "base_url": str(st.secrets.get("GROK_BASE_URL", "https://api.groq.com/openai/v1")),
        }

        if st.button("🚀 Start AI Investigation", type="primary", use_container_width=True, disabled=bool(snapshot and snapshot["status"] == "running")):
            st.session_state.workflow_result = None
            st.session_state.workflow_job_id = create_job(df.copy(), incident_id, llm_config)
            st.rerun()

        snapshot = get_snapshot(st.session_state.workflow_job_id) if st.session_state.workflow_job_id else None
        for name in AGENT_NAMES:
            row = st.container()
            c1, c2 = row.columns([3, 2])
            c1.markdown(f"**{name}**")
            status = snapshot["statuses"].get(name, "Waiting") if snapshot else "Waiting"
            icon = "▶️" if status == "WORKING" else ("✅" if status == "Completed" else "⏳")
            c2.markdown(f"{icon} **{status}**")

        current_placeholder = st.empty()
        progress = st.progress(0, text="Ready to start")
        if snapshot:
            completed = snapshot["completed_steps"]
            progress.progress(min(completed / 5, 1.0), text=f"Workflow progress: {completed}/5 agents completed")
            if snapshot["status"] == "running":
                current = snapshot["current_agent"] or "Preparing workflow"
                current_placeholder.info(f"🔵 CURRENT AGENT: **{current}** — {snapshot['detail']}")
                time.sleep(1)
                st.rerun()
            elif snapshot["status"] == "failed":
                current_placeholder.error(f"❌ Workflow failed: {snapshot['error']}")
            elif snapshot["status"] == "completed":
                current_placeholder.success("🏁 Investigation complete. No production action was executed.")
                st.session_state.workflow_result = snapshot["result"]

        result = st.session_state.workflow_result
        if result:
            st.divider()
            st.subheader("📋 Investigation Results")
            tabs = st.tabs(["Orchestrator", "Security Analysis", "Threat Intelligence", "Risk & Business", "Response Plan"])
            outputs = [result["orchestrator"], result["security_analysis"], result["threat_intelligence"], result["risk_business"], result["response_automation"]]
            for tab, output in zip(tabs, outputs):
                with tab:
                    st.markdown(output)

            st.divider()
            st.subheader("🔐 Human Approval Gate")
            st.warning("The response stage only prepared recommendations. NEXUS does not automatically block, isolate, modify, delete, SSH, or change production systems.")
            approve = st.checkbox("I have reviewed the response recommendations and want to mark this case as human-reviewed.")
            if approve:
                st.success("Human review recorded in this session. No external action was executed.")
