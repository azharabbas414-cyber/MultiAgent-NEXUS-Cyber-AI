import time
from pathlib import Path

import pandas as pd
import streamlit as st
import plotly.express as px

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
    .block-container {padding-top: 2.6rem; padding-bottom: 2rem;}
    .nexus-title {font-size: 2.1rem; line-height: 1.25; font-weight: 750; margin-bottom: 0.1rem; overflow: visible;}
    .nexus-subtitle {color: #667085; margin-bottom: 1.1rem;}
    .section-title {font-size: 1.35rem; font-weight: 700; margin-top: .4rem; margin-bottom: .7rem;}
    .status-card {border: 1px solid #e6e8ec; border-radius: 12px; padding: 14px 16px; background: #ffffff;}
    .status-label {font-size: .82rem; color: #667085; margin-bottom: 3px;}
    .status-value {font-size: 1.25rem; font-weight: 700;}
    .agent-current {border-left: 5px solid #3b82f6; background: #eff6ff; padding: 12px 15px; border-radius: 8px;}
    .small-muted {font-size: .84rem; color: #667085;}
    .dashboard-header {background: linear-gradient(135deg, #0f172a 0%, #1e293b 55%, #0f766e 100%); color: white; padding: 22px 24px; border-radius: 16px; margin-bottom: 18px;}
    .dashboard-header h2 {margin: 0 0 5px 0; color: white;}
    .dashboard-header p {margin: 0; color: #dbeafe;}
    .kpi-card {border: 1px solid #e5e7eb; border-radius: 14px; padding: 8px 12px; background: #ffffff; box-shadow: 0 2px 8px rgba(15,23,42,.05);}
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
    counts = counts.reindex(order).fillna(0).astype(int)
    return counts.rename_axis("Severity").reset_index(name="Events")


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
    df = get_dashboard_df()
    if df is None or df.empty:
        st.warning("No security dataset is available. Go to Data Sources to load one.")
    else:
        source_label = st.session_state.dataset_name or "Built-in synthetic dataset"
        st.markdown(
            f"""<div class="dashboard-header"><h2>🛡️ NEXUS SOC Dashboard</h2>
            <p>Security operations overview · {source_label} · {len(df):,} events</p></div>""",
            unsafe_allow_html=True,
        )

        incidents = int(df["incident_id"].nunique()) if "incident_id" in df.columns else 0
        critical = int((df["severity"].astype(str).str.lower() == "critical").sum()) if "severity" in df.columns else 0
        high = int((df["severity"].astype(str).str.lower() == "high").sum()) if "severity" in df.columns else 0
        assets = int(df["asset"].nunique()) if "asset" in df.columns else 0
        suspicious = int(df["action"].astype(str).str.lower().str.contains("suspicious|blocked|failed|denied", regex=True).sum()) if "action" in df.columns else 0

        kpis = st.columns(5)
        for col, label, value in zip(
            kpis,
            ["Security Events", "Incidents", "Critical Events", "High Events", "Affected Assets"],
            [len(df), incidents, critical, high, assets],
        ):
            with col:
                st.markdown('<div class="kpi-card">', unsafe_allow_html=True)
                st.metric(label, f"{value:,}")
                st.markdown('</div>', unsafe_allow_html=True)

        st.markdown("### 📊 Security Analytics")
        st.caption(f"{suspicious:,} events contain suspicious/blocked/failed/denied activity markers. Charts update automatically when you load another dataset.")

        # -----------------------------
        # Interactive chart builder
        # -----------------------------
        # Give every chart its own subtle card/border so the analytics area
        # feels like a professional SOC dashboard rather than one flat canvas.
        st.markdown(
            """
            <style>
            div[data-testid="stVerticalBlockBorderWrapper"] {
                border-radius: 14px;
                border: 1px solid rgba(49, 51, 63, 0.14);
                box-shadow: 0 5px 16px rgba(15, 23, 42, 0.08);
                background: #f8fafc;
                padding: 4px 6px 8px 6px;
            }
            </style>
            """,
            unsafe_allow_html=True,
        )

        def render_chart(data, category_col, value_col, title, key, default_type="Bar", horizontal=False, timeline=False):
            if data is None or data.empty:
                st.info(f"{title} needs usable data.")
                return

            options = ["Bar", "Line", "Pie", "Donut"]
            state_key = f"chart_type_{key}"
            if state_key not in st.session_state:
                st.session_state[state_key] = default_type

            # Keep the chart-type control compact: the gear button lives in the
            # chart card header instead of taking a separate row.
            with st.container(border=True):
                title_col, control_col = st.columns([0.94, 0.06], vertical_alignment="center")
                with title_col:
                    st.markdown(f"**{title}**")
                with control_col:
                    with st.popover("⚙", help="Change chart type"):
                        st.caption("Chart type")
                        st.radio(
                            "",
                            options,
                            index=options.index(st.session_state[state_key]),
                            key=f"chart_type_picker_{key}",
                            label_visibility="collapsed",
                        )
                        st.session_state[state_key] = st.session_state[f"chart_type_picker_{key}"]

                chart_type = st.session_state[state_key]
                plot_data = data.copy()
                if chart_type in ("Pie", "Donut"):
                    fig = px.pie(
                        plot_data,
                        names=category_col,
                        values=value_col,
                        title=None,
                        hole=0.55 if chart_type == "Donut" else 0,
                    )
                    fig.update_traces(textposition="inside", textinfo="percent+label")
                elif chart_type == "Line":
                    if horizontal:
                        # Line charts are most readable with the category on X.
                        fig = px.line(plot_data.sort_values(category_col), x=category_col, y=value_col, title=None, markers=True)
                    else:
                        fig = px.line(plot_data, x=category_col, y=value_col, title=None, markers=True)
                    fig.update_layout(hovermode="x unified")
                else:
                    if horizontal:
                        fig = px.bar(
                            plot_data.sort_values(value_col),
                            x=value_col,
                            y=category_col,
                            orientation="h",
                            title=None,
                            text=value_col,
                        )
                    else:
                        fig = px.bar(plot_data, x=category_col, y=value_col, title=None, text=value_col)
                    fig.update_traces(textposition="outside")

                fig.update_layout(height=330, margin=dict(l=10, r=10, t=20, b=10), showlegend=(chart_type in ("Pie", "Donut")), paper_bgcolor="#f8fafc", plot_bgcolor="#eef5fb", font=dict(color="#334155"))
                st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": True, "displaylogo": False})

        # Chart 1: event timeline
        timeline = pd.DataFrame()
        if "timestamp" in df.columns:
            temp = df.copy()
            temp["timestamp"] = pd.to_datetime(temp["timestamp"], errors="coerce")
            temp = temp.dropna(subset=["timestamp"])
            if not temp.empty:
                span = temp["timestamp"].max() - temp["timestamp"].min()
                if span <= pd.Timedelta(hours=6):
                    freq = "15min"
                    granularity = "15-minute"
                elif span <= pd.Timedelta(days=2):
                    freq = "1h"
                    granularity = "hourly"
                else:
                    freq = "1D"
                    granularity = "daily"
                timeline = temp.set_index("timestamp").resample(freq).size().reset_index(name="Events")
                timeline = timeline[timeline["Events"] > 0]
                if not timeline.empty:
                    timeline["Time Period"] = timeline["timestamp"].dt.strftime("%d %b %H:%M") if freq != "1D" else timeline["timestamp"].dt.strftime("%d %b %Y")
                    st.caption(f"Automatically using {granularity} intervals based on the dataset time range.")
                    render_chart(timeline, "Time Period", "Events", "Security Event Activity Over Time", "timeline", default_type="Line", timeline=True)
        if timeline.empty:
            st.info("Timeline chart needs a valid timestamp column.")

        # Charts 2 and 3
        left, right = st.columns(2)
        with left:
            sev = severity_counts(df)
            if not sev.empty:
                render_chart(sev, "Severity", "Events", "Events by Severity", "severity", default_type="Bar")

        with right:
            if "source_ip" in df.columns:
                src = df["source_ip"].astype(str).value_counts().head(8).rename_axis("Source IP").reset_index(name="Events")
                render_chart(src, "Source IP", "Events", "Top Source IPs", "source_ip", default_type="Bar", horizontal=True)

        # Charts 4 and 5
        left, right = st.columns(2)
        with left:
            if "event_type" in df.columns:
                et = df["event_type"].astype(str).value_counts().head(8).rename_axis("Event Type").reset_index(name="Events")
                render_chart(et, "Event Type", "Events", "Top Security Event Types", "event_type", default_type="Bar", horizontal=True)

        with right:
            if "asset" in df.columns:
                asset_counts = df["asset"].astype(str).value_counts().head(8).rename_axis("Asset").reset_index(name="Events")
                render_chart(asset_counts, "Asset", "Events", "Most Affected Assets", "assets", default_type="Bar", horizontal=True)

        st.divider()
        left, right = st.columns(2)
        with left:
            st.markdown('<div class="section-title">📋 Top Affected Assets</div>', unsafe_allow_html=True)
            if "asset" in df.columns:
                assets_df = df["asset"].astype(str).value_counts().head(8).rename_axis("Asset").reset_index(name="Events")
                st.dataframe(assets_df, use_container_width=True, hide_index=True)
        with right:
            st.markdown('<div class="section-title">🧾 Incident Overview</div>', unsafe_allow_html=True)
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
        "Investigation Coordinator Agent": "Coordinates the investigation, delegates stages and tracks handoffs.",
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
        tabs = st.tabs(["Investigation Coordinator", "Security", "Threat Intel", "Risk & Business", "Response"])
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
        agent_descriptions = {
            "Investigation Coordinator Agent": "Coordinates the investigation and decides what each agent should do.",
            "Security Analysis Agent": "Analyzes the security events to understand what happened.",
            "Threat Intelligence Agent": "Checks IPs, indicators, and threats to understand whether they are malicious.",
            "Risk & Business Agent": "Determines the risk to systems and business services.",
            "Response & Automation Agent": "Prepares recommended response actions for human approval.",
        }

        for name in AGENT_NAMES:
            row = st.container()
            c1, c2 = row.columns([3, 2])
            c1.markdown(f"**{name}**")
            c1.caption(agent_descriptions.get(name, "Specialized security investigation agent."))
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
            tabs = st.tabs(["Investigation Coordinator", "Security Analysis", "Threat Intelligence", "Risk & Business", "Response Plan"])
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
