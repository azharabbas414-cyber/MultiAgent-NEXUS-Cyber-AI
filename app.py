import streamlit as st
import pandas as pd

from config import APP_NAME, APP_FULL_NAME, SAMPLE_DATA_PATH
from data_loader import load_uploaded_file, load_from_url, prepare_dataset
from agents import AGENT_NAMES, agent_status_template
from workflow import run_workflow

st.set_page_config(page_title=APP_NAME, page_icon="🛡️", layout="wide")

st.title("🛡️ NEXUS Cyber AI")
st.caption(APP_FULL_NAME)
st.markdown("## Milestone 4 — Multi-Agent SOC Workflow")

with st.sidebar:
    st.header("Navigation")
    page = st.radio(
        "Select module",
        ["Data Sources", "Data Inspector", "AI Agents", "SOC Investigation"],
        index=0,
    )

if "dataset" not in st.session_state:
    st.session_state.dataset = None
if "dataset_name" not in st.session_state:
    st.session_state.dataset_name = None
if "inspection" not in st.session_state:
    st.session_state.inspection = None
if "source_type" not in st.session_state:
    st.session_state.source_type = None
if "workflow_result" not in st.session_state:
    st.session_state.workflow_result = None

if page == "Data Sources":
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
        st.subheader("Dataset Preview")
        st.dataframe(df.head(50), use_container_width=True)
        if report["security_dataset"] and report["invalid_ips"] == 0 and report["invalid_timestamps"] == 0:
            st.success("🟢 READY FOR AI ANALYSIS")
        else:
            st.warning("🟡 REVIEW DATA QUALITY BEFORE AI ANALYSIS")

elif page == "AI Agents":
    st.subheader("🤖 Five AI Agents")
    st.info("Milestone 4 connects these five CrewAI agents into a real sequential investigation workflow.")
    for item in agent_status_template():
        left, right = st.columns([2, 1])
        left.markdown(f"**{item['name']}**")
        right.write("⏳ " + item["status"])
    st.divider()
    st.subheader("Agent Responsibilities")
    descriptions = {
        "SOC Orchestrator Agent": "Coordinates the investigation, delegates tasks, tracks handoffs and approvals.",
        "Security Analysis Agent": "Correlates security events, reconstructs timelines and identifies suspicious activity.",
        "Threat Intelligence Agent": "Investigates IPs, domains, URLs, hashes and other indicators using available knowledge.",
        "Risk & Business Agent": "Maps technical findings to asset, service and business impact.",
        "Response & Automation Agent": "Prepares reports, tickets, response plans and escalation artifacts for human approval.",
    }
    for name in AGENT_NAMES:
        st.markdown(f"**{name}** — {descriptions[name]}")

else:
    st.subheader("🧠 SOC Investigation")
    st.caption("Run a human-controlled, read-only analysis workflow. No production changes are executed.")

    if st.session_state.dataset is None:
        st.warning("Load a security dataset first from **Data Sources**.")
    else:
        df = st.session_state.dataset
        if "incident_id" in df.columns:
            incident_values = [str(x) for x in df["incident_id"].dropna().unique().tolist()]
        else:
            incident_values = []

        if not incident_values:
            incident_values = ["Dataset-wide investigation"]

        incident_id = st.selectbox("Select incident", incident_values)
        st.write(f"**Evidence rows available:** {len(df[df['incident_id'].astype(str) == incident_id]) if 'incident_id' in df.columns and incident_id != 'Dataset-wide investigation' else len(df)}")

        st.divider()
        st.subheader("Live Agent Workflow")

        status_placeholders = {}
        detail_placeholder = st.empty()
        for name in AGENT_NAMES:
            row = st.container()
            c1, c2 = row.columns([3, 2])
            c1.markdown(f"**{name}**")
            status_placeholders[name] = c2.empty()
            status_placeholders[name].write("⏳ Waiting")

        current_placeholder = st.empty()
        progress = st.progress(0, text="Ready to start")

        def update_status(agent_name: str, status: str, detail: str) -> None:
            for name in AGENT_NAMES:
                if name == agent_name:
                    icon = "▶️" if status == "WORKING" else ("✅" if status == "Completed" else "⏳")
                    status_placeholders[name].markdown(f"{icon} **{status}**")
                elif status_placeholders.get(name) is not None:
                    # Preserve completed/waiting labels already rendered.
                    pass
            if status == "WORKING":
                current_placeholder.info(f"🔵 CURRENT AGENT: **{agent_name}** — {detail}")
            elif status == "Completed":
                current_placeholder.success(f"✅ **{agent_name}** completed — {detail}")
            completed = {
                "SOC Orchestrator Agent": 1,
                "Security Analysis Agent": 2,
                "Threat Intelligence Agent": 3,
                "Risk & Business Agent": 4,
                "Response & Automation Agent": 5,
            }.get(agent_name, 0) if status == "Completed" else 0
            if completed:
                progress.progress(completed / 5, text=f"Workflow progress: {completed}/5 agents completed")

        if st.button("🚀 Start AI Investigation", type="primary", use_container_width=True):
            st.session_state.workflow_result = None
            try:
                with st.spinner("NEXUS agents are investigating..."):
                    result = run_workflow(df, incident_id, update_status)
                st.session_state.workflow_result = result
                progress.progress(1.0, text="Workflow complete — human approval required for any response action")
                current_placeholder.success("🏁 Investigation complete. No production action was executed.")
            except Exception as exc:
                current_placeholder.error(f"Workflow failed: {exc}")
                st.exception(exc)

        result = st.session_state.workflow_result
        if result:
            st.divider()
            st.subheader("📋 Investigation Results")
            tabs = st.tabs([
                "Orchestrator",
                "Security Analysis",
                "Threat Intelligence",
                "Risk & Business",
                "Response Plan",
            ])
            outputs = [
                result["orchestrator"],
                result["security_analysis"],
                result["threat_intelligence"],
                result["risk_business"],
                result["response_automation"],
            ]
            for tab, output in zip(tabs, outputs):
                with tab:
                    st.markdown(output)

            st.divider()
            st.subheader("🔐 Human Approval Gate")
            st.warning("The response stage only prepared recommendations. NEXUS does not automatically block, isolate, modify, delete, SSH, or change production systems.")
            approve = st.checkbox("I have reviewed the response recommendations and want to mark this case as human-reviewed.")
            if approve:
                st.success("Human review recorded in this session. No external action was executed.")
