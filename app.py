import streamlit as st
import pandas as pd

from config import APP_NAME, APP_FULL_NAME, SAMPLE_DATA_PATH
from data_loader import (
    load_uploaded_file,
    load_from_url,
    prepare_dataset,
    inspect_dataset,
)

st.set_page_config(
    page_title=APP_NAME,
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ NEXUS Cyber AI")
st.caption(APP_FULL_NAME)

st.markdown("## Milestone 2 — Data Sources & Data Inspection")

with st.sidebar:
    st.header("Navigation")
    page = st.radio(
        "Select module",
        ["Data Sources", "Data Inspector"],
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

if page == "Data Sources":
    st.subheader("📥 Load Security Data")
    st.write("NEXUS can currently load CSV, Excel and JSON datasets.")

    source = st.radio(
        "Data source",
        ["Local File", "Direct URL", "Google Drive"],
        horizontal=True,
    )

    if source == "Local File":
        uploaded = st.file_uploader(
            "Upload a CSV, Excel or JSON file",
            type=["csv", "xlsx", "xls", "json"],
        )

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
        url = st.text_input(
            "Public file URL",
            placeholder="https://example.com/security_data.csv",
        )
        st.caption("Supported public file formats: CSV, Excel and JSON.")

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
        drive_url = st.text_input(
            "Public Google Drive file link",
            placeholder="https://drive.google.com/file/d/...",
        )
        st.caption(
            "The Drive file must be publicly accessible. Google Sheets will be added later."
        )

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

        st.markdown(
            f"**File:** `{st.session_state.dataset_name}`  \n"
            f"**Source:** `{st.session_state.source_type}`"
        )

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Rows", report["rows"])
        c2.metric("Columns", report["columns"])
        c3.metric("Missing Cells", report["missing_cells"])
        c4.metric("Duplicate Rows", report["duplicate_rows"])

        st.divider()

        st.subheader("Security Dataset Detection")

        if report["security_dataset"]:
            st.success(
                f"🟢 Security dataset detected — confidence {report['security_confidence']}%"
            )
        else:
            st.warning(
                f"🟡 Dataset does not strongly match the NEXUS security schema — "
                f"confidence {report['security_confidence']}%"
            )

        detected = report["detected_security_fields"]
        if detected:
            st.write("**Detected security fields:**")
            st.write(", ".join(detected))
        else:
            st.write("No standard security fields detected.")

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
            mapping_df = pd.DataFrame(
                [
                    {"Original Column": k, "NEXUS Column": v}
                    for k, v in report["column_mapping"].items()
                ]
            )
            st.dataframe(mapping_df, use_container_width=True)
        else:
            st.info("No column renaming was required.")

        st.subheader("Dataset Preview")
        st.dataframe(df.head(50), use_container_width=True)

        st.subheader("Ready for AI Analysis")
        if report["security_dataset"] and report["invalid_ips"] == 0 and report["invalid_timestamps"] == 0:
            st.success("🟢 READY FOR AI ANALYSIS")
        else:
            st.warning("🟡 REVIEW DATA QUALITY BEFORE AI ANALYSIS")
