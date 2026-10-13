
import streamlit as st
import pandas as pd

st.set_page_config(
    page_title="Vulnerability Prioritization",
    page_icon="🛡️",
    layout="wide"
)

st.title("AI-Assisted Vulnerability Prioritization")
st.caption("Identify, prioritize, and remediate security vulnerabilities.")

# Sample data for the initial UI.
# We will connect the scoring engine and AI module later.
data = [
    {
        "ID": "VULN-001",
        "Name": "SQL Injection",
        "Severity": "Critical",
        "CVSS": 9.8,
        "Asset": "Web Server",
        "Status": "Open"
    },
    {
        "ID": "VULN-002",
        "Name": "Cross-Site Scripting",
        "Severity": "High",
        "CVSS": 8.1,
        "Asset": "Customer Portal",
        "Status": "Open"
    },
    {
        "ID": "VULN-003",
        "Name": "Outdated TLS Configuration",
        "Severity": "Medium",
        "CVSS": 5.3,
        "Asset": "API Server",
        "Status": "In Progress"
    },
    {
        "ID": "VULN-004",
        "Name": "Information Disclosure",
        "Severity": "Low",
        "CVSS": 3.1,
        "Asset": "Internal Dashboard",
        "Status": "Resolved"
    }
]

df = pd.DataFrame(data)

# Summary metrics
total = len(df)
critical = (df["Severity"] == "Critical").sum()
high = (df["Severity"] == "High").sum()
open_count = (df["Status"] == "Open").sum()

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Vulnerabilities", total)
col2.metric("Critical", critical)
col3.metric("High", high)
col4.metric("Open", open_count)

st.divider()

# Filters
st.subheader("Prioritized Vulnerabilities")

filter_col1, filter_col2 = st.columns(2)

with filter_col1:
    severity_filter = st.multiselect(
        "Filter by severity",
        options=["Critical", "High", "Medium", "Low"],
        default=["Critical", "High", "Medium", "Low"]
    )

with filter_col2:
    search = st.text_input(
        "Search vulnerabilities",
        placeholder="Search by name, ID, or asset..."
    )

filtered_df = df[df["Severity"].isin(severity_filter)]

if search:
    mask = filtered_df.astype(str).apply(
        lambda column: column.str.contains(
            search, case=False, na=False
        )
    ).any(axis=1)
    filtered_df = filtered_df[mask]

# Show highest CVSS scores first
filtered_df = filtered_df.sort_values(
    by="CVSS", ascending=False
)

st.dataframe(
    filtered_df,
    use_container_width=True,
    hide_index=True
)

# Vulnerability details
st.subheader("Vulnerability Details")

if not filtered_df.empty:
    selected_id = st.selectbox(
        "Select a vulnerability",
        filtered_df["ID"].tolist()
    )

    selected = df[df["ID"] == selected_id].iloc[0]

    st.write(f"**Name:** {selected['Name']}")
    st.write(f"**Severity:** {selected['Severity']}")
    st.write(f"**CVSS Score:** {selected['CVSS']}")
    st.write(f"**Affected Asset:** {selected['Asset']}")
    st.write(f"**Status:** {selected['Status']}")

    st.info(
        "AI-generated remediation guidance will be integrated "
        "after the remediation module is connected."
    )
else:
    st.warning("No vulnerabilities match your filters.")
