
import json
from pathlib import Path

import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="Vulnerability Prioritization",
    page_icon="🛡️",
    layout="wide"
)

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_FILE = BASE_DIR / "prioritized_vulnerabilities.json"

PRIORITY_ORDER = ["Critical", "High", "Medium", "Low"]

PRIORITY_COLORS = {
    "Critical": "🔴",
    "High": "🟠",
    "Medium": "🟡",
    "Low": "🟢",
}


def load_vulnerabilities():
    """Load the scoring engine's JSON output."""
    if not OUTPUT_FILE.exists():
        return []

    with OUTPUT_FILE.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, list):
        raise ValueError("Expected a JSON list of vulnerabilities.")

    return data


st.title("AI-Assisted Vulnerability Prioritization")
st.caption(
    "Security findings ranked by contextual risk, "
    "exploit status, exposure, and asset criticality."
)

if st.button("Refresh vulnerability data"):
    st.rerun()

try:
    vulnerabilities = load_vulnerabilities()
except (json.JSONDecodeError, OSError, ValueError) as error:
    st.error(f"Could not load vulnerability data: {error}")
    st.stop()

if not vulnerabilities:
    st.warning(
        "No prioritized findings found. Run scoring_engine.py first."
    )
    st.stop()

df = pd.DataFrame(vulnerabilities)

required_columns = [
    "vuln_id",
    "title",
    "cvss_base",
    "contextual_risk_score",
    "priority",
    "priority_rank",
]

missing = [column for column in required_columns if column not in df.columns]

if missing:
    st.error(f"Missing required JSON fields: {', '.join(missing)}")
    st.stop()

# Convert scores to numeric values for sorting and display.
df["cvss_base"] = pd.to_numeric(df["cvss_base"], errors="coerce")
df["contextual_risk_score"] = pd.to_numeric(
    df["contextual_risk_score"], errors="coerce"
)
df["priority_rank"] = pd.to_numeric(
    df["priority_rank"], errors="coerce"
)

df["priority"] = df["priority"].fillna("Unknown")

# Summary metrics
total = len(df)
critical = int((df["priority"] == "Critical").sum())
high = int((df["priority"] == "High").sum())
review_count = int(
    df.get(
        "data_quality",
        pd.Series("", index=df.index)
    ).astype(str).str.contains("Review required", case=False).sum()
)

metric1, metric2, metric3, metric4 = st.columns(4)

metric1.metric("Total Findings", total)
metric2.metric("Critical Priority", critical)
metric3.metric("High Priority", high)
metric4.metric("Needs Data Review", review_count)

st.divider()

# Priority distribution
left, right = st.columns([1, 2])

with left:
    st.subheader("Priority Distribution")

    priority_counts = (
        df["priority"]
        .value_counts()
        .reindex(PRIORITY_ORDER, fill_value=0)
    )

    st.bar_chart(priority_counts)

with right:
    st.subheader("Prioritized Findings")

    search = st.text_input(
        "Search",
        placeholder="Search ID, title, asset, or owner..."
    )

    selected_priorities = st.multiselect(
        "Filter by priority",
        options=PRIORITY_ORDER,
        default=PRIORITY_ORDER
    )

    filtered = df[df["priority"].isin(selected_priorities)].copy()

    if search:
        searchable_columns = [
            column for column in
            ["vuln_id", "title", "asset_name", "asset_owner"]
            if column in filtered.columns
        ]

        mask = filtered[searchable_columns].fillna("").astype(str).apply(
            lambda column: column.str.contains(
                search, case=False, regex=False
            )
        ).any(axis=1)

        filtered = filtered[mask]

    filtered = filtered.sort_values(
        "priority_rank", na_position="last"
    )

    display_columns = [
        ("priority_rank", "Rank"),
        ("vuln_id", "Finding ID"),
        ("title", "Vulnerability"),
        ("priority", "Priority"),
        ("contextual_risk_score", "Contextual Risk"),
        ("cvss_base", "CVSS Base"),
    ]

    visible_columns = [
        column for column, label in display_columns
        if column in filtered.columns
    ]

    rename_columns = dict(display_columns)

    st.dataframe(
        filtered[visible_columns].rename(columns=rename_columns),
        use_container_width=True,
        hide_index=True,
        column_config={
            "Contextual Risk": st.column_config.NumberColumn(
                format="%.1f / 10"
            ),
            "CVSS Base": st.column_config.NumberColumn(
                format="%.1f / 10"
            ),
        },
    )

st.divider()

# Finding details
st.subheader("Finding Details")

if filtered.empty:
    st.info("No findings match the selected filters.")
else:
    options = {
        f"{row['vuln_id']} — {row['title']}": row["vuln_id"]
        for _, row in filtered.iterrows()
    }

    selected_label = st.selectbox(
        "Select a finding",
        options=list(options.keys())
    )

    selected_id = options[selected_label]
    finding = df[df["vuln_id"] == selected_id].iloc[0]

    detail1, detail2, detail3 = st.columns(3)

    detail1.metric(
        "Contextual Risk Score",
        f"{finding['contextual_risk_score']:.1f} / 10"
    )

    detail2.metric(
        "CVSS Base Score",
        f"{finding['cvss_base']:.1f} / 10"
        if pd.notna(finding["cvss_base"]) else "Unavailable"
    )

    detail3.metric(
        "Priority Rank",
        int(finding["priority_rank"])
        if pd.notna(finding["priority_rank"]) else "Unavailable"
    )

    st.markdown(f"### {finding['title']}")
    st.write(
        f"**Priority:** "
        f"{PRIORITY_COLORS.get(finding['priority'], '')} "
        f"{finding['priority']}"
    )

    info1, info2 = st.columns(2)

    with info1:
        st.write(f"**Finding ID:** {finding['vuln_id']}")
        st.write(
            f"**Affected asset:** "
            f"{finding.get('asset_name', 'Not provided')}"
        )
        st.write(
            f"**Asset owner:** "
            f"{finding.get('asset_owner', 'Not provided')}"
        )
        st.write(
            f"**Asset criticality:** "
            f"{finding.get('asset_criticality', 'Not provided')}"
        )

    with info2:
        st.write(
            f"**Internet exposed:** "
            f"{finding.get('internet_exposed', 'Unknown')}"
        )
        st.write(
            f"**Active exploit in the wild:** "
            f"{finding.get('active_exploit_in_wild', 'Unknown')}"
        )
        st.write(
            f"**Data quality:** "
            f"{finding.get('data_quality', 'Not provided')}"
        )

    st.markdown("#### Why was this finding prioritized?")

    reasons = finding.get("risk_reasons", [])

    if reasons:
        for reason in reasons:
            st.markdown(f"- {reason}")
    else:
        st.write("No risk reasons were provided.")

    st.markdown("#### Score Breakdown")

    breakdown = finding.get("score_breakdown", {})

    if isinstance(breakdown, dict) and breakdown:
        breakdown_df = pd.DataFrame(
            [
                {"Component": key.replace("_", " ").title(),
                 "Points": value}
                for key, value in breakdown.items()
            ]
        )
        st.dataframe(
            breakdown_df,
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No score breakdown available.")

    st.markdown("#### Recommended Remediation")

    # Add AI-Powered Rationale & Compensating Controls sections
    st.markdown("#### AI-Powered Rationale & Business Impact")
    st.success(
        finding.get(
            "ai_rationale",
            "AI rationale pending generation. Run ai_remediation.py to populate."
        )
    )

    col_ticket, col_waf = st.columns(2)

    with col_ticket:
        st.markdown("#### 🎫 Owner-Specific Developer Ticket")
        st.code(
            finding.get(
                "developer_ticket",
                f"Assignee: {finding.get('asset_owner', 'Unassigned')}\nAction: Patch required."
            ),
            language="markdown"
        )

    with col_waf:
        st.markdown("#### 🛡️ Temporary Compensating Controls (WAF)")
        st.info(
            finding.get(
                "waf_controls",
                "Apply rate limiting or inspect traffic headers at the edge WAF."
            )
        )
    st.info(
        finding.get(
            "recommended_action",
            "No recommended action provided."
        )
    )

    st.caption(
        "Contextual risk is calculated by the team's prototype scoring "
        "model. It is not an official CVSS score. Remediation suggestions "
        "should be reviewed by the responsible security team."
    )
