"""SentinelAI SOC Web Console.

A multi-tab Streamlit interface driving the FastAPI backend for file-based,
live, and historical analysis. Every control (upload/scan/live capture)
calls an API endpoint through ``SentinelClient`` so results are computed and
persisted server-side in ``sentinelai.db``.
"""

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.api.client import SentinelClient, SentinelClientError  # noqa: E402

st.set_page_config(
    page_title="SentinelAI SOC Console",
    page_icon=":shield:",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
      .block-container { padding-top: 1.2rem; }
      .stMetric {
        background: rgba(255,255,255,0.03);
        border: 1px solid rgba(128,128,128,0.25);
        border-radius: 10px;
        padding: 10px 14px;
      }
    </style>
    """,
    unsafe_allow_html=True,
)


def get_client() -> SentinelClient:
    """Return the shared API client stored in session state."""
    client = st.session_state.get("client")
    if client is None:
        client = SentinelClient()
        st.session_state["client"] = client
    return client


def refresh_api_state(client: SentinelClient) -> None:
    """Persist whether the backend is currently reachable."""
    st.session_state["api_ok"] = client.using_api


def show_connection_banner(client: SentinelClient) -> None:
    """Surface API connectivity status in the sidebar."""
    st.sidebar.subheader("Connection")
    if st.session_state.get("api_ok", client.health()):
        st.sidebar.success("API connected")
        st.sidebar.caption("Backend running on :8000/. Runs persist to sentinelai.db")
    else:
        st.sidebar.warning("API offline")
        st.sidebar.caption(
            "Running analyses in-process. Start the backend with: "
            "`python main.py --api`"
        )
    if st.sidebar.button("Recheck API"):
        client.health()
        refresh_api_state(client)
        st.rerun()


def render_metrics(result: dict) -> None:
    """Render the SOC KPI metric cards."""
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Total Packets", f"{result['packets']:,}")
    m2.metric("Flows", f"{result['flows']:,}")
    m3.metric("Suspicious Alerts", f"{result['suspicious_alerts']:,}")
    m4.metric("Critical Incidents", f"{result['critical_incidents']:,}")
    risk = result["max_risk_score"]
    m5.metric("Max Risk Score", f"{risk:.0f} / 100")


def render_verdicts(result: dict) -> None:
    """Render the per-verdict distribution chart."""
    counts = result["verdict_counts"].get("by_verdict", {})
    if not counts:
        st.caption("No verdicts recorded.")
        return
    chart = pd.DataFrame(
        {"verdict": list(counts.keys()), "count": list(counts.values())}
    )
    st.bar_chart(chart, x="verdict", y="count", width="stretch")


def render_incident_table(result: dict) -> None:
    """Render the scored-incident table with MITRE mapping."""
    rows = result.get("incidents", [])
    if not rows:
        st.info("No incidents to display for this capture.")
        return
    df = pd.DataFrame(rows)
    df = df.sort_values("risk_score", ascending=False)
    st.dataframe(
        df,
        width="stretch",
        column_config={
            "risk_score": st.column_config.ProgressColumn(
                "Risk (0-100)", min_value=0, max_value=100, format="%.1f"
            ),
            "risk_level": st.column_config.TextColumn("Level"),
            "techniques": st.column_config.TextColumn("MITRE Techniques"),
            "tactics": st.column_config.TextColumn("Tactics"),
        },
    )


def render_explanations(result: dict) -> None:
    """Render human-readable SHAP explanations for flagged flows."""
    explanations = result.get("explanations", [])
    st.subheader("Why was it flagged? (XAI / SHAP)")
    if not result.get("model_available", False):
        st.info(
            "No trained ML model found — run `python main.py --train` to "
            "enable SHAP explanations."
        )
        return
    if not explanations:
        st.success("No flagged flows in this capture, so nothing needs explaining.")
        return
    for expl in explanations:
        with st.expander(
            f"{expl['src_ip']} -> {expl['dst_ip']} ({expl['protocol']})  "
            f"[{expl['label']}]"
        ):
            st.markdown(
                f"**Model decision:** {expl['label']} (driving feature "
                f"`{expl['top_feature']}`)."
            )
            st.write(expl["reason"])


def render_results(result: dict | None) -> None:
    """Render the full SOC result set for a completed analysis."""
    if result is None:
        st.info("No analysis performed yet. Use the controls on the left.")
        return

    st.subheader(f"Analysis report — {result['pcap']}")
    if result.get("note"):
        st.warning(result["note"])

    render_metrics(result)

    st.markdown("#### Verdict distribution")
    render_verdicts(result)

    st.markdown("#### Scored incidents (risk + MITRE)")
    render_incident_table(result)

    render_explanations(result)


def run_action(client: SentinelClient, action, success_msg: str) -> None:
    """Execute an analysis action and stash its result in session state."""
    try:
        with st.spinner("Running hybrid analysis..."):
            result = action()
        st.session_state["result"] = result
        refresh_api_state(client)
    except SentinelClientError as exc:
        st.error(f"Analysis failed: {exc}")
    except Exception as exc:  # pragma: no cover - defensive
        st.error(f"Unexpected error during analysis: {exc}")


def render_scan_tab(client: SentinelClient) -> None:
    """File upload + one-click sample scan + live capture controls."""
    st.header("Scan & Detect")

    col_upload, col_live = st.columns(2, gap="large")

    with col_upload:
        st.subheader("PCAP file analysis")
        uploaded = st.file_uploader(
            "Upload a capture (.pcap / .pcapng)",
            type=["pcap", "pcapng"],
            accept_multiple_files=False,
        )
        if st.button(
            "Run Hybrid Analysis", type="primary", disabled=uploaded is None
        ) and uploaded is not None:
            file_bytes = uploaded.getvalue()
            run_action(
                client,
                lambda: client.analyze_upload(file_bytes, uploaded.name),
                "Upload analysis complete",
            )

        st.markdown("---")
        st.subheader("Quick scan")
        st.caption("Analyze the bundled sample capture immediately.")
        if st.button("Scan Sample PCAP", type="secondary"):
            run_action(
                client, client.analyze_default, "Sample analysis complete"
            )

    with col_live:
        st.subheader("Live capture")
        st.caption(
            "Sniff packets from an interface and run the full detection chain. "
            "Requires administrator/root privileges on this machine."
        )
        interface = st.text_input(
            "Interface (blank = default)", placeholder="e.g. Wi-Fi"
        )
        count = st.number_input(
            "Packets to capture", min_value=1, value=50, step=10
        )
        if st.button("Start Live Capture", type="primary"):
            run_action(
                client,
                lambda: client.analyze_live(
                    interface=interface or None, count=int(count)
                ),
                "Live capture complete",
            )

    st.divider()
    render_results(st.session_state.get("result"))


def render_soc_tab() -> None:
    """Dedicated full-screen view of the latest analysis."""
    st.header("SOC Results")
    render_results(st.session_state.get("result"))


def render_history_tab(client: SentinelClient) -> None:
    """Persisted analyses and incidents pulled from the backend/DB."""
    st.header("Analysis history")
    try:
        analyses = client.list_analyses()
    except SentinelClientError as exc:
        st.error(f"Could not load analyses: {exc}")
        return

    if not analyses:
        st.info("No persisted analyses yet.")
        return
    st.dataframe(pd.DataFrame(analyses), width="stretch")

    st.subheader("Persisted incidents")
    try:
        incidents = client.list_incidents()
    except SentinelClientError as exc:
        st.error(f"Could not load incidents: {exc}")
        return
    if not incidents:
        st.info("No persisted incidents yet.")
        return
    st.dataframe(pd.DataFrame(incidents), width="stretch")


def main() -> None:
    st.title("SentinelAI — Threat Detection Centre")
    st.caption("Explainable AI hybrid intrusion detection for WiFi networks")

    client = get_client()
    show_connection_banner(client)

    tabs = st.tabs(["Scan & Detect", "SOC Results", "History"])
    with tabs[0]:
        render_scan_tab(client)
    with tabs[1]:
        render_soc_tab()
    with tabs[2]:
        render_history_tab(client)


main()