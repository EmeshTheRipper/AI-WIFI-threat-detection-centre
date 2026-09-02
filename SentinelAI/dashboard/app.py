"""SentinelAI SOC Dashboard (Streamlit)."""

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.dashboard import analyze, level_distribution, to_summary_frame  # noqa: E402

st.set_page_config(page_title="SentinelAI SOC Dashboard", layout="wide")

st.title("SentinelAI — Threat Detection Centre")
st.caption("Explainable AI hybrid intrusion detection for WiFi networks")


@st.cache_data(show_spinner="Analyzing PCAP...")
def run_analysis(path: str):
    result = analyze(path)
    return {
        "summary": result.summary,
        "packets": result.packets,
        "flows": result.flows,
        "rows": to_summary_frame(result),
        "levels": level_distribution(result),
    }


def main():
    sample = ROOT / "data" / "samples" / "level2_sample.pcap"
    default = str(sample) if sample.exists() else ""

    pcap = st.text_input("PCAP file path", value=default)
    if not pcap:
        st.info("Enter a PCAP path to analyze.")
        return

    data = run_analysis(pcap)

    s = data["summary"]
    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Packets", data["packets"])
    k2.metric("Flows", data["flows"])
    k3.metric("Incidents", len(data["rows"]))
    k4.metric("Critical", int((data["rows"]["risk_level"] == "critical").sum()))

    col_a, col_b = st.columns(2)
    with col_a:
        st.subheader("Risk level distribution")
        levels = data["levels"]
        if not levels.empty:
            st.bar_chart(levels.set_index("risk_level"))

    with col_b:
        st.subheader("Verdict counts")
        st.write(s.get("by_verdict", {}))

    st.subheader("Scored incidents")
    rows = data["rows"]
    if rows.empty:
        st.info("No incidents found.")
        return

    rows_display = rows.sort_values("risk_score", ascending=False)
    st.dataframe(rows_display, use_container_width=True)

    top = rows_display.iloc[0]
    st.subheader("Highest-risk source")
    st.write(
        f"**{top['src_ip']}** — {top['risk_level'].upper()} "
        f"(risk {top['risk_score']:.0f}/100, {top['events']} events, "
        f"{top['targets']} targets)  \n"
        f"MITRE tactics: {top['tactics'] or 'none'}  \n"
        f"MITRE techniques: {top['techniques'] or 'none'}"
    )


main()
