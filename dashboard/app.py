import streamlit as st
import requests
import pandas as pd
import time
import json
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from utils.coverage_builder import build_coverage

API_BASE = "http://127.0.0.1:8000/dashboard"
ALERT_FILE = "outputs/alerts.json"

st.set_page_config(page_title="Zero Trust Dashboard", layout="wide")

st.title("🔐 Adaptive Zero Trust Dashboard")

windows_res = requests.get(f"{API_BASE}/windows")
# coverage_res = requests.get(f"{API_BASE}/coverage")

windows_data = windows_res.json().get("windows", [])
coverage_data = build_coverage()

left, right = st.columns([3, 1])


with left:

    if windows_data:
        df = pd.DataFrame(windows_data)

        trust_map = {"HIGH_TRUST": 3, "MEDIUM_TRUST": 2, "LOW_TRUST": 1}
        df["trust_score"] = df["trust_state"].map(trust_map)

        st.subheader("📈 Trust State Over Time")
        st.line_chart(df.set_index("window_id")["trust_score"])

        st.subheader("📊 Anomaly Ratio Trend")
        st.line_chart(df.set_index("window_id")["anomaly_ratio"])

        st.subheader("🔍 Explainability")
        latest = df.iloc[-1]

        st.write(f"**Trust:** {latest['trust_state']}")
        st.write(f"**Anomaly:** {latest['anomaly_ratio']:.3f}")

        for r in latest.get("explanation", []):
            st.write(f"- {r}")

with right:

    st.subheader("🚨 Live Alerts")

    try:
        with open(ALERT_FILE, "r") as f:
            alerts = json.load(f)
    except:
        alerts = []

    if alerts:
        latest_alert = alerts[-1]

        if latest_alert["severity"] in ["HIGH", "CRITICAL"]:
            st.error(
                f"🚨 {latest_alert['severity']} ALERT\n\n"
                f"Source: {latest_alert['source']}\n"
                f"Anomaly: {latest_alert['anomaly']}"
            )

        for alert in reversed(alerts[-5:]):

            if alert["severity"] == "CRITICAL":
                color = "#ff2e2e"
            elif alert["severity"] == "HIGH":
                color = "#ff7b00"
            else:
                color = "#ffaa00"

            st.markdown(
                f"""
                <div style="
                    padding:10px;
                    margin-bottom:8px;
                    border-radius:10px;
                    background-color:{color};
                    color:white;
                    font-size:13px;
                ">
                <b>{alert['severity']} ALERT</b><br>
                Source: {alert['source']}<br>
                Anomaly: {alert['anomaly']}
                </div>
                """,
                unsafe_allow_html=True
            )
    else:
        st.info("No alerts yet")

def safe_bar(data, title):
    st.write(f"### {title}")
    if data:
        df = pd.DataFrame.from_dict(data, orient="index", columns=["count"])
        if not df.empty:
            st.bar_chart(df)
        else:
            st.info("No data")
    else:
        st.info("No data")

st.subheader("📊 Rule Coverage")

if coverage_data:
    c1, c2, c3 = st.columns(3)

    with c1:
        safe_bar(coverage_data.get("rules", {}), "Rules")

    with c2:
        safe_bar(coverage_data.get("trust_states", {}), "Trust States")

    with c3:
        safe_bar(coverage_data.get("feature_triggers", {}), "Feature Triggers")

time.sleep(2)
st.rerun()
