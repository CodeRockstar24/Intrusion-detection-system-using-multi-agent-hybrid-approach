import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go

from agents.detection_agent import detect_traffic
from agents.analysis_agent import analyze_traffic
from agents.research_agent import run_research_agent
from agents.response_agent import run_response_agent

st.set_page_config(layout="wide")

# ---------- STYLING ----------
st.markdown("""
<style>
.block-container {padding-top: 1.5rem;}
.card {padding: 16px; border-radius: 12px; background: #111827; color: white;}
.title {font-size: 28px; font-weight: 600;}
.subtitle {color: #9CA3AF;}
</style>
""", unsafe_allow_html=True)

# ---------- NAV ----------
page = st.sidebar.radio("Navigation", ["Monitoring Dashboard", "Security Network Diagnosis"])

st.title("🛡️ Autonomous Cybersecurity SOC System")
st.markdown("<div class='subtitle'>Real-time detection → analysis → AI decision engine</div>", unsafe_allow_html=True)

uploaded_file = st.file_uploader("Upload Network Traffic CSV")

# ---------- STATE ----------
if "results" not in st.session_state:
    st.session_state.results = []

if "dataset" not in st.session_state:
    st.session_state.dataset = None

# ---------- LOAD DATA ONCE ----------
if uploaded_file and st.session_state.dataset is None:
    df = pd.read_csv(uploaded_file)
    st.session_state.dataset = df.sample(40, random_state=42)

# ---------- BUTTONS ----------
colA, colB = st.columns(2)
run_monitor = colA.button("▶️ Run Monitoring")
run_ai = colB.button("🧠 Run AI Diagnosis")

# =====================================================
# PAGE 1: MONITORING
# =====================================================
if page == "Monitoring Dashboard":

    if st.session_state.dataset is None:
        st.info("Upload dataset to begin")
    else:

        if run_monitor:
            st.session_state.results = []

            for _, row in st.session_state.dataset.iterrows():
                d = detect_traffic(row.to_dict())
                a = analyze_traffic(row.to_dict(), d)

                st.session_state.results.append({
                    "detection": d,
                    "analysis": a
                })

        results = st.session_state.results

        if len(results) > 0:

            recent = results[-40:]

            preds = [r["detection"]["prediction"] for r in recent]
            risks = [r["analysis"]["risk_score"] for r in recent]
            confs = [r["detection"]["confidence"] for r in recent]

            total = len(results)
            attacks = sum(r["detection"]["status"] == "ATTACK" for r in results)
            attack_rate = attacks / total

            # ---------- SYSTEM VERDICT ----------
            if attack_rate > 0.5:
                verdict = "🔴 Under Attack"
            elif attack_rate > 0.2:
                verdict = "🟠 Suspicious Activity"
            else:
                verdict = "🟢 Stable"

            st.subheader("📊 System Overview")

            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Flows", total)
            c2.metric("Attacks", attacks)
            c3.metric("Attack Rate", f"{attack_rate*100:.1f}%")
            c4.metric("System Status", verdict)

            # ---------- GAUGE ----------
            fig = go.Figure(go.Indicator(
                mode="gauge+number",
                value=attack_rate,
                title={'text': "Attack Rate"},
                gauge={'axis': {'range': [0,1]}}
            ))
            st.plotly_chart(fig, use_container_width=True)

            # ---------- CHARTS ----------
            st.subheader("📈 Traffic Analytics")

            col1, col2 = st.columns(2)
            col1.plotly_chart(px.bar(pd.Series(preds).value_counts()), use_container_width=True)
            col2.plotly_chart(px.line(risks), use_container_width=True)

            col3, col4 = st.columns(2)
            col3.plotly_chart(px.area(confs), use_container_width=True)
            col4.plotly_chart(px.pie(values=pd.Series(preds).value_counts().values,
                                     names=pd.Series(preds).value_counts().index),
                              use_container_width=True)

            # ---------- ALERTS ----------
            st.subheader("🚨 Active Alerts")
            for r in recent:
                if r["detection"]["status"] == "ATTACK":
                    st.error(f"{r['detection']['prediction']} detected")

# =====================================================
# PAGE 2: AI DIAGNOSIS
# =====================================================
if page == "Security Network Diagnosis":

    st.title("🧠 Security Network Diagnosis using Multi-Agents")

    results = st.session_state.results

    if len(results) == 0:
        st.warning("Run monitoring first")
    else:

        # ---------- PRIORITIZE ----------
        top = sorted(results, key=lambda x: x["analysis"]["risk_score"], reverse=True)
        top_attacks = [r for r in top if r["detection"]["status"] == "ATTACK"]

        if len(top_attacks) == 0:
            st.warning("No attacks detected — showing anomalies")
            top_attacks = top[:3]
        else:
            top_attacks = top_attacks[:3]

        # ---------- BUILD SUMMARY INPUT ----------
        summary_input = [{
            "attack_type": r["detection"]["prediction"],
            "risk_score": r["analysis"]["risk_score"],
            "confidence": r["detection"]["confidence"]
        } for r in top_attacks]

        # ---------- AI CALL (ONCE) ----------
        if run_ai:
            st.session_state.system_summary = run_research_agent(summary_input, summary_input)
            st.session_state.system_response = run_response_agent(summary_input, summary_input)

        # ---------- TABLE ----------
        table = []
        for r in top_attacks:
            risk = r["analysis"]["risk_score"]

            severity = "HIGH" if risk > 0.6 else "MEDIUM" if risk > 0.3 else "LOW"

            table.append({
                "Threat": r["detection"]["prediction"],
                "Risk Score": round(risk, 2),
                "Confidence": r["detection"]["confidence"],
                "Severity": severity
            })

        df_ai = pd.DataFrame(table).sort_values(by="Risk Score", ascending=False)

        st.subheader("📋 Threat Priority Table")
        st.dataframe(df_ai, use_container_width=True)

        # ---------- AI OUTPUT ----------
        if "system_summary" in st.session_state:

            colA, colB = st.columns(2)

            with colA:
                st.subheader("🧠 System Insight")
                st.write(st.session_state.system_summary)

            with colB:
                st.subheader("⚡ Recommended Actions")
                st.write(st.session_state.system_response)