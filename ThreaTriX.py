# ============================================================
# CYBER THREAT INTELLIGENCE MIS (FINAL - STRICT ENHANCED)
# ============================================================

import os
import re
import base64
import pandas as pd
import fitz
import streamlit as st
import altair as alt

#PDF_FOLDER = r"D:/Honeypot"
PDF_FOLDER = "data"

# ============================================================
# LOADER (ADDED - NON INTRUSIVE)
# ============================================================

def show_loader():
    with st.spinner("Loading Cyber Intelligence Dashboard..."):
        pass

# ============================================================
# PDF VIEWER (UNCHANGED)
# ============================================================

def show_pdf(file_path):
    try:
        with open(file_path, "rb") as f:
            base64_pdf = base64.b64encode(f.read()).decode('utf-8')

        pdf_display = f"""
        <iframe src="data:application/pdf;base64,{base64_pdf}"
        width="100%" height="600"></iframe>
        """
        st.markdown(pdf_display, unsafe_allow_html=True)
    except:
        st.error("Unable to load PDF")

# ============================================================
# EXTRACTION FUNCTIONS (UNCHANGED)
# ============================================================

def extract_text(pdf_path):
    text = ""
    try:
        doc = fitz.open(pdf_path)
        for page in doc:
            text += page.get_text("text")
    except:
        pass
    return text

def extract_start_date(text, filename):
    match = re.search(r"Report Duration\s*:\s*(.*)", text)
    if match:
        raw = match.group(1)
        parts = raw.split("to")
        start = parts[0].strip()

        m1 = re.search(r"\d{2}/\d{2}/\d{4}", start)
        if m1:
            return m1.group()

        m2 = re.search(r"\d{4}-\d{2}-\d{2}", start)
        if m2:
            return m2.group()

    fname_date = re.search(r"\d{2}-\d{2}-\d{4}", filename)
    return fname_date.group() if fname_date else "Unknown"

def extract_attack_stats(text):
    def get_val(pattern):
        m = re.search(pattern, text)
        return int(m.group(1).replace(",", "")) if m else 0

    return {
        "exploit": get_val(r"exploit:\s*([\d,]+)"),
        "attack_log": get_val(r"attack_log:\s*([\d,]+)"),
        "connect": get_val(r"connect:\s*([\d,]+)")
    }

def extract_ip_data(text, file):
    pattern = re.findall(
        r"(\d+\.\d+\.\d+\.\d+)\s+([a-zA-Z_,\s]+?)\s+(Very High|High|Medium|Low)",
        text
    )

    records = []
    for i, (ip, events, severity) in enumerate(pattern, start=1):
        records.append({
            "S_No": i,
            "IP_Address": ip,
            "Events": events.strip(),
            "Severity": severity,
            "Source_File": file
        })
    return records

def get_all_pdfs(folder):
    pdfs = []
    for root, _, files in os.walk(folder):
        for f in files:
            if f.lower().endswith(".pdf"):
                pdfs.append(os.path.join(root, f))
    return pdfs

# ============================================================
# INSIGHTS (UNCHANGED)
# ============================================================

def generate_insights(ip_data, stats):

    if len(ip_data) == 0:
        return "No threats detected", "Check parsing"

    df = pd.DataFrame(ip_data)

    total = len(df)
    high = df[df["Severity"].isin(["High","Very High"])].shape[0]
    top_ip = df["IP_Address"].value_counts().idxmax()

    insight = f"""
    The dataset indicates concentrated attack behavior originating from IP {top_ip}. 
    A total of {total} threat events were recorded, with {high} categorized as high severity. 
    This suggests targeted attack attempts rather than random background noise.

    The connection volume ({stats['connect']}) combined with exploit attempts ({stats['exploit']}) 
    reflects a structured attack pattern involving scanning followed by exploitation attempts.
    """

    if high > total * 0.7:
        reco = "Critical exposure → Immediate containment required"
    elif stats["connect"] > 5000:
        reco = "Heavy scanning → Apply filtering"
    else:
        reco = "Normal activity → Continue monitoring"

    return insight.strip(), reco

# ============================================================
# PROCESS (UNCHANGED)
# ============================================================

def process_pdfs(folder):

    all_ip = []
    summary = []

    files = get_all_pdfs(folder)

    for path in files:
        file = os.path.basename(path)
        text = extract_text(path)

        date = extract_start_date(text, file)
        stats = extract_attack_stats(text)
        ip_data = extract_ip_data(text, file)

        insight, reco = generate_insights(ip_data, stats)

        summary.append({
            "File": file,
            "File_Path": path,
            "Report_Date": date,
            **stats,
            "Total_IPs": len(ip_data),
            "Insights": insight,
            "Recommendation": reco
        })

        all_ip.extend(ip_data)

    ip_df = pd.DataFrame(all_ip)
    ip_df["S_No"] = range(1, len(ip_df)+1)

    summary_df = pd.DataFrame(summary)

    return ip_df, summary_df

# ============================================================
# DASHBOARD
# ============================================================

def run_dashboard(ip_df, summary_df):

    st.markdown("""
	    
    <hr><h1 style='text-align: center;color:#e74c3c;'>|T|hrea|T|riX</h1>
    <h3 style='text-align: center;color:#3498db;'>Cyber Threat Intelligence Dashboard</h3><hr>	

    """, unsafe_allow_html=True)

   


    # 🔥 ADDED MENU (NO REMOVAL)
    section = st.sidebar.radio("Navigation", [
        "Overview","Threat Data","Charts","Report Summary","Events","Insights","Report"
    ])

    st.sidebar.subheader("Filters")

    severity_filter = st.sidebar.multiselect("Severity", ip_df["Severity"].unique())
    report_filter = st.sidebar.multiselect("Reports", ip_df["Source_File"].unique())

    event_series_full = ip_df["Events"].str.split(",").explode().str.strip()
    unique_events = sorted(event_series_full.dropna().unique())

    event_filter = st.sidebar.multiselect("Events", unique_events)

    search_query = st.sidebar.text_input("Search (IP / Event)")

    filtered_df = ip_df.copy()

    if severity_filter:
        filtered_df = filtered_df[filtered_df["Severity"].isin(severity_filter)]

    if report_filter:
        filtered_df = filtered_df[filtered_df["Source_File"].isin(report_filter)]

    if event_filter:
        filtered_df = filtered_df[
            filtered_df["Events"].apply(lambda x: any(ev in x for ev in event_filter))
        ]

    if search_query:
        filtered_df = filtered_df[
            filtered_df["IP_Address"].str.contains(search_query, na=False) |
            filtered_df["Events"].str.contains(search_query, case=False, na=False)
        ]

    # 🔥 S.NO FIX (ADDED)
    filtered_df = filtered_df.reset_index(drop=True)
    filtered_df["S_No"] = range(1, len(filtered_df)+1)

    # ============================================================
    # OVERVIEW (ENHANCED DRILL ONLY)
    # ============================================================

    if section == "Overview":

        total_events = len(event_series_full)
        high = len(filtered_df[filtered_df["Severity"].isin(["High","Very High"])])
        medium = len(filtered_df[filtered_df["Severity"]=="Medium"])
        low = len(filtered_df[filtered_df["Severity"]=="Low"])

        col1, col2, col3 = st.columns(3)
        col1.metric("Reports", len(summary_df))
        col2.metric("Threats", len(filtered_df))
        col3.metric("Unique IPs", filtered_df["IP_Address"].nunique())

        col4, col5, col6 = st.columns(3)
        col4.metric("High Severity", high)
        col5.metric("Medium Severity", medium)
        col6.metric("Low Severity", low)

        col7, col8, col9 = st.columns(3)
        col7.metric("Total Events", total_events)
        col8.metric("Top IP Hits", filtered_df["IP_Address"].value_counts().max())
        col9.metric("Unique Events", len(unique_events))

        st.markdown("---")

        # 🔥 DRILL IP (FULL TABLE ADDED)
        if st.checkbox("Drill → IP"):
            ip_counts = filtered_df["IP_Address"].value_counts().reset_index()
            ip_counts.columns = ["IP_Address","Count"]

            st.dataframe(ip_counts)

            st.bar_chart(ip_counts.set_index("IP_Address"))

            selected_ip = st.selectbox("Select IP", ip_counts["IP_Address"])
            st.dataframe(filtered_df[filtered_df["IP_Address"] == selected_ip])

        # 🔥 DRILL EVENTS (FULL TABLE ADDED)
        if st.checkbox("Drill → Events"):
            ev = filtered_df["Events"].str.split(",").explode().str.strip()

            ev_counts = ev.value_counts().reset_index()
            ev_counts.columns = ["Event","Count"]

            st.dataframe(ev_counts)

            st.bar_chart(ev_counts.set_index("Event"))

            selected_event = st.selectbox("Select Event", ev_counts["Event"])
            st.dataframe(filtered_df[filtered_df["Events"].str.contains(selected_event)])

        if st.checkbox("Drill → Severity"):
            st.bar_chart(filtered_df["Severity"].value_counts())
            selected_sev = st.selectbox("Select Severity", filtered_df["Severity"].unique())
            st.dataframe(filtered_df[filtered_df["Severity"] == selected_sev])

    # ============================================================
    # NEW REPORT SECTION (ADDED)
    # ============================================================

    elif section == "Report":

        st.subheader("Full Report Table (Excel Style)")

        st.dataframe(filtered_df, width='stretch')

    # ============================================================
    # REST UNCHANGED
    # ============================================================

   # ============================================================
    # CHARTS (ENHANCED)
    # ============================================================

    elif section == "Charts":

        st.subheader("Severity Distribution")
        st.write("Shows how threats are distributed across severity levels")

        sev_df = filtered_df["Severity"].value_counts().reset_index()
        sev_df.columns = ["Severity","Count"]

        st.altair_chart(
            alt.Chart(sev_df).mark_bar().encode(
                x="Severity", y="Count", color="Severity"
            ), width='stretch'
        )

        st.subheader("Severity Proportion (Pie)")
        st.altair_chart(
            alt.Chart(sev_df).mark_arc().encode(
                theta="Count", color="Severity"
            ), width='stretch'
        )

        st.subheader("Top IP Activity")
        top_n = st.number_input("Top N IPs", 10, 500, 20)
        st.line_chart(filtered_df["IP_Address"].value_counts().head(top_n))

        st.subheader("All IPs Table (Excel-like)")
        st.dataframe(filtered_df["IP_Address"].value_counts())

    # ============================================================
    # EVENTS (FULL + DESCRIPTION)
    # ============================================================

    elif section == "Events":

        for event in unique_events:

            st.markdown(f"### {event}")
            count = event_series_full[event_series_full == event].count()
            st.metric("Occurrences", count)

            st.write(f"Description: '{event}' represents a type of network activity observed in logs, indicating potential behavior related to this event.")

            sample = ip_df[ip_df["Events"].str.contains(event, case=False)]
            if not sample.empty:
                st.write(sample.iloc[0][["IP_Address","Severity","Events"]])

            st.write("---")


    elif section == "Report Summary":
        for _, row in summary_df.iterrows():
            with st.expander(row["File"]):
                st.write(f"Date: {row['Report_Date']}")
                st.write(f"Total IPs: {row['Total_IPs']}")
                st.write(f"Exploit: {row['exploit']}")
                st.write(f"Attack Log: {row['attack_log']}")
                st.write(f"Connect: {row['connect']}")
                st.write("Recommendation:", row["Recommendation"])
                if st.button(f"Open {row['File']}"):
                    show_pdf(row["File_Path"])

    elif section == "Insights":
        for _, row in summary_df.iterrows():
            with st.expander(row["File"]):
                st.write(row["Insights"])

# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    show_loader()

    ip_df, summary_df = process_pdfs(PDF_FOLDER)

    ip_df.to_excel("IP_Threat_Data.xlsx", index=False)
    summary_df.to_excel("Report_Summary.xlsx", index=False)

    run_dashboard(ip_df, summary_df)