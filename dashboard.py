import streamlit as st
import sqlite3
import pandas as pd


st.set_page_config(
    page_title="Port Scanner",
    page_icon="🔍",
    layout="wide"
)

st.title("🔍 Advanced Port Scanner")

st.write(
    "Network scanning dashboard for authorized security testing."
)


connection = sqlite3.connect(
    "data/scans.db"
)

query = """
SELECT
    id,
    target,
    ip,
    port,
    scan_time
FROM scans
ORDER BY id DESC
"""

data = pd.read_sql_query(
    query,
    connection
)

connection.close()


if data.empty:

    st.info("No scan history available.")

else:

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Total Records",
        len(data)
    )

    col2.metric(
        "Unique Targets",
        data["target"].nunique()
    )

    col3.metric(
        "Open Ports",
        data["port"].nunique()
    )

    st.subheader("Scan History")

    st.dataframe(
        data,
        use_container_width=True
    )

    st.subheader("Ports Found")

    chart_data = (
        data["port"]
        .value_counts()
        .sort_index()
    )

    st.bar_chart(chart_data)