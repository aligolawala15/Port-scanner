
import sqlite3
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

# ================= CONFIG =================

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "data" / "scans.db"
REPORTS_DIR = BASE_DIR / "reports"

st.set_page_config(
    page_title="CYBER SCAN | Port Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ================= DESIGN =================

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

.stApp {
    background: #080e1b;
    color: #e5edf7;
    font-family: Inter, sans-serif;
}
[data-testid="stSidebar"] {
    background: #0d1728;
    border-right: 1px solid #24334b;
}
.block-container {
    padding-top: 1.7rem;
    padding-bottom: 2rem;
}
h1, h2, h3 {
    color: #f3f7ff !important;
}
p, label {
    color: #a7b6cc;
}
.metric-card {
    background: linear-gradient(145deg, #14243a, #0f192a);
    border: 1px solid #273b55;
    border-radius: 14px;
    padding: 18px;
    min-height: 115px;
}
.metric-label {
    color: #91a6c0;
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 1px;
}
.metric-value {
    color: #f5f8ff;
    font-size: 29px;
    font-weight: 800;
    margin-top: 12px;
}
.eyebrow {
    color: #35dfbd;
    font-size: 12px;
    letter-spacing: 2px;
    font-weight: 700;
}
.panel {
    background: #101b2c;
    border: 1px solid #253750;
    border-radius: 14px;
    padding: 16px;
}
div[data-testid="stDataFrame"] {
    border: 1px solid #253750;
    border-radius: 10px;
}
.stButton > button {
    background: #20c9ad;
    color: #07131b;
    border: none;
    border-radius: 8px;
    font-weight: 700;
}
.stButton > button:hover {
    background: #52efd0;
    color: #07131b;
}
div[data-testid="stDownloadButton"] button {
    border-radius: 8px;
}
hr {
    border-color: #253750;
}
</style>
""", unsafe_allow_html=True)


# ================= DATABASE =================

SERVICE_MAP = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MS RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    587: "SMTP Submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "MS SQL Server",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "Development Server",
    8080: "HTTP Alternate",
}


@st.cache_data(ttl=10)
def read_database(path, modified):
    with sqlite3.connect(path) as conn:
        return pd.read_sql_query(
            """
            SELECT id, target, ip, port, scan_time
            FROM scans
            ORDER BY id DESC
            """,
            conn,
        )


def load_data():
    if not DB_PATH.exists():
        return None, "Database not found. Run your scanner first."

    try:
        df = read_database(
            str(DB_PATH),
            DB_PATH.stat().st_mtime_ns,
        )

        if df.empty:
            return df, None

        df["port"] = pd.to_numeric(df["port"], errors="coerce")
        df = df.dropna(subset=["port"]).copy()
        df["port"] = df["port"].astype(int)
        df["scan_time"] = pd.to_datetime(
            df["scan_time"], errors="coerce"
        )
        df["service"] = df["port"].map(SERVICE_MAP).fillna("Unknown")

        return df, None

    except (sqlite3.Error, OSError, ValueError) as exc:
        return None, f"Database error: {exc}"


# ================= SIDEBAR =================

with st.sidebar:
    st.markdown("# 🛡️ CYBER SCAN")
    st.caption("NETWORK SECURITY CONSOLE")
    st.divider()

    page = st.radio(
        "WORKSPACE",
        [
            "Dashboard",
            "Port Explorer",
            "Scan History",
            "Reports",
            "About",
        ],
    )

    st.divider()
    if st.button("⟳ Refresh dashboard", use_container_width=True):
        read_database.clear()
        st.rerun()

    st.markdown("### FILTERS")

    st.caption("Filters are available after database loading.")


# ================= PAGE HEADER =================

st.markdown(
    '<div class="eyebrow">SECURITY OPERATIONS CENTER / PORT MONITOR</div>',
    unsafe_allow_html=True,
)
st.title("Network Security Dashboard")
st.caption(
    "Monitor recorded TCP port findings, review services, "
    "and export scan history."
)

df, error = load_data()

if error:
    st.warning(error)
    st.info(
        "Run `python advanced_scanner.py` to create your scan database."
    )
    st.stop()

if df.empty:
    st.info(
        "No scan records found. Run a scan against localhost "
        "or another system you are authorized to test."
    )
    st.stop()


# ================= FILTERS =================

with st.sidebar:
    targets = sorted(df["target"].dropna().unique().tolist())
    selected_targets = st.multiselect(
        "Target",
        targets,
        default=targets,
    )

    ports = sorted(df["port"].unique().tolist())
    selected_ports = st.multiselect(
        "Port",
        ports,
        default=ports,
    )

data = df[
    df["target"].isin(selected_targets)
    & df["port"].isin(selected_ports)
].copy()


# ================= KPI CARDS =================

last_time = data["scan_time"].max()
last_text = (
    last_time.strftime("%d %b %H:%M")
    if pd.notna(last_time)
    else "N/A"
)

kpis = [
    ("OPEN-PORT RECORDS", f"{len(data):,}"),
    ("UNIQUE TARGETS", f"{data['target'].nunique():,}"),
    ("UNIQUE PORTS", f"{data['port'].nunique():,}"),
    ("LATEST RECORD", last_text),
]

cols = st.columns(4)

for col, (label, value) in zip(cols, kpis):
    with col:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">{label}</div>
                <div class="metric-value">{value}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

st.write("")


# ================= DASHBOARD =================

if page == "Dashboard":
    left, right = st.columns([1.35, 1])

    with left:
        st.markdown("### 📊 Port Activity")
        st.caption("Number of recorded findings per port")

        if data.empty:
            st.info("No results match your filters.")
        else:
            chart_data = (
                data.groupby(["port", "service"])
                .size()
                .reset_index(name="Findings")
            )
            chart_data["Port / Service"] = (
                chart_data["port"].astype(str)
                + " · "
                + chart_data["service"]
            )

            fig = px.bar(
                chart_data.sort_values("Findings"),
                x="Findings",
                y="Port / Service",
                orientation="h",
                color="Findings",
                color_continuous_scale=["#155e75", "#2dd4bf"],
                template="plotly_dark",
            )
            fig.update_layout(
                height=350,
                showlegend=False,
                coloraxis_showscale=False,
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                margin=dict(l=0, r=5, t=10, b=5),
            )
            st.plotly_chart(fig, use_container_width=True)

    with right:
        st.markdown("### 🎯 Target Breakdown")
        st.caption("Distribution of recorded findings")

        if data.empty:
            st.info("No results to display.")
        else:
            target_data = (
                data.groupby("target")
                .size()
                .reset_index(name="Findings")
            )

            fig = px.pie(
                target_data,
                names="target",
                values="Findings",
                hole=0.65,
                template="plotly_dark",
                color_discrete_sequence=[
                    "#2dd4bf", "#60a5fa", "#a78bfa",
                    "#fbbf24", "#fb7185",
                ],
            )
            fig.update_layout(
                height=350,
                paper_bgcolor="rgba(0,0,0,0)",
                margin=dict(l=0, r=0, t=10, b=5),
            )
            st.plotly_chart(fig, use_container_width=True)

    st.markdown("### 🕒 Latest Port Findings")

    recent = data.head(10).copy()
    recent["scan_time"] = recent["scan_time"].dt.strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    st.dataframe(
        recent.rename(columns={
            "target": "Target",
            "ip": "IP Address",
            "port": "Port",
            "service": "Service",
            "scan_time": "Recorded At",
        })[["Target", "IP Address", "Port", "Service", "Recorded At"]],
        use_container_width=True,
        hide_index=True,
    )


# ================= PORT EXPLORER =================

elif page == "Port Explorer":
    st.markdown("### 🔎 Port Explorer")

    if data.empty:
        st.info("No ports match the selected filters.")
    else:
        selected_port = st.selectbox(
            "Select an open port",
            sorted(data["port"].unique()),
        )

        details = data[data["port"] == selected_port]
        a, b, c = st.columns(3)
        a.metric("Port", int(selected_port))
        b.metric("Service", details["service"].iloc[0])
        c.metric("Targets", details["target"].nunique())

        st.dataframe(
            details[["target", "ip", "port", "service", "scan_time"]]
            .rename(columns={
                "target": "Target",
                "ip": "IP Address",
                "port": "Port",
                "service": "Service",
                "scan_time": "Recorded At",
            }),
            use_container_width=True,
            hide_index=True,
        )

        st.info(
            "An open port is not automatically a vulnerability. "
            "Check whether the service is expected and secured."
        )


# ================= HISTORY =================

elif page == "Scan History":
    st.markdown("### 📋 Scan History")

    search = st.text_input("Search target, IP, or service")
    history = data.copy()

    if search:
        mask = (
            history["target"].astype(str).str.contains(
                search, case=False, na=False
            )
            | history["ip"].astype(str).str.contains(
                search, case=False, na=False
            )
            | history["service"].astype(str).str.contains(
                search, case=False, na=False
            )
        )
        history = history[mask]

    history["scan_time"] = history["scan_time"].dt.strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    st.dataframe(
        history.rename(columns={
            "id": "Record ID",
            "target": "Target",
            "ip": "IP Address",
            "port": "Port",
            "service": "Service",
            "scan_time": "Recorded At",
        }),
        use_container_width=True,
        hide_index=True,
    )
    st.caption(f"{len(history)} records")


# ================= REPORTS =================

elif page == "Reports":
    st.markdown("### 📁 Export Reports")

    export = data.copy()
    export["scan_time"] = export["scan_time"].astype(str)
    export = export[
        ["id", "target", "ip", "port", "service", "scan_time"]
    ]

    c1, c2 = st.columns(2)

    with c1:
        st.download_button(
            "⬇ Download CSV",
            export.to_csv(index=False).encode("utf-8"),
            "port_scanner_report.csv",
            "text/csv",
            use_container_width=True,
        )

    with c2:
        st.download_button(
            "⬇ Download JSON",
            export.to_json(orient="records", indent=2).encode("utf-8"),
            "port_scanner_report.json",
            "application/json",
            use_container_width=True,
        )

    st.markdown("#### Existing report files")

    if REPORTS_DIR.exists():
        files = sorted(
            [
                f for f in REPORTS_DIR.iterdir()
                if f.is_file()
                and f.suffix.lower() in {".csv", ".json", ".pdf", ".txt"}
            ],
            key=lambda f: f.stat().st_mtime,
            reverse=True,
        )

        if not files:
            st.caption("No existing report files.")
        else:
            for file in files:
                with st.expander(file.name):
                    st.download_button(
                        f"Download {file.name}",
                        file.read_bytes(),
                        file.name,
                        key=f"file_{file.name}",
                    )
    else:
        st.caption("The reports folder does not exist yet.")


# ================= ABOUT =================

elif page == "About":
    st.markdown("### 🛡️ About CYBER SCAN")

    st.write(
        "An educational Python-based TCP port scanner with "
        "multithreading, service identification, reports, and a "
        "SQLite-backed dashboard."
    )

    st.markdown("""
    **Project technologies**
    - Python and socket programming
    - ThreadPoolExecutor
    - SQLite
    - Streamlit
    - Pandas and Plotly

    **Scanner modules**
    - `src/scanner.py` — TCP scanning
    - `src/services.py` — service mapping
    - `src/banner.py` — banner detection
    - `src/web_checker.py` — HTTP header checks
    - `src/tls_checker.py` — TLS inspection
    - `src/reporter.py` — CSV/JSON reporting
    - `src/database.py` — scan history
    """)

    st.warning(
        "Only scan devices and networks you own or are authorized to test."
    )


# ================= FOOTER =================

st.divider()
st.caption(
    "CYBER SCAN • Advanced Python Port Scanner • "
    "Educational and authorized testing only"
)