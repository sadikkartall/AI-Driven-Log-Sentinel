"""Streamlit dashboard for AI-Driven Log Sentinel."""
import os
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np
import pandas as pd
import requests
import streamlit as st

# Configuration
# Try localhost first (for local development), then fallback to Docker network
API_URL = os.getenv("API_URL", "http://localhost:8000")
REPORTS_DIR = Path("outputs/reports")

# Debug: Show API URL in sidebar
if os.getenv("SHOW_API_URL", "false").lower() == "true":
    st.sidebar.info(f"API URL: {API_URL}")

# Disable Streamlit features for better performance
st.set_option('deprecation.showPyplotGlobalUse', False)
st.set_option('deprecation.showfileUploaderEncoding', False)

# Page config (disable emoji CDN to avoid tracking prevention errors)
st.set_page_config(
    page_title="AI-Driven Log Sentinel",
    page_icon=None,  # Disable emoji icon to avoid CDN calls
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'Get Help': None,
        'Report a bug': None,
        'About': None
    }
)

# Initialize session state for in-memory event store
if "modsec_events" not in st.session_state:
    st.session_state.modsec_events = []
if "lo2_log_events" not in st.session_state:
    st.session_state.lo2_log_events = []
if "lo2_metric_events" not in st.session_state:
    st.session_state.lo2_metric_events = []
if "api_status" not in st.session_state:
    st.session_state.api_status = None
if "last_refresh" not in st.session_state:
    st.session_state.last_refresh = 0


def plot_histogram(data: pd.Series, bins: int = 20) -> None:
    """Plot histogram using bar chart. Skips when data is insufficient (avoids Vega-Lite warnings)."""
    if len(data) == 0:
        st.caption("No data to display")
        return
    if len(data) < 2:
        st.caption("Add more events for histogram")
        return
    # Avoid Infinite extent Vega-Lite errors: ensure valid numeric range
    data_clean = pd.Series(data).dropna().replace([np.inf, -np.inf], np.nan).dropna()
    if len(data_clean) < 2:
        st.caption("Not enough valid data for chart")
        return
    bins = min(bins, max(5, len(data_clean) // 2))  # Fewer bins for small data
    counts, bin_edges = np.histogram(data_clean, bins=bins)
    if counts.sum() == 0:
        st.caption("No data to display")
        return
    bin_centers = (bin_edges[:-1] + bin_edges[1:]) / 2
    hist_df = pd.DataFrame({"value": bin_centers, "count": counts})
    st.bar_chart(hist_df.set_index("value")["count"])


def check_api_health() -> bool:
    """Check if API is available (cached in session state)."""
    # Check cache first (refresh every 60 seconds)
    import time
    current_time = time.time()
    if st.session_state.api_status is not None and (current_time - st.session_state.last_refresh) < 60:
        return st.session_state.api_status
    
    try:
        response = requests.get(f"{API_URL}/health", timeout=1)
        status = response.status_code == 200
        st.session_state.api_status = status
        st.session_state.last_refresh = current_time
        return status
    except Exception:
        st.session_state.api_status = False
        return False


def get_modsec_prediction(request_text: str) -> Optional[Dict]:
    """Get ModSecurity prediction from API."""
    try:
        # Try the configured API URL first
        url = f"{API_URL}/predict/modsec"
        response = requests.post(
            url,
            json={"request_text": request_text},
            timeout=10
        )
        if response.status_code == 200:
            result = response.json()
            # Event is stored on backend; user can click "Refresh All Events" to see it
            return result
        else:
            error_msg = f"API returned status {response.status_code}"
            try:
                error_detail = response.json().get("detail", response.text)
                error_msg += f": {error_detail}"
            except:
                error_msg += f": {response.text[:200]}"
            st.error(f"❌ {error_msg}")
            return None
    except requests.exceptions.ConnectionError as e:
        st.error(f"❌ Cannot connect to API at {API_URL}")
        st.info("💡 **Troubleshooting:**")
        st.info("1. Make sure backend is running: `docker compose up` or `python -m uvicorn app.main:app --port 8000`")
        st.info(f"2. Check API URL: {API_URL}")
        st.info("3. For Docker: Use `http://backend:8000`")
        st.info("4. For local: Use `http://localhost:8000`")
        return None
    except requests.exceptions.Timeout:
        st.error("⏱️ API request timed out (>10s). The model might be loading or the request is too complex.")
        return None
    except Exception as e:
        st.error(f"❌ Unexpected error: {str(e)}")
        st.exception(e)  # Show full error in expander
        return None


def get_lo2_log_score(log_text: str) -> Optional[Dict]:
    """Get LO2 log anomaly score from API."""
    try:
        response = requests.post(
            f"{API_URL}/score/lo2/log",
            json={"log_text": log_text},
            timeout=10
        )
        if response.status_code == 200:
            return response.json()
        else:
            st.error(f"API returned status {response.status_code}: {response.text}")
            return None
    except requests.exceptions.ConnectionError:
        st.error("❌ Cannot connect to API. Is the backend running?")
        return None
    except requests.exceptions.Timeout:
        st.error("⏱️ API request timed out. The backend might be slow or overloaded.")
        return None
    except Exception as e:
        st.error(f"❌ API error: {str(e)}")
        return None


def get_lo2_metric_score(metrics: Dict[str, float]) -> Optional[Dict]:
    """Get LO2 metric anomaly score from API."""
    try:
        response = requests.post(
            f"{API_URL}/score/lo2/metric",
            json={"metrics": metrics},
            timeout=10
        )
        if response.status_code == 200:
            return response.json()
        else:
            st.error(f"API returned status {response.status_code}: {response.text}")
            return None
    except requests.exceptions.ConnectionError:
        st.error("❌ Cannot connect to API. Is the backend running?")
        return None
    except requests.exceptions.Timeout:
        st.error("⏱️ API request timed out. The backend might be slow or overloaded.")
        return None
    except Exception as e:
        st.error(f"❌ API error: {str(e)}")
        return None


def get_events_summary() -> Dict[str, int]:
    """Get event counts summary from API."""
    try:
        response = requests.get(f"{API_URL}/events/summary", timeout=2)
        if response.status_code == 200:
            return response.json()
        return {"modsec": 0, "lo2_log": 0, "lo2_metric": 0}
    except Exception:
        return {"modsec": 0, "lo2_log": 0, "lo2_metric": 0}


def get_modsec_events_from_api(limit: int = 500) -> List[Dict]:
    """Get ModSecurity events from API."""
    try:
        response = requests.get(f"{API_URL}/events/modsec?limit={limit}", timeout=5)
        if response.status_code == 200:
            return response.json().get("events", [])
        return []
    except Exception:
        return []


def get_lo2_log_events_from_api(limit: int = 500) -> List[Dict]:
    """Get LO2 log events from API."""
    try:
        response = requests.get(f"{API_URL}/events/lo2/log?limit={limit}", timeout=5)
        if response.status_code == 200:
            return response.json().get("events", [])
        return []
    except Exception:
        return []


def get_lo2_metric_events_from_api(limit: int = 500) -> List[Dict]:
    """Get LO2 metric events from API."""
    try:
        response = requests.get(f"{API_URL}/events/lo2/metric?limit={limit}", timeout=5)
        if response.status_code == 200:
            return response.json().get("events", [])
        return []
    except Exception:
        return []


def clear_events() -> bool:
    """Clear all events via API."""
    try:
        response = requests.post(f"{API_URL}/events/clear", timeout=5)
        return response.status_code == 200
    except Exception:
        return False


@st.cache_data
def load_report_csv(path: Path) -> Optional[pd.DataFrame]:
    """Load CSV report file with caching."""
    try:
        if path.exists():
            return pd.read_csv(path)
    except Exception as e:
        st.warning(f"Could not load {path}: {e}")
    return None


def main():
    """Main dashboard application."""
    st.title("🛡️ AI-Driven Log Sentinel")
    st.markdown("Mini-SIEM Dashboard for Threat Detection & Anomaly Detection")
    
    # Sidebar
    with st.sidebar:
        st.header("Configuration")
        api_status = check_api_health()
        if api_status:
            st.success("✅ API Connected")
        else:
            st.error("❌ API Not Available")
            st.info(f"**API URL:** `{API_URL}`")
            st.info("**Check:**")
            st.info("• Backend running?")
            st.info("• Correct URL? (localhost vs backend)")
            st.info("• Firewall blocking?")
        
        st.markdown("---")
        st.markdown("### Event Store")
        
        # Get summary from API
        if api_status:
            summary = get_events_summary()
            st.info(f"ModSec Events: {summary.get('modsec', 0)}")
            st.info(f"LO2 Log Events: {summary.get('lo2_log', 0)}")
            st.info(f"LO2 Metric Events: {summary.get('lo2_metric', 0)}")
        else:
            st.info(f"ModSec Events: {len(st.session_state.modsec_events)}")
            st.info(f"LO2 Log Events: {len(st.session_state.lo2_log_events)}")
            st.info(f"LO2 Metric Events: {len(st.session_state.lo2_metric_events)}")
        
        if st.button("🔄 Refresh All Events"):
            with st.spinner("Refreshing events..."):
                if api_status:
                    st.session_state.modsec_events = get_modsec_events_from_api(limit=200)
                    st.session_state.lo2_log_events = get_lo2_log_events_from_api(limit=100)
                    st.session_state.lo2_metric_events = get_lo2_metric_events_from_api(limit=100)
            st.rerun()
        
        if st.button("🗑️ Clear Event Store"):
            if api_status:
                if clear_events():
                    st.success("Event store cleared!")
                    st.session_state.modsec_events = []
                    st.session_state.lo2_log_events = []
                    st.session_state.lo2_metric_events = []
                else:
                    st.error("Failed to clear event store")
            else:
                st.session_state.modsec_events = []
                st.session_state.lo2_log_events = []
                st.session_state.lo2_metric_events = []
            st.rerun()
    
    # Main tabs (Reports removed for performance)
    tab1, tab2 = st.tabs(["ModSecurity", "LO2"])
    
    # Tab 1: ModSecurity
    with tab1:
        st.header("ModSecurity Threat Detection")
        
        if not api_status:
            st.warning("⚠️ API is not available. Please start the backend service.")
        else:
            # Recent events table
            st.subheader("Recent Threat Events (Last 500)")
            
            # Load events from session state or API (only if empty)
            if not st.session_state.modsec_events:
                with st.spinner("Loading events..."):
                    api_events = get_modsec_events_from_api(limit=200)  # Reduced from 500
                    if api_events:
                        st.session_state.modsec_events = api_events
            
            if st.session_state.modsec_events:
                df_modsec = pd.DataFrame(st.session_state.modsec_events)
                # Keep only last 200 for performance
                df_modsec = df_modsec.tail(200)
                
                # Display table (limit columns and rows for performance)
                display_cols = ["risk_score", "threat_type"]  # Removed request_text and top_signals for performance
                available_cols = [col for col in display_cols if col in df_modsec.columns]
                
                # Show only first 50 rows initially
                max_rows = st.slider("Show rows", 20, min(200, len(df_modsec)), 50, key="modsec_rows")
                
                if available_cols:
                    st.dataframe(df_modsec[available_cols].head(max_rows), height=250)
                else:
                    st.dataframe(df_modsec.head(max_rows), height=250)
                
                # Threat distribution (simplified)
                col1, col2 = st.columns(2)
                
                with col1:
                    st.subheader("Threat Type Distribution")
                    if "threat_type" in df_modsec.columns:
                        threat_counts = df_modsec["threat_type"].value_counts().head(10)
                        if len(threat_counts) > 0 and threat_counts.sum() > 0:
                            st.bar_chart(threat_counts)
                        else:
                            st.caption("No threat data to chart")
                
                with col2:
                    st.subheader("Risk Score Distribution")
                    if "risk_score" in df_modsec.columns:
                        # Sample data for histogram (faster)
                        sample_scores = df_modsec["risk_score"].head(100)
                        plot_histogram(sample_scores)
                
                # Statistics (simplified)
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Total Events", len(df_modsec))
                with col2:
                    if "risk_score" in df_modsec.columns:
                        st.metric("Avg Risk Score", f"{df_modsec['risk_score'].mean():.3f}")
                with col3:
                    if "risk_score" in df_modsec.columns:
                        high_risk = (df_modsec["risk_score"] > 0.7).sum()
                        st.metric("High Risk (>0.7)", high_risk)
            else:
                st.info("No events yet. Run replay scripts to generate data.")
            
            # Manual test
            with st.expander("🧪 Manual Test", expanded=False):
                st.markdown("**Test ModSecurity threat detection:**")
                test_request = st.text_area(
                    "Enter HTTP request text:",
                    value="GET /index.php?id=1' OR '1'='1 HTTP/1.1",
                    height=100,
                    key="manual_test_input"
                )
                
                col1, col2 = st.columns([1, 4])
                with col1:
                    test_button = st.button("🚀 Test Request", type="primary", use_container_width=True)
                
                if test_button:
                    if not test_request or not test_request.strip():
                        st.warning("⚠️ Please enter a request text to test.")
                    else:
                        with st.spinner("Analyzing request..."):
                            result = get_modsec_prediction(test_request)
                            if result:
                                st.success("✅ Analysis complete!")
                                
                                # Display results in columns
                                col1, col2 = st.columns(2)
                                with col1:
                                    st.metric("Risk Score", f"{result.get('risk_score', 0):.3f}")
                                    st.metric("Threat Type", result.get('threat_type', 'UNKNOWN'))
                                with col2:
                                    if result.get('top_signals'):
                                        st.markdown("**Top Signals:**")
                                        for signal in result.get('top_signals', [])[:5]:
                                            st.write(f"• {signal}")
                                
                                # Show full JSON (cannot nest expanders)
                                st.markdown("**📋 Full Response JSON:**")
                                st.json(result)
                                
                                st.info("💡 Event has been added to the event store. Click '🔄 Refresh All Events' to see it.")
                            else:
                                st.error("❌ Failed to get prediction. Check API connection.")
    
    # Tab 2: LO2
    with tab2:
        st.header("LO2 Anomaly Detection")
        
        if not api_status:
            st.warning("⚠️ API is not available. Please start the backend service.")
        else:
            col1, col2 = st.columns(2)
            
            # LO2 Log Anomalies
            with col1:
                st.subheader("Log Anomalies")
                
                # Load events only if empty
                if not st.session_state.lo2_log_events:
                    with st.spinner("Loading log events..."):
                        api_log_events = get_lo2_log_events_from_api(limit=100)  # Reduced from 500
                        if api_log_events:
                            st.session_state.lo2_log_events = api_log_events
                
                if st.session_state.lo2_log_events:
                    df_log = pd.DataFrame(st.session_state.lo2_log_events)
                    df_log = df_log.tail(100)
                    
                    # Limit rows for performance
                    max_rows_log = min(30, len(df_log))
                    if "anomaly_score" in df_log.columns:
                        # Show only essential columns
                        display_df = df_log[["anomaly_score"]].head(max_rows_log)
                        st.dataframe(display_df, height=150)
                        
                        # Simplified visualization
                        sample_scores = df_log["anomaly_score"].head(50)
                        plot_histogram(sample_scores)
                        
                        st.metric("Avg Anomaly Score", f"{df_log['anomaly_score'].mean():.3f}")
                        high_anomaly = (df_log["anomaly_score"] > 0.7).sum()
                        st.metric("High Anomaly (>0.7)", high_anomaly)
                else:
                    st.info("No log events yet.")
            
            # LO2 Metric Anomalies
            with col2:
                st.subheader("Metric Anomalies")
                
                # Load events only if empty
                if not st.session_state.lo2_metric_events:
                    with st.spinner("Loading metric events..."):
                        api_metric_events = get_lo2_metric_events_from_api(limit=100)  # Reduced from 500
                        if api_metric_events:
                            st.session_state.lo2_metric_events = api_metric_events
                
                if st.session_state.lo2_metric_events:
                    df_metric = pd.DataFrame(st.session_state.lo2_metric_events)
                    df_metric = df_metric.tail(100)
                    
                    # Limit rows for performance
                    max_rows_metric = min(30, len(df_metric))
                    if "anomaly_score" in df_metric.columns:
                        # Show only essential columns
                        display_df = df_metric[["anomaly_score"]].head(max_rows_metric)
                        st.dataframe(display_df, height=150)
                        
                        # Simplified visualization
                        sample_scores = df_metric["anomaly_score"].head(50)
                        plot_histogram(sample_scores)
                        
                        st.metric("Avg Anomaly Score", f"{df_metric['anomaly_score'].mean():.3f}")
                        high_anomaly = (df_metric["anomaly_score"] > 0.7).sum()
                        st.metric("High Anomaly (>0.7)", high_anomaly)
                else:
                    st.info("No metric events yet.")
            
            # Load from reports if available (lazy loading with expander)
            with st.expander("📊 Top Anomalies from Reports", expanded=False):
                report_col1, report_col2 = st.columns(2)
                
                with report_col1:
                    log_report_path = REPORTS_DIR / "lo2" / "top_anomalies_log.csv"
                    if log_report_path.exists():
                        df_log_report = load_report_csv(log_report_path)
                        if df_log_report is not None:
                            st.dataframe(df_log_report.head(10), height=200)  # Reduced from 20
                
                with report_col2:
                    metric_report_path = REPORTS_DIR / "lo2" / "top_anomalies_metric.csv"
                    if metric_report_path.exists():
                        df_metric_report = load_report_csv(metric_report_path)
                        if df_metric_report is not None:
                            st.dataframe(df_metric_report.head(10), height=200)  # Reduced from 20
            
            # Manual tests
            st.divider()
            test_col1, test_col2 = st.columns(2)
            
            # LO2 Log Manual Test
            with test_col1:
                with st.expander("🧪 Manual Test - Log Anomaly", expanded=False):
                    st.markdown("**Test LO2 log anomaly detection:**")
                    test_log = st.text_area(
                        "Enter log text:",
                        value="2024-01-15 10:23:45 ERROR Database connection failed: timeout after 30s",
                        height=100,
                        key="manual_test_log_input"
                    )
                    
                    log_test_button = st.button("🚀 Test Log", type="primary", use_container_width=True, key="log_test_btn")
                    
                    if log_test_button:
                        if not test_log or not test_log.strip():
                            st.warning("⚠️ Please enter log text to test.")
                        else:
                            with st.spinner("Analyzing log..."):
                                result = get_lo2_log_score(test_log)
                                if result:
                                    st.success("✅ Analysis complete!")
                                    
                                    col1, col2 = st.columns(2)
                                    with col1:
                                        st.metric("Anomaly Score", f"{result.get('anomaly_score', 0):.3f}")
                                    with col2:
                                        risk_level = "High" if result.get('anomaly_score', 0) > 0.7 else "Medium" if result.get('anomaly_score', 0) > 0.4 else "Low"
                                        st.metric("Risk Level", risk_level)
                                    
                                    st.markdown("**📋 Full Response JSON:**")
                                    st.json(result)
                                    
                                    st.info("💡 Event has been added to the event store. Click '🔄 Refresh All Events' to see it.")
                                else:
                                    st.error("❌ Failed to get anomaly score. Check API connection.")
            
            # LO2 Metric Manual Test
            with test_col2:
                with st.expander("🧪 Manual Test - Metric Anomaly", expanded=False):
                    st.markdown("**Test LO2 metric anomaly detection:**")
                    st.markdown("Enter metric values (JSON format):")
                    
                    default_metrics = """{
  "cpu_usage": 85.5,
  "memory_usage": 92.3,
  "disk_io": 1500.0,
  "network_bytes": 1000000.0
}"""
                    
                    test_metrics_json = st.text_area(
                        "Metrics JSON:",
                        value=default_metrics,
                        height=150,
                        key="manual_test_metric_input"
                    )
                    
                    metric_test_button = st.button("🚀 Test Metrics", type="primary", use_container_width=True, key="metric_test_btn")
                    
                    if metric_test_button:
                        if not test_metrics_json or not test_metrics_json.strip():
                            st.warning("⚠️ Please enter metrics JSON to test.")
                        else:
                            try:
                                import json
                                metrics_dict = json.loads(test_metrics_json)
                                
                                # Validate it's a dict with numeric values
                                if not isinstance(metrics_dict, dict):
                                    st.error("❌ Metrics must be a JSON object/dictionary.")
                                else:
                                    # Convert all values to float
                                    metrics_dict = {k: float(v) for k, v in metrics_dict.items()}
                                    
                                    with st.spinner("Analyzing metrics..."):
                                        result = get_lo2_metric_score(metrics_dict)
                                        if result:
                                            st.success("✅ Analysis complete!")
                                            
                                            col1, col2 = st.columns(2)
                                            with col1:
                                                st.metric("Anomaly Score", f"{result.get('anomaly_score', 0):.3f}")
                                            with col2:
                                                risk_level = "High" if result.get('anomaly_score', 0) > 0.7 else "Medium" if result.get('anomaly_score', 0) > 0.4 else "Low"
                                                st.metric("Risk Level", risk_level)
                                            
                                            st.markdown("**📋 Full Response JSON:**")
                                            st.json(result)
                                            
                                            st.info("💡 Event has been added to the event store. Click '🔄 Refresh All Events' to see it.")
                                        else:
                                            st.error("❌ Failed to get anomaly score. Check API connection.")
                            except json.JSONDecodeError as e:
                                st.error(f"❌ Invalid JSON format: {str(e)}")
                            except ValueError as e:
                                st.error(f"❌ Invalid metric values: {str(e)}")
                            except Exception as e:
                                st.error(f"❌ Error: {str(e)}")


if __name__ == "__main__":
    main()
