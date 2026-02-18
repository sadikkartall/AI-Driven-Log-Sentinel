"""Replay script for LO2 log and metric anomaly detection demo."""
import csv
import random
import time
from pathlib import Path
from typing import Dict, List

import requests
from tqdm import tqdm

# Configuration
API_URL = "http://localhost:8000"  # Change to http://backend:8000 in Docker
NUM_LOG_REQUESTS = 100
NUM_METRIC_REQUESTS = 100
REPORTS_DIR = Path("outputs/reports/lo2")


def generate_log_samples() -> List[str]:
    """Generate sample log entries."""
    samples = []
    
    # Normal logs
    normal_logs = [
        "2024-01-15 10:23:45 INFO User login successful: user@example.com",
        "2024-01-15 10:24:12 DEBUG Processing request: GET /api/products",
        "2024-01-15 10:25:33 INFO Database query completed in 45ms",
        "2024-01-15 10:26:01 WARN Rate limit approaching: 80%",
        "2024-01-15 10:27:22 INFO Cache hit: /api/products?category=electronics",
        "2024-01-15 10:28:45 INFO User logout: user@example.com",
        "2024-01-15 10:29:12 DEBUG API response time: 120ms",
        "2024-01-15 10:30:33 INFO Scheduled task completed: cleanup_old_sessions",
    ]
    
    # Anomalous logs
    anomalous_logs = [
        "2024-01-15 10:23:45 ERROR Database connection failed: timeout after 30s",
        "2024-01-15 10:24:12 CRITICAL Memory usage exceeded 95% threshold",
        "2024-01-15 10:25:33 ERROR Unauthorized access attempt from 192.168.1.100",
        "2024-01-15 10:26:01 ERROR File not found: /etc/passwd",
        "2024-01-15 10:27:22 CRITICAL System crash detected: kernel panic",
        "2024-01-15 10:28:45 ERROR Invalid authentication token: expired",
        "2024-01-15 10:29:12 ERROR Disk I/O error: sector 12345 read failed",
        "2024-01-15 10:30:33 CRITICAL Network interface eth0 down",
        "2024-01-15 10:31:45 ERROR Process killed by OOM killer: pid 12345",
        "2024-01-15 10:32:12 ERROR Database deadlock detected: transaction rollback",
    ]
    
    # Mix normal and anomalous
    all_logs = normal_logs * 7 + anomalous_logs * 3
    random.shuffle(all_logs)
    
    return all_logs[:NUM_LOG_REQUESTS]


def load_metric_columns() -> List[str]:
    """Load metric column names from CSV."""
    csv_path = REPORTS_DIR / "selected_metric_columns.csv"
    if not csv_path.exists():
        print(f"⚠️  Warning: {csv_path} not found. Using empty metric list.")
        return []
    
    columns = []
    with open(csv_path, "r") as f:
        reader = csv.reader(f)
        next(reader)  # Skip header
        for row in reader:
            if row:
                columns.append(row[0])
    
    return columns


def generate_metric_samples(columns: List[str]) -> List[Dict[str, float]]:
    """Generate sample metric data."""
    samples = []
    
    for _ in range(NUM_METRIC_REQUESTS):
        metrics = {}
        
        # Generate normal or anomalous values
        is_anomalous = random.random() < 0.2  # 20% anomalous
        
        for col in columns:
            if "cpu" in col.lower():
                # CPU metrics: 0-100
                base_value = random.uniform(10, 80) if not is_anomalous else random.uniform(90, 100)
            elif "memory" in col.lower() or "mem" in col.lower():
                # Memory metrics: bytes
                base_value = random.uniform(1e9, 8e9) if not is_anomalous else random.uniform(15e9, 20e9)
            elif "disk" in col.lower():
                # Disk metrics: bytes
                base_value = random.uniform(1e10, 1e12) if not is_anomalous else random.uniform(1e13, 1e14)
            elif "network" in col.lower() or "netstat" in col.lower():
                # Network metrics: bytes or packets
                base_value = random.uniform(1e6, 1e9) if not is_anomalous else random.uniform(1e10, 1e11)
            elif "load" in col.lower():
                # Load average: 0-10
                base_value = random.uniform(0.5, 2.0) if not is_anomalous else random.uniform(8.0, 15.0)
            else:
                # Generic: use random positive value
                base_value = random.uniform(1, 1000) if not is_anomalous else random.uniform(10000, 100000)
            
            metrics[col] = base_value
        
        samples.append(metrics)
    
    return samples


def send_log_request(log_text: str) -> dict:
    """Send log text to API."""
    try:
        response = requests.post(
            f"{API_URL}/score/lo2/log",
            json={"log_text": log_text},
            timeout=5
        )
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def send_metric_request(metrics: Dict[str, float]) -> dict:
    """Send metrics to API."""
    try:
        response = requests.post(
            f"{API_URL}/score/lo2/metric",
            json={"metrics": metrics},
            timeout=5
        )
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"HTTP {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def main():
    """Main replay function."""
    print("🚀 Starting LO2 replay...")
    print(f"API URL: {API_URL}")
    
    # Check API health
    try:
        health_response = requests.get(f"{API_URL}/health", timeout=2)
        if health_response.status_code != 200:
            print(f"⚠️  Warning: API health check failed (status {health_response.status_code})")
    except Exception as e:
        print(f"❌ Error: Cannot connect to API at {API_URL}")
        print(f"   {e}")
        return
    
    # Process logs
    print(f"\n📝 Processing {NUM_LOG_REQUESTS} log samples...")
    log_samples = generate_log_samples()
    log_results = []
    
    for log_text in tqdm(log_samples, desc="Processing logs"):
        result = send_log_request(log_text)
        log_results.append({
            "log_text": log_text[:100],  # Truncate
            "anomaly_score": result.get("anomaly_score", 0.0),
            "timestamp": time.time()
        })
        time.sleep(0.1)
    
    # Process metrics
    print(f"\n📊 Processing {NUM_METRIC_REQUESTS} metric samples...")
    metric_columns = load_metric_columns()
    
    if not metric_columns:
        print("⚠️  No metric columns found. Skipping metric replay.")
    else:
        print(f"   Loaded {len(metric_columns)} metric columns")
        metric_samples = generate_metric_samples(metric_columns)
        metric_results = []
        
        for metrics in tqdm(metric_samples, desc="Processing metrics"):
            result = send_metric_request(metrics)
            metric_results.append({
                "metrics_count": len(metrics),
                "anomaly_score": result.get("anomaly_score", 0.0),
                "timestamp": time.time()
            })
            time.sleep(0.1)
    
    # Summary
    print("\n✅ Replay completed!")
    print(f"   Log requests: {len(log_results)}")
    
    if log_results:
        avg_log_score = sum(r.get("anomaly_score", 0) for r in log_results) / len(log_results)
        high_anomaly_logs = sum(1 for r in log_results if r.get("anomaly_score", 0) > 0.7)
        print(f"   Average log anomaly score: {avg_log_score:.3f}")
        print(f"   High anomaly logs (>0.7): {high_anomaly_logs}")
    
    if metric_columns:
        print(f"   Metric requests: {len(metric_results)}")
        if metric_results:
            avg_metric_score = sum(r.get("anomaly_score", 0) for r in metric_results) / len(metric_results)
            high_anomaly_metrics = sum(1 for r in metric_results if r.get("anomaly_score", 0) > 0.7)
            print(f"   Average metric anomaly score: {avg_metric_score:.3f}")
            print(f"   High anomaly metrics (>0.7): {high_anomaly_metrics}")
    
    print("\n💡 Note: Results are sent to API event store.")
    print("   View them in the dashboard at http://localhost:8501")


if __name__ == "__main__":
    main()
