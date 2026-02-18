"""Replay script for ModSecurity threat detection demo."""
import random
import time
from typing import List

import requests
from tqdm import tqdm

# Configuration
API_URL = "http://localhost:8000"
NUM_REQUESTS = 150


def generate_sample_requests() -> List[str]:
    """Generate sample HTTP requests (attacks + normal)."""
    samples = []
    
    sql_samples = [
        "GET /index.php?id=1' OR '1'='1 HTTP/1.1",
        "POST /login.php HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n\nusername=admin'--&password=pass",
        "GET /search.php?q=test' UNION SELECT * FROM users-- HTTP/1.1",
    ]
    
    xss_samples = [
        "GET /page.php?name=<script>alert('XSS')</script> HTTP/1.1",
        "GET /comment.php?text=<img src=x onerror=alert(1)> HTTP/1.1",
    ]
    
    rce_samples = [
        "GET /cgi-bin/test.cgi?cmd=whoami HTTP/1.1",
        "GET /api/exec?command=powershell -c \"Get-Process\" HTTP/1.1",
    ]
    
    traversal_samples = [
        "GET /../../etc/passwd HTTP/1.1",
        "GET /files/....//....//etc/shadow HTTP/1.1",
    ]
    
    scanner_samples = [
        "GET / HTTP/1.1\nUser-Agent: nikto/2.1.6",
        "GET /.git/config HTTP/1.1\nUser-Agent: gobuster/3.0.1",
    ]
    
    normal_samples = [
        "GET /index.html HTTP/1.1",
        "GET /products HTTP/1.1",
        "POST /api/login HTTP/1.1\nContent-Type: application/json\n\n{\"username\":\"user\",\"password\":\"pass123\"}",
    ]
    
    all_samples = (
        sql_samples * 20 +
        xss_samples * 15 +
        rce_samples * 10 +
        traversal_samples * 10 +
        scanner_samples * 15 +
        normal_samples * 80
    )
    
    random.shuffle(all_samples)
    return all_samples[:NUM_REQUESTS]


def send_request(request_text: str) -> dict:
    """Send request to API and return response."""
    try:
        response = requests.post(
            f"{API_URL}/predict/modsec",
            json={"request_text": request_text},
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
    print(f"Starting ModSecurity replay with {NUM_REQUESTS} requests...")
    print(f"API URL: {API_URL}")
    
    try:
        health_response = requests.get(f"{API_URL}/health", timeout=2)
        if health_response.status_code != 200:
            print(f"Warning: API health check failed (status {health_response.status_code})")
    except Exception as e:
        print(f"Error: Cannot connect to API at {API_URL}")
        print(f"   {e}")
        return
    
    samples = generate_sample_requests()
    results = []
    
    for sample in tqdm(samples, desc="Processing requests"):
        result = send_request(sample)
        results.append({
            "request_text": sample[:100],
            "risk_score": result.get("risk_score", 0.0),
            "threat_type": result.get("threat_type", "UNKNOWN"),
            "top_signals": result.get("top_signals", []),
            "timestamp": time.time()
        })
        time.sleep(0.1)
    
    print("\nReplay completed!")
    print(f"Total requests: {len(results)}")
    
    threat_types = {}
    for r in results:
        threat_type = r.get("threat_type", "UNKNOWN")
        threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
    
    print("\nThreat Type Distribution:")
    for threat_type, count in sorted(threat_types.items(), key=lambda x: -x[1]):
        print(f"   {threat_type}: {count}")
    
    avg_risk = sum(r.get("risk_score", 0) for r in results) / len(results)
    print(f"\nAverage Risk Score: {avg_risk:.3f}")
    print("\nNote: Results are sent to API event store.")
    print("View them in the dashboard at http://localhost:8501")


if __name__ == "__main__":
    main()
