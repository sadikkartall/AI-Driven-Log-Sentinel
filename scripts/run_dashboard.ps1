# Start Streamlit dashboard
Write-Host "Starting Streamlit dashboard..." -ForegroundColor Green
cd dashboard
$env:API_URL = "http://localhost:8000"
streamlit run app.py --server.port 8501
