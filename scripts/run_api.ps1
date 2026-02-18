# Start FastAPI backend server
Write-Host "Starting FastAPI backend..." -ForegroundColor Green
cd backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
