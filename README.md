# AI-Driven Log Sentinel

> Mini-SIEM (Security Information and Event Management) sistemi - ModSecurity tehdit tespiti ve LO2 log/metric anomali tespiti için MVP uygulaması.

**GitHub:** [github.com/sadikkartall/AI-Driven-Log-Sentinel](https://github.com/sadikkartall/AI-Driven-Log-Sentinel)

## Hızlı Başlangıç

```bash
git clone https://github.com/sadikkartall/AI-Driven-Log-Sentinel.git
cd AI-Driven-Log-Sentinel
docker compose up --build
```

- **Dashboard:** http://localhost:8501
- **API Docs:** http://localhost:8000/docs

## 📋 İçindekiler

- [Mimari](#mimari)
- [Kurulum](#kurulum)
  - [Docker ile Çalıştırma](#docker-ile-çalıştırma)
  - [Local Run (venv ile)](#local-run-venv-ile)
- [API Kullanımı](#api-kullanımı)
- [Replay & Test Scriptleri](#replay-scriptleri)
- [Dashboard](#dashboard)
- [Çıktılar](#çıktılar)
- [Testler](#testler)
- [Yapılandırma](#yapılandırma)
- [Sorun Giderme](#sorun-giderme)

## 📁 Proje Yapısı

```
AI-Driven-Log-Sentinel/
├── backend/              # FastAPI API
│   └── app/
│       ├── core/         # Ayarlar
│       ├── routers/      # API endpoint'leri (modsec, lo2, events)
│       ├── services/     # Model loader, event store
│       └── utils/       # Yardımcı modüller
├── dashboard/            # Streamlit arayüzü
├── scripts/              # Replay & test scriptleri
│   ├── replay_modsec.py  # ModSec demo verisi
│   ├── replay_lo2.py     # LO2 demo verisi
│   ├── setup_data.ps1    # outputs dizini kontrolü
│   └── run_*.ps1         # Başlatma scriptleri
├── outputs/              # Modeller ve raporlar
│   ├── models/           # ModSec & LO2 modelleri (.pkl)
│   │   ├── modsec/
│   │   └── lo2/
│   └── reports/          # CSV raporları
├── tests/                # pytest testleri
├── .streamlit/           # Streamlit yapılandırması
├── Dockerfile.backend    # Backend container
├── Dockerfile.dashboard  # Dashboard container
└── docker-compose.yml
```

## 🏗️ Mimari

Proje iki ana bileşenden oluşur:

### 1. ModSecurity Hattı
- **Amaç**: HTTP isteklerinde tehdit tespiti (SQL Injection, XSS, RCE, Path Traversal, Scanner, vb.)
- **Model**: `outputs/models/modsec/` altında eğitilmiş sınıflandırma modeli
  - Öncelik sırası: `threat_model_stable.pkl` > `threat_model_balanced.pkl` > `threat_model.pkl`
- **Endpoint**: `POST /predict/modsec`
- **Çıktı**: Risk skoru (0-1), tehdit tipi, tespit edilen sinyaller

### 2. LO2 Hattı
- **Amaç**: Log ve metrik verilerinde anomali tespiti
- **Modeller**:
  - **Log**: `log_tfidf.pkl` + `log_isoforest.pkl`
  - **Metric**: `metric_scaler.pkl` + `metric_isoforest.pkl` + `selected_metric_columns.csv`
- **Endpointler**: 
  - `POST /score/lo2/log` - Log metinleri için anomali skoru
  - `POST /score/lo2/metric` - Metrik verileri için anomali skoru
- **Çıktı**: Anomali skoru (0-1, 1 = en anormal)

## 🚀 Kurulum

### Docker ile Çalıştırma

**Gereksinimler:**
- Docker Desktop kurulu ve çalışıyor olmalı

**Adımlar:**

1. Projeyi klonlayın veya indirin
2. Terminal'de proje kök dizinine gidin
3. Docker Compose ile başlatın:

```bash
docker compose up --build
```

Bu komut:
- Backend servisini `http://localhost:8000` adresinde başlatır
- Dashboard'u `http://localhost:8501` adresinde başlatır
- `outputs/` klasörünü read-only olarak container'lara mount eder

**Beklenen Çıktı:**
```
[+] Running 2/2
 ✔ Container log-sentinel-backend    Started
 ✔ Container log-sentinel-dashboard  Started
```

**Servisler:**
- Backend API: http://localhost:8000
- API Docs (Swagger): http://localhost:8000/docs
- Dashboard: http://localhost:8501

**Durdurma:**
```bash
docker compose down
```

### Demo Akışı

1. **Sistemleri başlat:**
   ```bash
   docker compose up --build
   ```

2. **Dashboard'u aç:**
   - Tarayıcıda http://localhost:8501 adresine git
   - Sol menüde "API Connected" görünmeli
   - Event Store'da tüm event sayıları 0 olmalı

3. **Manual test ile event oluştur:**
   - Dashboard'da "ModSecurity" sekmesine git
   - "Manual Test" expander'ını aç
   - Test request'i gönder (örn: `GET /index.php?id=1' OR '1'='1 HTTP/1.1`)
   - "Test Request" butonuna tıkla
   - Sonuç görüntülenecek ve event store'a kaydedilecek

4. **Event'leri görüntüle:**
   - Sol menüdeki "🔄 Refresh All Events" butonuna tıkla
   - Event Store sayıları artmalı (ModSec Events: 1)
   - ModSecurity sekmesinde tablo ve grafikler görünmeli

5. **Replay scriptleri ile daha fazla event:**
   ```bash
   # Yeni bir terminalde
   pip install requests tqdm
   python scripts/replay_modsec.py
   python scripts/replay_lo2.py
   ```
   - Dashboard'da "🔄 Refresh All Events" butonuna tekrar tıkla
   - Event sayıları artmalı (ModSec Events: 150+, LO2 Log Events: 100+, vb.)

6. **Event store'u temizle:**
   - Sol menüdeki "🗑️ Clear Event Store" butonuna tıkla
   - Tüm event'ler temizlenecek ve sayılar 0'a dönecek

### Local Run (venv ile)

**Gereksinimler:**
- Python 3.11+
- PowerShell (Windows) veya bash (Linux/Mac)

**Adımlar:**

#### 1. Virtual environment kurulumu

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r backend/requirements.txt
pip install -r dashboard/requirements.txt
```

**Not (Windows):** PowerShell'de execution policy hatası alırsanız:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

#### 2. API'yi başlat (bir terminal)

```powershell
cd backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

veya PowerShell script ile:
```powershell
.\scripts\run_api.ps1
```

#### 3. ModSecurity model eğitimi ve replay (başka bir terminal)

**Not:** Model eğitimi için ayrı script gerekebilir. Demo için sadece replay çalıştırılabilir:

```powershell
# Replay scriptini çalıştır
python scripts/replay_modsec.py
```

veya PowerShell script ile:
```powershell
.\scripts\run_replay_modsec.ps1
```

#### 4. LO2 model eğitimi ve replay

**Not:** Model eğitimi için ayrı script gerekebilir. Demo için sadece replay çalıştırılabilir:

```powershell
python scripts/replay_lo2.py
```

veya PowerShell script ile:
```powershell
.\scripts\run_replay_lo2.ps1
```

#### 5. Dashboard (başka bir terminal)

```powershell
cd dashboard
streamlit run app.py --server.port 8501
```

veya PowerShell script ile:
```powershell
.\scripts\run_dashboard.ps1
```

## 📡 API Kullanımı

### Health Check

```bash
curl http://localhost:8000/health
```

**Yanıt:**
```json
{"status":"ok"}
```

### Event Store Endpoints

**Event Summary:**
```bash
curl http://localhost:8000/events/summary
```

**Yanıt:**
```json
{
  "modsec": 150,
  "lo2_log": 100,
  "lo2_metric": 100
}
```

**Get ModSecurity Events:**
```bash
curl http://localhost:8000/events/modsec?limit=100
```

**Get LO2 Log Events:**
```bash
curl http://localhost:8000/events/lo2/log?limit=100
```

**Get LO2 Metric Events:**
```bash
curl http://localhost:8000/events/lo2/metric?limit=100
```

**Clear All Events:**
```bash
curl -X POST http://localhost:8000/events/clear
```

### ModSecurity Tehdit Tespiti

```bash
curl -X POST http://localhost:8000/predict/modsec \
  -H "Content-Type: application/json" \
  -d '{"request_text": "GET /index.php?id=1'\'' OR '\''1'\''='\''1 HTTP/1.1"}'
```

**Yanıt:**
```json
{
  "risk_score": 0.95,
  "threat_type": "SQLI",
  "top_signals": [
    "SQLI: union select",
    "SQLI: 'or'"
  ]
}
```

### LO2 Log Anomali Tespiti

```bash
curl -X POST http://localhost:8000/score/lo2/log \
  -H "Content-Type: application/json" \
  -d '{"log_text": "2024-01-15 10:23:45 ERROR Database connection failed: timeout"}'
```

**Yanıt:**
```json
{
  "anomaly_score": 0.78
}
```

### LO2 Metric Anomali Tespiti

```bash
curl -X POST http://localhost:8000/score/lo2/metric \
  -H "Content-Type: application/json" \
  -d '{
    "metrics": {
      "node_cpu_seconds_total&cpu=0&mode=idle": 100.0,
      "node_memory_MemFree_bytes": 5000000000.0
    }
  }'
```

**Yanıt:**
```json
{
  "anomaly_score": 0.65
}
```

**Not:** Metric endpoint'i `outputs/reports/lo2/selected_metric_columns.csv` dosyasındaki kolonları kullanır. Eksik kolonlar 0 ile doldurulur, fazla kolonlar yok sayılır.

## 🎬 Replay & Test Scriptleri

Replay scriptleri demo verileri üretip API'ye gönderir. Manuel test scripti tüm endpoint'leri test eder. Bu scriptler production'da gerçek veri kaynaklarından (log dosyaları, metrik toplayıcılar) gelen verilerin yerini tutar.

### ModSecurity Replay

```bash
python scripts/replay_modsec.py
```

- 150 adet örnek HTTP isteği üretir (SQLI, XSS, RCE, Traversal, Scanner, Normal)
- Her isteği `/predict/modsec` endpoint'ine gönderir
- Sonuçları konsola yazdırır

### LO2 Replay

```bash
python scripts/replay_lo2.py
```

- 100 adet log örneği üretir ve `/score/lo2/log` endpoint'ine gönderir
- 100 adet metrik örneği üretir ve `/score/lo2/metric` endpoint'ine gönderir
- `selected_metric_columns.csv` dosyasından kolon listesini okur

**Not:** Replay scriptleri varsayılan olarak `http://localhost:8000` kullanır. Docker container içinden çalıştırıyorsanız `API_URL` veya script içindeki URL'yi `http://backend:8000` olarak güncelleyin.

## 📊 Dashboard

Streamlit dashboard'u şu özellikleri sunar:

### ModSecurity Sekmesi
- Son 500 tehdit olayının tablosu (in-memory event store)
- Tehdit tipi dağılımı (bar chart)
- Risk skoru histogramı
- İstatistikler (toplam olay, ortalama risk, yüksek riskli olaylar)

### LO2 Sekmesi
- Log anomali histogramı
- Metrik anomali histogramı
- Top anomalies tabloları (CSV raporlarından)
- İstatistikler
- Manuel test (Log & Metric)

**Erişim:** http://localhost:8501

## 📁 Çıktılar

### Model Dosyaları

- `outputs/models/modsec/` - ModSecurity tehdit tespit modelleri
- `outputs/models/lo2/` - LO2 anomali tespit modelleri

### Raporlar

- `outputs/reports/modsec/` - ModSecurity sınıflandırma raporları (CSV + PNG)
- `outputs/reports/lo2/` - LO2 anomali tespit raporları (CSV + PNG)

**Önemli:** `outputs/` klasörü proje kök dizininde bulunmalı ve container'lara read-only olarak mount edilir.

## 🧪 Testler

Backend için pytest testleri:

```bash
cd backend
pytest ../tests/ -v
```

## 🔧 Yapılandırma

### Environment Variables

**Backend:**
- `LOG_LEVEL`: Log seviyesi (default: `INFO`)
- `CORS_ORIGINS`: CORS izin verilen origin'ler (default: `*`)
- `MODSEC_MODEL_DIR`: ModSecurity model dizini (default: `outputs/models/modsec`)
- `LO2_MODEL_DIR`: LO2 model dizini (default: `outputs/models/lo2`)

**Dashboard:**
- `API_URL`: Backend API URL'i (Docker: `http://backend:8000`, Local: `http://localhost:8000`)

## 📝 Notlar

- Windows kullanıcıları için PowerShell komutları kullanılmıştır. Linux/Mac'te bash komutlarına çevrilebilir.
- Model dosyaları (`outputs/models/*.pkl`) GitHub 100MB limiti nedeniyle repo'da yoktur. Kendi modellerini eğitip bu klasöre koymanız veya mevcut modelleri ayrı indirmeniz gerekir.
- Replay scriptleri demo amaçlıdır. Production'da gerçek veri kaynaklarından veri alınmalıdır.
- Dashboard'daki event store in-memory'dir ve yeniden başlatıldığında sıfırlanır.

## 🐛 Sorun Giderme

**API bağlantı hatası:**
- Backend servisinin çalıştığından emin olun: `curl http://localhost:8000/health`
- Docker kullanıyorsanız, dashboard'un `API_URL=http://backend:8000` olarak ayarlandığından emin olun

**Model dosyası bulunamadı:**
- `outputs/models/` klasörünün mevcut olduğunu kontrol edin
- Model dosyalarının doğru isimlerle (`threat_model_stable.pkl`, vb.) mevcut olduğunu kontrol edin

**Metric kolonları bulunamadı:**
- `outputs/reports/lo2/selected_metric_columns.csv` dosyasının mevcut olduğunu kontrol edin

## 📄 Lisans

Bu proje MVP (Minimum Viable Product) amaçlı geliştirilmiştir.
