# 🔥 防火牆 Log 分析工具

自動分析防火牆 log，偵測異常連線行為，並整合 Ollama AI 提供攻擊手法分析與處置建議。

## 功能

- 🔴 高風險 Port 偵測（SSH/Telnet/RDP/SMB）
- 🟠 Port Scan 偵測（時間窗口內嘗試多個不同 port）
- 🟡 高頻連線異常偵測
- 🤖 Ollama AI 分析攻擊手法與建議處置步驟
- 📥 CSV 報告匯出
- 🗄️ 支援上傳 Log 檔案或直接讀取 SQLite DB
- ⚙️ 可自訂排除IP清單（例如排除路由器IP避免誤報）

## 支援格式

- Fortinet FortiGate 防火牆 Log
- SQLite DB（欄位含 ldate、ltime、msg）

## 使用方式

1. 安裝套件
    pip install streamlit requests

2. 啟動 Ollama（需先安裝）
    ollama run gemma3:4b

3. 執行網頁介面
    streamlit run app.py

4. 開啟瀏覽器 `localhost:8501`，選擇資料來源後開始分析

## 技術架構

- Python + Regex 解析 Fortinet log
- 規則式異常偵測引擎（三條偵測規則）
- Ollama（gemma3:4b）本地 AI 分析
- Streamlit 網頁介面
- SQLite 資料庫串接
- CSV 報告匯出（支援 Excel 開啟）

## 偵測邏輯

| 規則 | 說明 | 門檻值 |
|------|------|--------|
| 高風險Port | 嘗試連線SSH/Telnet/RDP/SMB | 任何一次即警告 |
| Port Scan | 短時間內嘗試多個不同port | 60秒內≥3個port |
| 高頻連線 | 同一IP連線次數過高 | 超過5次 |

## 注意事項

- Ollama 需在本機啟動才能使用 AI 分析功能
- SQLite DB 路徑請自行填入，勿將 DB 檔案上傳至版本控制
- 建議將路由器/防火牆本身的IP加入排除清單避免誤報