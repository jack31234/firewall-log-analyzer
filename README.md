# 🔥 防火牆 Log 分析工具

自動分析防火牆 log，偵測異常連線行為，並整合 Ollama AI 提供攻擊手法分析與處置建議。

## 功能

- 🔴 高風險 Port 偵測（SSH/Telnet/RDP/SMB）
- 🟠 Port Scan 偵測（時間窗口內嘗試多個不同 port）
- 🟡 高頻連線異常偵測
- 🤖 Ollama AI 分析攻擊手法與建議處置步驟
- 📥 CSV 報告匯出

## 使用方式

1. 安裝套件
    pip install streamlit requests

2. 啟動 Ollama（需先安裝）
    ollama run gemma3:4b

3. 執行網頁介面
    streamlit run app.py

4. 開啟瀏覽器 `localhost:8501`，上傳防火牆 log 檔案開始分析

## 技術架構

- Python + Regex 解析 log
- 規則式異常偵測引擎
- Ollama（gemma3:4b）本地 AI 分析
- Streamlit 網頁介面