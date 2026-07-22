import streamlit as st
import re
import csv
import io
import requests
from datetime import datetime

THRESHOLD = 5
SCAN_TIME_WINDOW = 60
SCAN_PORT_THRESHOLD = 3
HIGH_RISK_PORTS = [22, 23, 3389, 445]

def analyze_with_ollama(alert_type, ip, detail):
    prompt = f"""你是一位資深資安工程師，請用繁體中文分析以下資安事件：
事件類型：{alert_type}
來源IP：{ip}
詳細資訊：{detail}
請回答：
1. 這是什麼攻擊手法？
2. 風險等級（高/中/低）？
3. 建議立即處理步驟（3點以內）？"""
    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={"model": "gemma3:4b", "prompt": prompt, "stream": False},
            timeout=60
        )
        return response.json()["response"]
    except:
        return "Ollama連線失敗，請確認Ollama服務是否啟動"

def analyze_log(content):
    ip_counts = {}
    ip_port_log = {}
    alerts = []
    logs = []

    for line in content.splitlines():
        match = re.search(r"srcip=([\d.]+).*dstport=(\d+).*action=""(\w+[-\w]*)", line)
        if match:
            ip = match.group(1)
            port = int(match.group(2))
            action = match.group(3)

            if ip in ip_counts:
                ip_counts[ip] += 1
            else:
                ip_counts[ip] = 1

            if port in HIGH_RISK_PORTS and action in ["deny", "client-rst"]:
                logs.append({"type": "高風險", "ip": ip, "port": port, "msg": f"{ip} 嘗試連線高風險port {port}，應該被封鎖"})

            time_match = re.search(r"date=(\d{4}-\d{2}-\d{2}) time=(\d{2}:\d{2}:\d{2})", line)
            if time_match:
                timestamp = datetime.strptime(
                     f"{time_match.group(1)} {time_match.group(2)}", 
                     "%Y-%m-%d %H:%M:%S"
                )
                if ip not in ip_port_log:
                    ip_port_log[ip] = []
                ip_port_log[ip].append({"time": timestamp, "port": port})

    for ip, records in ip_port_log.items():
        records.sort(key=lambda x: x["time"])
        for i in range(len(records)):
            window_start = records[i]["time"]
            ports_in_window = set()
            for j in range(i, len(records)):
                time_diff = (records[j]["time"] - window_start).total_seconds()
                if time_diff <= SCAN_TIME_WINDOW:
                    ports_in_window.add(records[j]["port"])
                else:
                    break
            if len(ports_in_window) >= SCAN_PORT_THRESHOLD:
                logs.append({"type": "Port Scan", "ip": ip, "port": sorted(ports_in_window), "msg": f"{ip} 在60秒內嘗試了{len(ports_in_window)}個不同port：{sorted(ports_in_window)}"})
                alerts.append({"IP": ip, "連線次數": len(ports_in_window), "異常類型": "Port Scan", "說明": f"嘗試{len(ports_in_window)}個不同port"})
                break

    for ip, count in ip_counts.items():
        if count > THRESHOLD:
            logs.append({"type": "警告", "ip": ip, "msg": f"{ip} 共連線{count}次，疑似攻擊行為"})
            alerts.append({"IP": ip, "連線次數": count, "異常類型": "高頻連線", "說明": f"共連線{count}次，超過門檻值{THRESHOLD}"})

    return logs, alerts, ip_counts

# ===== Streamlit介面 =====
st.title("🔥 防火牆Log分析工具")
st.caption("上傳log檔案，自動偵測異常連線並進行AI分析")

uploaded_file = st.file_uploader("上傳防火牆log檔案", type=["log", "txt"])

if uploaded_file:
    content = uploaded_file.read().decode("utf-8")
    st.success(f"已載入檔案：{uploaded_file.name}，共 {len(content.splitlines())} 行")

    if st.button("開始分析"):
        with st.spinner("分析中..."):
            logs, alerts, ip_counts = analyze_log(content)

        st.subheader("📋 偵測結果")
        for log in logs:
            if log["type"] == "高風險":
                st.error(f"🔴 [{log['type']}] {log['msg']}")
            elif log["type"] == "Port Scan":
                st.warning(f"🟠 [{log['type']}] {log['msg']}")
            else:
                st.warning(f"🟡 [{log['type']}] {log['msg']}")

        st.subheader("🤖 AI攻擊分析")
        for alert in alerts:
            with st.expander(f"{alert['異常類型']} - {alert['IP']}"):
                with st.spinner("AI分析中..."):
                    result = analyze_with_ollama(alert['異常類型'], alert['IP'], alert['說明'])
                st.write(result)

        st.subheader("📥 下載報告")
        output = io.StringIO()
        output.write('\ufeff')
        writer = csv.DictWriter(output, fieldnames=["IP", "連線次數", "異常類型", "說明"])
        writer.writeheader()
        writer.writerows(alerts)
        st.download_button("下載CSV報告", output.getvalue(), "alert_report.csv", "text/csv")