import streamlit as st
import re
import csv
import io
import requests
import os
from datetime import datetime
from dotenv import load_dotenv
load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

THRESHOLD = 5
SCAN_TIME_WINDOW = 60
SCAN_PORT_THRESHOLD = 3
HIGH_RISK_PORTS = [22, 23, 3389, 445]

def check_virustotal(ip):
    """查詢IP是否為已知惡意來源"""
    if not VIRUSTOTAL_API_KEY:
        return "未設定VirusTotal API Key"
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers=headers,
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())
            country = data["data"]["attributes"].get("country", "未知")
            return f"惡意標記：{malicious}/{total}，可疑：{suspicious}/{total}，來源國家：{country}"
        else:
            return f"查詢失敗（HTTP {response.status_code}）"
    except Exception as e:
        return f"VirusTotal查詢錯誤：{e}"


def check_cve(port):
    """查詢該port相關的已知CVE漏洞"""
    port_service_map = {
        22: "SSH",
        23: "Telnet",
        445: "SMB",
        3389: "RDP"
    }
    service = port_service_map.get(port, f"port {port}")
    try:
        response = requests.get(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={service}&resultsPerPage=3",
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            cves = data.get("vulnerabilities", [])
            if not cves:
                return f"未找到 {service} 相關CVE"
            result = f"{service} 最新CVE：\n"
            for cve in cves:
                cve_id = cve["cve"]["id"]
                desc = cve["cve"]["descriptions"][0]["value"][:100]
                result += f"- {cve_id}：{desc}...\n"
            return result
        else:
            return f"CVE查詢失敗（HTTP {response.status_code}）"
    except Exception as e:
        return f"CVE查詢錯誤：{e}"

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

def analyze_log(content, exclude_ips=[]):
    ip_counts = {}
    ip_port_log = {}
    alerts = []
    logs = []

    for line in content.splitlines():
        match = re.search(r'srcip=([\d.]+).*dstport=(\d+).*action="(\w[\w-]*)"', line)
        if match:
            ip = match.group(1)
            if ip in exclude_ips:
                continue  # 跳過排除清單裡的IP
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
        else:
            logs.append({"type": "正常", "ip": ip, "msg": f"{ip} 共連線{count}次，正常"})

    return logs, alerts, ip_counts

# ===== Streamlit介面 =====
st.title("🔥 防火牆Log分析工具")
st.caption("上傳log檔案，自動偵測異常連線並進行AI分析")

source = st.radio("選擇資料來源", ["上傳Log檔案", "讀取SQLite DB"])

if source == "上傳Log檔案":
    uploaded_file = st.file_uploader("上傳防火牆log檔案", type=["log", "txt"])
    db_path = None
else:
    uploaded_file = None
    db_path = st.text_input("SQLite DB路徑", placeholder=r"例如：E:\project\firewall_analyzer\SQL\firewall.db")

st.subheader("⚙️ 設定")
exclude_input = st.text_input(
    "排除IP清單（多個IP用逗號分隔，例如：192.168.21.1, 192.168.21.2）",
    value=""  # 預設把路由器IP填進去
)
exclude_ips = [ip.strip() for ip in exclude_input.split(",") if ip.strip()]

content = None

if uploaded_file:
    content = uploaded_file.read().decode("utf-8")
    st.success(f"已載入檔案：{uploaded_file.name}，共 {len(content.splitlines())} 行")
elif db_path:
    try:
        import sqlite3
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT ldate, ltime, msg FROM logs ORDER BY utcsec DESC LIMIT 10000")
        rows = cursor.fetchall()
        conn.close()
        # 把DB資料組合成跟log檔案一樣的格式
        lines = []
        for row in rows:
            lines.append(f"date={row[0]} time={row[1]} {row[2]}")
        content = "\n".join(lines)
        st.success(f"已從DB載入 {len(rows)} 筆資料")
    except Exception as e:
        st.error(f"DB連線失敗：{e}")

if st.button("開始分析"):
        with st.spinner("分析中..."):
            logs, alerts, ip_counts = analyze_log(content, exclude_ips)

        st.subheader("📋 偵測結果")
        abnormal_logs = [l for l in logs if l["type"] != "正常"]

        if len(abnormal_logs) == 0:
           st.success("🟢 未偵測到異常，所有連線正常")
        else:
            for log in abnormal_logs:
               if log["type"] == "高風險":
                st.error(f"🔴 [{log['type']}] {log['msg']}")
               elif log["type"] == "Port Scan":
                st.warning(f"🟠 [{log['type']}] {log['msg']}")
               else:
                st.warning(f"🟡 [{log['type']}] {log['msg']}")

        st.subheader("🤖 AI攻擊分析")
        for alert in alerts:
            with st.expander(f"{alert['異常類型']} - {alert['IP']}"):
                
                # VirusTotal查詢
                st.markdown("**🔍 VirusTotal 情資查詢**")
                with st.spinner("查詢VirusTotal..."):
                    vt_result = check_virustotal(alert['IP'])
                st.info(vt_result)
                
                # CVE查詢（只有高風險Port才查）
                if alert['異常類型'] == "Port Scan":
                    st.markdown("**📋 相關CVE漏洞**")
                    ports = alert.get('說明', '')
                    for port in HIGH_RISK_PORTS:
                        if str(port) in ports:
                            with st.spinner(f"查詢port {port} 相關CVE..."):
                                cve_result = check_cve(port)
                            st.warning(cve_result)
                            break

                # Ollama AI分析
                st.markdown("**🤖 AI分析**")
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