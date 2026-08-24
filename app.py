import streamlit as st
import re
import csv
import io
import requests
import os
import sqlite3
import pandas as pd
from datetime import datetime
from dotenv import load_dotenv
load_dotenv()
from collections import defaultdict

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

def summarize_alerts(alerts):
    """依異常類型分組，避免同類型異常逐一重複問AI"""
    grouped = defaultdict(list)
    for alert in alerts:
        grouped[alert['異常類型']].append(alert)
    return grouped

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

def analyze_log_lines(lines, exclude_ips=[]):
    ip_counts = {}
    ip_port_log = {}
    alerts = []
    logs = []

    high_risk_hits = {}

    for line in lines:
        match = re.search(r'srcip=([\d.]+).*dstport=(\d+).*action="(\w[\w-]*)"', line)
        if match:
            ip = match.group(1)
            if ip in exclude_ips:
                continue
            port = int(match.group(2))
            action = match.group(3)

            ip_counts[ip] = ip_counts.get(ip, 0) + 1

            if port in HIGH_RISK_PORTS and action in ["deny", "client-rst"]:
                key = (ip, port)
                high_risk_hits[key] = high_risk_hits.get(key, 0) + 1
                logs.append({"type": "高風險", "ip": ip, "port": port, "msg": f"{ip} 嘗試連線高風險port {port}，應該被封鎖"})

            time_match = re.search(r"date=(\d{4}-\d{2}-\d{2}) time=(\d{2}:\d{2}:\d{2})", line)
            if time_match:
                timestamp = datetime.strptime(
                    f"{time_match.group(1)} {time_match.group(2)}",
                    "%Y-%m-%d %H:%M:%S"
                )
                ip_port_log.setdefault(ip, []).append({"time": timestamp, "port": port})

    for ip, records in ip_port_log.items():
        records.sort(key=lambda x: x["time"])
        for i in range(len(records)):
            window_start = records[i]["time"]
            ports_in_window = set()
            for j in range(i, len(records)):
                if (records[j]["time"] - window_start).total_seconds() <= SCAN_TIME_WINDOW:
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
    for (ip, port), count in high_risk_hits.items():
        alerts.append({
            "IP": ip,
            "連線次數": count,
            "異常類型": "高風險",
            "說明": f"嘗試連線高風險port {port}，共{count}次",
            "Port": port  # 額外存port，之後CVE查詢不用再用正規表達式解析
        })

    return logs, alerts, ip_counts


def analyze_log(content, exclude_ips=[]):
    return analyze_log_lines(content.splitlines(), exclude_ips)

def ensure_db_index(db_path):
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_utcsec ON logs(utcsec)")
    conn.commit()
    conn.close()

def db_line_generator(db_path, batch_size=50000):
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    cursor = conn.cursor()
    cursor.execute("SELECT ldate, ltime, msg FROM logs ORDER BY utcsec")
    while True:
        rows = cursor.fetchmany(batch_size)
        if not rows:
            break
        for row in rows:
            yield f"date={row[0]} time={row[1]} {row[2]}"
    conn.close()

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
    if os.path.exists(db_path):
        try:
            ensure_db_index(db_path)
            st.success(f"已指定DB路徑：{db_path}")
        except Exception as e:
            st.error(f"DB連線失敗：{e}")
    else:
        st.error("找不到指定的DB檔案，請確認路徑")

if st.button("開始分析"):
        if not content and not db_path:
            st.warning("請先上傳檔案或輸入DB路徑")
            st.stop()

        with st.spinner("分析中，資料量大時請耐心等候..."):
            if uploaded_file:
                logs, alerts, ip_counts = analyze_log(content, exclude_ips)
            else:
                try:
                    logs, alerts, ip_counts = analyze_log_lines(db_line_generator(db_path), exclude_ips)
                except Exception as e:
                    st.error(f"DB分析失敗：{e}")
                    st.stop()

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
        grouped_alerts = summarize_alerts(alerts)

        for alert_type, alert_list in grouped_alerts.items():
            ip_list = [a['IP'] for a in alert_list]
            with st.expander(f"{alert_type}（共 {len(alert_list)} 個IP）"):

                st.write(f"涉及IP：{', '.join(ip_list[:20])}" + ("...等" if len(ip_list) > 20 else ""))

                # VirusTotal：只抽查前3個IP，避免幾百個IP逐一查爆API額度
                st.markdown("**🔍 VirusTotal 情資查詢（抽查前3個IP）**")
                for alert in alert_list[:3]:
                    with st.spinner(f"查詢 {alert['IP']}..."):
                        vt_result = check_virustotal(alert['IP'])
                    st.info(f"{alert['IP']}：{vt_result}")

                # CVE查詢：只有「高風險」類型才查，且針對這組裡出現過的port各查一次
                if alert_type == "高風險":
                    st.markdown("**📋 相關CVE漏洞**")
                    checked_ports = set()
                    for alert in alert_list:
                        port = alert['Port']
                        if port not in checked_ports:
                            checked_ports.add(port)
                            with st.spinner(f"查詢port {port} 相關CVE..."):
                                cve_result = check_cve(port)
                            st.warning(f"Port {port}：{cve_result}")

                # AI分析：整組只問一次，用彙總後的資訊
                st.markdown("**🤖 AI分析（彙總分析）**")
                summary_detail = f"共有{len(alert_list)}個IP出現此類異常，範例事件：{alert_list[0]['說明']}"
                with st.spinner("AI分析中..."):
                    result = analyze_with_ollama(alert_type, f"{len(ip_list)}個IP（例如{ip_list[0]}）", summary_detail)
                st.write(result)

        st.subheader("📥 下載報告")
        output = io.StringIO()
        output.write('\ufeff')
        writer = csv.DictWriter(output, fieldnames=["IP", "連線次數", "異常類型", "說明", "Port"], restval="")
        writer.writeheader()
        writer.writerows(alerts)
        st.download_button("下載CSV報告", output.getvalue(), "alert_report.csv", "text/csv")