import re
import requests
import csv
from datetime import datetime

# ===== 設定值 =====
THRESHOLD = 5
SCAN_TIME_WINDOW = 60
SCAN_PORT_THRESHOLD = 3
HIGH_RISK_PORTS = [22, 23, 3389, 445]

# ===== 函式定義 =====
def analyze_with_ollama(alert_type, ip, detail):
    prompt = f"""你是一位資深資安工程師，請用繁體中文分析以下資安事件：

事件類型：{alert_type}
來源IP：{ip}
詳細資訊：{detail}

請回答：
1. 這是什麼攻擊手法？
2. 風險等級（高/中/低）？
3. 建議立即處理步驟（3點以內）？"""

    response = requests.post(
        "http://localhost:11434/api/generate",
        json={"model": "gemma3:4b", "prompt": prompt, "stream": False}
    )
    return response.json()["response"]

# ===== 主程式 =====
ip_counts = {}
ip_port_log = {}

with open("firwall_sample.log", "r", encoding="utf-8") as f:
    for line in f:
        match = re.search(r"SRC=(\d+\.\d+\.\d+\.\d+).*DPORT=(\d+).*ACTION=(\w+)", line)
        if match:
            ip = match.group(1)
            port = int(match.group(2))
            action = match.group(3)

            # 累計連線次數
            if ip in ip_counts:
                ip_counts[ip] += 1
            else:
                ip_counts[ip] = 1

            # 高風險port偵測
            if port in HIGH_RISK_PORTS and action == "DENY":
                print(f"[高風險] {ip} 嘗試連線高風險port {port}，已被封鎖")

            # 記錄時間與port供Port Scan分析
            time_match = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
            if time_match:
                timestamp = datetime.strptime(time_match.group(1), "%Y-%m-%d %H:%M:%S")
                if ip not in ip_port_log:
                    ip_port_log[ip] = []
                ip_port_log[ip].append({"time": timestamp, "port": port})

# Port Scan偵測
alerts = []
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
            print(f"[Port Scan] {ip} 在60秒內嘗試了 {len(ports_in_window)} 個不同port：{sorted(ports_in_window)}，時間區間：{window_start} ~ {records[j-1]['time']}")
            print(f"\n[分析中] {ip} Port Scan異常...")
            result = analyze_with_ollama(
                alert_type="Port Scan",
                ip=ip,
                detail=f"在{SCAN_TIME_WINDOW}秒內嘗試了{len(ports_in_window)}個不同port：{sorted(ports_in_window)}"
            )
            print(result)
             # 把Port Scan也加進CSV報告
            alerts.append({
                "IP": ip,
                "連線次數": len(ports_in_window),
                "異常類型": "Port Scan",
                "說明": f"在{SCAN_TIME_WINDOW}秒內嘗試{len(ports_in_window)}個不同port：{sorted(ports_in_window)}"
            })
            break

# 高頻連線偵測
for ip, count in ip_counts.items():
    if count > THRESHOLD:
        print(f"[警告] 異常IP偵測：{ip} 共連線 {count} 次，疑似攻擊行為")
        print(f"\n[分析中] {ip} 高頻連線異常...")
        result = analyze_with_ollama(
            alert_type="高頻連線異常",
            ip=ip,
            detail=f"共連線{count}次，超過門檻值{THRESHOLD}次"
        )
        print(result)
    else:
        print(f"[正常] {ip} 共連線 {count} 次")

# 輸出CSV報告
for ip, count in ip_counts.items():
    if count > THRESHOLD:
        alerts.append({
            "IP": ip,
            "連線次數": count,
            "異常類型": "高頻連線",
            "說明": f"共連線{count}次，超過門檻值{THRESHOLD}"
        })

with open("alert_report.csv", "w", newline="", encoding="utf-8-sig") as f:
    writer = csv.DictWriter(f, fieldnames=["IP", "連線次數", "異常類型", "說明"])
    writer.writeheader()
    writer.writerows(alerts)

print("\n分析完成，報告已輸出至 alert_report.csv")