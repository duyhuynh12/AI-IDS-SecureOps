import sys
import os
import time
import sqlite3
import numpy as np
import joblib
import warnings
from collections import defaultdict
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from colorama import init, Fore, Style

init(autoreset=True)
warnings.filterwarnings('ignore')

# ==========================================
# CẤU HÌNH ĐƯỜNG DẪN TỰ ĐỘNG
# ==========================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'ids_logs.db')
MODEL_PATH = os.path.join(BASE_DIR, 'RF_IDS_Multi.pkl')

print(Fore.CYAN + Style.BRIGHT + "=" * 65)
print(Fore.CYAN + Style.BRIGHT + "🛡️ HỆ THỐNG PHÒNG THỦ AI-IDS (CORE ENGINE) 🛡️")
print(Fore.CYAN + Style.BRIGHT + "=" * 65)

# ==========================================
# 1. KHỞI TẠO DATABASE (SQLITE3)
# ==========================================
print("[*] Đang kết nối Cơ sở dữ liệu SQLite...")
conn = sqlite3.connect(DB_PATH, check_same_thread=False)
cursor = conn.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS attack_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        src_ip TEXT,
        dst_ip TEXT,
        attack_type TEXT,
        severity TEXT
    )
''')
conn.commit()
print(Fore.GREEN + f"[+] Database '{DB_PATH}' đã sẵn sàng!\n")

# ==========================================
# 2. TẢI MÔ HÌNH HỌC MÁY
# ==========================================
try:
    print(f"[*] Đang tải mô hình từ: {MODEL_PATH}")
    model = joblib.load(MODEL_PATH)
    print(Fore.GREEN + "[+] Tải bộ não AI thành công!\n")
except Exception as e:
    print(Fore.RED + f"[!] LỖI: Không tìm thấy file model. Vui lòng kiểm tra lại. Chi tiết: {e}")
    sys.exit(1)

print(Fore.CYAN + "[*] Hệ thống IDS đang chạy. Đang rà quét card mạng...")

flow_history = defaultdict(list)
MAX_HISTORY = 10
LABELS_MULTI = {
    0: 'SẠCH (BENIGN)', 1: 'SYN FLOOD', 2: 'UDP FLOOD',
    3: 'MSSQL AMPLIFICATION', 4: 'LDAP AMPLIFICATION'
}


# ==========================================
# 3. HÀM BẮT GÓI TIN VÀ DỰ ĐOÁN
# ==========================================
def process_packet(packet):
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    protocol = packet[IP].proto
    length = len(packet)

    flow_key = f"{src_ip}->{dst_ip}"
    flow_history[flow_key].append(length)
    if len(flow_history[flow_key]) > MAX_HISTORY:
        flow_history[flow_key].pop(0)

    lengths = flow_history[flow_key]
    min_len = min(lengths)
    max_len = max(lengths)
    mean_len = float(np.mean(lengths))
    var_len = float(np.var(lengths)) if len(lengths) > 1 else 0.0

    fin, rst, psh, ack, urg = 0, 0, 0, 0, 0
    if packet.haslayer(TCP):
        flags = packet[TCP].flags
        fin = 1 if 'F' in flags else 0
        rst = 1 if 'R' in flags else 0
        psh = 1 if 'P' in flags else 0
        ack = 1 if 'A' in flags else 0
        urg = 1 if 'U' in flags else 0

    # Đưa vào AI dự đoán
    features = np.array([[protocol, fin, rst, psh, ack, urg, min_len, max_len, mean_len, var_len]])
    prediction = model.predict(features)[0]

    if prediction != 0:
        attack_name = LABELS_MULTI.get(prediction, "UNKNOWN")
        severity = "HIGH" if prediction in [3, 4] else "MEDIUM"

        # Ghi log tấn công vào Database
        cursor.execute("INSERT INTO attack_logs (src_ip, dst_ip, attack_type, severity) VALUES (?, ?, ?, ?)",
                       (src_ip, dst_ip, attack_name, severity))
        conn.commit()

        print(Fore.RED + Style.BRIGHT + f"🚨 GHI NHẬN TẤN CÔNG: {src_ip} -> {attack_name}")


try:
    sniff(filter="tcp or udp", prn=process_packet, store=False)
except KeyboardInterrupt:
    conn.close()
    print(Fore.YELLOW + "\n[*] Đã đóng Database và dừng hệ thống IDS.")
    sys.exit(0)