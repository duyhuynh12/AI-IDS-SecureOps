import sys
import os
import time
import sqlite3
import numpy as np
import joblib
import warnings
from functools import lru_cache
from collections import defaultdict
from scapy.all import sniff, get_working_ifaces
from scapy.layers.inet import IP, TCP, UDP
from colorama import init, Fore, Style

init(autoreset=True)
warnings.filterwarnings('ignore')

# ==========================================
# CẤU HÌNH ĐƯỜNG DẪN TỰ ĐỘNG & GIỚI HẠN DB
# ==========================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'backend', 'ids_logs.db') if os.path.exists(os.path.join(BASE_DIR, 'backend')) else os.path.join(BASE_DIR, 'ids_logs.db')
MODEL_PATH = os.path.join(BASE_DIR, 'backend', 'RF_IDS_Multi.pkl') if os.path.exists(os.path.join(BASE_DIR, 'backend', 'RF_IDS_Multi.pkl')) else os.path.join(BASE_DIR, 'RF_IDS_Multi.pkl')
MAX_DB_RECORDS = 20000
MAX_FLOWS = 5000

print(Fore.CYAN + Style.BRIGHT + "=" * 65)
print(Fore.CYAN + Style.BRIGHT + "🛡️ HỆ THỐNG PHÒNG THỦ AI-IDS (CORE ENGINE) 🛡️")
print(Fore.CYAN + Style.BRIGHT + "=" * 65)

# ==========================================
# 1. KHỞI TẠO DATABASE (SQLITE3 - WAL MODE)
# ==========================================
print("[*] Đang kết nối Cơ sở dữ liệu SQLite...")
conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10)
cursor = conn.cursor()
cursor.execute("PRAGMA journal_mode=WAL;")
cursor.execute("PRAGMA synchronous=NORMAL;")
cursor.execute('''
    CREATE TABLE IF NOT EXISTS attack_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT (datetime('now', 'localtime')),
        src_ip TEXT,
        dst_ip TEXT,
        attack_type TEXT,
        severity TEXT
    )
''')
cursor.execute("CREATE INDEX IF NOT EXISTS idx_attack_logs_timestamp ON attack_logs(timestamp DESC);")
conn.commit()
print(Fore.GREEN + f"[+] Database '{DB_PATH}' đã sẵn sàng (WAL Mode | Giới hạn: {MAX_DB_RECORDS:,} dòng)!\n")

# ==========================================
# 2. TẢI MÔ HÌNH HỌC MÁY
# ==========================================
try:
    print(f"[*] Đang tải mô hình từ: {MODEL_PATH}")
    model = joblib.load(MODEL_PATH)
    model.n_jobs = 1
    print(Fore.GREEN + "[+] Tải bộ não AI thành công!\n")
except Exception as e:
    print(Fore.RED + f"[!] LỖI: Không tìm thấy file model. Vui lòng kiểm tra lại. Chi tiết: {e}")
    sys.exit(1)


@lru_cache(maxsize=4096)
def predict_cached(protocol, min_len, max_len, mean_len, var_len, fin, rst, psh, ack, urg):
    features = np.array([[protocol, min_len, max_len, mean_len, var_len, fin, rst, psh, ack, urg]])
    return int(model.predict(features)[0])


print(Fore.CYAN + "[*] Hệ thống IDS đang chạy. Đang rà quét card mạng...")

flow_history = defaultdict(list)
MAX_HISTORY = 10
LABELS_MULTI = {
    0: 'SẠCH (BENIGN)', 1: 'SYN FLOOD', 2: 'UDP FLOOD',
    3: 'MSSQL AMPLIFICATION', 4: 'LDAP AMPLIFICATION'
}
attack_counter = 0


# ==========================================
# 3. HÀM BẮT GÓI TIN VÀ DỰ ĐOÁN
# ==========================================
def process_packet(packet):
    global attack_counter
    try:
        if not packet.haslayer(IP):
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        if packet.haslayer(TCP):
            length = len(packet[TCP].payload)
        elif packet.haslayer(UDP):
            length = len(packet[UDP].payload)
        else:
            length = len(packet[IP].payload)

        if len(flow_history) > MAX_FLOWS:
            flow_history.clear()

        flow_key = f"{src_ip}->{dst_ip}"
        flow_history[flow_key].append(length)
        if len(flow_history[flow_key]) > MAX_HISTORY:
            flow_history[flow_key].pop(0)

        lengths = flow_history[flow_key]
        min_len = min(lengths)
        max_len = max(lengths)
        mean_len = round(float(np.mean(lengths)), 2)
        var_len = round(float(np.var(lengths)), 2) if len(lengths) > 1 else 0.0

        fin, rst, psh, ack, urg = 0, 0, 0, 0, 0
        if packet.haslayer(TCP):
            flags = packet[TCP].flags
            fin = 1 if 'F' in flags else 0
            rst = 1 if 'R' in flags else 0
            psh = 1 if 'P' in flags else 0
            ack = 1 if 'A' in flags else 0
            urg = 1 if 'U' in flags else 0

        prediction = predict_cached(protocol, min_len, max_len, mean_len, var_len, fin, rst, psh, ack, urg)

        if prediction != 0:
            attack_counter += 1
            attack_name = LABELS_MULTI.get(prediction, "UNKNOWN")
            severity = "HIGH" if prediction in [3, 4] else "MEDIUM"

            cursor.execute(
                "INSERT INTO attack_logs (timestamp, src_ip, dst_ip, attack_type, severity) "
                "VALUES (datetime('now', 'localtime'), ?, ?, ?, ?)",
                (src_ip, dst_ip, attack_name, severity)
            )
            if attack_counter % 200 == 0:
                cursor.execute(
                    "DELETE FROM attack_logs WHERE id <= (SELECT MAX(id) - ? FROM attack_logs)",
                    (MAX_DB_RECORDS,)
                )
            conn.commit()

            print(Fore.RED + Style.BRIGHT + f"🚨 GHI NHẬN TẤN CÔNG: {src_ip} -> {dst_ip} | {attack_name}")
    except Exception:
        pass


try:
    ifaces = get_working_ifaces()
    BPF_FILTER = "(tcp or udp) and not port 8501"
    sniff(iface=ifaces if len(ifaces) > 1 else None, filter=BPF_FILTER, prn=process_packet, store=False)
except KeyboardInterrupt:
    conn.close()
    print(Fore.YELLOW + "\n[*] Đã đóng Database và dừng hệ thống IDS.")
    sys.exit(0)
