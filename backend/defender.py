import sys
import os
import sqlite3
import numpy as np
import joblib
import warnings
from collections import defaultdict
from scapy.all import sniff, get_working_ifaces, conf
from scapy.layers.inet import IP, TCP, UDP
from colorama import init, Fore, Style
from win10toast import ToastNotifier

# Khởi tạo màu sắc và tắt cảnh báo
init(autoreset=True)
warnings.filterwarnings('ignore')

# Khởi tạo đối tượng thông báo Desktop
toaster = ToastNotifier()

# ==========================================
# CẤU HÌNH ĐƯỜNG DẪN TỰ ĐỘNG & GIỚI HẠN DB
# ==========================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'ids_logs.db')
MODEL_PATH = os.path.join(BASE_DIR, 'RF_IDS_Multi.pkl')
MAX_DB_RECORDS = 20000  # Giới hạn tối đa 20.000 bản ghi mới nhất (Tự động xoay vòng chống tràn DB)

print(Fore.CYAN + Style.BRIGHT + "=" * 65)
print(Fore.CYAN + Style.BRIGHT + "🛡️ HỆ THỐNG PHÒNG THỦ AI-IDS (CORE ENGINE) 🛡️")
print(Fore.CYAN + Style.BRIGHT + "=" * 65)

# ==========================================
# 1. KHỞI TẠO DATABASE (SQLITE3 - WAL MODE)
# ==========================================
print("[*] Đang kết nối Cơ sở dữ liệu SQLite...")
conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10)
cursor = conn.cursor()
# Bật chế độ WAL giúp đọc/ghi đồng thời tốc độ cao, không bị lỗi "database is locked"
cursor.execute("PRAGMA journal_mode=WAL;")
cursor.execute("PRAGMA synchronous=NORMAL;")
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
cursor.execute("CREATE INDEX IF NOT EXISTS idx_attack_logs_timestamp ON attack_logs(timestamp DESC);")
conn.commit()
print(Fore.GREEN + f"[+] Database '{DB_PATH}' đã sẵn sàng (WAL Mode | Giới hạn: {MAX_DB_RECORDS:,} dòng)!\n")

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

flow_history = defaultdict(list)
MAX_HISTORY = 10
LABELS_MULTI = {
    0: 'SẠCH (BENIGN)', 1: 'SYN FLOOD', 2: 'UDP FLOOD',
    3: 'MSSQL AMPLIFICATION', 4: 'LDAP AMPLIFICATION'
}
packet_counter = 0
attack_counter = 0


# ==========================================
# 3. HÀM BẮT GÓI TIN VÀ DỰ ĐOÁN
# ==========================================
def process_packet(packet):
    global packet_counter, attack_counter
    if not packet.haslayer(IP):
        return

    packet_counter += 1
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    protocol = packet[IP].proto

    # Trích xuất độ dài Payload tầng Giao vận (khớp chuẩn CICFlowMeter / CIC-DDoS2019)
    if packet.haslayer(TCP):
        length = len(packet[TCP].payload)
    elif packet.haslayer(UDP):
        length = len(packet[UDP].payload)
    else:
        length = len(packet[IP].payload)

    # Tính toán các đặc trưng thống kê bằng Cửa sổ trượt
    flow_key = f"{src_ip}->{dst_ip}"
    flow_history[flow_key].append(length)
    if len(flow_history[flow_key]) > MAX_HISTORY:
        flow_history[flow_key].pop(0)

    lengths = flow_history[flow_key]
    min_len = min(lengths)
    max_len = max(lengths)
    mean_len = float(np.mean(lengths))
    var_len = float(np.var(lengths)) if len(lengths) > 1 else 0.0

    # Trích xuất Cờ TCP
    fin, rst, psh, ack, urg = 0, 0, 0, 0, 0
    if packet.haslayer(TCP):
        flags = packet[TCP].flags
        fin = 1 if 'F' in flags else 0
        rst = 1 if 'R' in flags else 0
        psh = 1 if 'P' in flags else 0
        ack = 1 if 'A' in flags else 0
        urg = 1 if 'U' in flags else 0

    # Đưa vào AI dự đoán (Đúng thứ tự 10 cột của RF_IDS_Multi.pkl:
    # Protocol, Min Packet Length, Max Packet Length, Packet Length Mean, Packet Length Variance,
    # FIN Flag Count, RST Flag Count, PSH Flag Count, ACK Flag Count, URG Flag Count)
    features = np.array([[protocol, min_len, max_len, mean_len, var_len, fin, rst, psh, ack, urg]])
    prediction = int(model.predict(features)[0])

    if prediction != 0:
        attack_counter += 1
        attack_name = LABELS_MULTI.get(prediction, "UNKNOWN")
        severity = "HIGH" if prediction in [3, 4] else "MEDIUM"

        # Ghi log tấn công vào Database
        cursor.execute("INSERT INTO attack_logs (src_ip, dst_ip, attack_type, severity) VALUES (?, ?, ?, ?)",
                       (src_ip, dst_ip, attack_name, severity))

        # Tự động xoay vòng (Auto-Pruning): Mỗi 200 gói tấn công sẽ kiểm tra và xóa bớt log cũ vượt ngưỡng MAX_DB_RECORDS
        if attack_counter % 200 == 0:
            cursor.execute(
                "DELETE FROM attack_logs WHERE id <= (SELECT MAX(id) - ? FROM attack_logs)",
                (MAX_DB_RECORDS,)
            )

        conn.commit()

        # In ra màn hình Terminal
        print(Fore.RED + Style.BRIGHT + f"🚨 GHI NHẬN TẤN CÔNG: {src_ip} -> {dst_ip} | {attack_name} [{severity}]")

        # Bật cảnh báo Pop-up trên màn hình Desktop
        if severity == "HIGH":
            try:
                toaster.show_toast(
                    "🚨 CẢNH BÁO SOC - AI IDS",
                    f"Phát hiện {attack_name} từ IP: {src_ip}",
                    duration=3,
                    threaded=True
                )
            except Exception:
                pass
    else:
        if packet_counter % 50 == 0:
            print(Fore.GREEN + f"[✓] Đã kiểm tra {packet_counter} gói tin (Trạng thái: SẠCH)...")


# ==========================================
# 4. CHỌN CARD MẠNG VÀ KÍCH HOẠT SNIFFER
# ==========================================
def select_interfaces():
    ifaces = get_working_ifaces()
    if not ifaces:
        return None

    print(Fore.YELLOW + "DANH SÁCH CARD MẠNG (NPCAP INTERFACES):")
    print(f"  [0] Tất cả các card mạng khả dụng ({len(ifaces)} card) - Khuyên dùng")
    for idx, iface in enumerate(ifaces, start=1):
        ip_addr = getattr(iface, 'ip', '') or 'N/A'
        print(f"  [{idx}] {iface.description} (IP: {ip_addr})")

    if len(ifaces) == 1 and "Loopback" in ifaces[0].description:
        print(Fore.RED + "\n[!] CẢNH BÁO: Npcap hiện chỉ nhìn thấy Card Loopback (127.0.0.1)!")
        print(Fore.YELLOW + "    Nếu muốn bắt gói tin từ máy khác trong mạng LAN/Wi-Fi, hãy mở CMD/PowerShell")
        print(Fore.YELLOW + "    với quyền Administrator và chạy: & \"C:\\Program Files\\Npcap\\NPFInstall.exe\" -r2\n")

    choice = input(Fore.CYAN + f"[?] Chọn card mạng cần giám sát (0-{len(ifaces)}, Mặc định = 0): ").strip()
    if choice.isdigit():
        idx = int(choice)
        if 1 <= idx <= len(ifaces):
            return ifaces[idx - 1]
    return ifaces if len(ifaces) > 1 else ifaces[0]


try:
    selected_iface = select_interfaces()
    print(Fore.CYAN + "\n[*] Hệ thống IDS đang chạy và lắng nghe gói tin TCP/UDP...")
    if selected_iface:
        sniff(iface=selected_iface, filter="tcp or udp", prn=process_packet, store=False)
    else:
        sniff(filter="tcp or udp", prn=process_packet, store=False)
except KeyboardInterrupt:
    conn.close()
    print(Fore.YELLOW + "\n[*] Đã đóng Database và dừng hệ thống IDS.")
    sys.exit(0)
