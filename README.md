# 🛡️ SecureOps - Hệ Thống Phát Hiện Xâm Nhập Mạng Ứng Dụng AI (AI-IDS)

**SecureOps AI-IDS** là hệ thống Phát hiện Xâm nhập Mạng theo thời gian thực (**Real-time Network Intrusion Detection System**) kết hợp mô hình Học máy (**Random Forest Multi-Class** huấn luyện trên bộ dữ liệu chuẩn **CIC-DDoS2019**), công cụ bắt gói tin tầng thấp (**Scapy & Npcap**), hệ thống quản trị giao diện trung tâm điều hành an ninh mạng (**SOC Dashboard - Streamlit**) và bộ công cụ giả lập tấn công kiểm thử xâm nhập (**Pentest Traffic Engine**).

---

## 🌟 Tính Năng Nổi Bật

### 1. Bộ Não AI Đa Lớp (`RF_IDS_Multi.pkl`)
Hệ thống trích xuất trực tiếp **10 đặc trưng thống kê mạng theo thời gian thực** bằng thuật toán **Cửa sổ trượt (Sliding Window)** trên từng luồng IP (`src_ip -> dst_ip`) để phân loại chính xác 5 trạng thái lưu lượng:
* `0` — **SẠCH (`BENIGN`)**: Lưu lượng mạng thông thường.
* `1` — **TCP SYN Flood (`MEDIUM`)**: Tấn công làm cạn kiệt tài nguyên kết nối ở tầng Giao vận (L4).
* `2` — **UDP Flood (`MEDIUM`)**: Tấn công làm ngập lụt băng thông mạng bằng gói tin UDP.
* `3` — **MSSQL Amplification (`HIGH`)**: Tấn công khuếch đại phản xạ qua giao thức MSSQL (Port `1434`).
* `4` — **LDAP Amplification (`HIGH`)**: Tấn công khuếch đại phản xạ cường độ cao qua giao thức LDAP (Port `389`).

### 2. Core IDS Sniffer (`backend/defender.py`)
* **Hỗ trợ đa Card mạng (Multi-Interface Sniffing)**: Tự động liệt kê các card mạng từ driver Npcap, cho phép giám sát đồng thời trên cả mạng LAN/Wi-Fi, mạng máy ảo VMware và Loopback (`127.0.0.1`).
* **Cơ sở dữ liệu SQLite tối ưu tốc độ cao (`WAL Mode`)**: Cho phép ghi hàng nghìn cảnh báo mỗi giây đồng thời với việc truy vấn từ Dashboard mà không xảy ra xung đột khóa (`database is locked`).
* **Cơ chế tự động xoay vòng (`Auto-Pruning`) & Chống tràn RAM**: Tự động giới hạn tối đa `20.000` bản ghi mới nhất trong DB và giải phóng bộ nhớ luồng `flow_history` khi gặp tấn công giả mạo IP (`IP Spoofing`).
* **Cảnh báo Desktop (`Windows Toast Notification`)**: Tự động bật thông báo Pop-up kèm âm thanh cho Quản trị viên khi phát hiện tấn công mức độ nguy hiểm `CAO` (có cơ chế `Cooldown` chống tràn luồng hệ điều hành).

### 3. Trung Tâm Điều Hành SOC Dashboard (`backend/ids_dashboard.py`)
Giao diện trực quan theo phong cách **Dark SOC Theme** gồm 4 phân hệ:
1. **📊 Bảng Điều Khiển (Real-time Dashboard)**: Cập nhật tự động mỗi 2 giây các chỉ số KPI (`Tổng Số Cảnh Báo`, `Cảnh Báo Nguy Hiểm`, `Số IP Kẻ Tấn Công`, `Dung lượng DB`), biểu đồ đường xu hướng tấn công theo chu kỳ 10 giây và biểu đồ tròn tỷ lệ các loại tấn công.
2. **🚨 Cảnh Báo (Alerts Center)**: Bộ lọc thông minh cho phép truy vết nhật ký tấn công theo mức độ (`CAO`, `TRUNG BÌNH`) và theo địa chỉ IP nguồn.
3. **🔍 Điều Tra (Threat Hunting & IP Forensics)**: Xếp hạng **Top 10 IP tấn công nguy hiểm nhất**, phân tích tương quan vũ khí DDoS và lập hồ sơ truy vết chuyên sâu cho từng IP kẻ tấn công.
4. **📄 Báo Cáo (SOC Incident Reporting)**: Tổng hợp bảng thống kê tỷ lệ sự cố và hỗ trợ xuất hồ sơ ra 3 định dạng: **Excel/CSV (`.csv`)**, **SIEM Log (`.json`)** và **Báo cáo Tóm tắt (`.md`)**.

### 4. Hệ Thống Giả Lập Tấn Công Kiểm Thử (`attacker.py`)
* Hỗ trợ tự động chuyển đổi định tuyến **Tầng 3 (`L3 - send`)** khi kiểm thử trên `127.0.0.1` và **Tầng 2 (`L2 Ethernet Broadcast - sendp`)** khi kiểm thử qua mạng LAN / Máy ảo.
* Tích hợp **5 chế độ vũ khí**:
  * `[1]` TCP SYN Flood
  * `[2]` UDP Flood
  * `[3]` MSSQL Amplification
  * `[4]` LDAP Amplification
  * `[5]` **Tổng tấn công đa hướng (`Multi-Vector DDoS`)** — kết hợp ngẫu nhiên cả 4 loại tấn công trong cùng một chiến dịch.

---

## 📁 Cấu Trúc Thư Mục Dự Án

```text
Pentest_Project/
├── backend/
│   ├── defender.py          # Core Engine: Bắt gói tin, trích xuất đặc trưng, AI dự đoán & ghi DB
│   ├── ids_dashboard.py     # Giao diện Web SOC Dashboard (Streamlit)
│   ├── RF_IDS_Multi.pkl     # Mô hình Random Forest phân loại đa lớp DDoS
│   └── ids_logs.db          # Cơ sở dữ liệu SQLite3 lưu nhật ký tấn công (tự động khởi tạo)
├── frontend/
│   └── CSS/
│       └── style.css        # Tùy chỉnh giao diện Dark Mode & hiệu ứng chớp cảnh báo
├── attacker.py              # Công cụ giả lập tấn công Pentest (Hỗ trợ cả LAN L2 & Localhost L3)
├── pentest_traffic.py       # Công cụ giả lập tấn công nhanh trên Localhost (L3)
├── sniffer_engine.py        # Bản Sniffer rút gọn chạy trên Terminal
├── requirements.txt         # Danh sách các thư viện Python cần cài đặt
└── README.md                # Tài liệu hướng dẫn sử dụng dự án
```

---

## ⚙️ Hướng Dẫn Cài Đặt

### Bước 1: Cài đặt yêu cầu hệ thống
1. **Python**: Phiên bản `3.10` trở lên.
2. **Npcap** (Bắt buộc trên Windows để Scapy bắt và gửi gói tin thô):
   * Tải và cài đặt từ [https://npcap.com/](https://npcap.com/).
   * Khi cài đặt, tích chọn:
     * ✅ *Support loopback traffic ("Npcap Loopback Adapter" will be created)*
     * ✅ *Install Npcap in WinPcap API-compatible Mode*

> **💡 Lưu ý nếu Npcap chỉ nhìn thấy Card Loopback mà chưa nhận Card Wi-Fi / LAN:**
> Mở **PowerShell với quyền Administrator** và chạy lệnh sau để Npcap gắn kết lại vào tất cả các card mạng:
> ```powershell
> & "C:\Program Files\Npcap\NPFInstall.exe" -r2
> net stop npcap
> net start npcap
> ```

### Bước 2: Cài đặt các thư viện Python
Mở Terminal tại thư mục dự án `Pentest_Project` và chạy:

```powershell
# (Khuyên dùng) Kích hoạt môi trường ảo .venv nếu có
pip install -r requirements.txt
```

---

## 🚀 Hướng Dẫn Khởi Chạy Dự Án

Để vận hành toàn bộ hệ thống (Phòng thủ + Bảng điều khiển + Tấn công kiểm thử), hãy mở **3 cửa sổ Terminal** (nên mở với quyền **Run as Administrator** để Npcap được cấp quyền truy cập card mạng):

### 🛡️ Terminal 1: Khởi chạy Hệ thống Phòng thủ AI-IDS (`defender.py`)
```powershell
python backend/defender.py
```
* Khi danh sách card mạng hiện ra, nhấn **`Enter`** (hoặc nhập `0`) để hệ thống lắng nghe trên **tất cả các card mạng khả dụng**.

### 📊 Terminal 2: Khởi chạy Giao diện SOC Dashboard (`ids_dashboard.py`)
```powershell
streamlit run backend/ids_dashboard.py
```
* Trình duyệt sẽ tự động mở địa chỉ: `http://localhost:8501`.

### ⚔️ Terminal 3: Khởi chạy Công cụ Giả lập Tấn công (`attacker.py`)
```powershell
python attacker.py
```
1. Nhập **IP Mục tiêu**:
   * Nhấn `Enter` để test ngay trên máy cục bộ (`127.0.0.1`).
   * Hoặc nhập **IP LAN/Wi-Fi của máy chạy `defender.py`** (ví dụ: `192.168.1.221`) nếu bắn từ máy khác hoặc máy ảo.
2. Chọn vũ khí từ **`1` đến `5`** (khuyên chọn phím **`5`** để test tổng tấn công đa hướng) và quan sát cảnh báo nhảy theo thời gian thực trên cả Terminal 1 lẫn giao diện Dashboard!

---

## ⚠️ Tuyên Bố Miễn Trừ Trách Nhiệm (Disclaimer)
Dự án này được xây dựng **chỉ nhằm mục đích nghiên cứu học thuật, đồ án môn học An toàn thông tin và kiểm thử trong môi trường phòng Lab được cấp phép**. Tuyệt đối không sử dụng công cụ giả lập lưu lượng (`attacker.py`, `pentest_traffic.py`) để tấn công vào các hệ thống mạng khi chưa có sự cho phép hợp pháp.
