import joblib
import pandas as pd

# Load mô hình của bạn
model = joblib.load('RandomForest_IDS_Model.pkl')


def test_model(win_size, ack, length, desc):
    # Cấu trúc 10 cột đặc trưng
    features = pd.DataFrame([{
        'Init_Win_bytes_forward': win_size, 'ACK Flag Count': ack, 'Inbound': 1.0,
        'URG Flag Count': 0.0, 'Packet Length Variance': 0.0, 'Packet Length Mean': length,
        'Max Packet Length': length, 'Fwd Packet Length Mean': length,
        'Fwd Packet Length Max': length, 'Packet Length Std': 0.0
    }])

    # Ép AI dự đoán
    pred = model.predict(features)[0]
    result = "🚨 ĐỎ (DDoS)  " if pred == 1 else "✅ XANH (Benign)"
    print(f"{result} | {desc}")


print("--- KIỂM TRA ĐIỂM KÍCH HOẠT CỦA AI ---")
# Test 1: Window 0, Payload 0 (Như lúc đầu bạn làm)
test_model(0, 0, 0, "Window=0, Length=0")

# Test 2: Window 512, Payload 0 (Chuẩn SYN Flood Hping3)
test_model(512, 0, 0, "Window=512, Length=0")

# Test 3: Window 512, Length 40 (Bao gồm header mạng)
test_model(512, 0, 40, "Window=512, Length=40")

# Test 4: Window 29200 (Giống hình ảnh bạn đã kéo ra màu đỏ trên web)
test_model(29200, 1, 40, "Window=29200, ACK=1, Length=40")

# Test 5: SYN Windows
test_model(65535, 0, 0, "Window=65535, Length=0")
test_model(1024, 0, 44, "Window=1024, Length=44")