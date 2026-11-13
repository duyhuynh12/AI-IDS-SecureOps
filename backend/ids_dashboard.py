import streamlit as st
import sqlite3
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import time
import os

# ==========================================
# CẤU HÌNH ĐƯỜNG DẪN TỰ ĐỘNG (AUTO-ROUTING)
# ==========================================
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BACKEND_DIR)

CSS_PATH = os.path.join(ROOT_DIR, "frontend", "CSS", "style.css")
DB_PATH = os.path.join(BACKEND_DIR, "ids_logs.db")

# ==========================================
# 1. CẤU HÌNH TRANG VÀ LOAD TÀI NGUYÊN
# ==========================================
st.set_page_config(page_title="SecureOps - AI IDS", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")


def load_css(css_file_path):
    try:
        with open(css_file_path, "r", encoding="utf-8") as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)
    except FileNotFoundError:
        st.warning(f"Không tìm thấy file CSS tại: {css_file_path}")


load_css(CSS_PATH)

# ==========================================
# 2. XÂY DỰNG SIDEBAR (Menu trái)
# ==========================================
with st.sidebar:
    st.markdown("##  SecureOps\n<small>v1.2.0 - Phân hệ AI IDS</small>", unsafe_allow_html=True)
    st.markdown("---")
    st.radio("DANH MỤC TÍNH NĂNG", ["Bảng Điều Khiển", "Cảnh Báo", "Điều Tra", "Xu Hướng", "Báo Cáo"], index=0)
    st.markdown("---")
    st.caption("Trạng thái: Đang rà quét Real-time")


# ==========================================
# 3. KẾT NỐI DATABASE
# ==========================================
def load_data():
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query("SELECT * FROM attack_logs ORDER BY timestamp DESC", conn)
        conn.close()
        if not df.empty:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
        return df
    except Exception:
        return pd.DataFrame(columns=['id', 'timestamp', 'src_ip', 'dst_ip', 'attack_type', 'severity'])


placeholder = st.empty()

# ==========================================
# 4. RENDER GIAO DIỆN ĐÃ VIỆT HÓA (VIEW)
# ==========================================
while True:
    df = load_data()
    # Unique ID chống lỗi duplicate chart
    loop_id = str(time.time())

    total_alerts = len(df)
    critical_alerts = len(df[df['severity'] == 'HIGH']) if not df.empty else 0
    unique_ips = df['src_ip'].nunique() if not df.empty else 0

    # Logic ngôn ngữ mức độ đe dọa
    threat_level = "NGUY HIỂM" if critical_alerts > 0 else ("CẢNH BÁO" if total_alerts > 0 else "BÌNH THƯỜNG")
    threat_html = f'<span class="status-badge-red">{threat_level}</span>' if threat_level != "BÌNH THƯỜNG" else '<span class="status-badge-green">BÌNH THƯỜNG</span>'

    with placeholder.container():
        # Hàng 0: Top Bar
        st.markdown(f"""
            <div class="top-bar">
                <div> <b>Tình trạng hệ thống:</b> <span class="status-badge-green">HOẠT ĐỘNG TỐT</span> &nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp; 
                 <b>Mức độ đe dọa:</b> {threat_html}</div>
                <div> Toàn thời gian &nbsp;&nbsp;|&nbsp;&nbsp; 👤 Quản trị viên SOC</div>
            </div>
        """, unsafe_allow_html=True)

        # Hàng 1: Thẻ KPI
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Tổng Số Cảnh Báo", f"{total_alerts:,}", "Tích lũy")
        col2.metric("Cảnh Báo Nguy Hiểm", f"{critical_alerts:,}", "+0 giờ qua" if total_alerts == 0 else "Khuếch đại")
        col3.metric("Số IP Kẻ Tấn Công", f"{unique_ips:,}", "Nguồn phát tán")
        col4.metric("Trạng Thái AI Engine", "Đang Hoạt Động", "Mô hình Random Forest")

        st.markdown("<br>", unsafe_allow_html=True)

        # Hàng 2: Đồ thị
        c_chart1, c_chart2 = st.columns([2, 1])

        with c_chart1:
            st.markdown("####  Biểu Đồ Xu Hướng Tấn Công")
            if df.empty:
                fig_line = go.Figure()
                fig_line.update_layout(template="plotly_dark", height=300, margin=dict(l=0, r=0, t=10, b=0))
                st.plotly_chart(fig_line, use_container_width=True, key=f"line_empty_{loop_id}")
            else:
                df_time = df.set_index('timestamp').resample('1Min').size().reset_index(name='count')
                fig_line = px.line(df_time, x='timestamp', y='count', template="plotly_dark")
                fig_line.update_traces(line_color='#ff4b4b', line_width=3)
                fig_line.update_layout(height=300, margin=dict(l=0, r=0, t=10, b=0), xaxis_title="", yaxis_title="")
                st.plotly_chart(fig_line, use_container_width=True, key=f"line_{loop_id}")

        with c_chart2:
            st.markdown("#### Phân Bố Mức Độ Cảnh Báo")
            if df.empty:
                fig_pie = go.Figure(
                    data=[go.Pie(labels=['Chưa có dữ liệu'], values=[1], hole=.6, marker_colors=['#333333'])])
                fig_pie.update_layout(template="plotly_dark", height=300, margin=dict(l=0, r=0, t=10, b=0),
                                      showlegend=False)
                st.plotly_chart(fig_pie, use_container_width=True, key=f"pie_empty_{loop_id}")
            else:
                fig_pie = px.pie(df, names='attack_type', hole=0.6, template="plotly_dark",
                                 color_discrete_sequence=['#ff4b4b', '#fecb52', '#00cc96', '#636efa'])
                fig_pie.update_layout(height=300, margin=dict(l=0, r=0, t=10, b=0))
                st.plotly_chart(fig_pie, use_container_width=True, key=f"pie_{loop_id}")

        st.markdown("---")

        # Hàng 3: Bảng Database
        st.markdown("#### Danh Sách Cảnh Báo & Nhật Ký Mạng")
        if df.empty:
            empty_df = pd.DataFrame(columns=['Thời gian', 'IP Kẻ Tấn Công', 'IP Mục Tiêu', 'Loại Tấn Công', 'Mức Độ'])
            st.dataframe(empty_df, use_container_width=True)
        else:
            display_df = df[['timestamp', 'src_ip', 'dst_ip', 'attack_type', 'severity']].head(20).copy()

            # Việt hóa nhãn trong cột Mức độ
            display_df['severity'] = display_df['severity'].replace({'HIGH': 'CAO', 'MEDIUM': 'TRUNG BÌNH'})

            # Đổi tên cột hiển thị
            display_df.rename(columns={
                'timestamp': 'Thời gian',
                'src_ip': 'IP Kẻ Tấn Công',
                'dst_ip': 'IP Mục Tiêu',
                'attack_type': 'Loại Tấn Công',
                'severity': 'Mức Độ'
            }, inplace=True)


            # Hàm tô màu theo chữ đã dịch
            def highlight_severity(val):
                color = '#ff4b4b' if val == 'CAO' else '#fecb52'
                return f'color: {color}; font-weight: bold'


            # Dùng style.map thay vì applymap (Tương thích Pandas phiên bản mới)
            try:
                st.dataframe(display_df.style.map(highlight_severity, subset=['Mức Độ']), use_container_width=True,
                             height=250)
            except AttributeError:
                st.dataframe(display_df.style.applymap(highlight_severity, subset=['Mức Độ']), use_container_width=True,
                             height=250)

    time.sleep(2)