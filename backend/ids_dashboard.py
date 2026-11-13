import streamlit as st
import sqlite3
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import time
import os
from streamlit_option_menu import option_menu

# ==========================================
# CẤU HÌNH ĐƯỜNG DẪN TỰ ĐỘNG (AUTO-ROUTING)
# ==========================================
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BACKEND_DIR)
CSS_PATH = os.path.join(ROOT_DIR, "frontend", "CSS", "style.css")
DB_PATH = os.path.join(BACKEND_DIR, "ids_logs.db")

# ==========================================
# KHAI BÁO BIẾN GIAO DIỆN (UI CONFIGS)
# ==========================================
MENU_STYLES = {
    "container": {"padding": "0!important", "background-color": "transparent"},
    "icon": {"color": "#fecb52", "font-size": "18px"},
    "nav-link": {
        "font-size": "15px", "text-align": "left", "margin": "5px 0px",
        "--hover-color": "#2d2d3f", "border-radius": "8px"
    },
    "nav-link-selected": {"background-color": "#ff4b4b", "color": "white", "font-weight": "bold"},
}

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
# 2. XÂY DỰNG SIDEBAR
# ==========================================
with st.sidebar:
    st.markdown("## 🛡️ SecureOps\n<small>v1.2.0 - Phân hệ AI IDS</small>", unsafe_allow_html=True)
    st.markdown("---")

    # Đoạn code Render giờ đây đã hoàn toàn sạch sẽ, chỉ chứa tham số cốt lõi
    menu_selection = option_menu(
        menu_title="DANH MỤC",
        options=["Bảng Điều Khiển", "Cảnh Báo"],
        icons=["speedometer2", "exclamation-triangle", "search", "graph-up-arrow", "file-earmark-text"],
        menu_icon="cast",
        default_index=0,
        styles=MENU_STYLES
    )
    st.markdown("---")
    st.caption("🟢 Trạng thái: Lắng nghe Real-time")


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
# 4. ĐỊNH TUYẾN & RENDER GIAO DIỆN (ROUTING)
# ==========================================

if menu_selection == "Bảng Điều Khiển":
    # ------------------------------------------------
    # TRANG 1: DASHBOARD (Real-time Auto Refresh)
    # ------------------------------------------------
    placeholder = st.empty()
    while True:
        df = load_data()
        loop_id = str(time.time())

        total_alerts = len(df)
        critical_alerts = len(df[df['severity'] == 'HIGH']) if not df.empty else 0
        unique_ips = df['src_ip'].nunique() if not df.empty else 0

        threat_level = "NGUY HIỂM" if critical_alerts > 0 else ("CẢNH BÁO" if total_alerts > 0 else "BÌNH THƯỜNG")
        threat_html = f'<span class="status-badge-red">{threat_level}</span>' if threat_level != "BÌNH THƯỜNG" else '<span class="status-badge-green">BÌNH THƯỜNG</span>'

        with placeholder.container():
            st.markdown(f"""
                <div class="top-bar">
                    <div> <b>Tình trạng hệ thống:</b> <span class="status-badge-green">HOẠT ĐỘNG TỐT</span> &nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp; 
                     <b>Mức độ đe dọa:</b> {threat_html}</div>
                    <div> Toàn thời gian &nbsp;&nbsp;|&nbsp;&nbsp; 👤 Quản trị viên SOC</div>
                </div>
            """, unsafe_allow_html=True)

            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Tổng Số Cảnh Báo", f"{total_alerts:,}", "Tích lũy")
            col2.metric("Cảnh Báo Nguy Hiểm", f"{critical_alerts:,}",
                        "Khuếch đại" if critical_alerts > 0 else "An toàn")
            col3.metric("Số IP Kẻ Tấn Công", f"{unique_ips:,}", "Nguồn phát tán")
            col4.metric("Trạng Thái AI Engine", "Đang Hoạt Động", "Random Forest")

            st.markdown("<br>", unsafe_allow_html=True)

            c_chart1, c_chart2 = st.columns([2, 1])
            with c_chart1:
                st.markdown("####  Biểu Đồ Xu Hướng Tấn Công")
                if df.empty:
                    fig_line = go.Figure().update_layout(template="plotly_dark", height=300,
                                                         margin=dict(l=0, r=0, t=10, b=0))
                    st.plotly_chart(fig_line, use_container_width=True, key=f"line_e_{loop_id}")
                else:
                    df_time = df.set_index('timestamp').resample('1Min').size().reset_index(name='count')
                    fig_line = px.line(df_time, x='timestamp', y='count', template="plotly_dark")
                    fig_line.update_traces(line_color='#ff4b4b', line_width=3)
                    fig_line.update_layout(height=300, margin=dict(l=0, r=0, t=10, b=0), xaxis_title="", yaxis_title="")
                    st.plotly_chart(fig_line, use_container_width=True, key=f"line_{loop_id}")

            with c_chart2:
                st.markdown("####  Phân Bố Mức Độ Cảnh Báo")
                if df.empty:
                    fig_pie = go.Figure(
                        data=[go.Pie(labels=['Chưa có dữ liệu'], values=[1], hole=.6, marker_colors=['#333333'])])
                    fig_pie.update_layout(template="plotly_dark", height=300, margin=dict(l=0, r=0, t=10, b=0),
                                          showlegend=False)
                    st.plotly_chart(fig_pie, use_container_width=True, key=f"pie_e_{loop_id}")
                else:
                    fig_pie = px.pie(df, names='attack_type', hole=0.6, template="plotly_dark",
                                     color_discrete_sequence=['#ff4b4b', '#fecb52', '#00cc96', '#636efa'])
                    fig_pie.update_layout(height=300, margin=dict(l=0, r=0, t=10, b=0))
                    st.plotly_chart(fig_pie, use_container_width=True, key=f"pie_{loop_id}")

        time.sleep(2)

elif menu_selection == "Cảnh Báo":
    # ------------------------------------------------
    # TRANG 2: BỘ LỌC CẢNH BÁO (Smart Filters)
    # ------------------------------------------------
    st.markdown("###  Trung Tâm Quản Lý Cảnh Báo (Alerts Center)")
    st.markdown("Sử dụng bộ lọc để truy vết các sự cố mạng.")

    df = load_data()

    if df.empty:
        st.success("Hệ thống chưa ghi nhận cuộc tấn công nào.")
    else:
        # Chuyển đổi ngôn ngữ hiển thị
        df['severity'] = df['severity'].replace({'HIGH': 'CAO', 'MEDIUM': 'TRUNG BÌNH'})

        # Hàng công cụ Lọc
        col_filter1, col_filter2, col_filter3 = st.columns(3)
        with col_filter1:
            sev_filter = st.multiselect("Lọc mức độ:", ["CAO", "TRUNG BÌNH"], default=["CAO", "TRUNG BÌNH"])
        with col_filter2:
            ip_list = ["Tất cả"] + list(df['src_ip'].unique())
            ip_filter = st.selectbox("Truy vết IP Nguồn:", ip_list)
        with col_filter3:
            if st.button(" Làm mới dữ liệu", use_container_width=True):
                st.rerun()

        # Áp dụng Logic Lọc
        filtered_df = df[df['severity'].isin(sev_filter)]
        if ip_filter != "Tất cả":
            filtered_df = filtered_df[filtered_df['src_ip'] == ip_filter]

        st.markdown(f"**Kết quả:** Tìm thấy {len(filtered_df)} bản ghi phù hợp.")

        # Hiển thị bảng
        filtered_df.rename(
            columns={'id': 'ID', 'timestamp': 'Thời gian', 'src_ip': 'IP Kẻ Tấn Công', 'dst_ip': 'IP Mục Tiêu',
                     'attack_type': 'Loại Tấn Công', 'severity': 'Mức Độ'}, inplace=True)


        def highlight_row(val):
            color = '#ff4b4b' if val == 'CAO' else '#fecb52'
            return f'color: {color}; font-weight: bold'


        try:
            st.dataframe(filtered_df.style.map(highlight_row, subset=['Mức Độ']), use_container_width=True, height=500)
        except AttributeError:
            st.dataframe(filtered_df.style.applymap(highlight_row, subset=['Mức Độ']), use_container_width=True,
                         height=500)

elif menu_selection in ["Điều Tra", "Xu Hướng", "Báo Cáo"]:
    st.info(f"Tính năng **{menu_selection}** đang được phát triển trong phiên bản tiếp theo.")