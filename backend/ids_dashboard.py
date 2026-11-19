import streamlit as st
import sqlite3
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import time
import os
from datetime import datetime
from streamlit_option_menu import option_menu

# ==========================================
# CẤU HÌNH ĐƯỜNG DẪN TỰ ĐỘNG (AUTO-ROUTING)
# ==========================================
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BACKEND_DIR)
CSS_PATH = os.path.join(ROOT_DIR, "frontend", "CSS", "style.css")
DB_PATH = os.path.join(BACKEND_DIR, "ids_logs.db")
MAX_DISPLAY_ROWS = 5000  # Giới hạn số dòng nạp lên RAM mỗi chu kỳ để chống đơ trình duyệt
MAX_DB_RECORDS = 20000

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
# 2. CÁC HÀM KẾT NỐI & QUẢN TRỊ DATABASE
# ==========================================
def load_data(limit=MAX_DISPLAY_ROWS):
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        df = pd.read_sql_query(
            f"SELECT * FROM attack_logs ORDER BY id DESC LIMIT {int(limit)}",
            conn
        )
        conn.close()
        if not df.empty:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
        return df
    except Exception:
        return pd.DataFrame(columns=['id', 'timestamp', 'src_ip', 'dst_ip', 'attack_type', 'severity'])


def get_db_stats():
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        cur = conn.cursor()
        row = cur.execute(
            "SELECT COUNT(*), "
            "COALESCE(SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END), 0), "
            "COUNT(DISTINCT src_ip) "
            "FROM attack_logs"
        ).fetchone()
        conn.close()
        db_size_kb = os.path.getsize(DB_PATH) / 1024.0 if os.path.exists(DB_PATH) else 0.0
        return int(row[0]), int(row[1]), int(row[2]), db_size_kb
    except Exception:
        return 0, 0, 0, 0.0


def clear_all_logs():
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        conn.execute("DELETE FROM attack_logs;")
        conn.commit()
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        conn.close()
        return True
    except Exception:
        return False


def highlight_severity(val):
    color = '#ff4b4b' if val in ['CAO', 'HIGH'] else '#fecb52'
    return f'color: {color}; font-weight: bold'


# ==========================================
# 3. XÂY DỰNG SIDEBAR
# ==========================================
with st.sidebar:
    st.markdown("## 🛡️ SecureOps\n<small>v1.2.0 - Phân hệ AI IDS</small>", unsafe_allow_html=True)
    st.markdown("---")

    menu_selection = option_menu(
        menu_title="DANH MỤC",
        options=["Bảng Điều Khiển", "Cảnh Báo", "Điều Tra", "Báo Cáo"],
        icons=["speedometer2", "exclamation-triangle", "search", "file-earmark-arrow-down"],
        menu_icon="cast",
        default_index=0,
        styles=MENU_STYLES
    )
    st.markdown("---")
    st.caption("🟢 Trạng thái: Lắng nghe Real-time")
    st.caption(f" Tự động xoay vòng: Tối đa {MAX_DB_RECORDS:,} dòng")

    if st.button(" Xóa toàn bộ Log (Reset DB)", use_container_width=True):
        if clear_all_logs():
            st.toast("Đã xóa toàn bộ dữ liệu log tấn công!", icon="✅")
            st.rerun()
        else:
            st.error("Không thể xóa Database lúc này.")


# ==========================================
# 4. ĐỊNH TUYẾN & RENDER GIAO DIỆN (ROUTING)
# ==========================================

if menu_selection == "Bảng Điều Khiển":
    # ------------------------------------------------
    # TRANG 1: DASHBOARD (Real-time Auto Refresh)
    # ------------------------------------------------
    placeholder = st.empty()
    while True:
        total_alerts, critical_alerts, unique_ips, db_size_kb = get_db_stats()
        df = load_data(limit=MAX_DISPLAY_ROWS)
        loop_id = str(time.time())

        threat_level = "NGUY HIỂM" if critical_alerts > 0 else ("CẢNH BÁO" if total_alerts > 0 else "BÌNH THƯỜNG")
        threat_html = f'<span class="status-badge-red">{threat_level}</span>' if threat_level != "BÌNH THƯỜNG" else '<span class="status-badge-green">BÌNH THƯỜNG</span>'

        with placeholder.container():
            st.markdown(f"""
                <div class="top-bar">
                    <div> <b>Tình trạng hệ thống:</b> <span class="status-badge-green">HOẠT ĐỘNG TỐT</span> &nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp; 
                     <b>Mức độ đe dọa:</b> {threat_html}</div>
                    <div> DB: {db_size_kb:,.1f} KB ({total_alerts:,}/{MAX_DB_RECORDS:,} dòng) &nbsp;&nbsp;|&nbsp;&nbsp; 👤 Quản trị viên SOC</div>
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
                st.markdown("####  Biểu Đồ Xu Hướng Tấn Công (Chu kỳ 10 giây)")
                if df.empty:
                    fig_line = go.Figure().update_layout(template="plotly_dark", height=300,
                                                         margin=dict(l=0, r=0, t=10, b=0))
                    st.plotly_chart(fig_line, use_container_width=True, key=f"line_e_{loop_id}")
                else:
                    df_time = df.set_index('timestamp').resample('10s').size().reset_index(name='count')
                    fig_line = px.line(df_time, x='timestamp', y='count', markers=True, template="plotly_dark")
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
    st.markdown("### Trung Tâm Quản Lý Cảnh Báo (Alerts Center)")
    st.markdown(f"Sử dụng bộ lọc để truy vết các sự cố mạng (Hiển thị tối đa {MAX_DISPLAY_ROWS:,} bản ghi mới nhất).")

    df = load_data(limit=MAX_DISPLAY_ROWS)

    if df.empty:
        st.success("Hệ thống chưa ghi nhận cuộc tấn công nào.")
    else:
        df['severity'] = df['severity'].replace({'HIGH': 'CAO', 'MEDIUM': 'TRUNG BÌNH'})

        col_filter1, col_filter2, col_filter3 = st.columns(3)
        with col_filter1:
            sev_filter = st.multiselect("Lọc mức độ:", ["CAO", "TRUNG BÌNH"], default=["CAO", "TRUNG BÌNH"])
        with col_filter2:
            ip_list = ["Tất cả"] + list(df['src_ip'].unique())
            ip_filter = st.selectbox("Truy vết IP Nguồn:", ip_list)
        with col_filter3:
            if st.button(" Làm mới dữ liệu", use_container_width=True):
                st.rerun()

        filtered_df = df[df['severity'].isin(sev_filter)]
        if ip_filter != "Tất cả":
            filtered_df = filtered_df[filtered_df['src_ip'] == ip_filter]

        st.markdown(f"**Kết quả:** Tìm thấy {len(filtered_df):,} bản ghi phù hợp.")

        filtered_df = filtered_df.rename(
            columns={'id': 'ID', 'timestamp': 'Thời gian', 'src_ip': 'IP Kẻ Tấn Công', 'dst_ip': 'IP Mục Tiêu',
                     'attack_type': 'Loại Tấn Công', 'severity': 'Mức Độ'}
        )

        try:
            st.dataframe(filtered_df.style.map(highlight_severity, subset=['Mức Độ']), use_container_width=True, height=500)
        except AttributeError:
            st.dataframe(filtered_df.style.applymap(highlight_severity, subset=['Mức Độ']), use_container_width=True,
                         height=500)

elif menu_selection == "Điều Tra":
    # ------------------------------------------------
    # TRANG 3: ĐIỀU TRA & TRUY VẾT KẺ TẤN CÔNG (THREAT HUNTING)
    # ------------------------------------------------
    st.markdown("###  Trung Tâm Điều Tra & Truy Vết IP (Threat Hunting)")
    st.markdown("Phân tích hành vi, xếp hạng các nguồn phát tán DDoS và lập hồ sơ chi tiết từng IP tấn công.")

    df = load_data(limit=MAX_DB_RECORDS)

    if df.empty:
        st.info("Chưa có dữ liệu tấn công để thực hiện điều tra. Hãy chạy `attacker.py` để tạo lưu lượng.")
    else:
        df['severity_vi'] = df['severity'].replace({'HIGH': 'CAO', 'MEDIUM': 'TRUNG BÌNH'})

        # Phần 1: Biểu đồ Top 10 IP Tấn công & Tương quan Vũ khí
        col_hunt1, col_hunt2 = st.columns([1, 1])

        with col_hunt1:
            st.markdown("####  Top 10 IP Tấn Công Mạnh Nhất")
            top_ips = (
                df.groupby('src_ip')
                .size()
                .reset_index(name='packet_count')
                .sort_values('packet_count', ascending=True)
                .tail(10)
            )
            fig_top = px.bar(
                top_ips,
                x='packet_count',
                y='src_ip',
                orientation='h',
                text='packet_count',
                template="plotly_dark",
                color='packet_count',
                color_continuous_scale=['#fecb52', '#ff4b4b']
            )
            fig_top.update_layout(
                height=340,
                margin=dict(l=0, r=10, t=10, b=0),
                xaxis_title="Số gói tấn công",
                yaxis_title="IP Nguồn",
                coloraxis_showscale=False
            )
            st.plotly_chart(fig_top, use_container_width=True)

        with col_hunt2:
            st.markdown("####  Phân Bố Loại Tấn Công Theo Mức Độ Đe Dọa")
            weapon_stats = (
                df.groupby(['attack_type', 'severity_vi'])
                .size()
                .reset_index(name='count')
            )
            fig_weapon = px.bar(
                weapon_stats,
                x='attack_type',
                y='count',
                color='severity_vi',
                text='count',
                barmode='group',
                template="plotly_dark",
                color_discrete_map={'CAO': '#ff4b4b', 'TRUNG BÌNH': '#fecb52'}
            )
            fig_weapon.update_layout(
                height=340,
                margin=dict(l=0, r=0, t=10, b=0),
                xaxis_title="Loại Tấn Công",
                yaxis_title="Số lượng gói",
                legend_title="Mức độ"
            )
            st.plotly_chart(fig_weapon, use_container_width=True)

        st.markdown("---")
        st.markdown("####  Hồ Sơ Truy Vết Chi Tiết Từng IP (IP Forensics Profile)")

        ip_ranking = df['src_ip'].value_counts().index.tolist()
        selected_ip = st.selectbox(
            " Chọn IP Kẻ Tấn Công cần điều tra chuyên sâu (Sắp xếp theo mức độ nguy hiểm):",
            ip_ranking
        )

        ip_df = df[df['src_ip'] == selected_ip].copy()
        ip_total = len(ip_df)
        ip_high = len(ip_df[ip_df['severity'] == 'HIGH'])
        ip_top_weapon = ip_df['attack_type'].mode()[0] if not ip_df.empty else "N/A"
        ip_first_seen = ip_df['timestamp'].min().strftime('%H:%M:%S - %d/%m/%Y')
        ip_last_seen = ip_df['timestamp'].max().strftime('%H:%M:%S - %d/%m/%Y')
        ip_threat_badge = "CAO (NGUY HIỂM)" if ip_high > 0 else "TRUNG BÌNH"

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Tổng Gói Tấn Công", f"{ip_total:,} gói", f"Chiếm {(ip_total / len(df) * 100):.1f}% tổng log")
        m2.metric("Mức Đe Dọa Của IP", ip_threat_badge, f"{ip_high:,} gói khuếch đại")
        m3.metric("Tấn Công Chủ Lực", ip_top_weapon, f"{ip_df['attack_type'].nunique()} loại vũ khí đã dùng")
        m4.metric("Hoạt Động Gần Nhất", ip_last_seen.split(' - ')[0], f"Từ {ip_first_seen.split(' - ')[0]}")

        st.markdown(f"** Nhật ký gói tin tấn công từ IP `{selected_ip}`:**")
        ip_display = ip_df[['id', 'timestamp', 'src_ip', 'dst_ip', 'attack_type', 'severity_vi']].rename(
            columns={'id': 'ID', 'timestamp': 'Thời gian', 'src_ip': 'IP Kẻ Tấn Công',
                     'dst_ip': 'IP Mục Tiêu', 'attack_type': 'Loại Tấn Công', 'severity_vi': 'Mức Độ'}
        )
        try:
            st.dataframe(ip_display.style.map(highlight_severity, subset=['Mức Độ']), use_container_width=True, height=300)
        except AttributeError:
            st.dataframe(ip_display.style.applymap(highlight_severity, subset=['Mức Độ']), use_container_width=True, height=300)

elif menu_selection == "Báo Cáo":
    # ------------------------------------------------
    # TRANG 4: BÁO CÁO & XUẤT DỮ LIỆU SOC (INCIDENT REPORTING)
    # ------------------------------------------------
    st.markdown("###  Trung Tâm Báo Cáo & Xuất Dữ Liệu SOC (SOC Reporting)")
    st.markdown("Tổng hợp số liệu thống kê sự cố an ninh mạng và trích xuất báo cáo (CSV / JSON / Markdown).")

    df = load_data(limit=MAX_DB_RECORDS)

    if df.empty:
        st.info("Chưa có dữ liệu sự cố để tạo báo cáo.")
    else:
        df['severity_vi'] = df['severity'].replace({'HIGH': 'CAO', 'MEDIUM': 'TRUNG BÌNH'})

        # Bộ lọc dữ liệu cần xuất báo cáo
        col_r1, col_r2 = st.columns(2)
        all_attacks = list(df['attack_type'].unique())
        with col_r1:
            selected_attacks = st.multiselect("Chọn loại tấn công đưa vào báo cáo:", all_attacks, default=all_attacks)
        with col_r2:
            selected_sevs = st.multiselect("Chọn mức độ cảnh báo:", ["CAO", "TRUNG BÌNH"], default=["CAO", "TRUNG BÌNH"])

        report_df = df[df['attack_type'].isin(selected_attacks) & df['severity_vi'].isin(selected_sevs)].copy()

        st.markdown("####  Bảng Tổng Hợp Thống Kê Theo Loại Tấn Công")
        if report_df.empty:
            st.warning("Không có bản ghi nào khớp với điều kiện lọc hiện tại.")
        else:
            summary_df = (
                report_df.groupby(['attack_type', 'severity_vi'])
                .agg(
                    total_packets=('id', 'count'),
                    unique_attackers=('src_ip', 'nunique'),
                    first_seen=('timestamp', 'min'),
                    last_seen=('timestamp', 'max')
                )
                .reset_index()
                .sort_values('total_packets', ascending=False)
            )
            summary_df['ratio'] = (summary_df['total_packets'] / len(report_df) * 100).round(2).astype(str) + '%'
            summary_df.rename(
                columns={
                    'attack_type': 'Loại Tấn Công',
                    'severity_vi': 'Mức Độ',
                    'total_packets': 'Tổng Số Gói',
                    'unique_attackers': 'Số IP Nguồn',
                    'ratio': 'Tỷ Lệ (%)',
                    'first_seen': 'Phát Hiện Đầu Tiên',
                    'last_seen': 'Ghi Nhận Cuối Cùng'
                },
                inplace=True
            )
            st.dataframe(summary_df, use_container_width=True, hide_index=True)

            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown("####  Trích Xuất Hồ Sơ Sự Cố (Export Files)")

            export_df = report_df[['id', 'timestamp', 'src_ip', 'dst_ip', 'attack_type', 'severity_vi']].rename(
                columns={
                    'id': 'ID',
                    'timestamp': 'Thoi_Gian',
                    'src_ip': 'IP_Ke_Tan_Cong',
                    'dst_ip': 'IP_Muc_Tieu',
                    'attack_type': 'Loai_Tan_Cong',
                    'severity_vi': 'Muc_Do'
                }
            )

            now_str = datetime.now().strftime("%Y%m%d_%H%M%S")
            csv_bytes = export_df.to_csv(index=False, encoding='utf-8-sig').encode('utf-8-sig')
            json_bytes = export_df.to_json(orient='records', force_ascii=False, date_format='iso', indent=2).encode('utf-8')

            # Tạo nội dung báo cáo Markdown tóm tắt cho đồ án
            md_report = f"""#  BÁO CÁO SỰ CỐ AN NINH MẠNG (AI-IDS SOC REPORT)
- **Thời gian trích xuất:** {datetime.now().strftime('%H:%M:%S - %d/%m/%Y')}
- **Tổng số cảnh báo ghi nhận:** {len(report_df):,} gói tin
- **Số cảnh báo mức độ CAO (Khuếch đại):** {len(report_df[report_df['severity'] == 'HIGH']):,} gói tin
- **Tổng số IP Kẻ tấn công (Unique Source IPs):** {report_df['src_ip'].nunique():,} IP
- **Mô hình AI phân tích:** Random Forest Multi-Class (`RF_IDS_Multi.pkl`)

## 1. Thống kê theo loại hình tấn công
{summary_df.to_markdown(index=False) if hasattr(summary_df, 'to_markdown') else summary_df.to_string(index=False)}

## 2. Top 5 IP tấn công nguy hiểm nhất
{report_df['src_ip'].value_counts().head(5).to_frame(name='Số gói tấn công').to_string()}
"""

            btn_col1, btn_col2, btn_col3 = st.columns(3)
            with btn_col1:
                st.download_button(
                    label="📥 Tải Báo Cáo Excel / CSV (.csv)",
                    data=csv_bytes,
                    file_name=f"SOC_IDS_Report_{now_str}.csv",
                    mime="text/csv",
                    use_container_width=True
                )
            with btn_col2:
                st.download_button(
                    label="📥 Tải Dữ Liệu SIEM (.json)",
                    data=json_bytes,
                    file_name=f"SOC_IDS_Logs_{now_str}.json",
                    mime="application/json",
                    use_container_width=True
                )
            with btn_col3:
                st.download_button(
                    label="📥 Tải Báo Cáo Tóm Tắt (.md)",
                    data=md_report.encode('utf-8'),
                    file_name=f"SOC_Summary_Report_{now_str}.md",
                    mime="text/markdown",
                    use_container_width=True
                )
