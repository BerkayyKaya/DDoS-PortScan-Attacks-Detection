# Bu arayüz yalnızca DDoS ve Port Scan saldırılarını tespit etmek için kullanılmaktadır
# This interface is used solely to detect DDoS and Port Scan attacks

import streamlit as st
import pandas as pd
import numpy as np
import joblib
import time
from datetime import datetime
from collections import Counter
from scapy.all import sniff, IP, TCP, UDP

# Model Yolları
MODEL_PATH = './models/model_balanced.pkl'
SCALER_PATH = './models/scaler/scaler_balanced.pkl'
INTERFACE_NAME = "VMware Virtual Ethernet Adapter for VMnet1" 
THRESHOLD = 0.50

st.set_page_config(page_title="Ağ Trafiği Paneli", page_icon="🛡️", layout="wide")

st.title("Canlı Network Trafiği İzleme Paneli")
st.markdown("---")

# Model Yükleme
@st.cache_resource
def load_ai_model():
    try:
        model = joblib.load(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
        return model, scaler
    except:
        return None, None

clf, scaler = load_ai_model()
if clf is None:
    st.error("Hata: Model dosyaları bulunamadı!")
    st.stop()

# Geçmiş Tanımlamaları
if "attack_log" not in st.session_state:
    st.session_state.attack_log = pd.DataFrame(columns=["Zaman", "Saldırgan IP", "Hedef Port", "Tespit", "Tür"])
if "traffic_history" not in st.session_state:
    st.session_state.traffic_history = []

# Sütunlarımız
col1, col2, col3, col4 = st.columns(4)

# Her sütun için boş bir placeholder
ph_kpi1 = col1.empty()
ph_kpi2 = col2.empty()
ph_kpi3 = col3.empty()
ph_kpi4 = col4.empty()

# Durum çubuğu için kutu
status_placeholder = st.empty()

# Grafik ve Loglar
c_chart, c_logs = st.columns([1, 1])
with c_chart:
    st.subheader("📈 Trafik Grafiği")
    chart_placeholder = st.empty()

with c_logs:
    st.subheader("📝 Saldırı Kayıtları")
    # if st.button("Logları Temizle"):
    #     st.session_state.attack_log = pd.DataFrame(columns=["Zaman", "Saldırgan IP", "Hedef Port", "Olasılık", "Tür"])
    log_placeholder = st.empty()

# Trafik Analiz Fonksiyonu
def analyze_traffic_ui(packets):
    if len(packets) == 0: 
        return None

    # İstatistikler
    flow_duration = 1000000 
    total_fwd_pkts = 0
    total_len_fwd = 0
    fwd_pkt_lens = []
    
    # IP ve Port Takibi (Sözlük yapısı >> {'ip': {paket atılan port bilgisi}})
    # Sözlük yapısı: { '192.168.1.50': {80, 443, 21...} }
    port_scan_tracker = {}
    
    source_ips = []
    dest_ports = []

    for pkt in packets:
        if IP in pkt:
            src_ip = pkt[IP].src
            source_ips.append(src_ip)
            
            total_fwd_pkts += 1
            pkt_len = len(pkt)
            total_len_fwd += pkt_len
            fwd_pkt_lens.append(pkt_len)
            
            # Port Scan Tespiti için Port Toplama
            dst_port = 0
            if TCP in pkt: 
                dst_port = pkt[TCP].dport
            elif UDP in pkt: 
                dst_port = pkt[UDP].dport
            
            if dst_port > 0:
                dest_ports.append(dst_port)
                # O IP için port kümesi oluştur veya güncelle
                if src_ip not in port_scan_tracker:
                    port_scan_tracker[src_ip] = set()
                port_scan_tracker[src_ip].add(dst_port)

    if len(fwd_pkt_lens) > 0:
        fwd_pkt_len_max = max(fwd_pkt_lens)
        fwd_pkt_len_min = min(fwd_pkt_lens)
    else:
        fwd_pkt_len_max = 0
        fwd_pkt_len_min = 0

    # DDoS İçin Model Tahmini
    input_data = pd.DataFrame([[
        flow_duration, total_fwd_pkts, 0, total_len_fwd, 0, fwd_pkt_len_max, fwd_pkt_len_min
    ]], columns=['Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Max', 'Fwd Pkt Len Min'])

    try:
        input_scaled = scaler.transform(input_data)
        prediction_prob = clf.predict_proba(input_scaled)[0][1]
    except:
        return None

    # Port Scan Saldırısı Kontrolü
    is_port_scan = False
    scan_attacker = None
    scanned_port_count = 0
    
    # 1 saniyede belli bir değerden fazla farklı porta giden IP var mı
    PORT_SCAN_THRESHOLD = 15 
    for ip, ports in port_scan_tracker.items():
        if len(ports) > PORT_SCAN_THRESHOLD:
            is_port_scan = True
            scan_attacker = ip
            scanned_port_count = len(ports)
            break # ilk saldıranı bulduğunda çık

    # Genel Saldırgan Bilgisi Eğer Port Scan Yoksa
    attacker_ip = "Yok"
    target_port = "-"
    if source_ips: attacker_ip = Counter(source_ips).most_common(1)[0][0]
    if dest_ports: target_port = Counter(dest_ports).most_common(1)[0][0]

    return {
        "prob": prediction_prob,
        "packets": total_fwd_pkts,
        "attacker_ip": attacker_ip,
        "target_port": target_port,
        "bytes": total_len_fwd,
        "is_port_scan": is_port_scan,
        "scan_attacker": scan_attacker,
        "scanned_port_count": scanned_port_count
    }

# Streamlit
if st.button("Sistemi Başlat", type="primary"):
    st.toast(f"Dinleme Başladı: {INTERFACE_NAME}", icon="📡")
    
    while True:
        packets = sniff(iface=INTERFACE_NAME, timeout=1, store=1)
        result = analyze_traffic_ui(packets)
        
        if result:
            prob = result["prob"]
            pkt_count = result["packets"]
            
            # Bilgilendirme Mesajları
            # Eğer Port Scan veya DDoS varsa Kritik yazacak
            risk_status = "Kritik" if (prob > THRESHOLD or result["is_port_scan"]) else "Güvenli"
            ph_kpi1.metric("Risk Durumu", risk_status, delta_color="inverse")
            
            ph_kpi2.metric("Saldırı Olasılığı", f"%{prob*100:.1f}")
            ph_kpi3.metric("Paket Hızı", f"{pkt_count} pkt/sn")
            ph_kpi4.metric("Veri Akışı", f"{result['bytes'] / 1024:.1f} KB/sn")
            
            # İlk Öncelik Model Tahmininde
            if prob > THRESHOLD:
                status_placeholder.error(
                    f"🚨 POTANSİYEL DDoS SALDIRISI TESPİT EDİLDİ!\tKaynak: {result['attacker_ip']} -> Hedef Port: {result['target_port']}"
                )
                log_type = "DDoS"
                log_attacker = result['attacker_ip']
                log_target = result['target_port']

            # Sonraki Öncelik Port Scan Taramasında
            elif result["is_port_scan"]:
                status_placeholder.warning(
                    f"⚠️ POTANSİYEL PORT TARAMASI TESPİT EDİLDİ!\tKaynak: {result['scan_attacker']} -> {result['scanned_port_count']} Farklı Port Tarandı"
                )
                log_type = "Port Scan"
                log_attacker = result['scan_attacker']
                log_target = "Çoklu Portlar"
                
            # Güvenli olduğu durum
            else:
                status_placeholder.success("✅ Ağ Trafiği Güvenli - Arayüz İzleniyor...")
                log_type = None

            # Saldırı Varsa Log Kaydı Yapılacak
            if log_type:
                new_log = pd.DataFrame([{
                    "Zaman": datetime.now().strftime("%H:%M:%S"),
                    "Saldırgan IP": log_attacker,
                    "Hedef Port": log_target,
                    "Tespit": f"AI %{prob*100:.1f}" if log_type == "DDoS" else "Kural Tabanlı",
                    "Tür": log_type
                }])
                st.session_state.attack_log = pd.concat([new_log, st.session_state.attack_log], ignore_index=True)

            # Grafik ve Tablo Güncelleme
            st.session_state.traffic_history.append(pkt_count)
            if len(st.session_state.traffic_history) > 60:
                st.session_state.traffic_history.pop(0)
            
            chart_placeholder.line_chart(st.session_state.traffic_history)
            
            log_placeholder.dataframe(
                st.session_state.attack_log, 
                use_container_width=True, 
                height=300, 
                hide_index=True
            )
            
        else:
            time.sleep(0.1)