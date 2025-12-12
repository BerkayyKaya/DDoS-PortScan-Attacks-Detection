import time
import pandas as pd
import numpy as np
import joblib
from scapy.all import sniff, IP, TCP, UDP
import warnings
import os

warnings.filterwarnings("ignore")

# Model ve Scaler yolları
MODEL_PATH = "./models/model_balanced.pkl"
SCALER_PATH = "./models/scaler/scaler_balanced.pkl"

# Eşik değeri:
THRESHOLD = 0.5

print("⏳ Model ve Scaler yükleniyor...")
try:
    print("RandomForest Classifier yükleniyor...")
    clf = joblib.load(MODEL_PATH)
    print("RandomForest Modeli Hazır!")
    print("\nScaler Yükleniyor...")
    scaler = joblib.load(SCALER_PATH)
    print("Scaler Hazır!")
    print("✅ Model ve Scaler başarıyla yüklendi!")
except Exception as e:
    print(f"❌ Hata: Model dosyaları bulunamadı! {e}")
    exit()

# Modelin eğitildiği özellikler sırası ile
FEATURE_COLUMNS = [
    'Flow Duration', 
    'Tot Fwd Pkts', 
    'Tot Bwd Pkts', 
    'TotLen Fwd Pkts', 
    'TotLen Bwd Pkts', 
    'Fwd Pkt Len Max', 
    'Fwd Pkt Len Min'
]

print("\n🚀 DDoS Tespit Sistemi Aktif!")
print("Ağ trafiği dinleniyor (Her 1 saniyede bir analiz edilecek)...")
print("-" * 50)

# Değişkenler
packets_buffer = []
start_time = time.time()

def process_packet(packet):
    global packets_buffer, start_time
    
    # Sadece IP paketlerini al
    if IP in packet:
        packets_buffer.append(packet)

    # 1 saniyelik pencere doldu mu
    current_time = time.time()
    if current_time - start_time >= 1.0:
        analyze_traffic(packets_buffer)
        
        # Buffer'ı ve zamanı sıfırla
        packets_buffer = []
        start_time = current_time

def analyze_traffic(packets):
    # Paket yoksa işlem yapma
    if len(packets) == 0:
        return

    flow_duration = 1000000 # Mikrosaniye cinsinden
    
    total_fwd_pkts = 0
    total_bwd_pkts = 0
    total_len_fwd = 0
    total_len_bwd = 0
    fwd_pkt_lens = []

    for pkt in packets:
        pkt_len = len(pkt)

        # DDoS saldırısında paket sayısı çok artacağı için
        # Total Fwd Packets değeri fırlayacaktır.
        total_fwd_pkts += 1
        total_len_fwd += pkt_len
        fwd_pkt_lens.append(pkt_len)

    # Hesaplamalar
    if len(fwd_pkt_lens) > 0:
        fwd_pkt_len_max = max(fwd_pkt_lens)
        fwd_pkt_len_min = min(fwd_pkt_lens)
    else:
        fwd_pkt_len_max = 0
        fwd_pkt_len_min = 0

        
    # Modelin beklediği sırada dataframe
    input_data = pd.DataFrame([[
        flow_duration,
        total_fwd_pkts,
        total_bwd_pkts,     # Demoda bunu 0 kabul edebiliriz veya rastgele 
        total_len_fwd,
        total_len_bwd,
        fwd_pkt_len_max,
        fwd_pkt_len_min
    ]], columns=FEATURE_COLUMNS)


    # değerleri eğitimdeki gibi scale ediyoruz
    input_scaled = scaler.transform(input_data)
    
    # Tahmin sonucu
    prediction_prob = clf.predict_proba(input_scaled)[0][1] # [0]=Benign, [1]=DDoS
    
    # Sonuçlar
    if prediction_prob > THRESHOLD:
        print(f"🔴 [SALDIRI TESPİT EDİLDİ] Olasılık: %{prediction_prob*100:.1f} | Paket/sn: {total_fwd_pkts}")
    else:
        # eğer güvenliyse sürekli yazdırma sürekli yazma bekle
        print(f"🟢 [Güvenli] Olasılık: %{prediction_prob*100:.1f} | Paket/sn: {total_fwd_pkts}", end='\r')

# dinleme başlatma
INTERFACE_NAME = "VMware Virtual Ethernet Adapter for VMnet1"
print(f"{INTERFACE_NAME} arayüzü dinleniyor...")
try:
    sniff(iface=INTERFACE_NAME ,prn=process_packet, store=0)
except KeyboardInterrupt:
    print("\nProgram kapatıldı.")
except Exception as e:
    print(f"\nHata oluştu (Yönetici olarak çalıştırmayı dene): {e}")