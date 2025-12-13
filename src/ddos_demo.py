import time
import pandas as pd
import numpy as np
import joblib
from scapy.all import sniff, IP, TCP, UDP
from collections import Counter
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
    if len(packets) == 0:
        return

    # --- 1. İSTATİSTİKLERİ HESAPLA ---
    # (Buradaki feature çıkarma kodların aynen kalacak)
    flow_duration = 1000000 
    total_fwd_pkts = 0
    total_len_fwd = 0
    fwd_pkt_lens = []
    
    # Saldırganı bulmak için IP listesi tutalım
    source_ips = []

    for pkt in packets:
        if IP in pkt:
            source_ips.append(pkt[IP].src) # Gönderen IP'yi listeye at
            
            pkt_len = len(pkt)
            total_fwd_pkts += 1
            total_len_fwd += pkt_len
            fwd_pkt_lens.append(pkt_len)

    # Min/Max hesaplamaları (Aynen kalsın)
    if len(fwd_pkt_lens) > 0:
        fwd_pkt_len_max = max(fwd_pkt_lens)
        fwd_pkt_len_min = min(fwd_pkt_lens)
    else:
        fwd_pkt_len_max = 0
        fwd_pkt_len_min = 0

    # --- 2. DEMO İÇİN GÜÇLENDİRME (ATOM BOMBASI MODU) ---
    # Eğer bu kısmı kullanıyorsan kalsın, yoksa silebilirsin.
    # Ama threshold düşürdüğün için buna gerek kalmamış olabilir.
    # Yine de paket sayısı çoksa saldırıyı garantiye almak iyidir.
    if total_fwd_pkts > 10:
        # Saldırı altındayız, değerleri şişirelim (Opsiyonel)
        # Burası senin tercihin, threshold %50 iken burayı silebilirsin de.
        pass 

    # --- 3. MODEL TAHMİNİ ---
    input_data = pd.DataFrame([[
        flow_duration,
        total_fwd_pkts,
        0, # bwd packets
        total_len_fwd,
        0, # len bwd
        fwd_pkt_len_max,
        fwd_pkt_len_min
    ]], columns=FEATURE_COLUMNS)

    try:
        input_scaled = scaler.transform(input_data)
        prediction_prob = clf.predict_proba(input_scaled)[0][1]
    except Exception as e:
        print(f"Hata: {e}")
        return

    # --- 4. SONUÇ VE SALDIRGAN TESPİTİ ---
    if prediction_prob > THRESHOLD:
        # En çok tekrar eden IP'yi bul (Saldırgan muhtemelen odur)
        if source_ips:
            most_common_ip, count = Counter(source_ips).most_common(1)[0]
            attacker_info = f" | 🚫 ŞÜPHELİ IP: {most_common_ip} ({count} paket)"
        else:
            attacker_info = ""

        print(f"🔴 [SALDIRI TESPİT EDİLDİ] Olasılık: %{prediction_prob*100:.1f}{attacker_info}")
        
    else:
        # Güvenli durumda sadece olasılığı yaz
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