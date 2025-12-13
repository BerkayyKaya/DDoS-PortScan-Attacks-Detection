import pandas as pd
import numpy as np
from scapy.all import sniff, IP, TCP
import joblib
from collections import defaultdict

import time
import warnings
warnings.filterwarnings("ignore")

# Bazı Ayarlamalar
MODEL_PATH = "./models/MultiClass_Models/Model/siber_guvenlik_modeli.pkl"
COLS_PATH = "./models/MultiClass_Models/Model/model_columns.pkl"
INTERFACE = "VMware Virtual Ethernet Adapter for VMnet1"  # dinlenecek arayüz bilgisi
FLOW_TIMEOUT = 5.0  # akış süresi

print(" [INFO] Model ve Sütun Listesi Yükleniyor...")
rf_model = joblib.load(MODEL_PATH)
model_columns = joblib.load(COLS_PATH)
print(" [SUCCESS] Model Yüklendi!")

# Akışları hafızada tutmak için sözlük
current_flows = defaultdict(list)

# Model çıktıları neyi ifade ediyor
label_map = {0: 'NORMAL', 1: 'DDoS SALDIRISI', 2: 'PORT TARAMA (SCAN)', 3: 'BRUTE FORCE'}

def extract_features(flow_key, packets):
    """
    Birikmiş paket listesinden modelin istediği 43 özelliği çıkarır.
    Not: Bu basitleştirilmiş bir feature extraction işlemidir.
    """
    df_features = pd.DataFrame([0] * len(model_columns), index = model_columns).T # dataframe'in transposesini alıyoruz ki indexten sütuna geçsin

    # Temel istatistikler
    start_time = packets[0].time
    end_time = packets[-1].time
    duration = end_time - start_time
    
    fwd_packets = [p for p in packets if p[IP].src == flow_key[0]]
    bwd_packets = [p for p in packets if p[IP].src == flow_key[1]]
    
    # Paket boyutları
    fwd_lens = [len(p) for p in fwd_packets]
    bwd_lens = [len(p) for p in bwd_packets]
    all_lens = fwd_lens + bwd_lens
    
    # TCP Bayrakları
    syn_count = sum(1 for p in packets if p.haslayer(TCP) and p[TCP].flags.S)
    fin_count = sum(1 for p in packets if p.haslayer(TCP) and p[TCP].flags.F)
    ack_count = sum(1 for p in packets if p.haslayer(TCP) and p[TCP].flags.A)
    rst_count = sum(1 for p in packets if p.haslayer(TCP) and p[TCP].flags.R)
    psh_count = sum(1 for p in packets if p.haslayer(TCP) and p[TCP].flags.P)
    urg_count = sum(1 for p in packets if p.haslayer(TCP) and p[TCP].flags.U)
    
    # IAT (Inter Arrival Time) Hesaplama
    packet_times = [p.time for p in packets]
    iats = [t2 - t1 for t1, t2 in zip(packet_times[:-1], packet_times[1:])]
    
    if not iats:
        iats = [0]
    
    # Flow & Paket Miktarları
    df_features['Total Fwd Packets'] = len(fwd_packets)
    df_features['Total Backward Packets'] = len(bwd_packets)
    df_features['Flow Duration'] = duration * 1000000 # Mikrosaniye
    df_features['Flow Packets/s'] = len(packets) / (duration + 1e-6)
    df_features['Flow Bytes/s'] = sum(all_lens) / (duration + 1e-6)
    
    # Uzunluk Bilgileri
    if fwd_lens:
        df_features['Total Length of Fwd Packets'] = sum(fwd_lens)
        df_features['Fwd Packet Length Max'] = max(fwd_lens)
        df_features['Fwd Packet Length Min'] = min(fwd_lens)
        df_features['Fwd Packet Length Mean'] = np.mean(fwd_lens)
        df_features['Fwd Packet Length Std'] = np.std(fwd_lens)
    
    if bwd_lens:
        df_features['Total Length of Bwd Packets'] = sum(bwd_lens)
        df_features['Bwd Packet Length Max'] = max(bwd_lens)
        df_features['Bwd Packet Length Min'] = min(bwd_lens)
        df_features['Bwd Packet Length Mean'] = np.mean(bwd_lens)
        df_features['Bwd Packet Length Std'] = np.std(bwd_lens)

    if all_lens:
        df_features['Min Packet Length'] = min(all_lens)
        df_features['Max Packet Length'] = max(all_lens)
        df_features['Packet Length Mean'] = np.mean(all_lens)
        df_features['Packet Length Std'] = np.std(all_lens)
        df_features['Packet Length Variance'] = np.var(all_lens)
        df_features['Average Packet Size'] = np.mean(all_lens)
        
    # IAT Değerleri
    df_features['Flow IAT Mean'] = np.mean(iats) * 1000000
    df_features['Flow IAT Std'] = np.std(iats) * 1000000
    df_features['Flow IAT Max'] = max(iats) * 1000000
    df_features['Flow IAT Min'] = min(iats) * 1000000
    
    # Bayraklar & Portlar
    df_features['SYN Flag Count'] = syn_count
    df_features['FIN Flag Count'] = fin_count
    df_features['RST Flag Count'] = rst_count
    df_features['ACK Flag Count'] = ack_count
    df_features['PSH Flag Count'] = psh_count
    df_features['URG Flag Count'] = urg_count
    df_features['Destination Port'] = flow_key[3]
    
    if packets and packets[0].haslayer(TCP):
         df_features['Init_Win_bytes_forward'] = packets[0][TCP].window
    
    # Eksik (NaN) değerleri 0 ile doldur
    df_features.fillna(0, inplace=True)
    
    return df_features

def process_packet(packet):
    """Her paketi yakalar, akışa ekler ve belirli aralıklarla tahmin yapar."""
    if not packet.haslayer(IP) or not packet.haslayer(TCP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = packet[TCP].sport
    dst_port = packet[TCP].dport
    proto = packet[IP].proto
    
    # Flow Key
    flow_key = (src_ip, dst_ip, src_port, dst_port, proto)
    
    # Paketi akışa ekle
    current_flows[flow_key].append(packet)
    
    # Her 20 pakette bir veya akış süresi dolunca tahmin yap
    packets_in_flow = current_flows[flow_key]
    
    if len(packets_in_flow) >= 15: # Demo için 15 paket birikince tahmin edecek
        
        # Özellikleri çıkar
        features = extract_features(flow_key, packets_in_flow)
        
        # Tahmin Yap
        prediction = rf_model.predict(features)[0]
        
        # Eğer saldırıysa KIRMIZI yazdır
        if prediction != 0:
            attack_name = label_map[prediction]
            print(f"\n[!!! DİKKAT !!!] SALDIRI TESPİT EDİLDİ!")
            print(f"TÜR: \033[91m{attack_name}\033[0m") # Kırmızı Renk
            print(f"KAYNAK: {src_ip}:{src_port} -> HEDEF: {dst_ip}:{dst_port}")
            print(f"NEDEN: DestPort={features['Destination Port'].values[0]}, PktSayısı={len(packets_in_flow)}")
            print("-" * 50)
        else:
            print("[DURUM] Normal Trafik")
        # Hafızayı temizle (Demo olduğu için sürekli şişmesin)
        del current_flows[flow_key]

print(f"[*]{INTERFACE} arayüzü dinleniyor...")
sniff(iface = INTERFACE, prn = process_packet, store = 0)