import pandas as pd
import numpy as np

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, confusion_matrix
import matplotlib.pyplot as plt
import joblib

import os
import warnings
warnings.filterwarnings("ignore")

data_path = "./data/final_dataset.csv"

TARGET_PER_CLASS = 250000 
CHUNK_SIZE = 100000

df_benign_list = []
df_ddos_list = []
benign_count = 0
ddos_count = 0

print("Veri seti taranıyor ve dengeli örneklem toplanıyor...")

# Dosyayı parça parça okuyoruz (RAM Dostu Yöntem)
for chunk in pd.read_csv(data_path, chunksize=CHUNK_SIZE):
    
    # Sütun adlarını temizle
    chunk.columns = chunk.columns.str.strip()
    
    # Bu chunk içindeki Benign ve DDoS'ları ayır
    benign_chunk = chunk[chunk['Label'] == 'Benign']
    ddos_chunk = chunk[chunk['Label'] != 'Benign'] # DDoS
    
    # Yeterli sayıya ulaşmadıysak listeye ekle
    if benign_count < TARGET_PER_CLASS:
        # İhtiyaç kadarını al
        needed = TARGET_PER_CLASS - benign_count
        to_take = benign_chunk.head(needed)
        df_benign_list.append(to_take)
        benign_count += len(to_take)
        
    if ddos_count < TARGET_PER_CLASS:
        needed = TARGET_PER_CLASS - ddos_count
        to_take = ddos_chunk.head(needed)
        df_ddos_list.append(to_take)
        ddos_count += len(to_take)
        
    # İki sınıftan da yeterince topladıysak döngüyü kır
    if benign_count >= TARGET_PER_CLASS and ddos_count >= TARGET_PER_CLASS:
        print("Hedeflenen veri sayısına ulaşıldı!")
        break

df_benign = pd.concat(df_benign_list)
df_ddos = pd.concat(df_ddos_list)

df = pd.concat([df_benign, df_ddos])
df = df.sample(frac=1, random_state=42).reset_index(drop=True) # karıştırma işlemi

print(f"Toplam Veri: {len(df)}")
print(f"Sınıf Dağılımı:\n{df['Label'].value_counts()}")

SELECTED_FEATURES = [
    'Flow Duration', 
    'Tot Fwd Pkts', 
    'Tot Bwd Pkts', 
    'TotLen Fwd Pkts', 
    'TotLen Bwd Pkts', 
    'Fwd Pkt Len Max', 
    'Fwd Pkt Len Min', 
    'Label' 
]

try:
    df = df[SELECTED_FEATURES]
except KeyError as e:
    print(f"Hata: Sütun ismi bulunamadı. Lütfen df.columns çıktısını kontrol et. Hata: {e}")
    drop_cols = ['Flow ID', 'Src IP','Dst IP', 'Src Port','Dst Port','Timestamp']
    existing_drop = [c for c in drop_cols if c in df.columns]
    df.drop(columns=existing_drop, inplace=True)

df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

# Label encoding
df['Label'] = df['Label'].apply(lambda x: 0 if x == 'Benign' else 1)

X = df.drop(columns=['Label'])
y = df['Label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

print("\nModel eğitiliyor...")
clf = RandomForestClassifier(n_estimators=50, random_state=42, n_jobs=-1)
clf.fit(X_train, y_train)

y_pred = clf.predict(X_test)
acc = accuracy_score(y_test, y_pred)
print(f'\nAccuracy: %{acc * 100:.2f}')

feature_imp = pd.Series(clf.feature_importances_, index=X.columns).sort_values(ascending=False)
print("\n--- Gerçek Özellik Önemleri ---")
print(feature_imp)

joblib.dump(scaler, 'scaler_balanced.pkl')
joblib.dump(clf, 'model_balanced.pkl')
print("Model ve Scaler kaydedildi.")