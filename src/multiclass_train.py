import pandas as pd
import numpy as np

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report, f1_score
import joblib

import seaborn as sns
import matplotlib.pyplot as plt
import time
import warnings
warnings.filterwarnings("ignore")

print("Veri Seti Yükleniyor...")
data_path = "./data/final_hybrid_data/final_dataset_selected_features.csv"
df = pd.read_csv(data_path)

X = df.drop(columns='Label')
y = df['Label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.2, random_state = 0, stratify = y) # stratify parametresi ile bütün classlardan aynı oranda örnek seçecek

print(f"Eğitim Seti: {X_train.shape}")
print(f"Test Seti: {X_test.shape}")

rf_model = RandomForestClassifier(n_estimators = 100, random_state = 0, n_jobs = -1) # n_jobs = -1 ile bütün çekirdekleri kullanacak

print("5 Katmanlı Cross Validation Başlatılıyor...")
start_time = time.time()
cv_scores = cross_val_score(rf_model, X_train, y_train, cv = 5, scoring="f1_weighted") # veriyi 5 parçaya bölüp biri ile eğitecek bunu 5 defa tekrarlayacak
end_time = time.time()

print("CV İşlemi Tamamlandı!")
print(f"CV İşlem Süresi: {end_time - start_time:.2f} saniye")
print(f"Her İşlem İçin F1 Skoru: {cv_scores}")
print(f"Ortalama F1 Skorumuz: %{cv_scores.mean() * 100:.2f}")
print(f"Standart Sapma: {cv_scores.std():.4f}")

plt.figure(figsize=(8, 6))
plt.title("5 Katmanlı Cross Validation Skorları")
plt.bar(range(1,6), cv_scores, color = "skyblue", edgecolor = "black")
plt.xlabel("Katman Numarası")
plt.ylabel("Ağırlıklı F1 Skoru")
plt.ylim(min(cv_scores) - 0.05, 1.0)
plt.axhline(y = cv_scores.mean(), color = "r", linestyle = "--", label = f"Ortalama: {cv_scores.mean():.3f}")
plt.legend()
plt.show()

print("Model Tüm Eğitim Veri Seti Üzerinde Eğitiliyor...")
rf_model.fit(X_train, y_train)

print("Test Seti Üzerinde Tahmin Yapılıyor...")
y_pred = rf_model.predict(X_test)

# Metrikler
acc = accuracy_score(y_test, y_pred)
f1_weighted = f1_score(y_test, y_pred, average="weighted")
f1_macro = f1_score(y_test, y_pred, average="macro")

print(f"\nNihai Model Performansları")
print(f"Accuracy Score: \t%{acc * 100:.2f}")
print(f"Weighted F1 Score: \t%{f1_weighted * 100:.2f}")
print(f"Macro F1 Score: \t%{f1_macro * 100:.2f}")

print("\n--- Detaylı Sınıflandırma Raporu ---")
target_names = ['Normal (0)', 'DDoS (1)', 'PortScan (2)', 'BruteForce (3)']
print(classification_report(y_test, y_pred, target_names=target_names))

# Karmaşıklık Matrisi
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(10, 8))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=target_names, yticklabels=target_names)
plt.xlabel('Tahmin Edilen')
plt.ylabel('Gerçek Değer')
plt.title('Confusion Matrix')
plt.show()

# Feature Importance
importances = rf_model.feature_importances_
indices = np.argsort(importances)[::-1]
top_n = 20 

plt.figure(figsize=(12, 6))
plt.title("Saldırı Tespitinde En Önemli 20 Özellik")
plt.bar(range(top_n), importances[indices[:top_n]], align="center", color='teal')
plt.xticks(range(top_n), X.columns[indices[:top_n]], rotation=90)
plt.tight_layout()
plt.show()



print("\nModel kaydediliyor...")
joblib.dump(rf_model, "siber_guvenlik_modeli.pkl")
joblib.dump(X.columns.tolist(), "model_columns.pkl")
print("Kayıt tamamlandı.")