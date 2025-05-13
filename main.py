import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

#Loading the dataset-----------------------------------------------------------------------
DATASET_PATH = os.path.join(os.getcwd(), "cybersecurity_intrusion_data.csv")

try:
    df = pd.read_csv(DATASET_PATH)
    print(f"Dataset loaded successfully with {df.shape[0]} rows and {df.shape[1]} columns.")
except FileNotFoundError:
    print(f"Dataset not found at {DATASET_PATH}. Please ensure the file is in the correct location.")
except Exception as e:
    print(f"Error loading dataset: {e}")

# print(df.head())

#Visualizing the data-----------------------------------------------------------------------
data_array = np.array([df[column].to_numpy() for column in df.columns])
print(data_array)

# Visualizing categorical features
sns.countplot(data=df, x='protocol_type', hue='attack_detected')
plt.title("Protocol Type Distribution")
plt.show()

sns.countplot(data=df, x='browser_type', hue='attack_detected')
plt.title("Browser Type Distribution")
plt.show()