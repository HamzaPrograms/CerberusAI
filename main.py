import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import OneHotEncoder


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

# Set up the figure layout
fig, axes = plt.subplots(3, 2, figsize=(20, 12))
fig.suptitle("Categorical Feature Distributions by Attack Detection", fontsize=18, weight='bold')

# List of features to plot
features = ['protocol_type', 'login_attempts', 'encryption_used', 'failed_logins', 'browser_type', 'unusual_time_access']
titles = [
    "Protocol Type Distribution", "Login Attempts Distribution", "Encryption Used Distribution", 
    "Failed Logins Distribution", "Browser Type Distribution", "Unusual Time Access Distribution"
]

# Iterate and plot
for i, (feature, title) in enumerate(zip(features, titles)):
    row, col = divmod(i, 2)
    sns.countplot(data=df, x=feature, hue='attack_detected', ax=axes[row, col])
    axes[row, col].set_title(title, fontsize=14, weight='bold')
    axes[row, col].tick_params(axis='x', rotation=30)
    axes[row, col].legend(title='Attack Detected', loc='upper right')

cont_features = ['network_packet_size', 'session_duration', 'ip_reputation_score']
cont_titles = ["Network Packet Size", "Session Duration", "IP Reputation Score"]

# Plot Continuous Features as Scatter Plots
fig, axes = plt.subplots(1, 3, figsize=(18, 6))
for i, (feature, title) in enumerate(zip(cont_features, cont_titles)):
    sns.scatterplot(data=df, x=feature, y='attack_detected', ax=axes[i], alpha=0.6)
    axes[i].set_title(title, fontsize=14, weight='bold')
    axes[i].grid(alpha=0.3)

plt.tight_layout(rect=[0, 0, 1, 0.95])
#plt.show()

#PreProcessing---------------------------------------------------------------------------

#Non numerical values before encoding
print("Unique Protocol Types:", df['protocol_type'].unique())
print("Unique Encryption Methods:", df['encryption_used'].unique())
print("Unique Browser Types:", df['browser_type'].unique())

# Instantiate the encoder
encoder = OneHotEncoder(drop='first', sparse_output=False)

# Columns to encode
cat_columns = ['protocol_type', 'encryption_used', 'browser_type']

# Apply the encoder
encoded_array = encoder.fit_transform(df[cat_columns]) #this is a NumPy array

# Create a DataFrame from the encoded array
encoded_df = pd.DataFrame(encoded_array, columns=encoder.get_feature_names_out(cat_columns))

# Drop the original categorical columns and concatenate the encoded columns
df = df.drop(cat_columns, axis=1)
df = pd.concat([df, encoded_df], axis=1)

df = df.drop('session_id', axis=1) #Dropped session if column bc it doesnt help in training

print("Data after encoding:\n", df.head())

print(df.columns)
#Keep in mind that not every option is added as a column for the encoded columns,
#This is because if all are zero (edge,firefox,safari,unknown) all = 0. Then the
#browser is chrome.