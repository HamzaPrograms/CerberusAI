import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import OneHotEncoder
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report


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

df = df.drop('session_id', axis=1) #Dropped session id column bc it doesnt help in training

#Keep in mind that not every option is added as a column for the encoded columns,
#This is because if all are zero, e.g (edge,firefox,safari,unknown) all = 0. Then the
#browser is chrome.

#Feature Extraction----------------------------------------------------------------------------------
df['failed_login_ratio'] = df['failed_logins'] / (df['login_attempts'] + 1)  # +1 to avoid division by zero
df['suspicious_browser'] = df[['browser_type_Unknown', 'browser_type_Safari']].max(axis=1)

#Feature Scaling----------------------------------------------------------------------------------
numerical_features = [
    'network_packet_size', 'session_duration', 'ip_reputation_score', 'login_attempts',
    'failed_logins', 'failed_login_ratio'
]

scaler = StandardScaler()
df[numerical_features] = scaler.fit_transform(df[numerical_features])
# print(df[numerical_features].mean())
# print(df[numerical_features].std())
# print(df.head)

#Split Data, Train, Test-------------------------------------------------------------------------------
#Separating Features and Target columns
X = df.drop('attack_detected', axis=1)
Y = df['attack_detected']

# Split the data
X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.3, random_state=42)
#random state makes sure that the random processes produce the same results each time. ^

print(f"Training set size: {X_train.shape}")
print(f"Testing set size: {X_test.shape}")

# Initialize the XGBoost Classifier
xgb_model = XGBClassifier(
    n_estimators=900,
    learning_rate=0.1,
    max_depth=6,
    random_state=42,
    use_label_encoder=False,
    eval_metric='logloss' #the model will minimize logistic loss during training
    #Logloss is used for binary classification
)

# Train the model
xgb_model.fit(X_train, Y_train)
print("Model training complete.")

# Predict on the test set
# y_pred = xgb_model.predict(X_test)

# # Evaluation Metrics
# accuracy = accuracy_score(Y_test, y_pred) #correct predictions/all predictions
# precision = precision_score(Y_test, y_pred)#correct positive predictions/all positive predictions
# recall = recall_score(Y_test, y_pred)#correct positive predictions/all actual positive cases.
# f1 = f1_score(Y_test, y_pred)#harmonic mean of precision and recall

# print(f"Accuracy: {accuracy:.4f}")
# print(f"Precision: {precision:.4f}")
# print(f"Recall: {recall:.4f}")
# print(f"F1 Score: {f1:.4f}")

# # Confusion Matrix
# conf_matrix = confusion_matrix(Y_test, y_pred)
# print("\nConfusion Matrix:\n", conf_matrix)

# # Classification Report
# print("\nClassification Report:\n", classification_report(Y_test, y_pred))



y_probs = xgb_model.predict_proba(X_test)[:, 1]  # Probabilities for the positive class
threshold = 0.25
y_pred_adjusted = (y_probs >= threshold).astype(int)

# Recalculate metrics with adjusted threshold
accuracy = accuracy_score(Y_test, y_pred_adjusted)
precision = precision_score(Y_test, y_pred_adjusted)
recall = recall_score(Y_test, y_pred_adjusted)
f1 = f1_score(Y_test, y_pred_adjusted)

print(f"Adjusted Threshold = {threshold}")
print(f"Accuracy: {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall: {recall:.4f}")
print(f"F1 Score: {f1:.4f}")

# Confusion Matrix
conf_matrix = confusion_matrix(Y_test, y_pred_adjusted)
print("\nConfusion Matrix with Adjusted Threshold:\n", conf_matrix)

#Test both thresholds before final product ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^