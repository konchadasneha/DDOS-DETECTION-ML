
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import LogisticRegression, LinearRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import LabelEncoder, StandardScaler
import joblib
import os

# Create 'models' folder if it doesn't exist
os.makedirs('models', exist_ok=True)

# Load dataset
df = pd.read_csv('revised_kddcup_dataset.csv')

# Split by protocol
icmp_data = df[df['protocol_type'] == 'icmp']
tcp_data = df[df['protocol_type'] == 'tcp']
udp_data = df[df['protocol_type'] == 'udp']

features = ['duration', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'su_attempted',
            'num_outbound_cmds', 'is_host_login', 'count', 'srv_count', 'serror_rate',
            'srv_serror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate']
target = 'result'

# Models to train
models = {
    'svm': SVC(),
    'knn': KNeighborsClassifier(),
    'logistic_regression': LogisticRegression(solver='liblinear', max_iter=1000),
    'linear_regression': LinearRegression(),
    'decision_tree': DecisionTreeClassifier(),
    'random_forest': RandomForestClassifier()
}

# Protocol data
protocol_data = {
    'icmp': icmp_data,
    'tcp': tcp_data,
    'udp': udp_data
}

# Accuracy storage
accuracy_results = []

# Loop through protocol types
for protocol, data in protocol_data.items():
    for model_name, model_instance in models.items():
        x = data[features]
        y = data[target]
         # Scale features for better performance
      #   scaler = StandardScaler()
      #   x = scaler.fit_transform(x)
      #   x = data[features]
        scaler = StandardScaler()
        x_scaled = scaler.fit_transform(x)
        x = pd.DataFrame(x_scaled, columns=features)  # Fix: restore column names after scaling

        # Encode target for regression models
        if model_name == 'linear_regression':
            label_encoder = LabelEncoder()
            y = label_encoder.fit_transform(y)

        # Split data
        x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=42)

        # Train model
        model_instance.fit(x_train, y_train)

        # Predict and calculate accuracy
        y_pred = model_instance.predict(x_test)

        if model_name == 'linear_regression':
            # Convert regression predictions to class labels
            y_pred = y_pred.round().astype(int)
            y_pred = [min(max(int(p), 0), len(label_encoder.classes_) - 1) for p in y_pred]

        acc = accuracy_score(y_test, y_pred)

        # Save model along with its accuracy
        model_data = {
            'model': model_instance,
            'accuracy': acc
        }
        model_path = f'models/{protocol}_{model_name}_model.pkl'
        joblib.dump(model_data, model_path)

        # Store accuracy
        accuracy_results.append({
            'Protocol': protocol.upper(),
            'Model': model_name.replace("_", " ").title(),
            'Accuracy': round(acc * 100, 2)
        })

# Save accuracy results to CSV
accuracy_df = pd.DataFrame(accuracy_results)
accuracy_df.to_csv('model_accuracies.csv', index=False)

# Print accuracies
print("=== Model Training Completed ===")
print(accuracy_df)
# import pandas as pd
# from sklearn.model_selection import train_test_split
# from sklearn.svm import SVC
# from sklearn.neighbors import KNeighborsClassifier
# from sklearn.linear_model import LogisticRegression, LinearRegression
# from sklearn.tree import DecisionTreeClassifier
# from sklearn.ensemble import RandomForestClassifier
# from sklearn.metrics import accuracy_score
# from sklearn.preprocessing import LabelEncoder, StandardScaler
# import joblib
# import os

# # Create 'models' folder if it doesn't exist
# os.makedirs('models', exist_ok=True)

# # Load dataset
# df = pd.read_csv('revised_kddcup_dataset.csv')

# # All 41 KDD features (replace or adjust if yours slightly differ)
# features = [
#     'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
#     'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
#     'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root',
#     'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
#     'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate',
#     'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
#     'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
#     'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
#     'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
#     'dst_host_serror_rate', 'dst_host_srv_serror_rate',
#     'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
# ]
# for feature in features:
#     if feature not in data.columns:
#         print(f"[INFO] Adding missing feature: {feature}")
#         data[feature] = 0 

# target = 'result'

# # Encode categorical features
# df['protocol_type'] = LabelEncoder().fit_transform(df['protocol_type'])
# df['service'] = LabelEncoder().fit_transform(df['service'])
# df['flag'] = LabelEncoder().fit_transform(df['flag'])

# # Split by protocol
# icmp_data = df[df['protocol_type'] == 1]  # ICMP label encoded as 1
# tcp_data = df[df['protocol_type'] == 0]   # TCP label encoded as 0
# udp_data = df[df['protocol_type'] == 2]   # UDP label encoded as 2

# protocol_data = {
#     'icmp': icmp_data,
#     'tcp': tcp_data,
#     'udp': udp_data
# }

# # Models to train
# models = {
#     'svm': SVC(),
#     'knn': KNeighborsClassifier(),
#     'logistic_regression': LogisticRegression(solver='liblinear', max_iter=1000),
#     'linear_regression': LinearRegression(),
#     'decision_tree': DecisionTreeClassifier(),
#     'random_forest': RandomForestClassifier()
# }

# # Accuracy storage
# accuracy_results = []

# # Loop through protocol types and train models
# for protocol, data in protocol_data.items():
#     for model_name, model_instance in models.items():
#         x = data[features]
#         y = data[target]

#         # Scale features
#         scaler = StandardScaler()
#         x_scaled = scaler.fit_transform(x)
#         x = pd.DataFrame(x_scaled, columns=features)

#         # Encode target for regression models
#         if model_name == 'linear_regression':
#             label_encoder = LabelEncoder()
#             y = label_encoder.fit_transform(y)

#         # Split data
#         x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=42)

#         # Train model
#         model_instance.fit(x_train, y_train)

#         # Predict and calculate accuracy
#         y_pred = model_instance.predict(x_test)

#         if model_name == 'linear_regression':
#             y_pred = y_pred.round().astype(int)
#             y_pred = [min(max(int(p), 0), len(label_encoder.classes_) - 1) for p in y_pred]

#         acc = accuracy_score(y_test, y_pred)

#         # Save model and accuracy
#         model_data = {
#             'model': model_instance,
#             'accuracy': acc
#         }
#         model_path = f'models/{protocol}_{model_name}_model.pkl'
#         joblib.dump(model_data, model_path)

#         accuracy_results.append({
#             'Protocol': protocol.upper(),
#             'Model': model_name.replace("_", " ").title(),
#             'Accuracy': round(acc * 100, 2)
#         })

# # Save accuracy results
# accuracy_df = pd.DataFrame(accuracy_results)
# accuracy_df.to_csv('model_accuracies.csv', index=False)

# # Print accuracies
# print("=== Model Training Completed ===")
# print(accuracy_df)




