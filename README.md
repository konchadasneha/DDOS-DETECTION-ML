🚨 DDoS Detection using Machine Learning
This project focuses on detecting Distributed Denial of Service (DDoS) attacks in real-time using machine learning techniques. By leveraging packet-level traffic analysis and advanced classification algorithms, it accurately identifies malicious activity in network traffic such as UDP, TCP, and ICMP floods.

🔍 How It Works:
📥 Users upload .pcapng network traffic files captured via Wireshark.

🧠 Features are dynamically extracted using PyShark (based on 41 KDD-style features).

📊 Users select an attack type and a machine learning model (e.g., SVM, Random Forest, KNN).

🧮 The backend predicts whether the traffic represents a DDoS attack or normal behavior.

🌐 A user-friendly web interface built with Flask guides the full detection workflow.

⚙️ Tech Stack:
Python, Flask, HTML/CSS (Frontend UI)

PyShark for feature extraction

Scikit-learn for model training (SVM, KNN, Logistic Regression, etc.)

Wireshark for packet capture

Dataset: KDD Cup 99 (or revised variant)

📈 Features:
Real-time prediction and flow analysis

Support for multiple attack types (UDP, TCP, ICMP)

Intuitive UI for selecting models and viewing results

Model accuracy and attack statistics shown clearly

📁 Dataset:
Used a labeled dataset containing both normal and attack traffic patterns with 41 key network features, enabling deep inspection and robust learning.
