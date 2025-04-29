
import os
from flask import Flask, render_template, request, redirect
from werkzeug.utils import secure_filename
import pandas as pd
from feature_extraction import aggregate_sessions
from model_loader import load_model

app = Flask(__name__, template_folder='../frontend/templates',static_folder='../frontend/static')

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
ALLOWED_EXTENSIONS = {'pcap', 'pcapng'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/process_file', methods=['POST'])
def process_file():
    if 'file' not in request.files:
        return redirect(request.url)

    file = request.files['file']
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        algorithm = request.form['algorithm']
        attack_type = request.form['attack']

        try:
            df = aggregate_sessions(file_path)
            if df.empty:
                return "Error: No data extracted from the uploaded file. Please check the file."

            features = df.iloc[0].to_dict()
            return render_template('form.html', features=features, algorithm=algorithm, attack_type=attack_type)

        except Exception as e:
            return f"Error processing the file: {str(e)}"
    
    return "Invalid file type. Please upload a .pcap or .pcapng file."

@app.route('/result', methods=['POST'])
def result():
    try:
        feature_values = request.form.to_dict()
        algorithm = feature_values.pop('algorithm')
        attack_type = feature_values.pop('attack_type')
        features = {}
        for k, v in feature_values.items():
            try:
                features[k] = float(v)
            except ValueError:
                continue  # Ignore non-numeric fields
        # Load model
        model, accuracy = load_model(attack_type, algorithm)

        # Read the latest uploaded file
        uploaded_files = sorted(os.listdir(app.config['UPLOAD_FOLDER']), key=lambda x: os.path.getmtime(os.path.join(app.config['UPLOAD_FOLDER'], x)), reverse=True)
        latest_file = os.path.join(app.config['UPLOAD_FOLDER'], uploaded_files[0])

        df_full = aggregate_sessions(latest_file)
        df_full = df_full.apply(pd.to_numeric, errors='coerce')
        df_full = df_full.dropna()

        if df_full.empty:
            return "Error: No valid data found in flows after processing."

        predictions = model.predict(df_full)

        total_flows = len(predictions)
        # Clean predictions to remove trailing dots and spaces
        cleaned_preds = [str(p).strip().lower().replace('.', '') for p in predictions]

        # Count how many are not 'normal'
        attack_count = sum(1 for p in cleaned_preds if p != 'normal')

        # attack_count = sum(int(p) for p in predictions)

        if attack_count > 0:
            result_text = f"⚠️ Attack Detected ({attack_count} / {total_flows} flows)"
        else:
            result_text = f"✅ No Attack Detected in {total_flows} flows"

        # return render_template('result.html', result=result_text, accuracy=accuracy)
        return render_template('result.html', 
                       result=result_text, 
                       accuracy=round(accuracy * 100, 2),  # if accuracy is in 0.994 format
                       total_flows=total_flows,
                       attack_count=attack_count)


    except Exception as e:
        return f"An error occurred: {str(e)}"

if __name__ == "__main__":
    app.run(debug=True)
