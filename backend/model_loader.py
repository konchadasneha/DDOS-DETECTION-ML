import os
import joblib

def load_model(attack_type, algorithm):
    model_path = os.path.abspath(f"models/{attack_type}_{algorithm}_model.pkl")
    print(f"Loading model from: {model_path}")

    # Load the saved dictionary
    model_data = joblib.load(model_path)

    # Extract model and accuracy
    if isinstance(model_data, dict):
        model = model_data.get('model')
        accuracy = model_data.get('accuracy', 'Unknown')
    else:
        model = model_data
        accuracy = 'Unknown'

    print(f"Model type: {type(model)}")
    print(f"Model accuracy: {accuracy}")
    print(f"Has predict method? {'predict' in dir(model)}")

    if not hasattr(model, 'predict'):
        raise Exception(f"Model for {attack_type} and {algorithm} does not have a 'predict' method.")

    return model, accuracy
