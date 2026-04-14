import joblib
import pandas as pd
model = joblib.load("models/model.pkl")
feature_order = [
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Total Length of Fwd Packets',
    'Total Length of Bwd Packets',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Flow IAT Mean',
    'Fwd IAT Mean',
    'Bwd IAT Mean',
    'Packet Length Mean',
    'SYN Flag Count',
    'ACK Flag Count'
]
#creating risk level mapping function
# Risk level mapping
def get_risk_level(prob):
    if prob > 0.85:
        return "HIGH"
    elif prob > 0.6:
        return "MEDIUM"
    else:
        return "LOW"
# Main detection function
def detect_traffic(input_data):
    try:
        # Convert input to DataFrame
        input_data = pd.DataFrame([input_data])
        # Ensure all required features exist
        for feature in feature_order:
            if feature not in input_data:
                raise ValueError(f"Missing feature: {feature}")

        # Reorder features
        input_data = input_data[feature_order]

        # Prediction
        prediction = model.predict(input_data)[0]
        probabilities = model.predict_proba(input_data)[0]

        attack_prob = probabilities[1]  # probability of class "ATTACK"

        # Determine status
        status = "ATTACK" if prediction == 1 else "NORMAL"

        # Determine risk level
        risk = get_risk_level(attack_prob)

        # Structured response
        result = {
            "status": status,
            "confidence": round(float(attack_prob), 3),
            "risk_level": risk
        }

        return result

    except Exception as e:
        return {
            "status": "ERROR",
            "message": str(e)
        }