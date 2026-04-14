import pandas as pd
data = pd.read_csv("data/cleaned_data.csv")
# Split normal vs attack
normal_data = data[data["Label"] == 0]
attack_data = data[data["Label"] == 1]
# Compute thresholds (midpoint between normal and attack means)
thresholds = {
    "SYN Flag Count": (normal_data["SYN Flag Count"].mean() + attack_data["SYN Flag Count"].mean()) / 2,
    "Flow Packets/s": (normal_data["Flow Packets/s"].mean() + attack_data["Flow Packets/s"].mean()) / 2,
    "Flow Bytes/s": (normal_data["Flow Bytes/s"].mean() + attack_data["Flow Bytes/s"].mean()) / 2
}
def analyze_traffic(input_data, detection_output):
    # If normal traffic, return early
    if detection_output["status"] == "NORMAL":
        return {
            "attack_type": "None",
            "risk_score": 0.0,
            "confidence": "LOW",
            "reason": "Traffic classified as normal"
        }
    score = 0
    reasons = []
    # Rule 1: SYN activity
    if input_data['SYN Flag Count'] > thresholds["SYN Flag Count"]:
        score += 3
        reasons.append("SYN activity above normal baseline")
    # Rule 2: Packet rate
    if input_data['Flow Packets/s'] > thresholds["Flow Packets/s"]:
        score += 2
        reasons.append("packet rate exceeds typical traffic")
    # Rule 3: Byte rate
    if input_data['Flow Bytes/s'] > thresholds["Flow Bytes/s"]:
        score += 2
        reasons.append("data transfer volume is unusually high")
    # Rule 4: Traffic imbalance (still heuristic)
    if input_data['Total Fwd Packets'] > 2 * input_data['Total Backward Packets']:
        score += 1
        reasons.append("asymmetric forward-heavy traffic")
    # Normalize score (max = 8)
    risk_score = round(score / 8, 2)
    # Decision logic
    if score >= 5:
        attack_type = "DDoS / Flood"
        confidence = "HIGH"
    elif score >= 3:
        attack_type = "Suspicious Activity"
        confidence = "MEDIUM"
    else:
        attack_type = "Anomalous Pattern"
        confidence = "LOW"
    return {
        "attack_type": attack_type,
        "risk_score": risk_score,
        "confidence": confidence,
        "reason": ", ".join(reasons)
    }