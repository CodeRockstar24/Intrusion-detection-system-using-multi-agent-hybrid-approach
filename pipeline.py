from agents.detection_agent import detect_traffic
from agents.analysis_agent import analyze_traffic
from agents.src.crew import MyCrew

def run_pipeline(input_data):
    # Step 1: Detection of potential attack
    detection = detect_traffic(input_data)
    # Step 2: Analysis
    analysis = analyze_traffic(input_data, detection)
    # Step 3: Research about the attack and  Respond only if there is a threat detected!
    if detection["status"] == "ATTACK":
        inputs = {
            "attack_type": analysis["attack_type"],
            "risk_level": analysis["confidence"]
        }
        crew_output = MyCrew().crew().kickoff(inputs=inputs)
        return {
            "detection": detection,
            "analysis": analysis,
            "crew_output": crew_output
        }
    else:
        return {
            "detection": detection,
            "analysis": analysis,
            "crew_output": "No threat detected so far!"
        }