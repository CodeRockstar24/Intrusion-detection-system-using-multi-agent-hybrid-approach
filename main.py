from agents.detection_agent import detect_traffic
from agents.analysis_agent import analyze_traffic
from agents.research_agent import run_research_agent
from agents.response_agent import run_response_agent
import pandas as pd

def run_system(input_data):

    detection_output = detect_traffic(input_data)
    analysis_output = analyze_traffic(input_data, detection_output)
    research_output = run_research_agent(detection_output, analysis_output)
    response_output = run_response_agent(detection_output, analysis_output)

    return {
        "detection": detection_output,
        "analysis": analysis_output,
        "research": research_output,
        "response": response_output
    }


if __name__ == "__main__":
    # Load 4 random rows
    df = pd.read_csv(r"C:\Users\elroy\OneDrive\Desktop\Cybersecurity Project CECS378\data\MachineLearningCVE\cleaned_data.csv")
    df_sample = df.sample(4, random_state=42)

    for i, row in df_sample.iterrows():
        print(f"\n========== SAMPLE {i} ==========")

        input_data = row.to_dict()

        result = run_system(input_data)

        print("\nDETECTION:", result["detection"])
        print("\nANALYSIS:", result["analysis"])
        print("\nRESPONSE:", result["response"])