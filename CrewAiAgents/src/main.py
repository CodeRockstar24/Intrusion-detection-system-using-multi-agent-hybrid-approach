import sys
from crew import MyCrew


def run():
    # Replace with your inputs, it will automatically interpolate any tasks and agents information
    inputs = {
        "attack_type": "ddos_attack"
    }
    MyCrew().crew().kickoff(inputs=inputs)

if __name__ == "__main__":
    run()