import json
class LIPAgent:
    def generate_intent(self):
        return {"intent": "example_intent"}
if __name__ == "__main__":
    agent = LIPAgent()
    print(json.dumps(agent.generate_intent(), indent=2))