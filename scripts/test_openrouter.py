from dotenv import load_dotenv
import os
from llm.gateway import OpenRouterGateway
from langchain_core.messages import HumanMessage

load_dotenv()

def test_openrouter():
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        print("Error: OPENROUTER_API_KEY not found in .env")
        return

    print(f"Testing OpenRouter with key: {api_key[:10]}...")
    try:
        # Using a model for testing
        gw = OpenRouterGateway(model="google/gemma-4-26b-a4b-it:free")
        response = gw.invoke([HumanMessage(content="Hello, are you working?")])
        print("Response received:")
        print("-" * 20)
        print(response.content)
        print("-" * 20)
        print("Test SUCCESSFUL!")
    except Exception as e:
        print(f"Test FAILED: {e}")

if __name__ == "__main__":
    test_openrouter()
