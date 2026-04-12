import requests
import os
from dotenv import load_dotenv

load_dotenv()

def list_openrouter_models():
    api_key = os.getenv("OPENROUTER_API_KEY")
    url = "https://openrouter.ai/api/v1/models"
    headers = {
        "Authorization": f"Bearer {api_key}"
    }
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        models = response.json().get("data", [])
        print(f"Total models found: {len(models)}")
        # Print top 10 for debugging
        for m in models[:10]:
            print(f"- {m['id']} ({m['name']})")
    except Exception as e:
        print(f"Failed to fetch models: {e}")

if __name__ == "__main__":
    list_openrouter_models()
