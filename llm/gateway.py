from typing import Any, List, Optional
from langchain_ollama import ChatOllama, OllamaEmbeddings
from langchain_openai import ChatOpenAI
import requests
import os

# The URL for the Ollama container's API
OLLAMA_BASE_URL = "http://localhost:11434"

# Use the auto-router to find the best available free model automatically
FREE_MODEL = "openrouter/auto"

class OpenRouterGateway(ChatOpenAI):
    """LangChain ChatModel wrapper for OpenRouter API"""
    
    def __init__(self, model=FREE_MODEL, **kwargs: Any):
        api_key = os.getenv("OPENROUTER_API_KEY")
        
        if "max_tokens" not in kwargs:
            kwargs["max_tokens"] = 128
            
        super().__init__(
            openai_api_key=api_key,
            openai_api_base="https://openrouter.ai/api/v1",
            model_name=model,
            default_headers={
                "HTTP-Referer": "http://localhost:8000",
                "X-Title": "Atlas-0 CTF Lab",
            },
            **kwargs
        )

    def invoke(self, input, config=None, **kwargs):
        try:
            return super().invoke(input, config, **kwargs)
        except Exception as e:
            print(f"DEBUG: OpenRouter Error. Retrying with {FREE_MODEL}. Error: {e}")
            fallback_gw = ChatOpenAI(
                openai_api_key=os.getenv("OPENROUTER_API_KEY"),
                openai_api_base="https://openrouter.ai/api/v1",
                model_name=FREE_MODEL,
                max_tokens=50
            )
            return fallback_gw.invoke(input, config, **kwargs)

    async def ainvoke(self, input, config=None, **kwargs):
        try:
            return await super().ainvoke(input, config, **kwargs)
        except Exception as e:
            print(f"DEBUG: OpenRouter Error (Async). Retrying with {FREE_MODEL}. Error: {e}")
            fallback_gw = ChatOpenAI(
                openai_api_key=os.getenv("OPENROUTER_API_KEY"),
                openai_api_base="https://openrouter.ai/api/v1",
                model_name=FREE_MODEL,
                max_tokens=50
            )
            return await fallback_gw.ainvoke(input, config, **kwargs)

    @property
    def _llm_type(self) -> str:
        return "openrouter-chat"

class TinyLlamaClient:
    """Low-level client for the Ollama service to maintain compatibility"""
    
    def __init__(self, base_url: str = f"{OLLAMA_BASE_URL}/api/generate"):
        self.base_url = base_url

    def generate_content(self, prompt: str) -> str:
        """mimics genai.GenerativeModel.generate_content().text behavior somewhat"""
        try:
            payload = {
                "model": "tinyllama",
                "prompt": prompt,
                "stream": False,
                "options": {
                    "num_predict": 512,
                    "temperature": 0.1
                }
            }
            response = requests.post(self.base_url, json=payload, timeout=60)
            response.raise_for_status()
            return response.json().get("response", "")
        except Exception as e:
            print(f"Error calling Ollama service: {e}")
            return "Error generating content."

    def start_chat(self, enable_automatic_function_calling=False):
        """Mock for genai.GenerativeModel.start_chat()"""
        return TinyLlamaChatSession(self)


class TinyLlamaChatSession:
    """Mock for genai.ChatSession using Ollama"""
    def __init__(self, client: TinyLlamaClient):
        self.client = client
        self.history = []

    def send_message(self, message: str) -> Any:
        full_prompt = ""
        for h in self.history:
            full_prompt += f"User: {h['user']}\nAssistant: {h['assistant']}\n"
        
        full_prompt += f"User: {message}\nAssistant: "
        
        response_text = self.client.generate_content(full_prompt)
        
        if "User:" in response_text:
            response_text = response_text.split("User:")[0].strip()
            
        self.history.append({"user": message, "assistant": response_text})
        
        class Response:
            text = response_text
        return Response()


class TinyLlamaGateway(ChatOllama):
    """LangChain ChatModel wrapper for Ollama TinyLlama service"""
    
    def __init__(self, **kwargs: Any):
        super().__init__(
            base_url=OLLAMA_BASE_URL,
            model="tinyllama",
            temperature=0.1,
            **kwargs
        )

    def bind_tools(self, tools: List[Any], **kwargs: Any) -> Any:
        return self

    @property
    def _llm_type(self) -> str:
        return "tinyllama-ollama-chat"


def get_embeddings():
    """Return Ollama embeddings for local execution"""
    return OllamaEmbeddings(
        base_url=OLLAMA_BASE_URL,
        model="tinyllama"
    )
