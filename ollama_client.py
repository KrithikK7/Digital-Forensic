import os
import requests

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
EMBED_MODEL = os.getenv("EMBED_MODEL", "mxbai-embed-large:latest")
CHAT_MODEL = os.getenv("CHAT_MODEL", "llama3.2:latest")


def embed_one(text: str, model: str | None = None) -> list[float]:
    m = model or EMBED_MODEL
    resp = requests.post(f"{OLLAMA_HOST}/api/embeddings", json={"model": m, "prompt": text})
    resp.raise_for_status()
    data = resp.json()
    return data.get("embedding") or data.get("data", [{}])[0].get("embedding", [])


def chat(messages: list[dict], model: str | None = None, stream: bool = False) -> str:
    m = model or CHAT_MODEL
    payload = {"model": m, "messages": messages, "stream": stream}
    resp = requests.post(f"{OLLAMA_HOST}/api/chat", json=payload, stream=stream)
    resp.raise_for_status()
    if stream:
        chunks = []
        for line in resp.iter_lines():
            if not line:
                continue
            try:
                obj = requests.utils.json.loads(line)
                msg = obj.get("message", {}).get("content", "")
                chunks.append(msg)
            except Exception:
                continue
        return "".join(chunks)
    data = resp.json()
    return data.get("message", {}).get("content", "")

