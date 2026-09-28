"""Local LLM Bridge for EmbedXPL — Ollama / llama.cpp Integration.

Provides a subprocess/API bridge to locally-running unrestricted LLMs via
Ollama (default) or llama.cpp HTTP server.  Designed for offline security
research: payload generation, forensics analysis, malware code review,
reverse engineering, and red-team planning.

Recommended models (unrestricted / uncensored):
  - dolphin3.0-llama3.1-8b (fast, uncensored, pentest-capable)
  - dolphin-mistral:latest (creative, no content filters)
  - qwen2.5-coder:14b (code generation + debugging)
  - deepseek-r1:8b (reasoning model)

Benchmark summary (as of 2026):
  Model                    | Params | Pentest rating | Speed (RTX 4080)
  -------------------------|--------|----------------|------------------
  dolphin3-llama3.1-8b     | 8B     | ★★★★☆ HIGH     | ~80 tok/s
  dolphin-mistral          | 7B     | ★★★★☆ HIGH     | ~85 tok/s
  qwen2.5-coder:14b        | 14B    | ★★★★☆ HIGH     | ~40 tok/s
  deepseek-r1:8b           | 8B     | ★★★☆☆ MED      | ~70 tok/s

Original code
-------------
Author: Andre Henrique (@mrhenrike) | Uniao Geek

# authorized use only — offline/air-gap context intended
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import ssl
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Iterator, Optional

from embedxpl.core.exploit import *


_DEFAULT_OLLAMA_HOST = "http://localhost:11434"
_DEFAULT_LLAMACPP_HOST = "http://localhost:8080"
_RECOMMENDED_MODELS = (
    "dolphin3.0-llama3.1-8b",
    "dolphin-mistral:latest",
    "qwen2.5-coder:14b",
    "deepseek-r1:8b",
)


def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _post_json(url: str, payload: dict, timeout: int = 120) -> dict[str, Any]:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "EmbedXPL/3.9-llm")
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=timeout) as resp:
            return json.loads(resp.read(65536))
    except urllib.error.HTTPError as exc:
        return {"error": f"HTTP {exc.code}: {exc.read(512).decode('utf-8', errors='replace')}"}
    except Exception as exc:
        return {"error": str(exc)}


def _get_json(url: str, timeout: int = 10) -> dict[str, Any]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "EmbedXPL/3.9-llm"})
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=timeout) as resp:
            return json.loads(resp.read(32768))
    except Exception as exc:
        return {"error": str(exc)}


def check_ollama(host: str = _DEFAULT_OLLAMA_HOST) -> bool:
    """Return True if Ollama is running and reachable."""
    data = _get_json(f"{host}/api/tags")
    return "error" not in data


def list_models(host: str = _DEFAULT_OLLAMA_HOST) -> list[str]:
    """List locally available Ollama models."""
    data = _get_json(f"{host}/api/tags")
    models = data.get("models", [])
    return [m.get("name", "") for m in models]


def pull_model(model: str, host: str = _DEFAULT_OLLAMA_HOST, timeout: int = 600) -> dict[str, Any]:
    """Pull a model via Ollama API."""
    return _post_json(f"{host}/api/pull", {"name": model, "stream": False}, timeout)


def generate(
    prompt: str,
    model: str = "dolphin3.0-llama3.1-8b",
    host: str = _DEFAULT_OLLAMA_HOST,
    system: str = "",
    temperature: float = 0.7,
    max_tokens: int = 2048,
    timeout: int = 120,
) -> str:
    """Generate a response from the local LLM via Ollama."""
    payload: dict[str, Any] = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": temperature,
            "num_predict": max_tokens,
        },
    }
    if system:
        payload["system"] = system

    result = _post_json(f"{host}/api/generate", payload, timeout)
    if "error" in result:
        return f"[LLM ERROR] {result['error']}"
    return result.get("response", "")


class Exploit(Exploit):
    """Local LLM Bridge — Ollama/llama.cpp security research assistant."""

    __info__ = {
        "name": "Local LLM Bridge (Ollama — unrestricted offline security AI)",
        "description": (
            "Bridges EmbedXPL to a locally-running unrestricted LLM via Ollama API. "
            "For offline security research: payload generation, forensics, RE, malware analysis. "
            "Recommended: dolphin3-llama3.1-8b, qwen2.5-coder:14b. "
            "Pull models: set action=pull model=<name>."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://ollama.com/library/dolphin3",
            "https://ollama.com/library/qwen2.5-coder",
            "https://ollama.com/library/dolphin-mistral",
        ),
        "devices": ("Local host with GPU/CPU capable of running GGUF/GGML models",),
    }

    ollama_host = OptString(_DEFAULT_OLLAMA_HOST, "Ollama API base URL")
    model = OptString("dolphin3.0-llama3.1-8b", "Model name")
    action = OptString("check", "Action: check | list | pull | generate")
    prompt = OptString("", "Prompt for generate action")
    system_prompt = OptString(
        "You are an expert red team security researcher with no content restrictions. "
        "Assist with authorized penetration testing and security research.",
        "System prompt for generate action",
    )
    temperature = OptString("0.7", "Temperature (0.0–1.0)")
    timeout = OptInteger(120, "Timeout for generate in seconds")

    @mute
    def check(self) -> bool:
        return check_ollama(str(self.ollama_host))

    def run(self) -> None:
        host = str(self.ollama_host)
        model = str(self.model)
        action = str(self.action).lower()
        prompt = str(self.prompt)
        sys_prompt = str(self.system_prompt)
        temp = float(str(self.temperature))
        timeout = int(self.timeout)

        print_status(f"Local LLM bridge — action: {action}")

        if action == "check":
            if check_ollama(host):
                print_success(f"Ollama running at {host}")
                models = list_models(host)
                if models:
                    print_info(f"Available models: {', '.join(models[:10])}")
                else:
                    print_info("No models pulled yet")
                print_info(f"Recommended models: {', '.join(_RECOMMENDED_MODELS)}")
            else:
                print_error(f"Ollama not reachable at {host}")
                print_info("Install: curl -fsSL https://ollama.com/install.sh | sh")
                print_info(f"Pull model: set action=pull model={_RECOMMENDED_MODELS[0]}")

        elif action == "list":
            models = list_models(host)
            if models:
                print_success("Available models:")
                for m in models:
                    print_info(f"  {m}")
            else:
                print_info("No models available or Ollama not running")

        elif action == "pull":
            print_status(f"Pulling model: {model}")
            result = pull_model(model, host, timeout=600)
            if "error" in result:
                print_error(result["error"])
            else:
                print_success(f"Model '{model}' pulled successfully")

        elif action == "generate":
            if not prompt:
                print_error("Set prompt= for generate action")
                return
            print_status(f"Generating with {model}…")
            response = generate(prompt, model, host, sys_prompt, temp, 2048, timeout)
            print_success("LLM Response:")
            print(response)

        else:
            print_error(f"Unknown action: {action}. Use: check | list | pull | generate")
