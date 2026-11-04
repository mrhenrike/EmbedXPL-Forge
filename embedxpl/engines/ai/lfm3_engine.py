"""LFM3-1.7B-abliterated — local LLM engine for offline offensive AI tasks.

Model: orcarouter/LFM3-1.7B-abliterated (Liquid Foundation Model, refusals removed)
Architecture: 24-layer hybrid conv+attention (13 gated short-conv + 11 GQA)
Size: ~3.4 GB bf16  |  VRAM: 5-6 GB minimum

Usage options:
  1. Direct via transformers (GPU/CPU):
       engine = LFM3Engine()
       print(engine.query("Analyze this firmware header: ..."))

  2. Via Ollama (quantized, recommended for CPU):
       ollama run hf.co/orcarouter/LFM3-1.7B-abliterated
       engine = LFM3Engine(backend="ollama")

WARNING: trust_remote_code=True is required — inspect model code before loading.
Model has no safety guardrails (abliterated). Use responsibly in lab environments.
"""
from __future__ import annotations

import json
import subprocess
from typing import Any


class LFM3Engine:
    """
    Thin wrapper around LFM3-1.7B-abliterated for EmbedXPL AI tasks.
    Backends: 'transformers' (GPU/CPU) or 'ollama' (quantized CPU inference).
    """

    MODEL_ID = "orcarouter/LFM3-1.7B-abliterated"
    OLLAMA_MODEL = "hf.co/orcarouter/LFM3-1.7B-abliterated"

    def __init__(self, backend: str = "ollama", device: str = "auto") -> None:
        """
        Args:
            backend: 'transformers' or 'ollama'
            device: 'auto', 'cuda', 'cpu' (only relevant for transformers backend)
        """
        self.backend = backend
        self.device = device
        self._model: Any = None
        self._tokenizer: Any = None

        if backend == "transformers":
            self._load_transformers()

    def _load_transformers(self) -> None:
        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer

            self._tokenizer = AutoTokenizer.from_pretrained(
                self.MODEL_ID, trust_remote_code=True
            )
            self._model = AutoModelForCausalLM.from_pretrained(
                self.MODEL_ID,
                torch_dtype=torch.bfloat16,
                device_map=self.device,
                trust_remote_code=True,
            )
        except ImportError as exc:
            raise ImportError(f"Install torch + transformers: pip install torch transformers — {exc}") from exc

    def query(self, prompt: str, max_tokens: int = 512, temperature: float = 0.3) -> str:
        """Send a prompt and return the model response as a string."""
        if self.backend == "ollama":
            return self._query_ollama(prompt, max_tokens, temperature)
        return self._query_transformers(prompt, max_tokens, temperature)

    def _query_ollama(self, prompt: str, max_tokens: int, temperature: float) -> str:
        payload = json.dumps({
            "model": self.OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
            "options": {"num_predict": max_tokens, "temperature": temperature},
        })
        try:
            result = subprocess.run(
                ["ollama", "run", self.OLLAMA_MODEL, prompt],
                capture_output=True, text=True, timeout=120
            )
            return result.stdout.strip()
        except FileNotFoundError:
            return "[LFM3] ollama not found — install from https://ollama.com or use backend='transformers'"
        except Exception as exc:
            return f"[LFM3] Error: {exc}"

    def _query_transformers(self, prompt: str, max_tokens: int, temperature: float) -> str:
        import torch

        inputs = self._tokenizer(prompt, return_tensors="pt").to(self._model.device)
        with torch.no_grad():
            outputs = self._model.generate(
                **inputs,
                max_new_tokens=max_tokens,
                temperature=temperature,
                do_sample=temperature > 0,
                pad_token_id=self._tokenizer.eos_token_id,
            )
        generated = outputs[0][inputs["input_ids"].shape[1]:]
        return self._tokenizer.decode(generated, skip_special_tokens=True).strip()

    # ------------------------------------------------------------------
    # Pentest-specific helpers
    # ------------------------------------------------------------------

    def analyze_firmware_header(self, hex_dump: str) -> str:
        """Identify firmware format, architecture, and compression from a hex dump."""
        return self.query(
            f"You are a firmware reverse engineer. Analyze this hex dump and identify: "
            f"firmware format (ELF/CRAMFS/SQUASHFS/etc), CPU architecture, compression, "
            f"and any interesting strings or hardcoded credentials.\n\nHex dump:\n{hex_dump}"
        )

    def suggest_exploit(self, service_banner: str, version: str) -> str:
        """Given a service banner and version, suggest known exploits and attack vectors."""
        return self.query(
            f"Given this service: {service_banner} version {version}\n"
            f"List known CVEs, public exploits, default credentials, and attack vectors. "
            f"Be specific with CVE IDs and exploit paths."
        )

    def interpret_scan_output(self, raw_output: str) -> str:
        """Parse and summarize raw nmap/masscan/banners output into actionable findings."""
        return self.query(
            f"Analyze this network scan output and extract: open ports, service versions, "
            f"potential vulnerabilities, default credentials, and recommended next steps.\n\n{raw_output[:4000]}"
        )

    def generate_payload(self, context: str, constraint: str = "") -> str:
        """Generate an exploit payload or command for a given context."""
        q = f"Generate a working exploit payload or command for: {context}"
        if constraint:
            q += f"\nConstraints: {constraint}"
        return self.query(q)
