"""
neural_engine.py - Character-level neural password generation (optional extra).

Trains and samples a character-level language model for password guessing in
the FLA and PassGPT tradition. The default architecture is a compact LSTM;
sampling supports temperature, guided generation with a prefix or a hashcat
mask, and Dynamic Password Guessing that adapts to a set of already recovered
passwords before sampling. External HuggingFace causal language models such as
PassGPT can be loaded as adapters for generation.

This module requires the optional dependency set installed with the ``[neural]``
extra (torch, and transformers for HuggingFace adapters). The rest of the tool
works without it; pcfg and markov remain the pure-Python probabilistic engines.

References: Melicher et al. (FLA, LSTM), Rando et al. (PassGPT),
Pasquini et al. (Dynamic Password Guessing).

Author: André Henrique (@mrhenrike)
Version: 1.0.0
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Generator, Optional

logger = logging.getLogger(__name__)

_INSTALL_HINT = (
    "Neural generation requires the optional 'neural' extra. Install it with:\n"
    "  pip install wordlistxpl-forge[neural]\n"
    "or:\n"
    "  pip install torch  (and 'transformers' for PassGPT adapters)"
)

# Special vocabulary tokens.
_PAD = "\x00"
_BOS = "\x02"
_EOS = "\x03"

# Mask class to character-set resolver, mirroring hashcat mask tokens.
_MASK_CLASSES = {
    "l": "abcdefghijklmnopqrstuvwxyz",
    "u": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "d": "0123456789",
    "s": "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ ",
    "a": "".join(chr(c) for c in range(32, 127)),
}


def _require_torch():
    """Import torch or raise a helpful error mentioning the extra.

    Returns:
        The imported torch module.

    Raises:
        RuntimeError: If torch is not installed.
    """
    try:
        import torch  # noqa: F401
        return torch
    except ImportError as exc:
        raise RuntimeError(_INSTALL_HINT) from exc


def _select_device(torch, compute_mode: str):
    """Pick a torch device honoring the requested compute mode."""
    if compute_mode == "cpu":
        return torch.device("cpu")
    if torch.cuda.is_available() and compute_mode in ("auto", "gpu", "cuda", "hybrid"):
        return torch.device("cuda")
    if getattr(torch.backends, "mps", None) and torch.backends.mps.is_available() \
            and compute_mode in ("auto", "gpu", "mps", "hybrid"):
        return torch.device("mps")
    return torch.device("cpu")


class CharVocab:
    """Character vocabulary with reserved PAD, BOS and EOS tokens."""

    def __init__(self, chars: list[str]) -> None:
        self.itos = [_PAD, _BOS, _EOS] + chars
        self.stoi = {c: i for i, c in enumerate(self.itos)}

    @property
    def pad(self) -> int:
        return self.stoi[_PAD]

    @property
    def bos(self) -> int:
        return self.stoi[_BOS]

    @property
    def eos(self) -> int:
        return self.stoi[_EOS]

    def __len__(self) -> int:
        return len(self.itos)

    def encode(self, word: str) -> list[int]:
        return [self.stoi[c] for c in word if c in self.stoi]

    @classmethod
    def from_words(cls, words: list[str], max_vocab: int = 0) -> "CharVocab":
        from collections import Counter
        counter: Counter = Counter()
        for w in words:
            counter.update(w)
        chars = [c for c, _ in counter.most_common(max_vocab or None)]
        chars.sort()
        return cls(chars)

    def to_dict(self) -> dict:
        return {"itos": self.itos}

    @classmethod
    def from_dict(cls, d: dict) -> "CharVocab":
        obj = cls.__new__(cls)
        obj.itos = d["itos"]
        obj.stoi = {c: i for i, c in enumerate(obj.itos)}
        return obj


def _build_model(torch, vocab_size: int, cfg: dict):
    """Construct the character-level LSTM model."""
    import torch.nn as nn

    class CharLSTM(nn.Module):
        def __init__(self, vocab, embed, hidden, layers):
            super().__init__()
            self.embed = nn.Embedding(vocab, embed, padding_idx=0)
            self.lstm = nn.LSTM(embed, hidden, layers, batch_first=True)
            self.head = nn.Linear(hidden, vocab)

        def forward(self, x, state=None):
            e = self.embed(x)
            out, state = self.lstm(e, state)
            return self.head(out), state

    return CharLSTM(
        vocab_size,
        int(cfg.get("embed", 64)),
        int(cfg.get("hidden", 256)),
        int(cfg.get("layers", 2)),
    )


def train_model(
    words: list[str],
    out_path: str,
    epochs: int = 5,
    batch_size: int = 256,
    max_len: int = 32,
    embed: int = 64,
    hidden: int = 256,
    layers: int = 2,
    lr: float = 2e-3,
    compute_mode: str = "auto",
    seed: int = 0,
) -> dict:
    """Train a character-level LSTM and save it.

    Args:
        words: Training passwords.
        out_path: Destination model file (.pt).
        epochs: Number of training epochs.
        batch_size: Mini-batch size.
        max_len: Maximum password length used for training.
        embed: Embedding dimension.
        hidden: LSTM hidden size.
        layers: Number of LSTM layers.
        lr: Learning rate.
        compute_mode: Compute backend selector.
        seed: RNG seed (0 = nondeterministic).

    Returns:
        Training statistics dict.
    """
    torch = _require_torch()
    import torch.nn as nn

    if seed:
        torch.manual_seed(seed)

    words = [w[:max_len] for w in words if w]
    if not words:
        raise ValueError("no training data")

    vocab = CharVocab.from_words(words)
    device = _select_device(torch, compute_mode)
    cfg = {"embed": embed, "hidden": hidden, "layers": layers, "max_len": max_len}
    model = _build_model(torch, len(vocab), cfg).to(device)
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    loss_fn = nn.CrossEntropyLoss(ignore_index=vocab.pad)

    encoded = [vocab.encode(w) for w in words]

    def _make_batch(rows: list[list[int]]):
        width = max(len(r) for r in rows) + 2
        xb = torch.full((len(rows), width), vocab.pad, dtype=torch.long)
        yb = torch.full((len(rows), width), vocab.pad, dtype=torch.long)
        for i, r in enumerate(rows):
            seq = [vocab.bos] + r + [vocab.eos]
            for j in range(len(seq) - 1):
                xb[i, j] = seq[j]
                yb[i, j] = seq[j + 1]
        return xb.to(device), yb.to(device)

    model.train()
    last_loss = 0.0
    steps = 0
    for _epoch in range(epochs):
        import random
        random.shuffle(encoded)
        for start in range(0, len(encoded), batch_size):
            rows = [r for r in encoded[start : start + batch_size] if r]
            if not rows:
                continue
            xb, yb = _make_batch(rows)
            opt.zero_grad()
            logits, _ = model(xb)
            loss = loss_fn(logits.reshape(-1, len(vocab)), yb.reshape(-1))
            loss.backward()
            opt.step()
            last_loss = float(loss.item())
            steps += 1

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    torch.save(
        {
            "state_dict": model.state_dict(),
            "vocab": vocab.to_dict(),
            "config": cfg,
            "model_type": "lstm",
        },
        str(out),
    )
    return {
        "words": len(words),
        "vocab": len(vocab),
        "epochs": epochs,
        "steps": steps,
        "final_loss": round(last_loss, 4),
        "device": str(device),
        "output": str(out),
    }


def _load_model(torch, model_path: str, compute_mode: str):
    """Load a trained LSTM model and its vocabulary."""
    ckpt = torch.load(model_path, map_location="cpu", weights_only=False)
    vocab = CharVocab.from_dict(ckpt["vocab"])
    cfg = ckpt["config"]
    device = _select_device(torch, compute_mode)
    model = _build_model(torch, len(vocab), cfg).to(device)
    model.load_state_dict(ckpt["state_dict"])
    model.eval()
    return model, vocab, device, cfg


def _mask_allowed_indices(vocab: CharVocab, klass: str) -> Optional[list[int]]:
    """Return the vocab indices allowed for a mask class, or None for free."""
    chars = _MASK_CLASSES.get(klass)
    if chars is None:
        return None
    idx = [vocab.stoi[c] for c in chars if c in vocab.stoi]
    return idx or None


def generate(
    model_path: str,
    count: int,
    temperature: float = 1.0,
    prefix: str = "",
    mask: str = "",
    max_len: int = 32,
    compute_mode: str = "auto",
    seed: int = 0,
    dedupe: bool = True,
) -> Generator[str, None, None]:
    """Sample passwords from a trained model.

    Args:
        model_path: Path to a trained .pt model.
        count: Number of candidates to emit.
        temperature: Sampling temperature (higher = more diverse).
        prefix: Fixed prefix for guided generation.
        mask: Hashcat-style mask constraining each position (guided generation).
        max_len: Maximum candidate length.
        compute_mode: Compute backend selector.
        seed: RNG seed (0 = nondeterministic).
        dedupe: Suppress duplicate candidates.

    Yields:
        Generated password candidates.
    """
    torch = _require_torch()
    if seed:
        torch.manual_seed(seed)
    model, vocab, device, cfg = _load_model(torch, model_path, compute_mode)

    mask_tokens: list[str] = []
    if mask:
        i = 0
        while i < len(mask):
            if mask[i] == "?" and i + 1 < len(mask):
                mask_tokens.append(mask[i + 1])
                i += 2
            else:
                mask_tokens.append("=" + mask[i])  # literal
                i += 1

    seen: set[str] = set()
    emitted = 0
    attempts = 0
    max_attempts = count * 40 + 100

    with torch.no_grad():
        while emitted < count and attempts < max_attempts:
            attempts += 1
            state = None
            chars: list[str] = []
            x = torch.tensor([[vocab.bos]], dtype=torch.long, device=device)
            # Warm the state with the prefix.
            for pch in prefix:
                if pch not in vocab.stoi:
                    continue
                chars.append(pch)
                _, state = model(x, state)
                x = torch.tensor([[vocab.stoi[pch]]], dtype=torch.long, device=device)

            limit = len(mask_tokens) if mask_tokens else max_len
            pos = len(chars)
            while len(chars) < limit:
                logits, state = model(x, state)
                logits = logits[0, -1] / max(1e-6, temperature)

                allowed: Optional[list[int]] = None
                if mask_tokens:
                    if pos >= len(mask_tokens):
                        break
                    tok = mask_tokens[pos]
                    if tok.startswith("="):
                        literal = tok[1:]
                        chars.append(literal)
                        nxt = vocab.stoi.get(literal, vocab.eos)
                        x = torch.tensor([[nxt]], dtype=torch.long, device=device)
                        pos += 1
                        continue
                    allowed = _mask_allowed_indices(vocab, tok)

                probs = torch.softmax(logits, dim=-1)
                if allowed is not None:
                    mask_vec = torch.zeros_like(probs)
                    mask_vec[allowed] = 1.0
                    probs = probs * mask_vec
                    if float(probs.sum()) <= 0:
                        probs = mask_vec
                    probs = probs / probs.sum()
                else:
                    # Do not sample PAD or BOS.
                    probs[vocab.pad] = 0.0
                    probs[vocab.bos] = 0.0
                    if not mask_tokens:
                        pass  # EOS allowed to end the word
                    probs = probs / probs.sum()

                nxt_idx = int(torch.multinomial(probs, 1).item())
                if nxt_idx == vocab.eos and not mask_tokens:
                    break
                if nxt_idx in (vocab.pad, vocab.bos, vocab.eos):
                    break
                ch = vocab.itos[nxt_idx]
                chars.append(ch)
                x = torch.tensor([[nxt_idx]], dtype=torch.long, device=device)
                pos += 1

            candidate = "".join(chars)
            if not candidate:
                continue
            if dedupe:
                if candidate in seen:
                    continue
                seen.add(candidate)
            emitted += 1
            yield candidate


def dpg_adapt(
    model_path: str,
    recovered: list[str],
    out_path: str,
    steps: int = 200,
    lr: float = 1e-3,
    compute_mode: str = "auto",
) -> dict:
    """Adapt a model toward a set of recovered passwords (Dynamic Password Guessing).

    Performs a short online fine-tune so subsequent sampling is biased toward the
    distribution of already recovered passwords.

    Args:
        model_path: Path to the base model.
        recovered: Passwords recovered so far (the adaptation target).
        out_path: Destination for the adapted model.
        steps: Number of fine-tune steps.
        lr: Learning rate.
        compute_mode: Compute backend selector.

    Returns:
        Adaptation statistics dict.
    """
    torch = _require_torch()
    import torch.nn as nn

    model, vocab, device, cfg = _load_model(torch, model_path, compute_mode)
    recovered = [w[: cfg.get("max_len", 32)] for w in recovered if w]
    if not recovered:
        raise ValueError("no recovered passwords for adaptation")

    opt = torch.optim.Adam(model.parameters(), lr=lr)
    loss_fn = nn.CrossEntropyLoss(ignore_index=vocab.pad)
    encoded = [vocab.encode(w) for w in recovered]
    model.train()

    import random
    last_loss = 0.0
    for _ in range(steps):
        rows = random.sample(encoded, min(64, len(encoded)))
        rows = [r for r in rows if r]
        if not rows:
            continue
        width = max(len(r) for r in rows) + 2
        xb = torch.full((len(rows), width), vocab.pad, dtype=torch.long)
        yb = torch.full((len(rows), width), vocab.pad, dtype=torch.long)
        for i, r in enumerate(rows):
            seq = [vocab.bos] + r + [vocab.eos]
            for j in range(len(seq) - 1):
                xb[i, j] = seq[j]
                yb[i, j] = seq[j + 1]
        xb, yb = xb.to(device), yb.to(device)
        opt.zero_grad()
        logits, _ = model(xb)
        loss = loss_fn(logits.reshape(-1, len(vocab)), yb.reshape(-1))
        loss.backward()
        opt.step()
        last_loss = float(loss.item())

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    torch.save(
        {
            "state_dict": model.state_dict(),
            "vocab": vocab.to_dict(),
            "config": cfg,
            "model_type": "lstm",
        },
        str(out),
    )
    return {"recovered": len(recovered), "steps": steps,
            "final_loss": round(last_loss, 4), "output": str(out)}


def generate_hf(
    model_name: str,
    count: int,
    temperature: float = 1.0,
    prefix: str = "",
    max_len: int = 32,
    compute_mode: str = "auto",
) -> Generator[str, None, None]:
    """Generate candidates from a HuggingFace causal LM adapter (for example PassGPT).

    Args:
        model_name: HuggingFace model id or local path.
        count: Number of candidates to emit.
        temperature: Sampling temperature.
        prefix: Optional prefix seed.
        max_len: Maximum new tokens.
        compute_mode: Compute backend selector.

    Yields:
        Generated password candidates.
    """
    torch = _require_torch()
    try:
        from transformers import AutoModelForCausalLM, AutoTokenizer
    except ImportError as exc:
        raise RuntimeError(
            "PassGPT adapter requires 'transformers'. Install with "
            "pip install wordlistxpl-forge[neural]"
        ) from exc

    device = _select_device(torch, compute_mode)
    tok = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForCausalLM.from_pretrained(model_name).to(device)
    model.eval()

    seed_text = prefix or (tok.bos_token or "")
    seen: set[str] = set()
    emitted = 0
    with torch.no_grad():
        while emitted < count:
            enc = tok(seed_text, return_tensors="pt").to(device)
            out = model.generate(
                **enc,
                do_sample=True,
                temperature=max(1e-6, temperature),
                max_new_tokens=max_len,
                num_return_sequences=min(64, count - emitted),
                pad_token_id=tok.pad_token_id or tok.eos_token_id,
            )
            for row in out:
                text = tok.decode(row, skip_special_tokens=True).strip()
                if not text or text in seen:
                    continue
                seen.add(text)
                emitted += 1
                yield text
                if emitted >= count:
                    break


def handle_neural(args, ctx: dict):
    """CLI handler for the ``neural`` command.

    Args:
        args: Parsed CLI arguments.
        ctx: Global execution context.

    Returns:
        A tuple (kind, payload). kind is 'status' with an iterable of lines, or
        'stream' with a generator of candidates, or None on error.
    """
    action = getattr(args, "neural_action", "generate")
    compute_mode = ctx.get("compute_mode", "auto")

    try:
        if action == "train":
            wl = getattr(args, "wordlist", None)
            if not wl:
                logger.error("neural train requires --wordlist FILE")
                return None
            words: list[str] = []
            max_lines = int(getattr(args, "max_lines", 0) or 0)
            for src in wl:
                p = Path(src)
                if not p.exists():
                    logger.warning("file not found: %s", src)
                    continue
                with p.open("r", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        w = line.rstrip("\n\r")
                        if w:
                            words.append(w)
                        if max_lines and len(words) >= max_lines:
                            break
            stats = train_model(
                words,
                out_path=getattr(args, "model", ".model/neural_lstm.pt"),
                epochs=int(getattr(args, "epochs", 5) or 5),
                batch_size=int(getattr(args, "batch_size", 256) or 256),
                max_len=int(getattr(args, "max_len", 32) or 32),
                embed=int(getattr(args, "embed", 64) or 64),
                hidden=int(getattr(args, "hidden", 256) or 256),
                layers=int(getattr(args, "layers", 2) or 2),
                compute_mode=compute_mode,
                seed=int(getattr(args, "seed", 0) or 0),
            )
            lines = [
                "Neural training complete:",
                f"  Words        : {stats['words']:,}",
                f"  Vocab        : {stats['vocab']}",
                f"  Epochs       : {stats['epochs']}",
                f"  Steps        : {stats['steps']:,}",
                f"  Final loss   : {stats['final_loss']}",
                f"  Device       : {stats['device']}",
                f"  Model        : {stats['output']}",
            ]
            return ("status", iter(lines))

        # generate
        adapter = getattr(args, "adapter", None)
        count = int(getattr(args, "count", 10000) or 10000)
        temperature = float(getattr(args, "temperature", 1.0) or 1.0)
        prefix = getattr(args, "prefix", "") or ""
        mask = getattr(args, "mask", "") or ""
        max_len = int(getattr(args, "max_len", 32) or 32)
        seed = int(getattr(args, "seed", 0) or 0)

        if adapter == "passgpt" or adapter == "hf":
            model_name = getattr(args, "model", None)
            if not model_name:
                logger.error("adapter requires --model NAME_OR_PATH")
                return None
            gen = generate_hf(model_name, count, temperature, prefix, max_len,
                              compute_mode)
            return ("stream", gen)

        model_path = getattr(args, "model", ".model/neural_lstm.pt")
        if not Path(model_path).exists():
            logger.error("model not found: %s (train first with 'neural train')",
                         model_path)
            return None

        adapt_file = getattr(args, "adapt", None)
        if adapt_file:
            recovered: list[str] = []
            ap = Path(adapt_file)
            if ap.exists():
                with ap.open("r", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        w = line.rstrip("\n\r")
                        if w:
                            recovered.append(w)
            adapted_path = str(Path(model_path).with_suffix(".dpg.pt"))
            dpg_adapt(model_path, recovered, adapted_path,
                      steps=int(getattr(args, "dpg_steps", 200) or 200),
                      compute_mode=compute_mode)
            model_path = adapted_path

        gen = generate(model_path, count, temperature, prefix, mask, max_len,
                       compute_mode, seed, dedupe=not getattr(args, "no_dedupe", False))
        return ("stream", gen)

    except RuntimeError as exc:
        logger.error(str(exc))
        return None
    except Exception as exc:  # noqa: BLE001
        logger.error("neural error: %s", exc)
        return None
