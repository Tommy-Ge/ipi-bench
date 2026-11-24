"""Async evaluation runner with resumable JSONL output."""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import time
from collections import defaultdict
from pathlib import Path

from tqdm.asyncio import tqdm_asyncio

from .defenses import Defense
from .models import ModelConfig, make_client


def stratified_subset(samples: list[dict], frac: float, seed: int = 0) -> list[dict]:
    """Deterministic subset keeping the technique x goal (and clean-per-carrier) balance."""
    if frac >= 1.0:
        return list(samples)
    strata: dict[tuple, list[dict]] = defaultdict(list)
    for s in samples:
        key = (s["technique"], s["goal"]) if s["injected"] else ("clean", s["carrier"])
        strata[key].append(s)
    out = []
    for key in sorted(strata, key=str):
        group = sorted(strata[key], key=lambda s: hashlib.sha256(f"{seed}:{s['id']}".encode()).hexdigest())
        out.extend(group[: max(1, math.ceil(len(group) * frac))])
    return out


def raw_path(results_dir: str | Path, model: str, defense: str) -> Path:
    return Path(results_dir) / "raw" / f"{model}__{defense}.jsonl"


def _done_ids(path: Path) -> set[str]:
    if not path.exists():
        return set()
    done = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rec = json.loads(line)
            if not rec.get("error"):
                done.add(rec["id"])
    return done


async def run_one_config(samples: list[dict], cfg: ModelConfig, defense: Defense, results_dir: str | Path,
                         concurrency: int | None = None) -> Path:
    out = raw_path(results_dir, cfg.name, defense.name)
    out.parent.mkdir(parents=True, exist_ok=True)
    done = _done_ids(out)
    todo = [s for s in samples if s["id"] not in done]
    if not todo:
        return out
    client = make_client(cfg)
    sem = asyncio.Semaphore(concurrency or cfg.concurrency)
    lock = asyncio.Lock()

    async def one(sample: dict):
        prompt = defense.build_prompt(sample)
        messages = prompt.render()
        rec = {"id": sample["id"], "model": cfg.name, "defense": defense.name, "response": None, "error": None,
               "detector_flagged_lines": prompt.meta.get("detector_flagged_lines")}
        async with sem:
            t0 = time.perf_counter()
            try:
                rec["response"] = await client.complete(messages, meta=sample)
            except Exception as e:  # recorded and retried on the next run
                rec["error"] = f"{type(e).__name__}: {e}"[:500]
            rec["latency_s"] = round(time.perf_counter() - t0, 3)
        async with lock:
            with out.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    try:
        await tqdm_asyncio.gather(*(one(s) for s in todo), desc=f"{cfg.name}/{defense.name}", leave=False)
    finally:
        await client.aclose()
    return out


def load_raw(results_dir: str | Path) -> list[dict]:
    """Latest successful record per (model, defense, id)."""
    recs: dict[tuple, dict] = {}
    for p in sorted((Path(results_dir) / "raw").glob("*.jsonl")):
        for line in p.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            key = (r["model"], r["defense"], r["id"])
            if r.get("error") and key in recs and not recs[key].get("error"):
                continue
            recs[key] = r
    return list(recs.values())
