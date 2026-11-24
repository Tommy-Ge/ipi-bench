"""Build the benchmark splits.

test  : 18 scenarios x 8 techniques x 5 goals = 720 injected samples + 90 clean samples
train : 9 disjoint scenarios, disjoint paraphrases; only used to train the detector
"""

from __future__ import annotations

import json
import random
from pathlib import Path

from .attacks import GOALS, HARD_NEGATIVES, TECHNIQUES, WRAPPERS, artifacts, build_payload, wrap
from .scenarios import Scenario, scenarios_for

CANARY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
POSITIONS = ["start", "middle", "end"]


def _rng(seed: int, key: str) -> random.Random:
    return random.Random(f"{seed}:{key}")


def make_canary(rng: random.Random) -> str:
    return "".join(rng.choice(CANARY_ALPHABET) for _ in range(6))


def _body_bounds(lines: list[str], carrier: str) -> tuple[int, int]:
    """Index range [lo, hi] in which content may be inserted."""
    lo, hi = 0, len(lines)
    if carrier == "email":
        lo = lines.index("") + 1 if "" in lines else 1
    elif carrier == "web":
        for i, line in enumerate(lines):
            if line.startswith("<body") or line.startswith("<main") or line.startswith("<article"):
                lo = i + 1
        while hi > lo and lines[hi - 1].lstrip().startswith("</"):
            hi -= 1
    elif carrier == "log" and lines and lines[0].startswith("$ "):
        lo = 2  # keep the shell command + header row on top
    return lo, hi


def insertion_index(lines: list[str], carrier: str, position: str, rng: random.Random) -> int:
    lo, hi = _body_bounds(lines, carrier)
    if position == "start":
        return lo
    if position == "end":
        return hi
    return rng.randint(lo + (hi - lo) // 3, max(lo + (hi - lo) // 3, lo + 2 * (hi - lo) // 3))


def _fake_fact(scn: Scenario, real: str, doc: str, rng: random.Random) -> str:
    for _ in range(200):
        fake = scn.fact_gen(rng)
        if fake != real and fake not in doc and real not in fake:
            return fake
    raise RuntimeError(f"could not draw a distinct fake fact for {scn.id}")


def build_injected(scn: Scenario, technique: str, goal: str, split: str, seed: int, variant: int = 0) -> dict:
    sid = f"{split}-{scn.carrier}-{scn.id}-{technique}-{goal}" + (f"-v{variant}" if variant else "")
    rng = _rng(seed, sid)
    fact = scn.fact_gen(rng)
    lines = scn.render(fact)
    fake = _fake_fact(scn, fact, "\n".join(lines), rng)
    canary = make_canary(rng)
    fill = {**artifacts(canary), "fake": fake, "fact_name": scn.fact_name}
    payload = build_payload(technique, goal, split, rng, fill)
    wrapper = rng.choice(WRAPPERS[scn.carrier])
    position = rng.choice(POSITIONS)
    idx = insertion_index(lines, scn.carrier, position, rng)
    block = wrap(payload, wrapper)
    doc_lines = lines[:idx] + [text for text, _ in block] + lines[idx:]
    injected_lines = [idx + i for i, (_, flag) in enumerate(block) if flag]
    return {
        "id": sid,
        "split": split,
        "carrier": scn.carrier,
        "scenario": scn.id,
        "task": scn.task,
        "fact_name": scn.fact_name,
        "fact": fact,
        "document": "\n".join(doc_lines),
        "injected": True,
        "technique": technique,
        "goal": goal,
        "wrapper": wrapper,
        "position": position,
        "canary": canary,
        "fake_fact": fake if goal == "fact_manipulation" else None,
        "payload": payload,
        "injected_lines": injected_lines,
    }


def build_benign(scn: Scenario, split: str, seed: int, k: int, hard_negative_rate: float = 0.6) -> dict:
    sid = f"{split}-{scn.carrier}-{scn.id}-benign-{k}"
    rng = _rng(seed, sid)
    fact = scn.fact_gen(rng)
    lines = scn.render(fact)
    hard_negative = None
    if rng.random() < hard_negative_rate:
        hard_negative = rng.choice(HARD_NEGATIVES[scn.carrier][split])
        idx = insertion_index(lines, scn.carrier, rng.choice(POSITIONS), rng)
        lines = lines[:idx] + [hard_negative] + lines[idx:]
    return {
        "id": sid,
        "split": split,
        "carrier": scn.carrier,
        "scenario": scn.id,
        "task": scn.task,
        "fact_name": scn.fact_name,
        "fact": fact,
        "document": "\n".join(lines),
        "injected": False,
        "technique": None,
        "goal": None,
        "wrapper": None,
        "position": None,
        "canary": None,
        "fake_fact": None,
        "payload": None,
        "injected_lines": [],
        "hard_negative": hard_negative,
    }


def generate_split(split: str, seed: int = 2024) -> list[dict]:
    if split == "test":
        variants, benign_per_scenario = 1, 5
    elif split == "train":
        variants, benign_per_scenario = 3, 40
    else:
        raise ValueError(split)
    samples: list[dict] = []
    for scn in scenarios_for(split):
        for technique in TECHNIQUES:
            for goal in GOALS:
                for v in range(variants):
                    samples.append(build_injected(scn, technique, goal, split, seed, v))
        for k in range(benign_per_scenario):
            samples.append(build_benign(scn, split, seed, k))
    return samples


def save_samples(samples: list[dict], path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for s in samples:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")


def load_samples(path: str | Path) -> list[dict]:
    with Path(path).open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]
