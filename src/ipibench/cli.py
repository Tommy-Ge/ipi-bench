"""Command line interface: ``ipibench {generate,train-detector,run,report,show,stats}``."""

from __future__ import annotations

import argparse
import asyncio
import json
from collections import Counter
from pathlib import Path

from .data import generate_split, load_samples, save_samples
from .defenses import DEFENSES, NEEDS_DETECTOR, get_defense


def cmd_generate(a):
    for split in ("test", "train"):
        samples = generate_split(split, seed=a.seed)
        path = Path(a.data) / f"ipi_{split}.jsonl"
        save_samples(samples, path)
        n_inj = sum(s["injected"] for s in samples)
        print(f"{split:5s}: {len(samples)} samples ({n_inj} injected, {len(samples) - n_inj} clean) -> {path}")


def cmd_stats(a):
    samples = load_samples(Path(a.data) / "ipi_test.jsonl")
    inj = [s for s in samples if s["injected"]]
    print(f"test split: {len(samples)} samples, {len(inj)} injected")
    for key in ("carrier", "technique", "goal", "wrapper", "position"):
        print(f"\n{key}:")
        for k, v in sorted(Counter(s[key] for s in inj).items()):
            print(f"  {k:20s} {v}")


def cmd_train_detector(a):
    from .detector import InjectionDetector, evaluate, train_tfidf

    test = load_samples(Path(a.data) / "ipi_test.jsonl")
    if a.backend == "tfidf":
        train = load_samples(Path(a.data) / "ipi_train.jsonl")
        det, info = train_tfidf(train)
        print("train (5-fold OOF):", json.dumps(info, indent=2))
    else:
        det = InjectionDetector("hf", hf_model=a.hf_model, threshold=a.threshold)
        info = {"hf_model": a.hf_model}
    if a.threshold is not None:
        det.threshold = a.threshold
    det.save(a.out)
    metrics = evaluate(det, test)
    metrics["train_info"] = info
    Path(a.results).mkdir(parents=True, exist_ok=True)
    (Path(a.results) / "detector_metrics.json").write_text(json.dumps(metrics, indent=2))
    print("test:", json.dumps(metrics, indent=2))
    print(f"saved detector -> {a.out}")


def _load_detector(path):
    from .detector import InjectionDetector

    if not Path(path).exists():
        raise SystemExit(f"detector not found at {path}; run `ipibench train-detector` first")
    return InjectionDetector.load(path)


def cmd_run(a):
    from .models import load_model_configs
    from .runner import run_one_config, stratified_subset

    cfgs = load_model_configs(a.config)
    unknown = [m for m in a.models if m not in cfgs]
    if unknown:
        raise SystemExit(f"unknown models {unknown}; defined in {a.config}: {list(cfgs)}")
    defenses = DEFENSES if a.defenses == ["all"] else a.defenses
    detector = _load_detector(a.detector) if set(defenses) & NEEDS_DETECTOR else None
    samples = stratified_subset(load_samples(Path(a.data) / "ipi_test.jsonl"), a.frac, seed=a.seed)
    print(f"{len(samples)} samples x {len(defenses)} defenses x {len(a.models)} models")

    async def main():
        for m in a.models:
            for d in defenses:
                out = await run_one_config(samples, cfgs[m], get_defense(d, detector), a.results, a.concurrency)
                print(f"done {m}/{d} -> {out}")

    asyncio.run(main())


def cmd_report(a):
    from .report import build_report, update_readme

    samples = load_samples(Path(a.data) / "ipi_test.jsonl")
    dm_path = Path(a.results) / "detector_metrics.json"
    dm = json.loads(dm_path.read_text()) if dm_path.exists() else None
    md = build_report(samples, a.results, dm)
    print(md)
    if a.update_readme:
        update_readme(Path(a.update_readme), md, results_rel=a.results.rstrip("/"))
        print(f"updated {a.update_readme}")


def cmd_show(a):
    samples = {s["id"]: s for s in load_samples(Path(a.data) / "ipi_test.jsonl")}
    if a.id not in samples:
        raise SystemExit(f"no sample {a.id!r}")
    detector = _load_detector(a.detector) if a.defense in NEEDS_DETECTOR else None
    for msg in get_defense(a.defense, detector).build(samples[a.id]):
        print(f"===== {msg['role']} =====\n{msg['content']}\n")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="ipibench", description=__doc__)
    ap.add_argument("--data", default="data")
    ap.add_argument("--results", default="results")
    ap.add_argument("--detector", default="artifacts/detector.joblib")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("generate", help="build data/ipi_test.jsonl and data/ipi_train.jsonl")
    p.add_argument("--seed", type=int, default=2024)
    p.set_defaults(fn=cmd_generate)

    p = sub.add_parser("stats", help="print dataset composition")
    p.set_defaults(fn=cmd_stats)

    p = sub.add_parser("train-detector", help="train + evaluate the injection classifier")
    p.add_argument("--backend", choices=["tfidf", "hf"], default="tfidf")
    p.add_argument("--hf-model", default="protectai/deberta-v3-base-prompt-injection-v2")
    p.add_argument("--threshold", type=float, default=None)
    p.add_argument("--out", default="artifacts/detector.joblib")
    p.set_defaults(fn=cmd_train_detector)

    p = sub.add_parser("run", help="query models under each defense")
    p.add_argument("--models", nargs="+", required=True)
    p.add_argument("--defenses", nargs="+", default=["all"], help=f"any of {DEFENSES} or 'all'")
    p.add_argument("--config", default="configs/models.yaml")
    p.add_argument("--frac", type=float, default=1.0, help="stratified fraction of the test split")
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--concurrency", type=int, default=None)
    p.set_defaults(fn=cmd_run)

    p = sub.add_parser("report", help="judge outputs and write results/summary.md + figures")
    p.add_argument("--update-readme", default=None, metavar="README.md")
    p.set_defaults(fn=cmd_report)

    p = sub.add_parser("show", help="print the exact prompt a sample gets under a defense")
    p.add_argument("id")
    p.add_argument("--defense", default="none", choices=DEFENSES)
    p.set_defaults(fn=cmd_show)

    a = ap.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
