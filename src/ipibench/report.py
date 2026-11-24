"""Aggregate raw model outputs into metrics, markdown tables and figures."""

from __future__ import annotations

import json
import math
import re
from pathlib import Path

import pandas as pd

from .data.attacks import GOALS, TECHNIQUES
from .defenses import DEFENSES
from .judge import judge
from .runner import load_raw

SURFACE, INK, MUTED, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
SERIES = ["#2a78d6", "#eb6834", "#1baf7a"]


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (math.nan, math.nan)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def judged_frame(samples: list[dict], results_dir: str | Path) -> pd.DataFrame:
    by_id = {s["id"]: s for s in samples}
    rows = []
    for r in load_raw(results_dir):
        s = by_id.get(r["id"])
        if s is None or r.get("error"):
            continue
        j = judge(s, r["response"])
        rows.append({"model": r["model"], "defense": r["defense"], "id": s["id"], "injected": s["injected"],
                     "carrier": s["carrier"], "technique": s["technique"], "goal": s["goal"],
                     "wrapper": s["wrapper"], "position": s["position"], **j})
    return pd.DataFrame(rows)


def _order(values, preferred):
    return [v for v in preferred if v in set(values)] + sorted(set(values) - set(preferred))


def _pct(x: float) -> str:
    return "-" if pd.isna(x) else f"{100 * x:.1f}"


def md_table(df: pd.DataFrame, index_name: str) -> str:
    cols = [index_name] + [str(c) for c in df.columns]
    lines = ["| " + " | ".join(cols) + " |", "|" + "|".join(["---"] + [":-:"] * len(df.columns)) + "|"]
    for idx, row in df.iterrows():
        lines.append("| " + " | ".join([str(idx)] + [str(v) for v in row.values]) + " |")
    return "\n".join(lines)


def summarize(df: pd.DataFrame) -> dict:
    inj, clean = df[df.injected], df[~df.injected]
    defenses = _order(df.defense.unique(), DEFENSES)
    models = sorted(df.model.unique())

    def asr(sub):
        return sub.attack_success.astype(float).mean()

    main = {}
    for m in models:
        for d in defenses:
            a = inj[(inj.model == m) & (inj.defense == d)]
            c = clean[(clean.model == m) & (clean.defense == d)]
            k, n = int(a.attack_success.sum()), len(a)
            lo, hi = wilson(k, n)
            main[(m, d)] = {"asr": k / n if n else math.nan, "asr_lo": lo, "asr_hi": hi, "n_inj": n,
                            "util_attacked": a.utility.mean() if n else math.nan,
                            "util_clean": c.utility.mean() if len(c) else math.nan, "n_clean": len(c)}
    pooled = {}
    for d in defenses:
        a, c = inj[inj.defense == d], clean[clean.defense == d]
        k, n = int(a.attack_success.sum()), len(a)
        pooled[d] = {"asr": k / n if n else math.nan, "ci": wilson(k, n), "n": n,
                     "util_attacked": a.utility.mean(), "util_clean": c.utility.mean() if len(c) else math.nan,
                     "warned_clean": c.warned.mean() if len(c) else math.nan}
    return {"models": models, "defenses": defenses, "main": main, "pooled": pooled}


def _breakdown(inj: pd.DataFrame, col: str, order: list[str], defenses: list[str]) -> pd.DataFrame:
    t = inj.pivot_table(index=col, columns="defense", values="attack_success", aggfunc="mean")
    t = t.reindex(index=_order(t.index, order), columns=[d for d in defenses if d in t.columns])
    return t.map(_pct)


def make_figures(df: pd.DataFrame, summary: dict, fig_dir: Path) -> list[Path]:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig_dir.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update({"font.size": 10, "axes.edgecolor": GRID, "axes.labelcolor": MUTED, "xtick.color": MUTED,
                         "ytick.color": MUTED, "text.color": INK, "figure.facecolor": SURFACE,
                         "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE})
    paths = []
    models, defenses = summary["models"], summary["defenses"]

    # 1. heatmap: ASR by model x defense (sequential single hue)
    grid = [[summary["main"][(m, d)]["asr"] * 100 for d in defenses] for m in models]
    fig, ax = plt.subplots(figsize=(1.25 * len(defenses) + 2.2, 0.6 * len(models) + 1.6))
    im = ax.imshow(grid, cmap="Blues", vmin=0, vmax=100, aspect="auto")
    for i, row in enumerate(grid):
        for j, v in enumerate(row):
            ax.text(j, i, "-" if math.isnan(v) else f"{v:.0f}%", ha="center", va="center",
                    color="white" if v > 55 else INK, fontsize=10)
    ax.set_xticks(range(len(defenses)), defenses)
    ax.set_yticks(range(len(models)), models)
    ax.tick_params(length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.set_title("Attack success rate by model and defense", loc="left", fontsize=12, color=INK)
    cb = fig.colorbar(im, ax=ax, fraction=0.03, pad=0.02)
    cb.outline.set_visible(False)
    cb.set_label("ASR (%)")
    fig.tight_layout()
    p = fig_dir / "asr_heatmap.png"
    fig.savefig(p, dpi=180)
    plt.close(fig)
    paths.append(p)

    # 2. grouped bars: ASR by technique, baseline vs strongest defense (pooled over models)
    inj = df[df.injected]
    best = min((d for d in defenses if d != "none"), key=lambda d: summary["pooled"][d]["asr"], default=None)
    series = [d for d in ["none", best] if d]
    techs = _order(inj.technique.dropna().unique(), TECHNIQUES)
    fig, ax = plt.subplots(figsize=(9, 3.8))
    width = 0.8 / len(series)
    for k, d in enumerate(series):
        vals = [inj[(inj.defense == d) & (inj.technique == t)].attack_success.mean() * 100 for t in techs]
        xs = [i + (k - (len(series) - 1) / 2) * width for i in range(len(techs))]
        ax.bar(xs, vals, width=width - 0.04, color=SERIES[k], label=d, edgecolor=SURFACE, linewidth=1)
    ax.set_xticks(range(len(techs)), [t.replace("_", "\n") for t in techs])
    ax.set_ylabel("ASR (%)")
    ax.set_ylim(0, 100)
    ax.grid(axis="y", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)
    ax.tick_params(length=0)
    ax.legend(frameon=False, loc="upper left", ncol=len(series))
    ax.set_title("Attack success by injection technique (all models pooled)", loc="left", fontsize=12, color=INK)
    fig.tight_layout()
    p = fig_dir / "asr_by_technique.png"
    fig.savefig(p, dpi=180)
    plt.close(fig)
    paths.append(p)
    return paths


def build_report(samples: list[dict], results_dir: str | Path, detector_metrics: dict | None = None) -> str:
    results_dir = Path(results_dir)
    df = judged_frame(samples, results_dir)
    if df.empty:
        raise SystemExit(f"no results found in {results_dir}/raw - run `ipibench run` first")
    df.to_csv(results_dir / "judged.csv", index=False)
    s = summarize(df)
    figs = make_figures(df, s, results_dir / "figures")
    models, defenses, main, pooled = s["models"], s["defenses"], s["main"], s["pooled"]
    mock_only = all(m.startswith("mock") for m in models)

    out = ["# Results", ""]
    if mock_only:
        out += ["> **Warning:** these numbers come from the `mock` model and only test the pipeline. "
                "They are not experimental results.", ""]
    n_inj = pooled[defenses[0]]["n"] // max(1, len(models))
    out += [f"Models: {', '.join(models)} · injected samples per model/defense: {n_inj} · "
            "ASR = attack success rate (lower is better) · Utility = the reply still contains the correct key fact.", ""]

    if "none" in pooled:
        best = min((d for d in defenses if d != "none"), key=lambda d: pooled[d]["asr"], default=None)
        if best:
            b, w = pooled["none"], pooled[best]
            out += [f"**Headline:** pooled ASR drops from **{_pct(b['asr'])}%** (no defense) to "
                    f"**{_pct(w['asr'])}%** with `{best}` (95% CI {_pct(w['ci'][0])}-{_pct(w['ci'][1])}%), "
                    f"while clean-task utility goes from {_pct(b['util_clean'])}% to {_pct(w['util_clean'])}%.", ""]

    t = pd.DataFrame({d: [_pct(main[(m, d)]["asr"]) for m in models] for d in defenses}, index=models)
    out += ["## Attack success rate (%) by model and defense", "", md_table(t, "model"), ""]

    rows = {}
    for d in defenses:
        p = pooled[d]
        rows[d] = [_pct(p["asr"]), f"{_pct(p['ci'][0])}-{_pct(p['ci'][1])}", _pct(p["util_attacked"]),
                   _pct(p["util_clean"]), _pct(p["warned_clean"])]
    t = pd.DataFrame(rows, index=["ASR", "ASR 95% CI", "Utility under attack", "Utility on clean docs",
                                  "False alarm on clean docs"]).T
    out += ["## Defense summary (all models pooled, %)", "", md_table(t, "defense"), ""]

    t = pd.DataFrame({d: [_pct(main[(m, d)]["util_clean"]) for m in models] for d in defenses}, index=models)
    out += ["## Clean-document utility (%) by model and defense", "", md_table(t, "model"), ""]

    inj = df[df.injected]
    out += ["## ASR (%) by injection technique", "", md_table(_breakdown(inj, "technique", TECHNIQUES, defenses), "technique"), ""]
    out += ["## ASR (%) by attacker goal", "", md_table(_breakdown(inj, "goal", GOALS, defenses), "goal"), ""]
    out += ["## ASR (%) by carrier", "", md_table(_breakdown(inj, "carrier", ["log", "email", "web"], defenses), "carrier"), ""]
    out += ["## ASR (%) by injection position", "", md_table(_breakdown(inj, "position", ["start", "middle", "end"], defenses), "position"), ""]

    if detector_metrics:
        dm = detector_metrics
        out += ["## Detector (test split, line level)", "",
                f"precision {_pct(dm['line_precision'])}% · recall {_pct(dm['line_recall'])}% · "
                f"F1 {_pct(dm['line_f1'])}% · AUC {dm['line_auc']:.3f} · "
                f"payload fully removed in {_pct(dm['doc_full_removal_rate'])}% of injected docs · "
                f"false positive on {_pct(dm['clean_doc_false_positive_rate'])}% of clean docs", ""]

    out += ["## Figures", ""] + [f"![{p.stem}](figures/{p.name})" for p in figs] + [""]
    md = "\n".join(out)
    (results_dir / "summary.md").write_text(md, encoding="utf-8")
    (results_dir / "summary.json").write_text(json.dumps(
        {"pooled": {d: {k: (list(v) if isinstance(v, tuple) else v) for k, v in p.items()} for d, p in pooled.items()},
         "by_model": {f"{m}|{d}": v for (m, d), v in main.items()}}, indent=2, default=float), encoding="utf-8")
    return md


def update_readme(readme: Path, summary_md: str, results_rel: str = "results") -> None:
    start, end = "<!-- RESULTS:START -->", "<!-- RESULTS:END -->"
    text = readme.read_text(encoding="utf-8")
    if start not in text:
        return
    body = summary_md.split("\n", 1)[1].replace("](figures/", f"]({results_rel}/figures/")
    body = re.sub(r"^## ", "### ", body, flags=re.M)
    new = text.split(start)[0] + start + "\n" + body.strip() + "\n" + end + text.split(end)[1]
    readme.write_text(new, encoding="utf-8")
