"""Line-level prompt-injection detection classifier.

Default backend: TF-IDF (word 1-2 grams + char 3-5 grams) + logistic regression, trained on the
``train`` split only (disjoint scenarios and paraphrases). The decision threshold is picked on
out-of-fold predictions grouped by document, so it is never tuned on test data.

Optional backend ``hf``: any Hugging Face text-classification model, e.g.
``protectai/deberta-v3-base-prompt-injection-v2`` (install with ``pip install -e .[hf]``).
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import joblib
import numpy as np

from .defenses import REMOVED


def line_dataset(samples: list[dict]) -> tuple[list[str], np.ndarray, np.ndarray]:
    texts, labels, groups = [], [], []
    for gi, s in enumerate(samples):
        inj = set(s["injected_lines"])
        for i, line in enumerate(s["document"].split("\n")):
            if not line.strip():
                continue
            texts.append(line)
            labels.append(int(i in inj))
            groups.append(gi)
    return texts, np.array(labels), np.array(groups)


def _make_pipeline():
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import FeatureUnion, Pipeline

    features = FeatureUnion(
        [
            ("word", TfidfVectorizer(analyzer="word", ngram_range=(1, 2), min_df=2, sublinear_tf=True)),
            ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, sublinear_tf=True, max_features=200_000)),
        ]
    )
    clf = LogisticRegression(C=4.0, class_weight="balanced", max_iter=2000)
    return Pipeline([("features", features), ("clf", clf)])


class InjectionDetector:
    def __init__(self, backend: str = "tfidf", model=None, threshold: float = 0.5, neighbor_factor: float = 0.5,
                 hf_model: str | None = None):
        self.backend = backend
        self.model = model
        self.threshold = threshold
        self.neighbor_factor = neighbor_factor
        self.hf_model = hf_model
        self._hf = None

    # ----------------------------------------------------------------- scoring
    def score_lines(self, lines: list[str]) -> np.ndarray:
        scores = np.zeros(len(lines))
        idx = [i for i, line in enumerate(lines) if line.strip()]
        if not idx:
            return scores
        texts = [lines[i] for i in idx]
        if self.backend == "tfidf":
            scores[idx] = self.model.predict_proba(texts)[:, 1]
        elif self.backend == "hf":
            scores[idx] = self._hf_scores(texts)
        else:
            raise ValueError(self.backend)
        return scores

    def _hf_scores(self, texts: list[str]) -> np.ndarray:
        if self._hf is None:
            from transformers import pipeline

            self._hf = pipeline("text-classification", model=self.hf_model, truncation=True, max_length=512)
        out = self._hf(texts, batch_size=16)
        res = []
        for o in out:
            label = o["label"].upper()
            positive = "INJECTION" in label or label in {"LABEL_1", "UNSAFE", "JAILBREAK"}
            res.append(o["score"] if positive else 1 - o["score"])
        return np.array(res)

    def flag(self, lines: list[str]) -> list[int]:
        scores = self.score_lines(lines)
        flagged = set(np.where(scores >= self.threshold)[0].tolist())
        # Multi-line payloads: also drop adjacent lines that are moderately suspicious.
        low = self.threshold * self.neighbor_factor
        changed = True
        while changed:
            changed = False
            for i in list(flagged):
                for j in (i - 1, i + 1):
                    if 0 <= j < len(lines) and j not in flagged and scores[j] >= low:
                        flagged.add(j)
                        changed = True
        return sorted(flagged)

    def sanitize(self, document: str) -> tuple[str, list[int]]:
        lines = document.split("\n")
        flagged = set(self.flag(lines))
        out, prev_removed = [], False
        for i, line in enumerate(lines):
            if i in flagged:
                if not prev_removed:
                    out.append(REMOVED)
                prev_removed = True
            else:
                out.append(line)
                prev_removed = False
        return "\n".join(out), sorted(flagged)

    # ----------------------------------------------------------------- persistence
    def save(self, path: str | Path) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"backend": self.backend, "model": self.model, "threshold": self.threshold,
                     "neighbor_factor": self.neighbor_factor, "hf_model": self.hf_model}, path)

    @classmethod
    def load(cls, path: str | Path) -> InjectionDetector:
        d = joblib.load(path)
        return cls(**d)


def train_tfidf(train_samples: list[dict], seed: int = 0) -> tuple[InjectionDetector, dict]:
    from sklearn.metrics import precision_recall_curve, roc_auc_score
    from sklearn.model_selection import GroupKFold

    texts, y, groups = line_dataset(train_samples)
    oof = np.zeros(len(texts))
    for tr, va in GroupKFold(n_splits=5).split(texts, y, groups):
        m = _make_pipeline().fit([texts[i] for i in tr], y[tr])
        oof[va] = m.predict_proba([texts[i] for i in va])[:, 1]
    prec, rec, thr = precision_recall_curve(y, oof)
    f1 = 2 * prec * rec / np.clip(prec + rec, 1e-9, None)
    # When the train data separates (almost) perfectly, a wide range of thresholds ties for
    # the best F1; take the middle of that plateau rather than its fragile lower edge.
    f1 = f1[:-1]
    plateau = thr[f1 >= f1.max() - 0.005]
    threshold = float(np.clip(np.median(plateau), 0.5, 0.95))
    best = int(np.argmax(f1))
    model = _make_pipeline().fit(texts, y)
    info = {"train_lines": len(texts), "train_pos": int(y.sum()), "oof_auc": float(roc_auc_score(y, oof)),
            "oof_f1": float(f1[best]), "threshold": threshold}
    return InjectionDetector("tfidf", model, threshold), info


def evaluate(detector: InjectionDetector, samples: list[dict]) -> dict:
    from sklearn.metrics import precision_recall_fscore_support, roc_auc_score

    texts, y, groups = line_dataset(samples)
    # score per document so neighbour expansion is applied exactly as at inference time
    pred = np.zeros(len(texts), dtype=int)
    scores = np.zeros(len(texts))
    pos = 0
    doc_rows = []
    by_tech = defaultdict(lambda: [0, 0])
    for s in samples:
        lines = s["document"].split("\n")
        sc = detector.score_lines(lines)
        flagged = set(detector.flag(lines))
        inj = set(s["injected_lines"])
        nonempty = [i for i, line in enumerate(lines) if line.strip()]
        for i in nonempty:
            pred[pos] = int(i in flagged)
            scores[pos] = sc[i]
            pos += 1
        inj_nonempty = {i for i in inj if lines[i].strip()}
        detected = bool(flagged & inj_nonempty)
        fully = inj_nonempty <= flagged if inj_nonempty else False
        doc_rows.append((s["injected"], detected, fully, bool(flagged - inj)))
        if s["injected"]:
            by_tech[s["technique"]][0] += int(fully)
            by_tech[s["technique"]][1] += 1
    p, r, f, _ = precision_recall_fscore_support(y, pred, average="binary", zero_division=0)
    inj_docs = [d for d in doc_rows if d[0]]
    clean_docs = [d for d in doc_rows if not d[0]]
    return {
        "threshold": detector.threshold,
        "line_precision": float(p),
        "line_recall": float(r),
        "line_f1": float(f),
        "line_auc": float(roc_auc_score(y, scores)) if len(set(y)) > 1 else None,
        "doc_detect_rate": float(np.mean([d[1] for d in inj_docs])) if inj_docs else None,
        "doc_full_removal_rate": float(np.mean([d[2] for d in inj_docs])) if inj_docs else None,
        "clean_doc_false_positive_rate": float(np.mean([d[3] for d in clean_docs])) if clean_docs else None,
        "full_removal_by_technique": {k: v[0] / v[1] for k, v in sorted(by_tech.items())},
        "n_injected_docs": len(inj_docs),
        "n_clean_docs": len(clean_docs),
    }
