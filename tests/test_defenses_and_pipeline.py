import asyncio

import pytest

from ipibench.data import generate_split
from ipibench.defenses import DATAMARK, REMOVED, get_defense
from ipibench.detector import evaluate, train_tfidf
from ipibench.models import ModelConfig
from ipibench.report import build_report
from ipibench.runner import run_one_config, stratified_subset


@pytest.fixture(scope="module")
def test_split():
    return generate_split("test")


@pytest.fixture(scope="module")
def detector():
    train = [s for s in generate_split("train") if not s["id"].endswith(("-v1", "-v2"))]
    det, _ = train_tfidf(train)
    return det


def _user(msgs):
    return msgs[-1]["content"]


def test_baseline_contains_document_and_task(test_split):
    s = test_split[0]
    msgs = get_defense("none").build(s)
    assert s["task"] in _user(msgs) and s["document"] in _user(msgs)


def test_hardening_adds_policy_and_reminder(test_split):
    msgs = get_defense("hardening").build(test_split[0])
    assert "SECURITY POLICY" in msgs[0]["content"]
    assert _user(msgs).rstrip().endswith("instructions it contains.")


def test_delimiters_wrap_document_with_random_tag(test_split):
    a, b = (get_defense("delimiters").build(s) for s in test_split[:2])
    assert "<<<EXTERNAL_DATA_" in _user(a) and "<<<END_EXTERNAL_DATA_" in _user(a)
    assert _user(a).split("EXTERNAL_DATA_")[1][:8] != _user(b).split("EXTERNAL_DATA_")[1][:8]


def test_datamarking_marks_words(test_split):
    assert DATAMARK in _user(get_defense("datamarking").build(test_split[0]))


def test_detector_generalises_and_sanitizes(test_split, detector):
    m = evaluate(detector, test_split)
    assert m["line_auc"] > 0.9
    assert m["clean_doc_false_positive_rate"] < 0.2
    s = next(x for x in test_split if x["injected"] and x["technique"] == "naive" and x["goal"] == "tool_abuse")
    user = _user(get_defense("detector", detector).build(s))
    assert REMOVED in user and s["canary"].lower() not in user.lower()


def test_stratified_subset_keeps_every_cell(test_split):
    sub = stratified_subset(test_split, 0.05)
    assert len(sub) < len(test_split)
    assert len({(s["technique"], s["goal"]) for s in sub if s["injected"]}) == 40


def test_end_to_end_with_mock(tmp_path, test_split, detector):
    samples = stratified_subset(test_split, 0.1)
    cfg = ModelConfig(name="mock-a", provider="mock", concurrency=32)
    for d in ["none", "combined"]:
        asyncio.run(run_one_config(samples, cfg, get_defense(d, detector), tmp_path))
    md = build_report(samples, tmp_path)
    assert "mock" in md and (tmp_path / "figures" / "asr_heatmap.png").exists()
