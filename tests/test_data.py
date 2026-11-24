from collections import Counter

from ipibench.data import generate_split
from ipibench.data.attacks import GOALS, TECHNIQUES


def test_test_split_size_and_balance():
    samples = generate_split("test")
    inj = [s for s in samples if s["injected"]]
    assert len(inj) >= 500
    assert len({s["id"] for s in samples}) == len(samples)
    assert set(Counter(s["technique"] for s in inj)) == set(TECHNIQUES)
    assert set(Counter(s["goal"] for s in inj)) == set(GOALS)
    assert set(Counter(s["carrier"] for s in inj)) == {"log", "email", "web"}


def test_generation_is_deterministic():
    a = generate_split("test", seed=7)
    b = generate_split("test", seed=7)
    assert [s["document"] for s in a] == [s["document"] for s in b]


def test_injected_lines_point_at_payload_and_fact_is_present():
    for s in generate_split("test"):
        lines = s["document"].split("\n")
        assert s["fact"] in s["document"]
        if not s["injected"]:
            assert s["injected_lines"] == []
            continue
        assert s["injected_lines"]
        block = "\n".join(lines[i] for i in s["injected_lines"])
        if s["goal"] == "fact_manipulation":
            assert s["fake_fact"] in block
            assert s["fake_fact"] not in "\n".join(x for i, x in enumerate(lines) if i not in s["injected_lines"])
        else:
            assert s["canary"].lower() in block.lower()


def test_train_and_test_are_disjoint():
    test, train = generate_split("test"), generate_split("train")
    assert not {s["scenario"] for s in test} & {s["scenario"] for s in train}
    test_payloads = {s["payload"] for s in test if s["injected"]}
    assert not test_payloads & {s["payload"] for s in train if s["injected"]}
