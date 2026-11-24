PY ?= python
MODELS ?= gpt-4o llama-3.1-8b qwen2.5-7b
FRAC ?= 1.0

.PHONY: install data detector eval report mock test lint

install:
	$(PY) -m pip install -e ".[dev]"

data:
	ipibench generate

detector: data
	ipibench train-detector

eval:
	ipibench run --models $(MODELS) --defenses all --frac $(FRAC)

report:
	ipibench report --update-readme README.md

mock:
	ipibench --results results_mock run --models mock-a mock-b --defenses all
	cp results/detector_metrics.json results_mock/ 2>/dev/null || true
	ipibench --results results_mock report

test:
	pytest -q

lint:
	ruff check src tests
