# Contributing

## Running tests

```bash
pip install -r requirements.txt pytest
python -m pytest tests/ -v
```

All 61 tests must pass before submitting a PR.

## Adding a detection rule

1. Add the detector function in `log_analyzer.py` following the pattern of `detect_brute_force`
2. Wire it into the detection pipeline in `main()` alongside the existing detectors
3. Add the threshold constants and a `score_severity` entry
4. Add a section to `config.example.yaml`
5. Write pytest unit tests in `tests/test_detection.py`

## Submitting a pull request

1. Fork the repo and create a branch from `main`
2. Make your changes and ensure all tests pass
3. Open a PR against `main` with a clear description of what and why
4. Keep PRs focused — one feature or fix per PR
