# Contributing

Contributions are welcome. Keep SecretSentry dependency-free at runtime, avoid printing detected secret values, and include tests for behavior changes.

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -v
```

If Ruff is installed, run `ruff check .` before opening a pull request. Add tests for bug fixes and features. Do not use real credentials in tests, examples, issues, or pull requests; use obviously synthetic values.

## Pull requests

1. Create a focused branch.
2. Describe the change and its security impact.
3. Include test results and any known limitations.
4. Ensure the CI workflow passes.
