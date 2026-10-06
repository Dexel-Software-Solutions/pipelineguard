# Contributing

1. Fork, then `pip install -e ".[dev]"`.
2. Add a rule in `pipelineguard/rules.py` (+ title in `RULE_TITLES`) and a test in `tests/`.
3. `ruff check . && pytest -q && pipelineguard scan . --fail-on high` must all pass.
4. Open a pull request. Questions: dexelsoftwaresolutions@gmail.com
