# Contributing to ModelFuzz

Thanks for your interest in contributing. This document covers how to set up a development environment, run tests, and submit changes.

## Development Setup

ModelFuzz uses [uv](https://github.com/astral-sh/uv) for dependency management.

```bash
git clone https://github.com/higagan/modelfuzz.git
cd modelfuzz
uv sync
```

This installs the package and its dependencies, including dev tools (`pytest`, `ruff`), into a local virtual environment.

## Running Tests

```bash
uv run pytest
```

Tests live under [tests/](tests/) and are organized by module (`test_decorator.py`, `test_engine.py`, `test_rules.py`). Add tests alongside the code they cover, and make sure new policies or behaviors are exercised by at least one test.

## Linting

```bash
uv run ruff check .
```

CI runs lint and tests against Python 3.10, 3.11, and 3.12 on every push and pull request (see [.github/workflows/ci.yml](.github/workflows/ci.yml)). Please make sure both pass locally before opening a PR.

## Submitting Changes

1. Fork the repository and create a branch from `main`.
2. Make your changes, with tests covering new behavior.
3. Run `uv run ruff check .` and `uv run pytest` locally.
4. Open a pull request describing the change and its motivation.

## Reporting Issues

Use [GitHub Issues](https://github.com/higagan/modelfuzz/issues) to report bugs or propose features. Include a minimal reproduction where possible.

## License

By contributing, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).
