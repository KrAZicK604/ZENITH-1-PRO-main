# ZENITH-1-PRO Logistic Map Lab

A deterministic Streamlit lab for exploring the logistic map and sensitivity
to initial conditions.

[![Streamlit smoke test](https://github.com/KrAZicK604/ZENITH-1-PRO-main/actions/workflows/smoke-test.yml/badge.svg)](https://github.com/KrAZicK604/ZENITH-1-PRO-main/actions/workflows/smoke-test.yml)

## What it does

- evolves `x[n + 1] = r * x[n] * (1 - x[n])` with bounded controls;
- compares a primary orbit with a shadow orbit offset by `1e-9`;
- visualizes both trajectories and their final divergence;
- performs no network requests, file writes, or real-world execution.

## Run locally

Prerequisite: install `uv` if you don't already have it.

```sh
curl -LsSf https://astral.sh/uv/install.sh | sh
```

1. Sync the dependencies

   ```sh
   uv sync --locked
   ```

2. Run the app

   ```sh
   uv run --locked streamlit run streamlit_app.py
   ```

## Test

```sh
uv run --locked python -m unittest discover -s tests -v
```

The project intentionally keeps its original dependency baseline: Streamlit is
the only declared runtime dependency.
