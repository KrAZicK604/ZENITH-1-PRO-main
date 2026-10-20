# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and version numbers follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Coordinated vulnerability-disclosure guidance.
- A reproducible release checklist for the first versioned release.

### Security

- Expanded Bandit to scan every repository Python file and strengthened the
  configuration tests to reject unpinned external GitHub Actions.

## [0.1.0] - Unreleased

### Added

- Deterministic logistic-map evolution with bounded inputs.
- Primary and shadow-orbit comparison with visualized divergence.
- Streamlit entry-point and boundary smoke tests.
- Strict configuration tests for the development container and Streamlit
  security settings.

### Security

- Streamlit `1.66.0` runtime enforcement while retaining the declared
  `streamlit>=1.61.1,<2` compatibility policy.
- Lock-managed Bandit `1.9.4` and pip-audit `2.10.1` checks.
- Immutable GitHub Action revisions, read-only workflow permissions, and
  disabled checkout credential persistence.
- Locked dependency validation through `uv lock --check` and `uv run --locked`.

`0.1.0` remains unreleased until the release checklist is completed against a
specific protected-branch commit.
