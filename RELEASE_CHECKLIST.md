# ZENITH-1-PRO Release Checklist

Use this checklist to prepare `v0.1.0` from a reviewed commit on protected
`main`. Completing the checklist records software-release evidence; it does
not establish production authority or real-world scientific validation.

## 1. Freeze the candidate

- [ ] Record the full candidate commit SHA.
- [ ] Confirm the candidate is the current protected `main` head.
- [ ] Confirm there are no unreviewed application or dependency changes.
- [ ] Confirm `pyproject.toml` declares version `0.1.0`.
- [ ] Confirm the intended tag is exactly `v0.1.0`.

## 2. Reproduce the required checks

Run the same locked commands used by CI:

```sh
uv lock --check
uv run --locked python -m unittest discover -s tests -v
uv run --locked --group security bandit -q -r logistic_map.py streamlit_app.py tests
uv run --locked --group security pip-audit --strict --path .venv/lib/python3.14/site-packages --progress-spinner off
```

- [ ] Lockfile check passes without modifying `uv.lock`.
- [ ] The complete unittest suite passes, including the Streamlit runtime
  assertion.
- [ ] Bandit exits successfully for every Python file in the repository.
- [ ] Strict pip-audit exits successfully and its result is recorded.

## 3. Preserve GitHub evidence

- [ ] `smoke-test` succeeds for the exact candidate SHA.
- [ ] `Analyze (actions)` succeeds for the exact candidate SHA.
- [ ] `Analyze (python)` succeeds for the exact candidate SHA.
- [ ] Record the workflow-run URLs in the release notes.
- [ ] Confirm workflow permissions remain `contents: read`.
- [ ] Confirm checkout still uses `persist-credentials: false`.
- [ ] Confirm every third-party action remains pinned to a full commit SHA.

## 4. Perform the release security review

- [ ] Review Dependabot and code-scanning results for unresolved alerts.
- [ ] Search the candidate tree and history for credentials or private data.
- [ ] Confirm `.streamlit/config.toml` keeps CORS and XSRF protection enabled
  and usage telemetry disabled.
- [ ] Confirm the app performs no external network requests, persistent file
  writes, or real-world execution.
- [ ] Confirm `SECURITY.md` describes the current private-reporting route.

## 5. Publish deliberately

- [ ] Create tag `v0.1.0` from the recorded candidate SHA only after every
  required check passes.
- [ ] Create the GitHub release from that exact tag.
- [ ] Copy the `0.1.0` changelog section into the release notes and replace
  `Unreleased` with the publication date in a follow-up reviewed change.
- [ ] Attach only reviewed artifacts. Record SHA-256 digests for any manually
  uploaded artifact.
- [ ] Do not include secrets, local state, credentials, or raw private evidence.

## 6. Verify after publication

- [ ] Confirm the tag resolves to the recorded commit SHA.
- [ ] Confirm the release page links to the successful checks.
- [ ] Download and verify any attached artifact against its recorded digest.
- [ ] Open a corrective pull request instead of moving or replacing the tag if
  a release defect is found.
