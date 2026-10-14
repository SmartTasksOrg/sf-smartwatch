# Contributing

Contributions are welcome. **Security problems do not go here**: see [SECURITY.md](SECURITY.md).

## Before you start

- For anything larger than a fix, open an issue first and say what you want to change and why.
- By contributing you agree that your contribution is licensed under the licence in [LICENSE](LICENSE).
  There is no separate contributor agreement.
- Be decent: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Set up and run the checks

From a clone, Python 3.10 or later:

    python -m venv .venv
    # Windows PowerShell: .\.venv\Scripts\Activate.ps1   Linux/macOS: . .venv/bin/activate
    python -m pip install -e ".[jwt]" pytest
    python -m pytest -q
    python spec/tools/make_vectors.py --check
    python scripts/check_install_lines.py
    ports/conformance/run.sh          # every engine whose toolchain you have
    ports/conformance/interop.sh      # every port's reporter and poller against the Python monitor

## Rules a change must keep

1. No secrets, tokens or personal data in the repository. Tests make their own tokens and keys at run
   time; `.env` files and key files are ignored by git.
2. No new runtime dependency without a maintainer's decision (the Python package has none; the optional
   extra `jwt` adds `cryptography`; every port has none).
3. A change to the engine changes the vectors: run `python spec/tools/make_vectors.py`, review the diff
   of `spec/conformance/`, copy the files to `src/sf_smartwatch/data/conformance/`, update
   `spec/SEMANTICS.md`, and update every port until `ports/conformance/run.sh` and `interop.sh` pass.
   The vectors are the contract.
4. The engine stays deterministic: no clock, no randomness, no floating point outside the formulas in
   SEMANTICS.md.
5. Say what was tested and what was not. Do not write that something works on a platform or at a scale
   it was not run on.
6. Install lines name only packages listed with `"registered": true` in `names.json`;
   `scripts/check_install_lines.py` enforces it in CI.
7. Add a line to [CHANGELOG.md](CHANGELOG.md) under "Unreleased".

## Pull requests

One topic per pull request. Describe what changes for a user, which tests cover it, and the commands
you ran with their results.
