# defensive-python-labs

Educational Python labs and utilities for **defensive cybersecurity**.

This project is for people who want to learn cybersecurity concepts using Python in a safe, legal and structured way: recon, basic crypto, forensics, and more.

> **Disclaimer:** This project is for educational and defensive purposes only.
> Do **not** use any code in this repository against systems you do not own or lack explicit permission to test.

## Features (initial scope)

- Recon utilities (e.g. simple TCP port scanner)
- Classic cryptography ciphers (for learning, not production use)
- Basic forensics helpers (e.g. metadata extraction)
- Jupyter notebooks explaining each concept step-by-step

## Getting started

```bash
git clone https://github.com/cutewizzy11/defensive-python-labs.git
cd defensive-python-labs

python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell
# .venv\\Scripts\\Activate.ps1

pip install .
# Or, for development
pip install .[dev]
```

Run tests:

```bash
pytest
```

## Project structure

```text
src/defensive_python_labs/
  recon/
  crypto/
  forensics/
examples/notebooks/
docs/
tests/
```

## Contributing

Contributions are very welcome!

- Read [`CONTRIBUTING.md`](CONTRIBUTING.md) for how to set up your environment and submit a PR.
- Look for issues labeled `good first issue` and `help wanted`.
- You can contribute:
  - New labs (modules or notebooks)
  - Documentation improvements
  - Tests and refactors

## Code of Conduct

This project follows a Code of Conduct. See [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
