# Contributing to RSSI Cartographer

Thanks for contributing.

## Development Setup

1. Clone the repository.
2. Run the app locally:

```bash
./run.sh --no-open
```

3. Validate basic integrity before opening a PR:

```bash
python3 -m py_compile ./rssicartographer.py
```

## Contribution Focus

- Radar rendering quality and interaction improvements
- Wi-Fi-focused distance modeling and calibration workflows
- Scan reliability and performance on real home networks
- Documentation and reproducibility improvements

## Pull Request Guidelines

- Keep changes focused and atomic.
- Include rationale for any model-constant changes.
- Note user-facing behavior changes in the PR description.
- Update docs if flags, defaults, or calibration behavior changes.

## Reporting Bugs

Use the issue templates and include:

- macOS version
- Command used to run the app
- Local network characteristics (high-level)
- Expected vs actual behavior
- Logs and screenshots where relevant
