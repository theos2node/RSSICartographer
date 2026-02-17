# RSSI Cartographer

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)
[![Platform: macOS](https://img.shields.io/badge/Platform-macOS-111111)](https://www.apple.com/macos/)
[![Runtime: Python 3](https://img.shields.io/badge/Runtime-Python%203-blue)](https://www.python.org/)

A lightweight, live-updating Wi-Fi radar map for local-network device discovery on macOS.

`RSSI Cartographer` scans your LAN, estimates relative device distance, and renders an interactive 2D radar with zoom, ring labels, collision-aware device layout, and click-to-inspect details.

## Quick Start

### One command (download + run)

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/theos2node/RSSICartographer/main/bootstrap.sh)"
```

### Local run (inside cloned repo)

```bash
./run.sh
```

## What You Get

- Live radar with auto-refreshing network scan state
- Adaptive meter rings with auto-fit range scaling
- Manual zoom controls (`+`, `Auto`, `-`, and mouse wheel)
- Collision-avoidance placement to reduce node overlap
- Device inspector (click any dot or legend entry)
- Ferdus apartment calibration profile enabled by default

## Ferdus Calibration (Default)

The default profile is tuned to avoid unrealistic long-distance spikes in apartment-scale environments.

- `ref_rssi_1m_dbm = -49.0`
- `path_loss_exponent = 2.7`
- `rtt_gain_m_per_ms_pow = 3.2`
- `rtt_exponent = 1.12`
- `rtt_delta_cap_ms = 6.0`
- `max_distance_m = 65.0`

You can adjust these live in the UI and re-apply defaults with `Use Ferdus Preset`.

## CLI Options

```bash
./run.sh --no-open
./run.sh --port 9000
./run.sh --refresh 10
./run.sh --max-hosts 256
```

## Requirements

- macOS
- Python 3
- No third-party Python dependencies

## Accuracy Notes

- Distances are calibrated estimates, not guaranteed true physical meters for every device.
- RTT and RSSI can be affected by congestion, power-save behavior, and multipath.
- Meter-level hard ranging generally requires dedicated ranging technologies (for example FTM/UWB anchors).

## Privacy

- Runs locally on your machine
- No cloud dependency required for scanning or rendering
- Uses local network/system commands only

## Contributing

Contributions are welcome. Start with `CONTRIBUTING.md` and open an issue before large changes.

## License

MIT License (`LICENSE`)
