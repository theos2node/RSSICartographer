# RSSI Cartographer

`RSSI Cartographer` is a lightweight macOS live radar mapper for your local network.

It captures available MacBook sensor/network signals (Wi-Fi, Bluetooth snapshot, battery + interface info), scans your local subnet for reachable devices, and renders a live-updating 2D radar map in the browser.

## One-command run (download + launch)

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/theos2node/RSSICartographer/main/bootstrap.sh)"
```

## One-command run (inside cloned repo)

```bash
./run.sh
```

That command:

1. Runs an initial local subnet scan.
2. Collects available local sensor snapshots.
3. Starts a tiny local web server and background rescans.
4. Opens your browser to a radar map that updates automatically.

## Requirements

- macOS
- `python3` (no pip dependencies)

## Notes

- This is best-effort discovery on your LAN and relies on reachable hosts + ARP visibility.
- Some sensor snapshots can be limited by OS/hardware permissions.
- Distance is estimated with a calibration-aware hybrid model (Wi-Fi RSSI anchor + RTT heuristic).
- Meter-level physical ranging for all devices is not guaranteed without dedicated ranging stacks (for example FTM/UWB anchors).
- Stop the server with `Ctrl+C`.

## In-app controls

- `+ / Auto / -` zoom controls (mouse wheel zoom also supported)
- Adaptive ring labels in meters (auto range fit)
- Collision-avoidance layout to reduce overlapping device dots
- Click any dot or legend row for full device details
- `Ferdus` apartment preset (default) to keep estimates in realistic apartment-scale ranges
- Calibration sliders:
  - path-loss exponent
  - reference RSSI at 1 meter
  - RTT gain
  - RTT exponent
  - RTT delta cap

## Optional flags

```bash
./run.sh --no-open
./run.sh --port 9000
./run.sh --refresh 10
./run.sh --max-hosts 256
```

## Open source license

MIT (`LICENSE`)
