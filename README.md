# RSSI Cartographer

`RSSI Cartographer` is a lightweight macOS radar-style mapper for your local network.

It captures available MacBook sensor/network signals (Wi-Fi, Bluetooth snapshot, battery + interface info), scans your local subnet for reachable devices, and renders a 2D radar map in the browser.

## One-command run (download + launch)

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/theos2node/RSSICartographer/main/bootstrap.sh)"
```

## One-command run (inside cloned repo)

```bash
./run.sh
```

That command:

1. Runs a local subnet scan.
2. Collects available local sensor snapshots.
3. Starts a tiny local web server.
4. Opens your browser to a radar map.

## Requirements

- macOS
- `python3` (no pip dependencies)

## Notes

- This is best-effort discovery on your LAN and relies on reachable hosts + ARP visibility.
- Some sensor snapshots can be limited by OS/hardware permissions.
- Stop the server with `Ctrl+C`.

## Optional flags

```bash
./run.sh --no-open
./run.sh --port 9000
```

## Open source license

MIT (`LICENSE`)
