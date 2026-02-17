#!/usr/bin/env python3
"""RSSI Cartographer: local network radar map for macOS.

- Scans local subnet for reachable devices
- Pulls available local sensor snapshots (Wi-Fi, Bluetooth, battery)
- Serves a lightweight radar-style 2D map in the browser
"""

from __future__ import annotations

import argparse
import hashlib
import html
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


APP_TITLE = "RSSI Cartographer"
DEFAULT_PORT = 8765
MAX_SCAN_HOSTS = 512


def run_cmd(cmd: list[str], timeout: float = 2.5) -> tuple[bool, str]:
    """Run a command and return (ok, stdout)."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False, ""
    return proc.returncode == 0, (proc.stdout or "").strip()


def parse_route_default_interface() -> str | None:
    ok, out = run_cmd(["route", "-n", "get", "default"], timeout=2)
    if not ok:
        return None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("interface:"):
            return line.split(":", 1)[1].strip()
    return None


def get_if_ipv4(interface: str) -> str | None:
    ok, out = run_cmd(["ipconfig", "getifaddr", interface], timeout=2)
    if ok and out:
        return out.strip()
    return None


def get_if_netmask(interface: str) -> str | None:
    ok, out = run_cmd(["ipconfig", "getoption", interface, "subnet_mask"], timeout=2)
    if ok and out:
        return out.strip()

    ok, out = run_cmd(["ifconfig", interface], timeout=2)
    if not ok:
        return None
    m = re.search(r"netmask 0x([0-9a-fA-F]+)", out)
    if not m:
        return None
    mask_hex = m.group(1)
    mask_int = int(mask_hex, 16)
    return ".".join(str((mask_int >> shift) & 0xFF) for shift in (24, 16, 8, 0))


def get_if_mac(interface: str) -> str | None:
    ok, out = run_cmd(["ifconfig", interface], timeout=2)
    if not ok:
        return None
    m = re.search(r"\bether\s+([0-9a-fA-F:]{17})", out)
    if not m:
        return None
    return m.group(1).lower()


def to_prefix_len(netmask: str) -> int:
    bits = "".join(f"{int(o):08b}" for o in netmask.split("."))
    return bits.count("1")


def subnet_from_interface(interface: str) -> ipaddress.IPv4Network | None:
    ip = get_if_ipv4(interface)
    mask = get_if_netmask(interface)
    if not ip or not mask:
        return None
    prefix = to_prefix_len(mask)
    return ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)


def parse_airport_info() -> dict[str, Any]:
    airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
    if not Path(airport_path).exists():
        return {}
    ok, out = run_cmd([airport_path, "-I"], timeout=2)
    if not ok or not out:
        return {}

    info: dict[str, Any] = {}
    for line in out.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        info[key] = value

    def to_int(k: str) -> int | None:
        v = info.get(k)
        if v is None:
            return None
        try:
            return int(str(v))
        except ValueError:
            return None

    return {
        "ssid": info.get("SSID"),
        "bssid": info.get("BSSID"),
        "channel": info.get("channel"),
        "rssi": to_int("agrCtlRSSI"),
        "noise": to_int("agrCtlNoise"),
        "tx_rate": to_int("lastTxRate"),
        "phy_mode": info.get("link auth") or info.get("op mode"),
    }


def parse_bluetooth_snapshot() -> dict[str, Any]:
    ok, out = run_cmd(["system_profiler", "SPBluetoothDataType", "-json"], timeout=9)
    if not ok or not out:
        return {}
    try:
        payload = json.loads(out)
    except json.JSONDecodeError:
        return {}

    top = payload.get("SPBluetoothDataType", [])
    if not top:
        return {}

    root = top[0]
    power_state = root.get("device_power")
    discoverable = root.get("discoverable")

    paired_count = 0
    connected_count = 0

    # system_profiler key names vary by macOS versions, so keep this broad.
    def walk(obj: Any) -> None:
        nonlocal paired_count, connected_count
        if isinstance(obj, dict):
            if "device_isconnected" in obj:
                paired_count += 1
                if str(obj.get("device_isconnected", "")).lower() in {"yes", "true", "connected"}:
                    connected_count += 1
            for value in obj.values():
                walk(value)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(root)

    return {
        "power": power_state,
        "discoverable": discoverable,
        "paired_devices_seen": paired_count,
        "connected_devices_seen": connected_count,
    }


def parse_battery_snapshot() -> dict[str, Any]:
    ok, out = run_cmd(["pmset", "-g", "batt"], timeout=2)
    if not ok or not out:
        return {}

    result: dict[str, Any] = {"raw": out.splitlines()[0] if out else ""}
    m_pct = re.search(r"(\d+)%", out)
    if m_pct:
        result["percent"] = int(m_pct.group(1))

    if "discharging" in out.lower():
        result["state"] = "discharging"
    elif "charging" in out.lower():
        result["state"] = "charging"
    elif "charged" in out.lower():
        result["state"] = "charged"

    m_eta = re.search(r"(\d+:\d+) remaining", out)
    if m_eta:
        result["eta"] = m_eta.group(1)

    return result


def parse_arp_table() -> dict[str, dict[str, str]]:
    ok, out = run_cmd(["arp", "-an"], timeout=2)
    if not ok:
        return {}

    table: dict[str, dict[str, str]] = {}
    # Example:
    # ? (192.168.1.4) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
    pattern = re.compile(
        r"\((?P<ip>\d+\.\d+\.\d+\.\d+)\)\s+at\s+(?P<mac>[0-9a-fA-F:]+|\(incomplete\))\s+on\s+(?P<if>\w+)"
    )
    for line in out.splitlines():
        m = pattern.search(line)
        if not m:
            continue
        ip = m.group("ip")
        mac = m.group("mac")
        iface = m.group("if")
        if mac == "(incomplete)":
            continue
        table[ip] = {"mac": mac.lower(), "interface": iface}
    return table


def ping_host(ip: str, timeout_seconds: float = 1.0) -> dict[str, Any] | None:
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            ["ping", "-c", "1", ip],
            capture_output=True,
            text=True,
            timeout=max(1.0, timeout_seconds + 0.3),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None

    if proc.returncode != 0:
        return None

    elapsed_ms = (time.perf_counter() - start) * 1000
    out = proc.stdout or ""
    m = re.search(r"time[=<]([\d.]+)\s*ms", out)
    latency = float(m.group(1)) if m else round(elapsed_ms, 2)
    return {"ip": ip, "latency_ms": round(latency, 2)}


def reverse_dns(ip: str) -> str | None:
    try:
        socket.setdefaulttimeout(0.35)
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return None


def capped_hosts(network: ipaddress.IPv4Network, local_ip: str | None) -> list[str]:
    hosts = [str(h) for h in network.hosts()]
    if local_ip and local_ip in hosts:
        hosts.remove(local_ip)
    if len(hosts) <= MAX_SCAN_HOSTS:
        return hosts
    return hosts[:MAX_SCAN_HOSTS]


def scan_network_devices(network: ipaddress.IPv4Network, local_ip: str | None) -> list[dict[str, Any]]:
    host_ips = capped_hosts(network, local_ip)

    ping_results: dict[str, dict[str, Any]] = {}
    workers = min(96, max(12, (os.cpu_count() or 8) * 4))

    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_map = {pool.submit(ping_host, ip): ip for ip in host_ips}
        for future in as_completed(future_map):
            result = future.result()
            if result:
                ping_results[result["ip"]] = result

    arp = parse_arp_table()

    seen_ips = set(arp.keys()) | set(ping_results.keys())
    devices: list[dict[str, Any]] = []
    for ip in sorted(seen_ips, key=lambda v: tuple(int(x) for x in v.split("."))):
        if local_ip and ip == local_ip:
            continue
        arp_info = arp.get(ip, {})
        ping_info = ping_results.get(ip, {})
        hostname = reverse_dns(ip)

        latency = ping_info.get("latency_ms")
        if latency is None:
            latency = round(2.0 + (stable_hash_num(ip) % 40), 2)

        devices.append(
            {
                "ip": ip,
                "mac": arp_info.get("mac"),
                "interface": arp_info.get("interface"),
                "hostname": hostname,
                "latency_ms": latency,
                "signal_score": signal_score_from_latency(latency),
            }
        )

    return devices


def signal_score_from_latency(latency_ms: float) -> int:
    # Convert rough network latency into 0-100 strength score.
    normalized = max(0.0, min(100.0, 100.0 - (latency_ms * 2.7)))
    return int(round(normalized))


def stable_hash_num(value: str) -> int:
    return int(hashlib.sha256(value.encode("utf-8")).hexdigest()[:8], 16)


def position_devices(devices: list[dict[str, Any]], radius_min: int = 80, radius_max: int = 300) -> None:
    for dev in devices:
        seed = stable_hash_num(dev["ip"])
        angle = seed % 360
        signal = dev.get("signal_score") or 0
        # Stronger signal appears closer to center.
        closeness = signal / 100.0
        base = radius_max - ((radius_max - radius_min) * closeness)
        jitter = ((seed >> 8) % 24) - 12
        radius = max(radius_min, min(radius_max, int(base + jitter)))
        dev["angle_deg"] = angle
        dev["radius_px"] = radius


def display_name(device: dict[str, Any]) -> str:
    for key in ("hostname", "mac", "ip"):
        value = device.get(key)
        if value:
            return str(value)
    return "unknown"


def generate_html(payload: dict[str, Any]) -> str:
    json_blob = json.dumps(payload, indent=2)

    return f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>{APP_TITLE}</title>
  <style>
    :root {{
      --bg-0: #06160f;
      --bg-1: #0a2318;
      --grid: #1d5b40;
      --text: #dcffe9;
      --muted: #96c7ae;
      --accent: #53ff9f;
      --alert: #ffe88d;
      --panel: rgba(0, 0, 0, 0.28);
    }}
    * {{ box-sizing: border-box; }}
    html, body {{
      margin: 0;
      width: 100%;
      height: 100%;
      font-family: Menlo, Monaco, ui-monospace, monospace;
      background: radial-gradient(circle at 20% 20%, #0f3f2a, var(--bg-0));
      color: var(--text);
      overflow: hidden;
    }}
    #wrap {{
      position: relative;
      width: 100%;
      height: 100%;
    }}
    canvas {{
      position: absolute;
      inset: 0;
      width: 100%;
      height: 100%;
      display: block;
    }}
    .panel {{
      position: absolute;
      left: 16px;
      top: 16px;
      width: min(410px, calc(100vw - 32px));
      background: var(--panel);
      border: 1px solid rgba(83,255,159,0.38);
      border-radius: 12px;
      padding: 12px;
      backdrop-filter: blur(4px);
    }}
    .panel h1 {{
      margin: 0;
      font-size: 1rem;
      letter-spacing: .08em;
      text-transform: uppercase;
    }}
    .meta {{
      margin-top: 8px;
      color: var(--muted);
      font-size: .85rem;
      line-height: 1.35;
    }}
    .chip-row {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 10px;
    }}
    .chip {{
      border: 1px solid rgba(83,255,159,0.35);
      border-radius: 100px;
      padding: 4px 10px;
      font-size: .78rem;
      color: var(--text);
      background: rgba(17, 47, 34, 0.5);
      white-space: nowrap;
    }}
    .legend {{
      position: absolute;
      right: 16px;
      bottom: 16px;
      width: min(420px, calc(100vw - 32px));
      max-height: 42vh;
      overflow: auto;
      background: var(--panel);
      border: 1px solid rgba(83,255,159,0.38);
      border-radius: 12px;
      padding: 12px;
      backdrop-filter: blur(4px);
    }}
    .legend h2 {{
      margin: 0 0 8px;
      font-size: .95rem;
      letter-spacing: .06em;
      text-transform: uppercase;
    }}
    .legend-item {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      padding: 6px 0;
      border-bottom: 1px dotted rgba(150, 199, 174, 0.25);
      font-size: .83rem;
    }}
    .legend-item:last-child {{ border-bottom: 0; }}
    .left {{ color: var(--text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
    .right {{ color: var(--muted); white-space: nowrap; }}
    .warn {{ color: var(--alert); }}
  </style>
</head>
<body>
  <div id=\"wrap\">
    <canvas id=\"radar\"></canvas>
    <div class=\"panel\">
      <h1>RSSI Cartographer</h1>
      <div class=\"meta\" id=\"meta\"></div>
      <div class=\"chip-row\" id=\"chips\"></div>
    </div>
    <div class=\"legend\">
      <h2>Detected Devices</h2>
      <div id=\"legendList\"></div>
    </div>
  </div>
  <script>
    const DATA = {json_blob};

    const canvas = document.getElementById('radar');
    const ctx = canvas.getContext('2d');

    const metaEl = document.getElementById('meta');
    const chipsEl = document.getElementById('chips');
    const legendEl = document.getElementById('legendList');

    function esc(v) {{
      return String(v ?? '').replace(/[&<>\"']/g, s => ({{
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '\"': '&quot;',
        "'": '&#39;'
      }}[s]));
    }}

    function sizeCanvas() {{
      const dpr = window.devicePixelRatio || 1;
      canvas.width = Math.floor(window.innerWidth * dpr);
      canvas.height = Math.floor(window.innerHeight * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }}

    function deviceColor(signal) {{
      if (signal >= 75) return '#53ff9f';
      if (signal >= 45) return '#d8ff84';
      return '#ffcc66';
    }}

    function drawGrid(cx, cy, maxR) {{
      ctx.save();
      ctx.strokeStyle = 'rgba(83,255,159,.22)';
      ctx.lineWidth = 1;
      for (let i = 1; i <= 4; i++) {{
        const r = (maxR / 4) * i;
        ctx.beginPath();
        ctx.arc(cx, cy, r, 0, Math.PI * 2);
        ctx.stroke();
      }}

      for (let a = 0; a < 360; a += 30) {{
        const rad = (a * Math.PI) / 180;
        const x = cx + Math.cos(rad) * maxR;
        const y = cy + Math.sin(rad) * maxR;
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.lineTo(x, y);
        ctx.stroke();
      }}
      ctx.restore();
    }}

    function drawSweep(cx, cy, maxR, t) {{
      const angle = (t / 40) % 360;
      const rad = (angle * Math.PI) / 180;
      const grad = ctx.createRadialGradient(cx, cy, 0, cx, cy, maxR);
      grad.addColorStop(0, 'rgba(83,255,159,0.15)');
      grad.addColorStop(1, 'rgba(83,255,159,0.0)');

      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(rad);
      ctx.fillStyle = grad;
      ctx.beginPath();
      ctx.moveTo(0, 0);
      ctx.arc(0, 0, maxR, -0.15, 0.15);
      ctx.closePath();
      ctx.fill();

      ctx.strokeStyle = 'rgba(83,255,159,0.88)';
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.moveTo(0, 0);
      ctx.lineTo(maxR, 0);
      ctx.stroke();
      ctx.restore();
    }}

    function drawLocalNode(cx, cy) {{
      ctx.save();
      ctx.fillStyle = '#53ff9f';
      ctx.shadowColor = 'rgba(83,255,159,0.8)';
      ctx.shadowBlur = 16;
      ctx.beginPath();
      ctx.arc(cx, cy, 7, 0, Math.PI * 2);
      ctx.fill();
      ctx.restore();

      ctx.save();
      ctx.fillStyle = '#dcffe9';
      ctx.font = '12px Menlo, Monaco, monospace';
      ctx.fillText('THIS MAC', cx + 12, cy - 10);
      ctx.restore();
    }}

    function drawDevices(cx, cy, maxR, t) {{
      const pulse = Math.sin(t / 220) * 0.8;
      for (const dev of DATA.devices) {{
        const angle = (dev.angle_deg * Math.PI) / 180;
        const radius = Math.min(maxR - 12, dev.radius_px);
        const x = cx + Math.cos(angle) * radius;
        const y = cy + Math.sin(angle) * radius;

        const dotR = 3 + ((dev.signal_score || 0) / 100) * 4 + pulse;
        ctx.beginPath();
        ctx.fillStyle = deviceColor(dev.signal_score || 0);
        ctx.shadowColor = ctx.fillStyle;
        ctx.shadowBlur = 12;
        ctx.arc(x, y, dotR, 0, Math.PI * 2);
        ctx.fill();

        ctx.shadowBlur = 0;
        ctx.font = '11px Menlo, Monaco, monospace';
        ctx.fillStyle = 'rgba(220,255,233,0.9)';
        const label = dev.hostname || dev.mac || dev.ip;
        ctx.fillText(label, x + 8, y - 6);
      }}
    }}

    function renderLegend() {{
      if (!DATA.devices.length) {{
        legendEl.innerHTML = '<div class="legend-item warn">No remote devices detected yet. Keep the page open and rerun to refresh scan.</div>';
        return;
      }}

      legendEl.innerHTML = DATA.devices.map(dev => {{
        const name = esc(dev.hostname || dev.mac || dev.ip);
        const ip = esc(dev.ip || 'unknown');
        const sig = Number.isFinite(dev.signal_score) ? `${{dev.signal_score}}%` : 'n/a';
        const lat = Number.isFinite(dev.latency_ms) ? `${{dev.latency_ms.toFixed(1)}}ms` : 'n/a';
        return `<div class="legend-item">
          <span class="left">${{name}} <span class="right">(${{ip}})</span></span>
          <span class="right">${{sig}} • ${{lat}}</span>
        </div>`;
      }}).join('');
    }}

    function renderMeta() {{
      const host = DATA.host || {{}};
      const wifi = DATA.sensors?.wifi || {{}};
      const bt = DATA.sensors?.bluetooth || {{}};
      const battery = DATA.sensors?.battery || {{}};

      const lines = [
        `Scan Time: ${{esc(DATA.generated_at)}}`,
        `Interface: ${{esc(host.interface || 'unknown')}}`,
        `Local IP: ${{esc(host.ip || 'unknown')}}`,
        `Subnet: ${{esc(DATA.network || 'unknown')}}`,
        `Devices Seen: ${{DATA.devices.length}}`
      ];
      metaEl.innerHTML = lines.join('<br>');

      const chips = [];
      if (wifi.ssid) chips.push(`Wi-Fi ${{esc(wifi.ssid)}}`);
      if (Number.isFinite(wifi.rssi)) chips.push(`RSSI ${{wifi.rssi}} dBm`);
      if (Number.isFinite(wifi.noise)) chips.push(`Noise ${{wifi.noise}} dBm`);
      if (wifi.channel) chips.push(`Channel ${{esc(wifi.channel)}}`);
      if (Number.isFinite(bt.connected_devices_seen)) chips.push(`BT Connected ${{bt.connected_devices_seen}}`);
      if (Number.isFinite(bt.paired_devices_seen)) chips.push(`BT Paired Seen ${{bt.paired_devices_seen}}`);
      if (Number.isFinite(battery.percent)) chips.push(`Battery ${{battery.percent}}%`);
      if (battery.state) chips.push(`Power ${{esc(battery.state)}}`);

      chipsEl.innerHTML = chips.length
        ? chips.map(v => `<span class="chip">${{v}}</span>`).join('')
        : '<span class="chip">Sensor snapshots unavailable (permissions/platform)</span>';
    }}

    function tick(t) {{
      const w = window.innerWidth;
      const h = window.innerHeight;
      const cx = w / 2;
      const cy = h / 2;
      const maxR = Math.min(w, h) * 0.42;

      ctx.clearRect(0, 0, w, h);
      drawGrid(cx, cy, maxR);
      drawSweep(cx, cy, maxR, t);
      drawLocalNode(cx, cy);
      drawDevices(cx, cy, maxR, t);

      requestAnimationFrame(tick);
    }}

    renderMeta();
    renderLegend();
    sizeCanvas();
    requestAnimationFrame(tick);
    window.addEventListener('resize', sizeCanvas);
  </script>
</body>
</html>
"""


def build_payload() -> dict[str, Any]:
    interface = parse_route_default_interface() or "en0"
    local_ip = get_if_ipv4(interface)
    local_mac = get_if_mac(interface)
    network = subnet_from_interface(interface)

    wifi = parse_airport_info()
    bluetooth = parse_bluetooth_snapshot()
    battery = parse_battery_snapshot()

    devices: list[dict[str, Any]] = []
    if network:
        devices = scan_network_devices(network, local_ip)
        position_devices(devices)

    host = {
        "hostname": socket.gethostname(),
        "interface": interface,
        "ip": local_ip,
        "mac": local_mac,
    }

    payload = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "network": str(network) if network else None,
        "host": host,
        "sensors": {
            "wifi": wifi,
            "bluetooth": bluetooth,
            "battery": battery,
        },
        "devices": devices,
    }
    return payload


def pick_port(preferred: int) -> int:
    for port in [preferred, *(preferred + i for i in range(1, 40))]:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError("No free port available")


def serve_html(html_text: str, port: int, auto_open: bool) -> None:
    temp_dir = Path(tempfile.mkdtemp(prefix="rssicartographer-"))
    index_path = temp_dir / "index.html"
    index_path.write_text(html_text, encoding="utf-8")

    handler = partial(SimpleHTTPRequestHandler, directory=str(temp_dir))
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    url = f"http://127.0.0.1:{port}/"

    stop_event = threading.Event()

    def shutdown(*_: Any) -> None:
        if not stop_event.is_set():
            stop_event.set()
            threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    if auto_open:
        subprocess.Popen(["open", url])

    print(f"\n[{APP_TITLE}] Radar live at {url}")
    print(f"[{APP_TITLE}] Press Ctrl+C to stop.\n")

    try:
        server.serve_forever(poll_interval=0.3)
    finally:
        server.server_close()
        shutil.rmtree(temp_dir, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Local network radar map for macOS")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Preferred local HTTP port")
    parser.add_argument("--no-open", action="store_true", help="Do not auto-open browser")
    args = parser.parse_args()

    print(f"[{APP_TITLE}] Collecting sensor snapshots and scanning local network...")
    payload = build_payload()

    html_page = generate_html(payload)
    chosen_port = pick_port(args.port)
    serve_html(html_page, chosen_port, auto_open=not args.no_open)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
