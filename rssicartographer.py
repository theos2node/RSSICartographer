#!/usr/bin/env python3
"""RSSI Cartographer: live local-network radar map for macOS.

Features:
- Background LAN rescans with live browser updates
- Radar rings with meter labels and auto-fit range
- Manual zoom + click-to-inspect device details
- Calibration-aware distance heuristics (Wi-Fi RSSI anchor + RTT model)

Note:
Distance for generic LAN devices is heuristic unless the environment supports
true ranging primitives (for example IEEE 802.11mc/802.11az FTM or UWB).
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import ipaddress
import json
import math
import os
import re
import signal
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


APP_TITLE = "RSSI Cartographer"
DEFAULT_PORT = 8765
DEFAULT_REFRESH_SECONDS = 16
DEFAULT_MAX_SCAN_HOSTS = 512
MAX_PORT_PROBES = 40

# Exponential smoothing factors used between scans.
RTT_EWMA_ALPHA = 0.35
DIST_EWMA_ALPHA = 0.40

DEFAULT_DISTANCE_MODEL = {
    "ref_rssi_1m_dbm": -52.0,
    "path_loss_exponent": 2.2,
    "rtt_gain_m_per_ms_pow": 28.0,
    "rtt_exponent": 1.30,
    "max_distance_m": 250.0,
}


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


def parse_route_default() -> dict[str, str | None]:
    ok, out = run_cmd(["route", "-n", "get", "default"], timeout=2)
    if not ok:
        return {"interface": None, "gateway": None}

    interface: str | None = None
    gateway: str | None = None

    for line in out.splitlines():
        line = line.strip()
        if line.startswith("interface:"):
            interface = line.split(":", 1)[1].strip()
        elif line.startswith("gateway:"):
            gateway = line.split(":", 1)[1].strip()

    return {"interface": interface, "gateway": gateway}


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
    mask_int = int(m.group(1), 16)
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


def stable_hash_num(value: str) -> int:
    return int(hashlib.sha256(value.encode("utf-8")).hexdigest()[:8], 16)


def display_name(device: dict[str, Any]) -> str:
    for key in ("hostname", "mac", "ip"):
        value = device.get(key)
        if value:
            return str(value)
    return "unknown"


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
        info[key.strip()] = value.strip()

    def to_int(k: str) -> int | None:
        val = info.get(k)
        if val is None:
            return None
        try:
            return int(str(val))
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
    ok, out = run_cmd(["system_profiler", "SPBluetoothDataType", "-json"], timeout=8)
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

    def walk(obj: Any) -> None:
        nonlocal paired_count, connected_count
        if isinstance(obj, dict):
            if "device_isconnected" in obj:
                paired_count += 1
                status = str(obj.get("device_isconnected", "")).lower()
                if status in {"yes", "true", "connected"}:
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

    lower = out.lower()
    if "discharging" in lower:
        result["state"] = "discharging"
    elif "charging" in lower:
        result["state"] = "charging"
    elif "charged" in lower:
        result["state"] = "charged"

    m_eta = re.search(r"(\d+:\d+) remaining", out)
    if m_eta:
        result["eta"] = m_eta.group(1)

    return result


def reverse_dns(ip: str) -> str | None:
    try:
        socket.setdefaulttimeout(0.35)
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return None


def parse_ping_stats(ping_output: str) -> tuple[float | None, float | None, int]:
    """Return (latency_ms, jitter_ms, sample_count)."""
    latency: float | None = None
    jitter: float | None = None
    sample_count = 1

    m_time = re.search(r"time[=<]([\d.]+)\s*ms", ping_output)
    if m_time:
        latency = float(m_time.group(1))

    m_stats = re.search(
        r"round-trip min/avg/max/(?:stddev|mdev) = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms",
        ping_output,
    )
    if m_stats:
        latency = float(m_stats.group(2))
        jitter = float(m_stats.group(4))

    m_tx = re.search(r"(\d+) packets transmitted", ping_output)
    if m_tx:
        sample_count = int(m_tx.group(1))

    return latency, jitter, sample_count


def ping_host(ip: str, timeout_seconds: float = 1.0) -> dict[str, Any] | None:
    cmd = ["ping", "-n", "-c", "1", ip]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(1.0, timeout_seconds + 0.35),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None

    if proc.returncode != 0:
        return None

    stdout = proc.stdout or ""
    latency_ms, jitter_ms, sample_count = parse_ping_stats(stdout)

    if latency_ms is None:
        return None

    return {
        "ip": ip,
        "latency_ms": round(latency_ms, 2),
        "latency_jitter_ms": round(jitter_ms, 2) if jitter_ms is not None else None,
        "latency_samples": sample_count,
    }


def probe_rtt_baseline(gateway_ip: str | None) -> float | None:
    if not gateway_ip:
        return None

    cmd = ["ping", "-n", "-c", "3", gateway_ip]
    ok, out = run_cmd(cmd, timeout=3)
    if not ok or not out:
        return None

    latency_ms, _, _ = parse_ping_stats(out)
    if latency_ms is None:
        return None
    return round(latency_ms, 2)


def parse_arp_table(interface: str, network: ipaddress.IPv4Network | None) -> dict[str, dict[str, str]]:
    ok, out = run_cmd(["arp", "-an"], timeout=2)
    if not ok:
        return {}

    entries: dict[str, dict[str, str]] = {}
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

        if iface != interface or mac == "(incomplete)":
            continue

        if network is not None:
            try:
                if ipaddress.IPv4Address(ip) not in network:
                    continue
            except ipaddress.AddressValueError:
                continue

        entries[ip] = {"mac": mac.lower(), "interface": iface}

    return entries


def capped_hosts(network: ipaddress.IPv4Network, local_ip: str | None, max_hosts: int) -> list[str]:
    hosts = [str(h) for h in network.hosts()]
    if local_ip and local_ip in hosts:
        hosts.remove(local_ip)
    if len(hosts) <= max_hosts:
        return hosts
    return hosts[:max_hosts]


def wifi_distance_from_rssi(rssi_dbm: int | float | None, ref_rssi_1m_dbm: float, path_loss_exp: float) -> float | None:
    """Estimate distance from RSSI using log-distance path loss model."""
    if rssi_dbm is None:
        return None

    if path_loss_exp <= 0:
        return None

    distance = 10 ** ((ref_rssi_1m_dbm - float(rssi_dbm)) / (10.0 * path_loss_exp))
    return round(max(0.5, distance), 2)


def estimate_distance_from_rtt(
    latency_ms: float | None,
    baseline_ms: float,
    anchor_distance_m: float | None,
    model: dict[str, float],
) -> float | None:
    """Heuristic RTT -> distance estimator anchored by local Wi-Fi RSSI distance."""
    if latency_ms is None:
        return None

    delta = max(0.0, latency_ms - baseline_ms)
    anchor = anchor_distance_m if anchor_distance_m is not None else 3.0
    gain = model["rtt_gain_m_per_ms_pow"]
    exponent = model["rtt_exponent"]

    # Small floor keeps nearby hosts off the exact center.
    estimate = anchor + (max(0.05, delta) ** exponent) * gain
    estimate = max(0.8, min(model["max_distance_m"], estimate))
    return round(estimate, 2)


def rtt_confidence(latency_ms: float | None, jitter_ms: float | None, baseline_ms: float) -> float:
    if latency_ms is None:
        return 0.0

    conf = 0.18
    if latency_ms <= baseline_ms + 0.7:
        conf += 0.1

    if jitter_ms is None:
        conf += 0.02
    elif jitter_ms < 0.15:
        conf += 0.16
    elif jitter_ms < 0.35:
        conf += 0.1
    elif jitter_ms < 0.8:
        conf += 0.05
    else:
        conf -= 0.03

    return round(max(0.1, min(0.52, conf)), 2)


def signal_score_from_distance(distance_m: float | None, confidence: float) -> int:
    if distance_m is None:
        return 8
    raw = 100.0 - min(distance_m, 220.0) * 0.44
    raw = raw * (0.72 + confidence * 0.28)
    return int(max(5, min(100, round(raw))))


def scan_network_devices(
    network: ipaddress.IPv4Network,
    local_ip: str | None,
    interface: str,
    max_hosts: int,
) -> list[dict[str, Any]]:
    host_ips = capped_hosts(network, local_ip, max_hosts=max_hosts)
    ping_results: dict[str, dict[str, Any]] = {}

    workers = min(96, max(12, (os.cpu_count() or 8) * 4))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(ping_host, ip): ip for ip in host_ips}
        for future in as_completed(futures):
            result = future.result()
            if result:
                ping_results[result["ip"]] = result

    arp_entries = parse_arp_table(interface=interface, network=network)

    seen_ips = set(ping_results.keys()) | set(arp_entries.keys())
    if local_ip:
        seen_ips.discard(local_ip)

    hostnames: dict[str, str | None] = {}
    if seen_ips:
        with ThreadPoolExecutor(max_workers=min(24, max(4, len(seen_ips)))) as pool:
            host_futures = {pool.submit(reverse_dns, ip): ip for ip in seen_ips}
            for future in as_completed(host_futures):
                ip = host_futures[future]
                try:
                    hostnames[ip] = future.result()
                except Exception:
                    hostnames[ip] = None

    devices: list[dict[str, Any]] = []
    for ip in sorted(seen_ips, key=lambda v: tuple(int(x) for x in v.split("."))):
        arp_info = arp_entries.get(ip, {})
        ping_info = ping_results.get(ip, {})

        devices.append(
            {
                "id": stable_hash_num(ip),
                "ip": ip,
                "mac": arp_info.get("mac"),
                "interface": arp_info.get("interface") or interface,
                "hostname": hostnames.get(ip),
                "reachable": ip in ping_results,
                "latency_ms": ping_info.get("latency_ms"),
                "latency_jitter_ms": ping_info.get("latency_jitter_ms"),
                "latency_samples": ping_info.get("latency_samples") or (1 if ip in ping_results else 0),
            }
        )

    return devices


def build_payload(max_hosts: int) -> dict[str, Any]:
    route = parse_route_default()
    interface = route.get("interface") or "en0"
    gateway_ip = route.get("gateway")

    local_ip = get_if_ipv4(interface)
    local_mac = get_if_mac(interface)
    network = subnet_from_interface(interface)

    wifi = parse_airport_info()
    bluetooth = parse_bluetooth_snapshot()
    battery = parse_battery_snapshot()

    model = dict(DEFAULT_DISTANCE_MODEL)
    wifi_anchor_m = wifi_distance_from_rssi(
        wifi.get("rssi"),
        ref_rssi_1m_dbm=model["ref_rssi_1m_dbm"],
        path_loss_exp=model["path_loss_exponent"],
    )

    rtt_baseline_ms = probe_rtt_baseline(gateway_ip) or 1.2

    devices: list[dict[str, Any]] = []
    if network:
        devices = scan_network_devices(
            network=network,
            local_ip=local_ip,
            interface=interface,
            max_hosts=max_hosts,
        )

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for dev in devices:
        latency_ms = dev.get("latency_ms")
        jitter_ms = dev.get("latency_jitter_ms")

        is_gateway = bool(gateway_ip and dev.get("ip") == gateway_ip)
        distance_method = "rtt_relative"

        if is_gateway and wifi_anchor_m is not None:
            distance_m = wifi_anchor_m
            confidence = 0.58
            distance_method = "wifi_rssi_anchor"
        else:
            distance_m = estimate_distance_from_rtt(
                latency_ms=latency_ms,
                baseline_ms=rtt_baseline_ms,
                anchor_distance_m=wifi_anchor_m,
                model=model,
            )
            confidence = rtt_confidence(
                latency_ms=latency_ms,
                jitter_ms=jitter_ms,
                baseline_ms=rtt_baseline_ms,
            )

        dev["distance_m"] = distance_m
        dev["distance_confidence"] = confidence if distance_m is not None else 0.0
        dev["distance_method"] = distance_method if distance_m is not None else "unknown"
        dev["signal_score"] = signal_score_from_distance(distance_m, dev["distance_confidence"])
        dev["display_name"] = display_name(dev)
        dev["is_gateway"] = is_gateway
        dev["last_seen"] = generated_at

    devices.sort(
        key=lambda d: (
            float("inf") if d.get("distance_m") is None else float(d["distance_m"]),
            d.get("ip") or "",
        )
    )

    payload = {
        "generated_at": generated_at,
        "generated_at_epoch_ms": int(time.time() * 1000),
        "network": str(network) if network else None,
        "host": {
            "hostname": socket.gethostname(),
            "interface": interface,
            "ip": local_ip,
            "mac": local_mac,
            "gateway_ip": gateway_ip,
        },
        "sensors": {
            "wifi": wifi,
            "bluetooth": bluetooth,
            "battery": battery,
        },
        "distance_model": {
            "name": "hybrid_rssi_rtt_heuristic",
            "rtt_baseline_ms": rtt_baseline_ms,
            "gateway_anchor_m": wifi_anchor_m,
            "calibration_defaults": model,
            "notes": [
                "RSSI uses log-distance path-loss model with configurable n and reference RSSI.",
                "RTT-derived ranges are relative estimates and should be treated as low-confidence without FTM/UWB anchors.",
                "Highest practical accuracy for consumer indoor ranging is currently achieved with IEEE 802.11mc/802.11az FTM and IEEE 802.15.4z UWB.",
            ],
        },
        "devices": devices,
    }

    return payload


class LiveScanState:
    def __init__(self, refresh_seconds: int, max_hosts: int):
        self.refresh_seconds = max(6, int(refresh_seconds))
        self.max_hosts = max(16, int(max_hosts))

        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._worker = threading.Thread(target=self._run_loop, daemon=True, name="rssi-scanner")

        self._payload: dict[str, Any] = {
            "generated_at": None,
            "generated_at_epoch_ms": None,
            "network": None,
            "host": {},
            "sensors": {},
            "distance_model": {},
            "devices": [],
            "scan": {
                "sequence": 0,
                "refresh_seconds": self.refresh_seconds,
                "duration_ms": None,
                "last_error": None,
            },
        }

        self._seq = 0
        self._latency_cache: dict[str, float] = {}
        self._distance_cache: dict[str, float] = {}
        self._seen_cache_ts: dict[str, float] = {}

    def start(self) -> None:
        self.scan_once()
        self._worker.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._worker.is_alive():
            self._worker.join(timeout=2.5)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._payload)

    def _smooth_value(self, cache: dict[str, float], key: str, value: float | None, alpha: float) -> float | None:
        if value is None:
            return cache.get(key)
        prev = cache.get(key)
        smoothed = value if prev is None else (prev * (1.0 - alpha) + value * alpha)
        cache[key] = smoothed
        return smoothed

    def _apply_history(self, payload: dict[str, Any]) -> None:
        now_ts = time.time()
        seen_now: set[str] = set()

        for dev in payload.get("devices", []):
            key = str(dev.get("ip") or dev.get("mac") or dev.get("id") or "")
            if not key:
                continue
            seen_now.add(key)

            latency = dev.get("latency_ms")
            smoothed_latency = self._smooth_value(self._latency_cache, key, latency, RTT_EWMA_ALPHA)
            if smoothed_latency is not None:
                dev["latency_ms"] = round(smoothed_latency, 2)

            distance = dev.get("distance_m")
            smoothed_distance = self._smooth_value(self._distance_cache, key, distance, DIST_EWMA_ALPHA)
            if smoothed_distance is not None:
                dev["distance_m"] = round(smoothed_distance, 2)
                if distance is None:
                    # Keep unknown devices visible near prior position when RTT is unavailable.
                    dev["distance_method"] = "cached_last_known"
                    dev["distance_confidence"] = round(float(dev.get("distance_confidence") or 0.0) * 0.75, 2)

            dev["signal_score"] = signal_score_from_distance(
                dev.get("distance_m"),
                float(dev.get("distance_confidence") or 0.0),
            )

            self._seen_cache_ts[key] = now_ts

        stale_cutoff = now_ts - (self.refresh_seconds * 6)
        for key in list(self._seen_cache_ts.keys()):
            if self._seen_cache_ts[key] < stale_cutoff:
                self._seen_cache_ts.pop(key, None)
                self._latency_cache.pop(key, None)
                self._distance_cache.pop(key, None)

    def scan_once(self) -> None:
        started = time.perf_counter()
        error_msg: str | None = None

        try:
            payload = build_payload(max_hosts=self.max_hosts)
            self._apply_history(payload)
        except Exception as exc:
            error_msg = f"{type(exc).__name__}: {exc}"
            payload = self.snapshot()

        duration_ms = int((time.perf_counter() - started) * 1000)
        self._seq += 1

        payload["scan"] = {
            "sequence": self._seq,
            "refresh_seconds": self.refresh_seconds,
            "duration_ms": duration_ms,
            "last_error": error_msg,
        }

        with self._lock:
            self._payload = payload

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            loop_started = time.perf_counter()
            self.scan_once()
            elapsed = time.perf_counter() - loop_started
            wait_seconds = max(0.5, self.refresh_seconds - elapsed)
            if self._stop_event.wait(wait_seconds):
                break


class RadarRequestHandler(BaseHTTPRequestHandler):
    html_page: str = ""
    state: LiveScanState | None = None

    def _send_bytes(self, payload: bytes, content_type: str, status_code: int = 200) -> None:
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if path in {"/", "/index.html"}:
            self._send_bytes(self.html_page.encode("utf-8"), "text/html; charset=utf-8")
            return

        if path == "/api/state":
            if self.state is None:
                self._send_bytes(b'{"error":"state unavailable"}', "application/json", status_code=503)
                return
            data = self.state.snapshot()
            payload = json.dumps(data, separators=(",", ":")).encode("utf-8")
            self._send_bytes(payload, "application/json; charset=utf-8")
            return

        if path == "/healthz":
            self._send_bytes(b"ok", "text/plain; charset=utf-8")
            return

        self._send_bytes(b"Not found", "text/plain; charset=utf-8", status_code=404)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        # Keep terminal output readable while radar runs.
        return


def pick_port(preferred: int) -> int:
    for port in [preferred, *(preferred + i for i in range(1, MAX_PORT_PROBES))]:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError("No free local port available")


def generate_html(initial_state: dict[str, Any]) -> str:
    page = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>RSSI Cartographer</title>
  <style>
    :root {
      --bg-0: #04130d;
      --bg-1: #0a2d1f;
      --bg-2: #145739;
      --text: #ddffec;
      --muted: #96cdb0;
      --accent: #53ff9f;
      --warn: #ffd685;
      --panel: rgba(1, 13, 9, 0.62);
      --panel-border: rgba(83, 255, 159, 0.33);
    }

    * { box-sizing: border-box; }

    html, body {
      margin: 0;
      width: 100%;
      height: 100%;
      color: var(--text);
      font-family: Menlo, Monaco, Consolas, ui-monospace, monospace;
      background:
        radial-gradient(circle at 12% 14%, rgba(28, 111, 72, 0.45), transparent 42%),
        radial-gradient(circle at 84% 18%, rgba(22, 90, 60, 0.36), transparent 46%),
        linear-gradient(150deg, var(--bg-1), var(--bg-0));
      overflow: hidden;
    }

    #wrap {
      position: relative;
      width: 100%;
      height: 100%;
    }

    canvas {
      position: absolute;
      inset: 0;
      width: 100%;
      height: 100%;
      display: block;
      cursor: crosshair;
    }

    .panel {
      position: absolute;
      top: 14px;
      left: 14px;
      width: min(460px, calc(100vw - 28px));
      max-height: min(72vh, 760px);
      overflow: auto;
      background: var(--panel);
      border: 1px solid var(--panel-border);
      border-radius: 12px;
      padding: 12px;
      backdrop-filter: blur(5px);
    }

    .panel h1 {
      margin: 0;
      font-size: 1rem;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }

    .sub {
      margin-top: 6px;
      color: var(--muted);
      font-size: 0.77rem;
      line-height: 1.35;
    }

    .meta {
      margin-top: 10px;
      color: var(--muted);
      font-size: 0.82rem;
      line-height: 1.35;
    }

    .chip-row {
      display: flex;
      flex-wrap: wrap;
      gap: 7px;
      margin-top: 10px;
    }

    .chip {
      border: 1px solid rgba(83, 255, 159, 0.35);
      border-radius: 999px;
      padding: 4px 9px;
      font-size: 0.76rem;
      background: rgba(14, 45, 31, 0.5);
      color: var(--text);
      white-space: nowrap;
    }

    .cal {
      margin-top: 10px;
      border-top: 1px dotted rgba(150, 205, 176, 0.35);
      padding-top: 10px;
    }

    .cal h2 {
      margin: 0 0 8px;
      font-size: 0.83rem;
      letter-spacing: 0.06em;
      text-transform: uppercase;
      color: var(--muted);
    }

    .control {
      margin-bottom: 8px;
      font-size: 0.76rem;
      color: var(--muted);
    }

    .control label {
      display: flex;
      justify-content: space-between;
      gap: 10px;
      margin-bottom: 4px;
    }

    .control input[type="range"] {
      width: 100%;
      accent-color: var(--accent);
    }

    .zoom {
      margin-top: 10px;
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }

    .zoom button {
      border: 1px solid rgba(83, 255, 159, 0.45);
      background: rgba(18, 54, 37, 0.8);
      color: var(--text);
      border-radius: 8px;
      padding: 5px 9px;
      font-size: 0.78rem;
      cursor: pointer;
    }

    .zoom button:hover { filter: brightness(1.1); }

    .zoom .range {
      color: var(--muted);
      font-size: 0.77rem;
      white-space: nowrap;
    }

    .inspector {
      position: absolute;
      top: 14px;
      right: 14px;
      width: min(380px, calc(100vw - 28px));
      max-height: min(42vh, 460px);
      overflow: auto;
      background: var(--panel);
      border: 1px solid var(--panel-border);
      border-radius: 12px;
      padding: 12px;
      backdrop-filter: blur(5px);
      font-size: 0.8rem;
      line-height: 1.35;
    }

    .inspector h2 {
      margin: 0 0 6px;
      font-size: 0.88rem;
      letter-spacing: 0.06em;
      text-transform: uppercase;
    }

    .warn { color: var(--warn); }

    .legend {
      position: absolute;
      right: 14px;
      bottom: 14px;
      width: min(560px, calc(100vw - 28px));
      max-height: min(48vh, 500px);
      overflow: auto;
      background: var(--panel);
      border: 1px solid var(--panel-border);
      border-radius: 12px;
      padding: 12px;
      backdrop-filter: blur(5px);
    }

    .legend h2 {
      margin: 0 0 8px;
      font-size: 0.9rem;
      letter-spacing: 0.06em;
      text-transform: uppercase;
    }

    .legend-item {
      width: 100%;
      border: 0;
      border-bottom: 1px dotted rgba(150, 205, 176, 0.25);
      background: transparent;
      color: var(--text);
      padding: 7px 0;
      text-align: left;
      display: flex;
      justify-content: space-between;
      gap: 10px;
      align-items: center;
      cursor: pointer;
      font-size: 0.79rem;
    }

    .legend-item:last-child { border-bottom: 0; }

    .legend-item:hover { color: #f3fffa; }

    .legend-item .left {
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      max-width: 68%;
    }

    .legend-item .right {
      color: var(--muted);
      white-space: nowrap;
      font-size: 0.76rem;
    }

    .legend-item.active {
      color: var(--accent);
      border-color: rgba(83, 255, 159, 0.5);
    }

    @media (max-width: 980px) {
      .panel {
        max-height: min(46vh, 470px);
      }
      .inspector {
        top: auto;
        bottom: 14px;
        left: 14px;
        right: auto;
        width: min(460px, calc(100vw - 28px));
        max-height: min(34vh, 340px);
      }
      .legend {
        top: 14px;
        right: 14px;
        bottom: auto;
        width: min(420px, calc(100vw - 28px));
        max-height: min(42vh, 420px);
      }
    }
  </style>
</head>
<body>
  <div id="wrap">
    <canvas id="radar"></canvas>

    <div class="panel">
      <h1>RSSI Cartographer</h1>
      <div class="sub" id="statusLine">Live network radar</div>
      <div class="meta" id="meta"></div>
      <div class="chip-row" id="chips"></div>

      <div class="cal">
        <h2>Calibration</h2>
        <div class="control">
          <label>
            <span>Path-Loss Exponent (n)</span>
            <span id="pathLossVal"></span>
          </label>
          <input id="pathLossSlider" type="range" min="1.6" max="3.6" step="0.05" />
        </div>
        <div class="control">
          <label>
            <span>Reference RSSI @1m (dBm)</span>
            <span id="rssiRefVal"></span>
          </label>
          <input id="rssiRefSlider" type="range" min="-75" max="-35" step="1" />
        </div>
        <div class="control">
          <label>
            <span>RTT Gain</span>
            <span id="rttGainVal"></span>
          </label>
          <input id="rttGainSlider" type="range" min="8" max="70" step="1" />
        </div>
        <div class="control">
          <label>
            <span>RTT Exponent</span>
            <span id="rttExpVal"></span>
          </label>
          <input id="rttExpSlider" type="range" min="0.8" max="1.9" step="0.05" />
        </div>
      </div>

      <div class="zoom">
        <button id="zoomOut" title="Zoom out">-</button>
        <button id="zoomReset" title="Reset to auto range">Auto</button>
        <button id="zoomIn" title="Zoom in">+</button>
        <span class="range" id="rangeReadout">Range: --</span>
      </div>
    </div>

    <div class="inspector" id="inspector">
      <h2>Device Inspector</h2>
      Click a device dot or legend row to inspect details.
    </div>

    <div class="legend">
      <h2>Detected Devices</h2>
      <div id="legendList"></div>
    </div>
  </div>

  <script>
    const INITIAL_STATE = __INITIAL_STATE__;

    const canvas = document.getElementById('radar');
    const ctx = canvas.getContext('2d');

    const metaEl = document.getElementById('meta');
    const chipsEl = document.getElementById('chips');
    const legendEl = document.getElementById('legendList');
    const inspectorEl = document.getElementById('inspector');
    const statusLineEl = document.getElementById('statusLine');
    const rangeReadoutEl = document.getElementById('rangeReadout');

    const pathLossSlider = document.getElementById('pathLossSlider');
    const rssiRefSlider = document.getElementById('rssiRefSlider');
    const rttGainSlider = document.getElementById('rttGainSlider');
    const rttExpSlider = document.getElementById('rttExpSlider');
    const pathLossVal = document.getElementById('pathLossVal');
    const rssiRefVal = document.getElementById('rssiRefVal');
    const rttGainVal = document.getElementById('rttGainVal');
    const rttExpVal = document.getElementById('rttExpVal');

    const zoomInBtn = document.getElementById('zoomIn');
    const zoomOutBtn = document.getElementById('zoomOut');
    const zoomResetBtn = document.getElementById('zoomReset');

    const RADAR = {
      data: INITIAL_STATE,
      nodes: [],
      layoutDirty: true,
      selectedKey: null,
      hoveredKey: null,
      zoom: 1,
      minZoom: 0.45,
      maxZoom: 8,
      ringCount: 5,
      autoRangeM: 25,
      ringStepM: 5,
      pollMs: 7000,
      fetching: false,
      calibrationInitialized: false,
      calibration: {
        ref_rssi_1m_dbm: -52,
        path_loss_exponent: 2.2,
        rtt_gain_m_per_ms_pow: 28,
        rtt_exponent: 1.30,
        max_distance_m: 250,
      }
    };

    function esc(value) {
      return String(value ?? '').replace(/[&<>"']/g, s => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
      }[s]));
    }

    function clamp(value, min, max) {
      return Math.max(min, Math.min(max, value));
    }

    function toNum(value) {
      const n = Number(value);
      return Number.isFinite(n) ? n : null;
    }

    function hash32(text) {
      let h = 2166136261 >>> 0;
      const input = String(text || '');
      for (let i = 0; i < input.length; i++) {
        h ^= input.charCodeAt(i);
        h = Math.imul(h, 16777619);
      }
      return h >>> 0;
    }

    function deviceKey(device) {
      return String(device.ip || device.mac || device.hostname || device.id || Math.random());
    }

    function deviceLabel(device) {
      return device.hostname || device.mac || device.ip || 'unknown';
    }

    function confidenceLabel(conf) {
      if (conf >= 0.55) return 'medium';
      if (conf >= 0.35) return 'low+';
      if (conf > 0) return 'low';
      return 'n/a';
    }

    function colorForNode(distance, confidence) {
      if (!Number.isFinite(distance)) return '#ffe08a';
      if (confidence >= 0.52) return '#53ff9f';
      if (confidence >= 0.35) return '#d6ff8a';
      return '#ffc96b';
    }

    function niceStep(rawStep) {
      if (!Number.isFinite(rawStep) || rawStep <= 0) return 5;
      const exponent = Math.floor(Math.log10(rawStep));
      const base = Math.pow(10, exponent);
      const fraction = rawStep / base;

      let niceFraction = 1;
      if (fraction <= 1) niceFraction = 1;
      else if (fraction <= 2) niceFraction = 2;
      else if (fraction <= 2.5) niceFraction = 2.5;
      else if (fraction <= 5) niceFraction = 5;
      else niceFraction = 10;

      return niceFraction * base;
    }

    function fmtDistance(meters) {
      if (!Number.isFinite(meters)) return 'n/a';
      if (meters < 10) return `${meters.toFixed(1)} m`;
      if (meters < 100) return `${meters.toFixed(0)} m`;
      return `${meters.toFixed(0)} m`;
    }

    function fmtLatency(ms) {
      if (!Number.isFinite(ms)) return 'n/a';
      return `${ms.toFixed(2)} ms`;
    }

    function effectiveGatewayAnchor() {
      const wifiRssi = toNum(RADAR.data?.sensors?.wifi?.rssi);
      const ref = RADAR.calibration.ref_rssi_1m_dbm;
      const n = RADAR.calibration.path_loss_exponent;
      if (Number.isFinite(wifiRssi) && Number.isFinite(ref) && Number.isFinite(n) && n > 0) {
        const anchor = Math.pow(10, (ref - wifiRssi) / (10 * n));
        return clamp(anchor, 0.5, RADAR.calibration.max_distance_m);
      }

      const fallback = toNum(RADAR.data?.distance_model?.gateway_anchor_m);
      if (Number.isFinite(fallback)) return fallback;
      return 3;
    }

    function deriveDistance(device) {
      const baseline = toNum(RADAR.data?.distance_model?.rtt_baseline_ms) ?? 1.2;
      const gatewayIp = RADAR.data?.host?.gateway_ip || null;
      const latency = toNum(device.latency_ms);
      const anchor = effectiveGatewayAnchor();

      if (gatewayIp && device.ip === gatewayIp && Number.isFinite(toNum(RADAR.data?.sensors?.wifi?.rssi))) {
        return clamp(anchor, 0.5, RADAR.calibration.max_distance_m);
      }

      if (!Number.isFinite(latency)) {
        const known = toNum(device.distance_m);
        return Number.isFinite(known) ? clamp(known, 0.5, RADAR.calibration.max_distance_m) : null;
      }

      const delta = Math.max(0, latency - baseline);
      const estimate = anchor + Math.pow(Math.max(0.05, delta), RADAR.calibration.rtt_exponent) * RADAR.calibration.rtt_gain_m_per_ms_pow;
      return clamp(estimate, 0.8, RADAR.calibration.max_distance_m);
    }

    function applyCalibrationDefaultsIfNeeded() {
      if (RADAR.calibrationInitialized) return;

      const defaults = RADAR.data?.distance_model?.calibration_defaults || {};
      if (Number.isFinite(toNum(defaults.ref_rssi_1m_dbm))) RADAR.calibration.ref_rssi_1m_dbm = Number(defaults.ref_rssi_1m_dbm);
      if (Number.isFinite(toNum(defaults.path_loss_exponent))) RADAR.calibration.path_loss_exponent = Number(defaults.path_loss_exponent);
      if (Number.isFinite(toNum(defaults.rtt_gain_m_per_ms_pow))) RADAR.calibration.rtt_gain_m_per_ms_pow = Number(defaults.rtt_gain_m_per_ms_pow);
      if (Number.isFinite(toNum(defaults.rtt_exponent))) RADAR.calibration.rtt_exponent = Number(defaults.rtt_exponent);
      if (Number.isFinite(toNum(defaults.max_distance_m))) RADAR.calibration.max_distance_m = Number(defaults.max_distance_m);

      RADAR.calibrationInitialized = true;
      syncCalibrationControls();
    }

    function syncCalibrationControls() {
      pathLossSlider.value = String(RADAR.calibration.path_loss_exponent);
      rssiRefSlider.value = String(RADAR.calibration.ref_rssi_1m_dbm);
      rttGainSlider.value = String(RADAR.calibration.rtt_gain_m_per_ms_pow);
      rttExpSlider.value = String(RADAR.calibration.rtt_exponent);

      pathLossVal.textContent = RADAR.calibration.path_loss_exponent.toFixed(2);
      rssiRefVal.textContent = `${RADAR.calibration.ref_rssi_1m_dbm.toFixed(0)} dBm`;
      rttGainVal.textContent = RADAR.calibration.rtt_gain_m_per_ms_pow.toFixed(0);
      rttExpVal.textContent = RADAR.calibration.rtt_exponent.toFixed(2);
    }

    function markCalibrationChanged() {
      RADAR.layoutDirty = true;
      renderLegend();
      renderMeta();
      renderInspector();
    }

    pathLossSlider.addEventListener('input', () => {
      RADAR.calibration.path_loss_exponent = Number(pathLossSlider.value);
      syncCalibrationControls();
      markCalibrationChanged();
    });

    rssiRefSlider.addEventListener('input', () => {
      RADAR.calibration.ref_rssi_1m_dbm = Number(rssiRefSlider.value);
      syncCalibrationControls();
      markCalibrationChanged();
    });

    rttGainSlider.addEventListener('input', () => {
      RADAR.calibration.rtt_gain_m_per_ms_pow = Number(rttGainSlider.value);
      syncCalibrationControls();
      markCalibrationChanged();
    });

    rttExpSlider.addEventListener('input', () => {
      RADAR.calibration.rtt_exponent = Number(rttExpSlider.value);
      syncCalibrationControls();
      markCalibrationChanged();
    });

    function recomputeDerivedDevices() {
      const devices = RADAR.data?.devices || [];
      for (const dev of devices) {
        const distance = deriveDistance(dev);
        dev.ui_distance_m = Number.isFinite(distance) ? Number(distance.toFixed(2)) : null;

        const confRaw = toNum(dev.distance_confidence);
        dev.ui_confidence = Number.isFinite(confRaw)
          ? clamp(confRaw, 0, 1)
          : (Number.isFinite(dev.ui_distance_m) ? 0.2 : 0);
      }
    }

    function computeAutoRange() {
      const distances = (RADAR.data?.devices || [])
        .map(d => toNum(d.ui_distance_m))
        .filter(d => Number.isFinite(d) && d > 0);

      if (!distances.length) {
        RADAR.ringStepM = 5;
        RADAR.autoRangeM = 25;
        return;
      }

      const maxDistance = Math.max(...distances, 8);
      const rawStep = maxDistance / RADAR.ringCount;
      const step = niceStep(rawStep);
      RADAR.ringStepM = step;
      RADAR.autoRangeM = step * RADAR.ringCount;
    }

    function sizeCanvas() {
      const dpr = window.devicePixelRatio || 1;
      canvas.width = Math.floor(window.innerWidth * dpr);
      canvas.height = Math.floor(window.innerHeight * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      RADAR.layoutDirty = true;
    }

    function updateZoomReadout() {
      const effectiveRange = RADAR.autoRangeM / RADAR.zoom;
      rangeReadoutEl.textContent = `Range: ${fmtDistance(effectiveRange)} (zoom ${RADAR.zoom.toFixed(2)}x)`;
    }

    function adjustZoom(factor) {
      RADAR.zoom = clamp(RADAR.zoom * factor, RADAR.minZoom, RADAR.maxZoom);
      RADAR.layoutDirty = true;
      updateZoomReadout();
    }

    zoomInBtn.addEventListener('click', () => adjustZoom(1.18));
    zoomOutBtn.addEventListener('click', () => adjustZoom(1 / 1.18));
    zoomResetBtn.addEventListener('click', () => {
      RADAR.zoom = 1;
      RADAR.layoutDirty = true;
      updateZoomReadout();
    });

    canvas.addEventListener('wheel', event => {
      event.preventDefault();
      adjustZoom(event.deltaY < 0 ? 1.13 : 1 / 1.13);
    }, { passive: false });

    function buildLayout() {
      const devices = [...(RADAR.data?.devices || [])];

      const w = window.innerWidth;
      const h = window.innerHeight;
      const cx = w / 2;
      const cy = h / 2;
      const radarRadius = Math.min(w, h) * 0.41;
      const effectiveRange = RADAR.autoRangeM / RADAR.zoom;
      const metersPerPixel = effectiveRange / radarRadius;

      // Order by distance so near targets retain priority in dense layouts.
      devices.sort((a, b) => {
        const da = Number.isFinite(toNum(a.ui_distance_m)) ? Number(a.ui_distance_m) : Number.POSITIVE_INFINITY;
        const db = Number.isFinite(toNum(b.ui_distance_m)) ? Number(b.ui_distance_m) : Number.POSITIVE_INFINITY;
        return da - db;
      });

      const maxDraw = 220;
      const clipped = devices.slice(0, maxDraw);

      const nodes = clipped.map((dev, idx) => {
        const key = deviceKey(dev);
        const seed = hash32(key);
        const baseAngleDeg = (seed % 3600) / 10;
        const angle = (baseAngleDeg * Math.PI) / 180;

        const distM = toNum(dev.ui_distance_m);
        const targetRadius = Number.isFinite(distM)
          ? clamp(distM / metersPerPixel, 22, radarRadius - 8)
          : clamp(radarRadius - 20 - (idx % 5) * 3, 22, radarRadius - 8);

        const pointR = 4 + clamp((dev.ui_confidence || 0) * 5, 0, 5) + (dev.is_gateway ? 1.2 : 0);

        return {
          key,
          dev,
          angle,
          targetRadius,
          pointR,
          x: cx + Math.cos(angle) * targetRadius,
          y: cy + Math.sin(angle) * targetRadius,
        };
      });

      const n = nodes.length;
      const iterations = n > 120 ? 36 : 72;

      for (let iter = 0; iter < iterations; iter++) {
        for (let i = 0; i < n; i++) {
          for (let j = i + 1; j < n; j++) {
            const a = nodes[i];
            const b = nodes[j];
            let dx = b.x - a.x;
            let dy = b.y - a.y;
            let distSq = dx * dx + dy * dy;
            if (distSq < 0.0001) {
              dx = 0.1;
              dy = 0.1;
              distSq = 0.02;
            }

            const dist = Math.sqrt(distSq);
            const minSep = a.pointR + b.pointR + 10;
            if (dist < minSep) {
              const push = (minSep - dist) * 0.5;
              const ux = dx / dist;
              const uy = dy / dist;
              a.x -= ux * push;
              a.y -= uy * push;
              b.x += ux * push;
              b.y += uy * push;
            }
          }
        }

        for (const node of nodes) {
          const tx = cx + Math.cos(node.angle) * node.targetRadius;
          const ty = cy + Math.sin(node.angle) * node.targetRadius;

          node.x += (tx - node.x) * 0.06;
          node.y += (ty - node.y) * 0.06;

          const dx = node.x - cx;
          const dy = node.y - cy;
          const radial = Math.sqrt(dx * dx + dy * dy) || 0.001;
          const maxR = radarRadius - node.pointR - 5;
          if (radial > maxR) {
            node.x = cx + (dx / radial) * maxR;
            node.y = cy + (dy / radial) * maxR;
          }
        }
      }

      RADAR.nodes = nodes;
      RADAR.layoutDirty = false;
      updateZoomReadout();
    }

    function drawGrid(cx, cy, radarRadius) {
      ctx.save();
      ctx.strokeStyle = 'rgba(83,255,159,0.22)';
      ctx.lineWidth = 1;

      for (let i = 1; i <= RADAR.ringCount; i++) {
        const r = (radarRadius / RADAR.ringCount) * i;
        ctx.beginPath();
        ctx.arc(cx, cy, r, 0, Math.PI * 2);
        ctx.stroke();

        const meters = RADAR.ringStepM * i / RADAR.zoom;
        ctx.fillStyle = 'rgba(150, 205, 176, 0.9)';
        ctx.font = '11px Menlo, Monaco, monospace';
        ctx.fillText(`${meters.toFixed(meters < 10 ? 1 : 0)} m`, cx + 9, cy - r + 12);
      }

      for (let deg = 0; deg < 360; deg += 30) {
        const rad = (deg * Math.PI) / 180;
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.lineTo(cx + Math.cos(rad) * radarRadius, cy + Math.sin(rad) * radarRadius);
        ctx.stroke();
      }

      ctx.restore();
    }

    function drawSweep(cx, cy, radarRadius, t) {
      const angle = ((t / 45) % 360) * Math.PI / 180;
      const spread = 0.15;
      const grad = ctx.createRadialGradient(cx, cy, 0, cx, cy, radarRadius);
      grad.addColorStop(0, 'rgba(83,255,159,0.18)');
      grad.addColorStop(1, 'rgba(83,255,159,0.0)');

      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(angle);

      ctx.fillStyle = grad;
      ctx.beginPath();
      ctx.moveTo(0, 0);
      ctx.arc(0, 0, radarRadius, -spread, spread);
      ctx.closePath();
      ctx.fill();

      ctx.strokeStyle = 'rgba(83,255,159,0.84)';
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.moveTo(0, 0);
      ctx.lineTo(radarRadius, 0);
      ctx.stroke();

      ctx.restore();
    }

    function drawLocalNode(cx, cy) {
      ctx.save();
      ctx.fillStyle = '#53ff9f';
      ctx.shadowColor = 'rgba(83,255,159,0.8)';
      ctx.shadowBlur = 14;
      ctx.beginPath();
      ctx.arc(cx, cy, 7.2, 0, Math.PI * 2);
      ctx.fill();
      ctx.restore();

      ctx.save();
      ctx.fillStyle = '#defeea';
      ctx.font = '12px Menlo, Monaco, monospace';
      ctx.fillText('THIS MAC', cx + 12, cy - 10);
      ctx.restore();
    }

    function drawNodeTooltip(node) {
      const dev = node.dev;
      const title = deviceLabel(dev);
      const distance = fmtDistance(dev.ui_distance_m);

      ctx.save();
      ctx.font = '11px Menlo, Monaco, monospace';
      const text = `${title} | ${distance}`;
      const width = ctx.measureText(text).width + 12;
      const height = 18;
      const x = node.x + 10;
      const y = node.y - 22;

      ctx.fillStyle = 'rgba(5, 20, 14, 0.86)';
      ctx.strokeStyle = 'rgba(83,255,159,0.45)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.rect(x, y, width, height);
      ctx.fill();
      ctx.stroke();

      ctx.fillStyle = '#dcffe9';
      ctx.fillText(text, x + 6, y + 12.5);
      ctx.restore();
    }

    function drawDevices(t) {
      const pulse = Math.sin(t / 220) * 0.7;

      for (const node of RADAR.nodes) {
        const dev = node.dev;
        const selected = node.key === RADAR.selectedKey;
        const hovered = node.key === RADAR.hoveredKey;

        const color = colorForNode(dev.ui_distance_m, dev.ui_confidence || 0);
        const radius = node.pointR + pulse;

        ctx.save();
        ctx.fillStyle = color;
        ctx.shadowColor = color;
        ctx.shadowBlur = hovered || selected ? 16 : 11;
        ctx.beginPath();
        ctx.arc(node.x, node.y, radius, 0, Math.PI * 2);
        ctx.fill();

        if (selected || hovered) {
          ctx.shadowBlur = 0;
          ctx.strokeStyle = 'rgba(220,255,233,0.96)';
          ctx.lineWidth = 1.8;
          ctx.beginPath();
          ctx.arc(node.x, node.y, radius + 4.5, 0, Math.PI * 2);
          ctx.stroke();
        }

        if (dev.is_gateway) {
          ctx.shadowBlur = 0;
          ctx.strokeStyle = 'rgba(255,214,133,0.9)';
          ctx.lineWidth = 1.3;
          ctx.beginPath();
          ctx.arc(node.x, node.y, radius + 2.4, 0, Math.PI * 2);
          ctx.stroke();
        }

        ctx.restore();
      }

      const focus = RADAR.nodes.find(n => n.key === RADAR.selectedKey) || RADAR.nodes.find(n => n.key === RADAR.hoveredKey);
      if (focus) drawNodeTooltip(focus);
    }

    function pickNode(clientX, clientY) {
      const rect = canvas.getBoundingClientRect();
      const x = clientX - rect.left;
      const y = clientY - rect.top;

      let best = null;
      let bestDist = Number.POSITIVE_INFINITY;

      for (const node of RADAR.nodes) {
        const dx = x - node.x;
        const dy = y - node.y;
        const d = Math.sqrt(dx * dx + dy * dy);
        const hitR = node.pointR + 7;
        if (d <= hitR && d < bestDist) {
          best = node;
          bestDist = d;
        }
      }
      return best;
    }

    canvas.addEventListener('mousemove', event => {
      const picked = pickNode(event.clientX, event.clientY);
      const newHover = picked ? picked.key : null;
      if (newHover !== RADAR.hoveredKey) {
        RADAR.hoveredKey = newHover;
        canvas.style.cursor = picked ? 'pointer' : 'crosshair';
      }
    });

    canvas.addEventListener('mouseleave', () => {
      RADAR.hoveredKey = null;
      canvas.style.cursor = 'crosshair';
    });

    canvas.addEventListener('click', event => {
      const picked = pickNode(event.clientX, event.clientY);
      RADAR.selectedKey = picked ? picked.key : null;
      renderLegend();
      renderInspector();
    });

    function renderMeta() {
      const data = RADAR.data || {};
      const host = data.host || {};
      const scan = data.scan || {};
      const devices = data.devices || [];

      const rendered = RADAR.nodes.length;
      const total = devices.length;
      const hidden = Math.max(0, total - rendered);

      const lines = [
        `Scan Time: ${esc(data.generated_at || 'unknown')}`,
        `Interface: ${esc(host.interface || 'unknown')}`,
        `Local IP: ${esc(host.ip || 'unknown')}`,
        `Gateway: ${esc(host.gateway_ip || 'unknown')}`,
        `Subnet: ${esc(data.network || 'unknown')}`,
        `Devices: ${total}${hidden ? ` (showing ${rendered})` : ''}`,
        `Scan #${esc(scan.sequence || 0)} • Duration ${esc(scan.duration_ms || 0)} ms • Refresh ${esc(scan.refresh_seconds || '-') } s`
      ];
      metaEl.innerHTML = lines.join('<br>');

      statusLineEl.textContent = scan.last_error
        ? `Scan warning: ${scan.last_error}`
        : 'Live network radar (auto-updating)';

      const chips = [];
      const wifi = data.sensors?.wifi || {};
      const bt = data.sensors?.bluetooth || {};
      const batt = data.sensors?.battery || {};

      if (wifi.ssid) chips.push(`Wi-Fi ${esc(wifi.ssid)}`);
      if (Number.isFinite(toNum(wifi.rssi))) chips.push(`RSSI ${Number(wifi.rssi)} dBm`);
      if (Number.isFinite(toNum(wifi.noise))) chips.push(`Noise ${Number(wifi.noise)} dBm`);
      if (wifi.channel) chips.push(`Channel ${esc(wifi.channel)}`);
      if (Number.isFinite(toNum(bt.connected_devices_seen))) chips.push(`BT Connected ${Number(bt.connected_devices_seen)}`);
      if (Number.isFinite(toNum(bt.paired_devices_seen))) chips.push(`BT Paired ${Number(bt.paired_devices_seen)}`);
      if (Number.isFinite(toNum(batt.percent))) chips.push(`Battery ${Number(batt.percent)}%`);
      if (batt.state) chips.push(`Power ${esc(batt.state)}`);
      chips.push(`Anchor ${fmtDistance(effectiveGatewayAnchor())}`);

      chipsEl.innerHTML = chips.length
        ? chips.map(v => `<span class="chip">${v}</span>`).join('')
        : '<span class="chip">Sensor snapshots unavailable</span>';
    }

    function renderLegend() {
      const devices = RADAR.data?.devices || [];
      if (!devices.length) {
        legendEl.innerHTML = '<div class="warn">No remote devices detected yet. Radar will update automatically.</div>';
        return;
      }

      const rows = devices.map(dev => {
        const key = deviceKey(dev);
        const active = key === RADAR.selectedKey ? 'active' : '';
        const name = esc(deviceLabel(dev));
        const ip = esc(dev.ip || 'unknown');
        const distance = fmtDistance(dev.ui_distance_m);
        const latency = fmtLatency(toNum(dev.latency_ms));
        const conf = confidenceLabel(toNum(dev.ui_confidence) || 0);
        const method = esc(dev.distance_method || 'unknown');

        return `<button class="legend-item ${active}" data-key="${esc(key)}">
          <span class="left">${name} <span class="right">(${ip})</span></span>
          <span class="right">${distance} • ${latency} • ${conf} • ${method}</span>
        </button>`;
      });

      legendEl.innerHTML = rows.join('');
    }

    legendEl.addEventListener('click', event => {
      const row = event.target.closest('[data-key]');
      if (!row) return;
      RADAR.selectedKey = row.getAttribute('data-key');
      renderLegend();
      renderInspector();
    });

    function renderInspector() {
      const devices = RADAR.data?.devices || [];
      const selected = devices.find(dev => deviceKey(dev) === RADAR.selectedKey);

      if (!selected) {
        inspectorEl.innerHTML = `
          <h2>Device Inspector</h2>
          Click a device dot or legend row to inspect details.<br>
          <span class="warn">Distance note:</span> Current distances are calibrated estimates. True meter-level ranging typically requires IEEE 802.11mc/802.11az FTM or UWB.
        `;
        return;
      }

      const lines = [
        `<h2>${esc(deviceLabel(selected))}</h2>`,
        `IP: <b>${esc(selected.ip || 'unknown')}</b><br>`,
        `MAC: <b>${esc(selected.mac || 'unknown')}</b><br>`,
        `Hostname: <b>${esc(selected.hostname || 'unknown')}</b><br>`,
        `Distance: <b>${esc(fmtDistance(selected.ui_distance_m))}</b><br>`,
        `Distance Confidence: <b>${esc(confidenceLabel(toNum(selected.ui_confidence) || 0))}</b><br>`,
        `Distance Method: <b>${esc(selected.distance_method || 'unknown')}</b><br>`,
        `Latency: <b>${esc(fmtLatency(toNum(selected.latency_ms)))}</b><br>`,
        `Jitter: <b>${esc(fmtLatency(toNum(selected.latency_jitter_ms)))}</b><br>`,
        `Samples: <b>${esc(selected.latency_samples || 0)}</b><br>`,
        `Gateway Node: <b>${selected.is_gateway ? 'yes' : 'no'}</b><br>`,
        `Last Seen: <b>${esc(selected.last_seen || 'unknown')}</b><br>`,
        `<br><span class="warn">Calibration:</span> Path-loss n=${RADAR.calibration.path_loss_exponent.toFixed(2)}, RSSI@1m=${RADAR.calibration.ref_rssi_1m_dbm.toFixed(0)} dBm, RTT gain=${RADAR.calibration.rtt_gain_m_per_ms_pow.toFixed(0)}, RTT exp=${RADAR.calibration.rtt_exponent.toFixed(2)}.`
      ];

      inspectorEl.innerHTML = lines.join('');
    }

    async function refreshState() {
      if (RADAR.fetching) return;
      RADAR.fetching = true;

      try {
        const response = await fetch(`/api/state?ts=${Date.now()}`, { cache: 'no-store' });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const nextState = await response.json();
        RADAR.data = nextState;

        applyCalibrationDefaultsIfNeeded();
        recomputeDerivedDevices();
        computeAutoRange();
        RADAR.layoutDirty = true;

        renderMeta();
        renderLegend();
        renderInspector();
      } catch (error) {
        statusLineEl.textContent = `Refresh error: ${String(error)}`;
      } finally {
        RADAR.fetching = false;
      }
    }

    function tick(t) {
      const w = window.innerWidth;
      const h = window.innerHeight;
      const cx = w / 2;
      const cy = h / 2;
      const radarRadius = Math.min(w, h) * 0.41;

      if (RADAR.layoutDirty) {
        buildLayout();
      }

      ctx.clearRect(0, 0, w, h);
      drawGrid(cx, cy, radarRadius);
      drawSweep(cx, cy, radarRadius, t);
      drawLocalNode(cx, cy);
      drawDevices(t);

      requestAnimationFrame(tick);
    }

    window.addEventListener('resize', sizeCanvas);

    function bootstrap() {
      applyCalibrationDefaultsIfNeeded();
      recomputeDerivedDevices();
      computeAutoRange();
      sizeCanvas();
      renderMeta();
      renderLegend();
      renderInspector();
      updateZoomReadout();
      requestAnimationFrame(tick);
      refreshState();
      setInterval(refreshState, RADAR.pollMs);
    }

    bootstrap();
  </script>
</body>
</html>
"""

    return page.replace("__INITIAL_STATE__", json.dumps(initial_state))


def serve_app(state: LiveScanState, html_page: str, port: int, auto_open: bool) -> None:
    handler_cls = RadarRequestHandler
    handler_cls.state = state
    handler_cls.html_page = html_page

    server = ThreadingHTTPServer(("127.0.0.1", port), handler_cls)
    url = f"http://127.0.0.1:{port}/"

    shutting_down = threading.Event()

    def shutdown(*_: Any) -> None:
        if shutting_down.is_set():
            return
        shutting_down.set()

        def close_server() -> None:
            state.stop()
            server.shutdown()

        threading.Thread(target=close_server, daemon=True).start()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    if auto_open:
        subprocess.Popen(["open", url])

    print(f"\n[{APP_TITLE}] Radar live at {url}")
    print(f"[{APP_TITLE}] Auto-refresh every {state.refresh_seconds}s. Press Ctrl+C to stop.\n")

    try:
        server.serve_forever(poll_interval=0.3)
    finally:
        server.server_close()
        state.stop()


def main() -> int:
    parser = argparse.ArgumentParser(description="Live local network radar for macOS")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Preferred local HTTP port")
    parser.add_argument("--refresh", type=int, default=DEFAULT_REFRESH_SECONDS, help="Rescan interval in seconds")
    parser.add_argument("--max-hosts", type=int, default=DEFAULT_MAX_SCAN_HOSTS, help="Max hosts to probe per scan")
    parser.add_argument("--no-open", action="store_true", help="Do not auto-open browser")
    args = parser.parse_args()

    print(f"[{APP_TITLE}] Starting live scanner...")
    print(f"[{APP_TITLE}] Running initial scan (this can take a few seconds)...")

    state = LiveScanState(refresh_seconds=args.refresh, max_hosts=args.max_hosts)
    state.start()

    initial = state.snapshot()
    html_page = generate_html(initial)

    port = pick_port(args.port)
    serve_app(state=state, html_page=html_page, port=port, auto_open=not args.no_open)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
