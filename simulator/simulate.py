"""Fake charging stations for testing the backend without hardware.

Each simulated station behaves like the ESP32 sketch: it sends a 2-second averaged
reading to POST /api/ingest, obeys the thresholds in the reply, and prints commands.
One station (the "target") can be made to misbehave with --scenario.

Examples (run from the project root, backend running on port 8000):
    python simulator/simulate.py                                   # 3 normal stations
    python simulator/simulate.py --stations 5 --scenario offline   # sim-01 goes silent
    python simulator/simulate.py --scenario reboot --after 10
    python simulator/simulate.py --list                            # describe all scenarios
"""
import argparse
import asyncio
import random
import time

import httpx

SCENARIOS = {
    "normal":          "No faults. Stations alternate between idle and charging a phone.",
    "offline":         "Target stops sending for --duration seconds, then comes back.",
    "dropout":         "Target randomly misses ~40% of its sends (flaky Wi-Fi).",
    "reboot":          "Target's uptime_s resets to 0 (ESP32 restarted / power-cycled).",
    "unplug":          "Charger supply lost: target reports ~0 V while still online.",
    "sag":             "Target voltage sags to ~4.3 V (weak or overloaded charger).",
    "overvoltage":     "Target voltage rises to ~5.8 V (faulty charger).",
    "spike":           "Target current spikes to ~2.9 A for a few readings.",
    "unexpected_load": "No phone, but ~120 mA is drawn (hidden inline module in the port).",
    "sensor_fault":    "Reported power no longer matches V x I (sensor fault / tampered data).",
    "reversed":        "Negative current (INA219 VIN+ / VIN- swapped).",
    "tamper":          "Target reports data_blocked=false (firmware was modified).",
    "bad_key":         "Target uses a wrong API key (rogue device) -> 401s.",
    "clone":           "A second sender also claims the target's device_id (cloned station).",
    "garbage":         "Target sends impossible values (40 V) -> 422s.",
}

NO_SUPPLY_V, HYST, CONSECUTIVE = 1.0, 0.10, 3


class Station:
    def __init__(self, device_id: str, args, is_target: bool, label: str | None = None):
        self.id = device_id
        self.label = label or device_id
        self.args = args
        self.is_target = is_target
        self.boot = time.monotonic()
        self.sag_v, self.over_v = 4.50, 5.50
        self.alert, self.candidate, self.bad, self.good = "NONE", "NONE", 0, 0
        self.last_state = None
        self.rebooted = False
        # Charging cycle: each station gets its own rhythm.
        self.cycle_s = random.uniform(40, 90)
        self.phase_offset = random.uniform(0, self.cycle_s)
        self.base_v = random.uniform(5.00, 5.12)
        self.max_ma = random.uniform(900, 2000)

    # ---------------------------------------------------------- scenario
    def active(self, t: float) -> bool:
        a = self.args
        return self.is_target and a.scenario != "normal" and a.after <= t < a.after + a.duration

    # ---------------------------------------------------------- physics
    def reading(self, t: float) -> dict:
        sc = self.args.scenario if self.active(t) else "normal"

        if sc == "reboot" and not self.rebooted:
            self.rebooted = True
            self.boot = time.monotonic()
            self.log(t, "*** simulated reboot: uptime reset to 0")

        pos = ((t + self.phase_offset) % self.cycle_s) / self.cycle_s
        charging = pos < 0.6  # 60% of the cycle a phone is plugged in
        if charging:  # taper as the "battery" fills
            current = self.max_ma * (1 - 0.5 * pos / 0.6) + random.gauss(0, 15)
        else:
            current = random.uniform(0.5, 3.0)
        voltage = self.base_v - current / 1000 * 0.12 + random.gauss(0, 0.01)

        if sc == "unplug":
            voltage, current = random.uniform(0.0, 0.05), 0.0
        elif sc == "sag":
            voltage = 4.30 + random.gauss(0, 0.02)
        elif sc == "overvoltage":
            voltage = 5.80 + random.gauss(0, 0.02)
        elif sc == "spike":
            current = 2900 + random.gauss(0, 30)
        elif sc == "unexpected_load":
            current = 120 + random.gauss(0, 5)
        elif sc == "reversed":
            current = -abs(current) - 50
        elif sc == "garbage":
            voltage = 40.0

        current = round(current, 1)
        shunt = current * 0.1  # 0.1 ohm shunt: mV = mA x 0.1
        power = voltage * current if current > 0 else 0.0
        if sc == "sensor_fault":
            power *= 0.45

        self.update_alert(voltage)
        return {
            "device_id": self.id,
            "voltage_v": round(voltage, 3),
            "source_voltage_v": round(voltage + shunt / 1000, 3),
            "shunt_mv": round(shunt, 2),
            "current_ma": current,
            "power_mw": round(power, 1),
            "data_blocked": sc != "tamper",
            "device_alert": self.alert,
            "source": "simulator",
            "rssi": random.randint(-72, -50) if sc != "dropout" else random.randint(-88, -80),
            "uptime_s": int(time.monotonic() - self.boot),
        }

    def update_alert(self, v: float):
        """Same sustained-alert logic as updateAlert() in the ESP32 sketch."""
        if v < NO_SUPPLY_V:
            self.alert, self.candidate, self.bad, self.good = "NONE", "NONE", 0, 0
            return
        if self.alert == "NONE":
            now = "LOW_VOLTAGE" if v < self.sag_v else "HIGH_VOLTAGE" if v > self.over_v else "NONE"
            if now == "NONE":
                self.bad, self.candidate = 0, "NONE"
                return
            self.bad = self.bad + 1 if now == self.candidate else 1
            self.candidate = now
            if self.bad >= CONSECUTIVE:
                self.alert, self.good = self.candidate, 0
        else:
            ok = self.sag_v + HYST < v < self.over_v - HYST
            self.good = self.good + 1 if ok else 0
            if self.good >= CONSECUTIVE:
                self.alert, self.candidate, self.bad, self.good = "NONE", "NONE", 0, 0

    # ---------------------------------------------------------- network
    def log(self, t: float, msg: str):
        print(f"[{t:6.1f}s] {self.label:<14} {msg}", flush=True)

    async def run(self, client: httpx.AsyncClient, t0: float, stop: asyncio.Event):
        await asyncio.sleep(random.uniform(0, self.args.interval))  # stagger start
        announced = False
        while not stop.is_set():
            t = time.monotonic() - t0
            sc = self.args.scenario if self.active(t) else "normal"
            if self.active(t) and not announced:
                announced = True
                self.log(t, f"*** scenario '{self.args.scenario}' START ({self.args.duration:.0f}s)")
            if announced and not self.active(t) and t >= self.args.after + self.args.duration:
                announced = False
                self.log(t, f"*** scenario '{self.args.scenario}' END - back to normal")

            skip = sc == "offline" or (sc == "dropout" and random.random() < 0.4)
            if not skip:
                await self.send(client, t, self.reading(t), sc)
            await asyncio.sleep(self.args.interval)

    async def send(self, client: httpx.AsyncClient, t: float, body: dict, sc: str):
        key = "wrong-key-000" if sc == "bad_key" else self.args.key
        summary = f"V={body['voltage_v']:.2f} I={body['current_ma']:7.1f}mA"
        try:
            r = await client.post(self.args.url, json=body, headers={"X-API-Key": key}, timeout=3)
        except httpx.HTTPError as e:
            self.log(t, f"{summary} -> cannot reach server ({type(e).__name__})")
            return
        if r.status_code != 200:
            self.log(t, f"{summary} -> HTTP {r.status_code} {r.text[:120]}")
            return
        reply = r.json()
        th = reply.get("thresholds") or {}
        self.sag_v = th.get("sag_v", self.sag_v)
        self.over_v = th.get("over_voltage_v", self.over_v)
        for cmd in reply.get("commands", []):
            self.log(t, f"[CMD] received '{cmd}'")
        state = reply.get("state")
        if self.args.verbose or state != self.last_state:
            self.log(t, f"{summary} -> 200 {state}")
        self.last_state = state


async def main():
    p = argparse.ArgumentParser(description="Simulate USB charging stations.")
    p.add_argument("--url", default="http://127.0.0.1:8000/api/ingest")
    p.add_argument("--key", default="station-key-123", help="must equal DEVICE_API_KEY in backend/.env")
    p.add_argument("--stations", type=int, default=3)
    p.add_argument("--prefix", default="sim-")
    p.add_argument("--scenario", default="normal", choices=SCENARIOS)
    p.add_argument("--after", type=float, default=15, help="seconds before the scenario starts")
    p.add_argument("--duration", type=float, default=30, help="how long the scenario lasts")
    p.add_argument("--interval", type=float, default=2.0, help="seconds between sends (ESP32 uses 2)")
    p.add_argument("--run-for", type=float, default=0, help="stop after N seconds (0 = until Ctrl+C)")
    p.add_argument("--seed", type=int)
    p.add_argument("--verbose", "-v", action="store_true", help="print every reading, not just changes")
    p.add_argument("--list", action="store_true", help="list scenarios and exit")
    args = p.parse_args()

    if args.list:
        for k, v in SCENARIOS.items():
            print(f"  {k:<16} {v}")
        return
    if args.seed is not None:
        random.seed(args.seed)

    ids = [f"{args.prefix}{i:02d}" for i in range(1, args.stations + 1)]
    stations = [Station(d, args, is_target=(i == 0)) for i, d in enumerate(ids)]
    if args.scenario == "clone":  # extra sender with the same id, active only during the scenario
        clone_args = argparse.Namespace(**{**vars(args), "scenario": "normal"})
        clone = Station(ids[0], clone_args, is_target=False, label=f"{ids[0]}(CLONE)")
        stations.append(_CloneWrapper(clone, args))

    print(f"Simulating {', '.join(ids)} -> {args.url}")
    print(f"Scenario '{args.scenario}' on {ids[0]}: {SCENARIOS[args.scenario]}")
    if args.scenario != "normal":
        print(f"  starts at {args.after:.0f}s, lasts {args.duration:.0f}s")
    print("Ctrl+C to stop.\n")

    stop = asyncio.Event()
    t0 = time.monotonic()
    async with httpx.AsyncClient() as client:
        tasks = [asyncio.create_task(s.run(client, t0, stop)) for s in stations]
        try:
            if args.run_for > 0:
                await asyncio.sleep(args.run_for)
            else:
                await asyncio.Event().wait()
        finally:
            stop.set()
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)


class _CloneWrapper:
    """Runs a cloned station only while the clone scenario is active."""

    def __init__(self, station: Station, args):
        self.s, self.args = station, args
        self.s.boot -= 5000  # different uptime than the real station, as a real clone would have

    async def run(self, client, t0, stop):
        a = self.args
        while not stop.is_set():
            t = time.monotonic() - t0
            if a.after <= t < a.after + a.duration:
                await self.s.send(client, t, self.s.reading(t), "normal")
            await asyncio.sleep(a.interval)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nStopped.")
