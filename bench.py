#!/usr/bin/env python3
"""Performance harness. Measures the collector headless and the full app (window + page).

    python3 bench.py                 # collector: real + demo x1 + demo x10; app: demo x1 + x10
    python3 bench.py --label v2      # appends results to perf/history.jsonl under that label
"""
import argparse
import json
import os
import resource
import statistics
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


def collector_bench(demo_scale, n=25):
    code = f"""
import argparse, json, time, statistics, resource, sys
sys.path.insert(0, {HERE!r})
import collector
collector.setup(argparse.Namespace(demo={demo_scale > 0}, demo_scale={max(demo_scale, 1)}, interval=2.0, no_sniff=True, token=None))
collector.SAMPLER.sample()
t = []
for i in range({n}):
    t0 = time.perf_counter(); collector.SAMPLER.sample(); t.append((time.perf_counter() - t0) * 1000)
    time.sleep(0.05)
ser = []
for i in range(10):
    collector.SAMPLER._snap_json = None
    t0 = time.perf_counter(); b = collector.SAMPLER.snapshot_json(); ser.append((time.perf_counter() - t0) * 1000)
snap = collector.SAMPLER.snapshot
ex = []
for nd in snap["nodes"][:20]:
    t0 = time.perf_counter(); collector.explain(nd["id"]); ex.append((time.perf_counter() - t0) * 1000)
ss = [x[0] for x in collector.SAMPLER.timing]
cpu = resource.getrusage(resource.RUSAGE_SELF); ch = resource.getrusage(resource.RUSAGE_CHILDREN)
print(json.dumps(dict(sampleMs_med=round(statistics.median(t), 2), sampleMs_p95=round(sorted(t)[int(.95 * len(t))], 2),
    ssMs_med=round(statistics.median(ss), 2), serializeMs_med=round(statistics.median(ser), 2), explainMs_med=round(statistics.median(ex), 3) if ex else None,
    jsonKB=round(len(b) / 1024, 1), sockets=snap["perf"]["sockets"], nodes=len(snap["nodes"]), links=len(snap["links"]),
    rssMB=round(cpu.ru_maxrss / 1024, 1), cpuPerSampleMs=round((cpu.ru_utime + cpu.ru_stime + ch.ru_utime + ch.ru_stime) * 1000 / ({n} + 1), 2))))
"""
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=300)
    if out.returncode:
        return {"error": out.stderr[-800:]}
    return json.loads(out.stdout.strip().splitlines()[-1])


def app_bench(demo_scale, seconds=14):
    path = os.path.join("/tmp" if not os.environ.get("PT_TMP") else os.environ["PT_TMP"], f"pt-bench-{os.getpid()}-{demo_scale}.json")
    args = [sys.executable, os.path.join(HERE, "networkgrafh.py"), "--bench", path, "--delay", str(seconds)]
    if demo_scale:
        args += ["--demo", "--demo-scale", str(demo_scale)]
    p = subprocess.run(args, capture_output=True, text=True, timeout=seconds + 60)
    try:
        with open(path) as f:
            r = json.load(f)
        os.unlink(path)
        return r
    except (OSError, ValueError):
        return {"error": (p.stderr or p.stdout)[-800:]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", default=time.strftime("%H:%M"))
    ap.add_argument("--quick", action="store_true", help="skip the x10 app run")
    a = ap.parse_args()
    res = {"label": a.label, "time": time.time()}
    res["collector_real"] = collector_bench(0)
    res["collector_demo1"] = collector_bench(1)
    res["collector_demo10"] = collector_bench(10)
    res["app_demo1"] = app_bench(1)
    if not a.quick:
        res["app_demo10"] = app_bench(10)
    os.makedirs(os.path.join(HERE, "perf"), exist_ok=True)
    with open(os.path.join(HERE, "perf", "history.jsonl"), "a") as f:
        f.write(json.dumps(res) + "\n")
    print(json.dumps(res, indent=1))


if __name__ == "__main__":
    main()
