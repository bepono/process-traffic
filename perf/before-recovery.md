# Benchmark results before the 2026-11 folder loss

The original `perf/history.jsonl` was lost with the folder. These are the summaries `bench.py` printed
on 2026-11-07, copied from the session transcript (not re-measured). New runs append to `history.jsonl`.

| Run | Real collector sample | Demo ×10 sample | Page fps (demo ×1 / ×10) | Long frames (×1 / ×10) |
|---|---|---|---|---|
| baseline-v2 | 80.44 ms | 11.35 ms | 50.5 / 18.8 | 9 / 89 |
| r2-design+netlink | 17.04 ms | 14.02 ms | 59.2 / 30.1 | 2 / 13 |
| r3-perf2 | 18.5 ms | 16.38 ms | 57.7 / 41.8 | 3 / 12 |
| r4-design4+nolayout | 18.41 ms | 17.99 ms | 57.5 / 39.8 | 4 / 13 |
| r5-perf3 | 16.98 ms | 19.54 ms | 58.2 / 39.8 | 3 / 20 |
| r7-pass7 | 19.29 ms | 20.09 ms | 54.1 / 39.4 | 8 / 11 |
