# OT3 — 4 cấu hình Bảng 5.6

> threshold=0.3, α=0.5, ε=0.01. ΔF1 = (Pair-F1 − Greedy baseline) / Greedy baseline.

| Cấu hình | #MA | NMI | ARI | Pair-F1 | ΔF1 | Time(s) |
|---|---|---|---|---|---|---|
| Greedy (baseline) | 42 | 0.3319 | 0.1138 | 0.3343 | — | 152.9000 |
| LCS+Jaccard only | 41 | 0.3561 | 0.1706 | 0.4324 | +29.3% | 248.4000 |
| Sinkhorn OT only | 35 | 0.3420 | 0.1455 | 0.4052 | +21.2% | 217.5000 |
| LCS+Jaccard + Sinkhorn OT | 35 | 0.3431 | 0.1472 | 0.4081 | +22.1% | 234.2000 |
