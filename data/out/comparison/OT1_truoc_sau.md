# Bảng 4.4 — So sánh kết quả trước và sau khi thay đổi cấu hình

> Sinkhorn OT tại ε=0.1 (chưa điều chỉnh) so với Greedy baseline. δ=0.5, θ=0.3.

| Chỉ số | Trước (Greedy) | Sau (Sinkhorn OT ε=0.1) | Thay đổi |
|---|---|---|---|
| Số meta-alert | 42 | 40 | -4.8% |
| NMI ↑ | 0.3319 | 0.3063 | -7.7% |
| ARI ↑ | 0.1138 | 0.0900 | -20.9% |
| Pair-Precision ↑ | 0.9737 | 0.9819 | +0.8% |
| Pair-Recall ↑ | 0.2018 | 0.1593 | -21.1% |
| Pair-F1 ↑ | 0.3343 | 0.2741 | -18.0% |
| Thời gian (s) | 152.9 | 212.1 | +36.9% |
