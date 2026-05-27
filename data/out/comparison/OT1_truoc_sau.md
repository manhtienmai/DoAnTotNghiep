# Bảng 4.4 — So sánh kết quả trước và sau khi thay đổi cấu hình

> Sinkhorn OT tại ε=0.1 (chưa điều chỉnh) so với Greedy baseline. δ=0.5, θ=0.3.

| Chỉ số | Trước (Greedy) | Sau (Sinkhorn OT ε=0.1) | Thay đổi |
|---|---|---|---|
| Số meta-alert | 43 | 43 | +0.0% |
| NMI ↑ | 0.3323 | 0.3061 | -7.9% |
| ARI ↑ | 0.1303 | 0.0849 | -34.8% |
| Pair-Precision ↑ | 0.9944 | 0.9841 | -1.0% |
| Pair-Recall ↑ | 0.2168 | 0.1501 | -30.8% |
| Pair-F1 ↑ | 0.3560 | 0.2605 | -26.8% |
| Thời gian (s) | 111.9431 | 163.1190 | +45.7% |
