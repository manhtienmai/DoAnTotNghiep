# aecid-alert-aggregation
Khóa luận sử dụng code từ repository https://github.com/ait-aecid/aecid-alert-aggregation của tác giá Landauer. Phần lớn là giữ nguyên code ban đầu của tác giả, chỉ chỉnh sửa thêm thuật toán liên quan LCS, Jaccard và Sinkhorn OT, các file tạo ra bảng số liệu cần thiết cho khóa luận.
# Hướng dẫn chạy

Dữ liệu được sử dụng trong repository là những cảnh báo sinh ra bởi [aminer](https://github.com/ait-aecid/logdata-anomaly-miner) và [Wazuh](https://wazuh.com/),thuộc bộ dữ liệu [AIT-LDSv1.1](https://zenodo.org/record/4264796#.X7vQTFAxnmE).

Cài thư viện: `pip install -r requirements.txt`

Tất cả output ghi vào `data/out/comparison/<tên>.md`

## Bảng → lệnh chạy

| Bảng                                                                     | Lệnh |
|--------------------------------------------------------------------------|---|
| `A1_clustering_quality.md` (Bản gốc với LCS+Jaccard, tổng quan)          | `python evaluation/compare_versions.py` |
| `A2b_per_phase_compare.md` (Recall/Precision/F1 theo các phase tấn công) | `python evaluation/compare_versions.py` |
| `alpha_sweep.md` (quét α xem cái nào tốt nhất ở LCS + Jaccrd)            | `python evaluation/compare_alpha.py` |
| `per_host_pairf1.md` (Pair-F1 theo host × các phương pháp)               | `python evaluation/compare_per_host.py` |
| `OT1_truoc_sau.md` (Greedy vs Sinkhorn OT ε=0.1)                         | `python evaluation/compare_ot.py --only OT1` |
| `OT2_epsilon_sweep.md` (quét ε của OT)                                   | `python evaluation/compare_ot.py --only OT2` |
| `OT3_combined.md` (4 cấu hình: Greedy / LCS+Jaccard / OT / Combined)     | `python evaluation/compare_ot.py --only OT3` |

## Mặc định

Định nghĩa ở `compare_versions.py`:
- `DEFAULT_FILES`: 4 cặp (ossec, aminer) cho cup / onion / insect / spiral
- `DEFAULT_DELTAS = [0.5]`
- `DEFAULT_THRESHOLD = 0.3`

Override qua CLI: `--threshold`, `--deltas`, `--alphas`, `--min-lens`, `--epsilons`, `--only`.
Một số bảng kết quả:
# A1 — So sánh chất lượng tổng hợp cảnh báo tổng thể

> δ=0.5, θ=0.3, datasets=['cup', 'onion', 'insect', 'spiral']. Mũi tên ↑ biểu thị giá trị càng cao càng tốt.

| Chỉ số | Bản gốc | LCS+Jaccard | Thay đổi |
|---|---|---|---|
| Số meta-alert | 42 | 41 | -2.4% |
| Purity ↑ | 0.9810 | 0.9805 | -0.05% |
| NMI ↑ | 0.3319 | 0.3561 | +7.3% |
| ARI ↑ | 0.1138 | 0.1706 | +49.9% |
| Pair-Precision ↑ | 0.9737 | 0.9928 | +2.0% |
| Pair-Recall ↑ | 0.2018 | 0.2764 | +37.0% |
| Pair-F1 ↑ | 0.3343 | 0.4324 | +29.3% |


# A2b — So sánh F1/Recall/Precision per-phase (Orig vs New)

> Δ F1 = F1(New) − F1(Orig). Số dương ⇒ New tốt hơn.

| Delta | Phase | Support | F1 Orig | F1 New | Δ F1 | Recall Orig | Recall New | Δ Recall | Precision Orig | Precision New |
|---|---|---|---|---|---|---|---|---|---|---|
| 0.5 | nmap | 6 | 0.4211 | 0.4211 | 0.0000 | 0.2667 | 0.2667 | 0.0000 | 1.0000 | 1.0000 |
| 0.5 | nikto | 1640 | 0.3428 | 0.4318 | 0.0890 | 0.2072 | 0.2756 | 0.0685 | 0.9928 | 0.9962 |
| 0.5 | vrfy | 25 | 0.4755 | 0.4727 | -0.0028 | 0.3967 | 0.3967 | 0.0000 | 0.5935 | 0.5848 |
| 0.5 | hydra | 245 | 0.1264 | 0.1186 | -0.0078 | 0.0720 | 0.0660 | -0.0060 | 0.5178 | 0.5864 |
| 0.5 | upload | 15 | 0.0875 | 0.1356 | 0.0481 | 0.0667 | 0.0952 | 0.0286 | 0.1273 | 0.2353 |
| 0.5 | exploit | 16 | 0.3909 | 0.3909 | 0.0000 | 0.2500 | 0.2500 | 0.0000 | 0.8955 | 0.8955 |
| 0.5 | non-attack | 1 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |

# Ảnh hưởng của hệ số α đến chất lượng tổng hợp và thời gian chạy (δ=0.5, θ=0.3)

> α=0 ⇒ chỉ Jaccard; α=1 ⇒ chỉ LCS; α=0.5 = cấu hình được chọn.

| α | NMI ↑ | Pair-F1 ↑ | #MA | Thời gian (s) |
|---|---|---|---|---|
| 0.0 (chỉ Jaccard) | 0.3433 | 0.3742 | 42 | 179.5000 |
| 0.25 | 0.3307 | 0.3220 | 41 | 281.9000 |
| 0.5 (LCS+Jaccard) | 0.3561 | 0.4324 | 41 | 248.4000 |
| 0.75 | 0.3484 | 0.3724 | 41 | 247.5000 |
| 1.0 (chỉ LCS) | 0.3308 | 0.2849 | 43 | 247.0000 |

# So sánh Pair-F1 theo Host × Phương pháp

> delta=0.5, threshold=0.3, repeats=1, alpha=0.5 (LCS+Jaccard), epsilon=0.01 (Sinkhorn OT). Mean ± SD tính qua 4 host.

| Host | #groups | Baseline Pair-F1 | LCS+Jaccard | Sinkhorn OT | Combined |
|---|---|---|---|---|---|
| cup | 125 | 0.1855 | 0.1924 | 0.2074 | 0.2006 |
| spiral | 919 | 0.7054 | 0.7054 | 0.5152 | 0.8302 |
| onion | 19 | 0.3288 | 0.3288 | 0.3514 | 0.3514 |
| insect | 885 | 0.3093 | 0.3162 | 0.3758 | 0.3759 |
| Mean ± SD | — | 0.3822 ± 0.2246 | 0.3857 ± 0.2218 | 0.3624 ± 0.1260 | 0.4395 ± 0.2717 |

# OT2 — Ảnh hưởng của ε trong Sinkhorn OT (δ=0.5, θ=0.3)

> Hàng in đậm là cấu hình được chọn. ΔF1 (%) so với Greedy baseline (PairF1=0.3343).

| Epsilon | #MA | NMI | ARI | PairF1 | ΔF1 vs Greedy (%) | Time(s) |
|---|---|---|---|---|---|---|
| **0.01** | **35** | **0.3420** | **0.1455** | **0.4052** | **+21.2%** | **217.5000** |
| 0.05 | 40 | 0.3062 | 0.0897 | 0.2733 | -18.2% | 210.8000 |
| 0.1 | 40 | 0.3063 | 0.0900 | 0.2741 | -18.0% | 212.1000 |
| 0.5 | 44 | 0.3419 | 0.1441 | 0.3909 | +16.9% | 219.6000 |
| 1.0 | 53 | 0.2745 | 0.0607 | 0.2008 | -39.9% | 231.2000 |
