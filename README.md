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
