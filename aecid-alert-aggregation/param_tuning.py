import os
import time
import csv
import gc
import copy

from preprocessing import label
from preprocessing import read_input
from merging.objects import MetaAlertManager, KnowledgeBase

# =====================================================================
# DOC THAM SO TU aggregate_config.py (giu nhat quan voi pipeline chinh)
# =====================================================================

import aggregate_config

files                      = aggregate_config.files
input_type                 = aggregate_config.input_type
# Chi tune tren 1 delta de tiet kiem thoi gian (~3-6h thay vi ~15h)
# Chon delta=5 vi cho it group hon -> evaluate pairwise O(n^2) nhanh hon ~10x so voi delta=0.5
# Sau khi tune xong, chay evaluate_combined.py voi best config tren ca 2 deltas de lay so lieu chinh thuc.
deltas                     = [5]
threshold                  = aggregate_config.threshold
max_val_limit              = aggregate_config.max_val_limit
min_key_occurrence         = aggregate_config.min_key_occurrence
min_val_occurrence         = aggregate_config.min_val_occurrence
alignment_weight           = aggregate_config.alignment_weight
max_groups_per_meta_alert  = aggregate_config.max_groups_per_meta_alert
min_alert_match_similarity = aggregate_config.min_alert_match_similarity
w                          = aggregate_config.w

labels = [
    'network_scans',
    'service_scans',
    'dirb',
    'wpscan',
    'webshell',
    'cracking',
    'reverse_shell',
    'privilege_escalation',
    'service_stop',
    'dnsteal',
    'non-attack',
    'multiple'
]

# =====================================================================
# GRID SEARCH: ALPHA × MIN_LENGTH
# =====================================================================

# ALPHA = 0.0 nghĩa là chỉ dùng Jaccard
# ALPHA = 1.0 nghĩa là chỉ dùng LCS
# ALPHA = 0.5 nghĩa là kết hợp đều LCS và Jaccard
ALPHA_GRID = [0.0, 0.3, 0.5, 0.7, 1.0]

# Chỉ dùng string similarity nếu chuỗi đủ dài
# MIN=5 da duoc loai vi: (a) chậm gấp 12x baseline do kich hoat LCS cho ca token ngan ("GET", "POST", IP),
#                       (b) gay over-match -> F1 thap hon Baseline (smoke test: 0.22 vs 0.23)
MIN_LEN_GRID = [10, 15, 20, 30]

# Giới hạn chuỗi quá dài để tránh LCS O(n*m) quá chậm
MAX_LEN_FIXED = 500

# 1 baseline + 25 cấu hình cải tiến
configs = [(None, None, None, "Baseline")]

for alpha in ALPHA_GRID:
    for min_len in MIN_LEN_GRID:
        configs.append(
            (alpha, min_len, MAX_LEN_FIXED, f"A{alpha}_MIN{min_len}")
        )


# =====================================================================
# HÀM TÍNH LABEL CHO GROUP
# =====================================================================

def get_group_label(group):
    """
    Nếu group chỉ có 1 attack label thì lấy label đó.
    Nếu có nhiều attack label thì gán là 'multiple'.
    """
    if len(group.attacks) == 1:
        return str(list(group.attacks)[0])
    return 'multiple'


# =====================================================================
# HÀM CHẠY PIPELINE VÀ EVALUATE CHO 1 CẤU HÌNH
# =====================================================================

def run_one_config(groups_dict, alpha, min_len, max_len, config_name):
    """
    Chạy pipeline + evaluate cho 1 cấu hình.

    alpha = None:
        Baseline, tắt string similarity.

    alpha != None:
        Bật string similarity với:
        - ALPHA = alpha
        - MIN_LENGTH_THRESHOLD = min_len
        - MAX_LENGTH_THRESHOLD = max_len

    Trả về:
        list[dict] kết quả từng attack label.
    """

    print(f"\n{'=' * 60}")
    print(f"  Config: {config_name}")

    if alpha is None:
        print("  Baseline — không dùng string similarity")
    else:
        print(f"  ALPHA={alpha}, MIN_LEN={min_len}, MAX_LEN={max_len}")

    print(f"{'=' * 60}")

    import similarity.string_similarity as ss
    import similarity.similarity as sim_module

    # Lưu trạng thái gốc để khôi phục sau mỗi config
    original_sim_should_use = sim_module.should_use_string_similarity
    original_ss_should_use = ss.should_use_string_similarity

    original_alpha = getattr(ss, 'ALPHA', None)
    original_min_len = getattr(ss, 'MIN_LENGTH_THRESHOLD', None)
    original_max_len = getattr(ss, 'MAX_LENGTH_THRESHOLD', None)

    try:
        # =============================================================
        # 1. BẬT / TẮT STRING SIMILARITY
        # =============================================================

        if alpha is None:
            # Baseline: tắt hoàn toàn cải tiến LCS + Jaccard
            sim_module.should_use_string_similarity = lambda a, b, t=None: False

        else:
            # Cấu hình cải tiến LCS + Jaccard
            ss.ALPHA = alpha
            ss.MIN_LENGTH_THRESHOLD = min_len

            if hasattr(ss, 'MAX_LENGTH_THRESHOLD'):
                ss.MAX_LENGTH_THRESHOLD = max_len

            # Xóa cache để kết quả config trước không ảnh hưởng config sau
            if hasattr(ss, '_cached_similarity'):
                ss._cached_similarity.cache_clear()

            # Patch đúng module similarity.py, nơi get_json_similarity đang gọi
            sim_module.should_use_string_similarity = ss.should_use_string_similarity

        # =============================================================
        # 2. CHẠY PIPELINE AGGREGATION
        # =============================================================

        min_sim_val = (
            min_alert_match_similarity
            if min_alert_match_similarity is not None
            else threshold
        )

        kb = KnowledgeBase(max_groups_per_meta_alert, evaluate=True)
        mam = MetaAlertManager(kb)

        runtime = 0.0

        for file_group_index, delta_dicts in groups_dict.items():
            print(f"  Processing file group {file_group_index + 1}/{len(groups_dict)}...")

            for delta, groups in delta_dicts.items():
                for group in groups:
                    label.label_group(group)

                    start = time.time()

                    group.create_bag_of_alerts(
                        min_sim_val,
                        max_val_limit=max_val_limit,
                        min_key_occurrence=min_key_occurrence,
                        min_val_occurrence=min_val_occurrence
                    )

                    mam.add_to_meta_alerts(
                        group,
                        delta,
                        threshold,
                        min_alert_match_similarity=min_sim_val,
                        max_val_limit=max_val_limit,
                        min_key_occurrence=min_key_occurrence,
                        min_val_occurrence=min_val_occurrence,
                        w=w,
                        alignment_weight=alignment_weight
                    )

                    kb.add_group_delta(group, delta)

                    runtime += time.time() - start

        # =============================================================
        # 3. EVALUATE PAIRWISE
        # =============================================================

        results = []

        for delta, groups in kb.delta_dict.items():
            tp = {l: 0 for l in labels}
            fp = {l: 0 for l in labels}
            tn = {l: 0 for l in labels}
            fn = {l: 0 for l in labels}

            for g_outer in groups:
                for g_inner in groups:
                    if g_outer == g_inner:
                        continue

                    o_label = get_group_label(g_outer)
                    i_label = get_group_label(g_inner)

                    if g_outer.meta_alert == g_inner.meta_alert:
                        if o_label == i_label:
                            tp[o_label] += 1
                        else:
                            fp[o_label] += 1
                    else:
                        if g_outer.attacks == g_inner.attacks:
                            fn[o_label] += 1
                        else:
                            tn[o_label] += 1

            num_meta_alerts = len(mam.meta_alerts.get(delta, []))

            for attack_label in labels:
                recall = (
                    tp[attack_label] / (tp[attack_label] + fn[attack_label])
                    if (tp[attack_label] + fn[attack_label]) > 0
                    else 0.0
                )

                fpr = (
                    fp[attack_label] / (fp[attack_label] + tn[attack_label])
                    if (fp[attack_label] + tn[attack_label]) > 0
                    else 0.0
                )

                precision = (
                    tp[attack_label] / (tp[attack_label] + fp[attack_label])
                    if (tp[attack_label] + fp[attack_label]) > 0
                    else 0.0
                )

                f1 = (
                    tp[attack_label] /
                    (tp[attack_label] + 0.5 * (fp[attack_label] + fn[attack_label]))
                    if (tp[attack_label] + fp[attack_label] + fn[attack_label]) > 0
                    else 0.0
                )

                results.append({
                    'config': config_name,
                    'alpha': alpha if alpha is not None else 'N/A',
                    'min_len': min_len if min_len is not None else 'N/A',
                    'max_len': max_len if max_len is not None else 'N/A',
                    'delta': delta,
                    'attack': attack_label,
                    'tp': tp[attack_label],
                    'fp': fp[attack_label],
                    'fn': fn[attack_label],
                    'tn': tn[attack_label],
                    'recall': round(recall, 4),
                    'fpr': round(fpr, 4),
                    'precision': round(precision, 4),
                    'f1': round(f1, 4),
                    'meta_alerts': num_meta_alerts,
                    'groups': len(groups),
                    'runtime': round(runtime, 1)
                })

                if (
                    tp[attack_label] > 0
                    or fp[attack_label] > 0
                    or fn[attack_label] > 0
                ):
                    print(
                        f"  {attack_label:<25} "
                        f"Prec={precision:.3f}  "
                        f"Recall={recall:.3f}  "
                        f"F1={f1:.3f}"
                    )

            print(
                f"  Delta={delta} | "
                f"Meta-alerts: {num_meta_alerts} | "
                f"Groups: {len(groups)} | "
                f"Runtime: {runtime:.1f}s"
            )

        return results

    finally:
        # =============================================================
        # 4. KHÔI PHỤC TRẠNG THÁI GỐC SAU MỖI CONFIG
        # =============================================================

        sim_module.should_use_string_similarity = original_sim_should_use
        ss.should_use_string_similarity = original_ss_should_use

        if original_alpha is not None:
            ss.ALPHA = original_alpha

        if original_min_len is not None:
            ss.MIN_LENGTH_THRESHOLD = original_min_len

        if original_max_len is not None and hasattr(ss, 'MAX_LENGTH_THRESHOLD'):
            ss.MAX_LENGTH_THRESHOLD = original_max_len

        if hasattr(ss, '_cached_similarity'):
            ss._cached_similarity.cache_clear()


# =====================================================================
# HÀM TÓM TẮT KẾT QUẢ
# =====================================================================

def get_active_results(all_results, config_name):
    """
    Chỉ lấy các attack label có dữ liệu thật.
    Bỏ các label tp=fp=fn=0 vì chúng không đóng góp ý nghĩa vào F1 trung bình.
    """
    return [
        r for r in all_results
        if r['config'] == config_name
        and (r['tp'] > 0 or r['fp'] > 0 or r['fn'] > 0)
    ]


def summarize_results(all_results):
    """
    In bảng F1 trung bình cho từng config và tìm config tốt nhất.
    """

    print(f"\n{'=' * 80}")
    print("BẢNG TÓM TẮT — F1 / PRECISION / RECALL TRUNG BÌNH")
    print(f"{'=' * 80}")
    print(f"{'Config':<22} {'AvgPrec':>8} {'AvgRec':>8} {'AvgF1':>8} {'Meta':>6} {'Runtime':>9}")
    print(f"{'-' * 22} {'-' * 8} {'-' * 8} {'-' * 8} {'-' * 6} {'-' * 9}")

    summary_rows = []

    for alpha, min_len, max_len, name in configs:
        config_results = get_active_results(all_results, name)

        if not config_results:
            continue

        n = len(config_results)
        avg_f1   = sum(r['f1']        for r in config_results) / n
        avg_prec = sum(r['precision'] for r in config_results) / n
        avg_rec  = sum(r['recall']    for r in config_results) / n
        meta_alerts = config_results[0]['meta_alerts']
        runtime = config_results[0]['runtime']

        summary_rows.append({
            'config': name,
            'alpha': alpha if alpha is not None else 'N/A',
            'min_len': min_len if min_len is not None else 'N/A',
            'max_len': max_len if max_len is not None else 'N/A',
            'avg_precision': round(avg_prec, 4),
            'avg_recall': round(avg_rec, 4),
            'avg_f1': round(avg_f1, 4),
            'meta_alerts': meta_alerts,
            'runtime': runtime
        })

        print(
            f"{name:<22} "
            f"{avg_prec:>8.4f} "
            f"{avg_rec:>8.4f} "
            f"{avg_f1:>8.4f} "
            f"{meta_alerts:>6} "
            f"{runtime:>8.1f}s"
        )

    if not summary_rows:
        print("Không có kết quả hợp lệ để tóm tắt.")
        return []

    best = max(summary_rows, key=lambda x: x['avg_f1'])

    print(f"\n{'=' * 80}")
    print("CONFIG TỐT NHẤT THEO AVG F1")
    print(f"{'=' * 80}")
    print(f"Best config : {best['config']}")
    print(f"Alpha       : {best['alpha']}")
    print(f"Min length  : {best['min_len']}")
    print(f"Max length  : {best['max_len']}")
    print(f"Avg Prec    : {best['avg_precision']:.4f}")
    print(f"Avg Recall  : {best['avg_recall']:.4f}")
    print(f"Avg F1      : {best['avg_f1']:.4f}")
    print(f"Meta-alerts : {best['meta_alerts']}")
    print(f"Runtime     : {best['runtime']:.1f}s")

    return summary_rows


# =====================================================================
# HEATMAP PIVOT α × MIN_LENGTH
# =====================================================================

def build_pivot(summary_rows, value_key):
    """
    Trả về dict[alpha][min_len] = value_key (vd: 'avg_f1').
    Bỏ qua Baseline (alpha = 'N/A').
    """
    pivot = {a: {m: None for m in MIN_LEN_GRID} for a in ALPHA_GRID}
    for row in summary_rows:
        if row['alpha'] == 'N/A':
            continue
        pivot[row['alpha']][row['min_len']] = row[value_key]
    return pivot


def print_pivot(pivot, title, value_fmt="{:>7.4f}"):
    """In bảng pivot α (hàng) × MIN_LEN (cột) ra terminal."""
    print(f"\n{'=' * 80}")
    print(title)
    print(f"{'=' * 80}")

    header = f"{'α \\ MIN':<10}" + "".join(f"{m:>10}" for m in MIN_LEN_GRID)
    print(header)
    print("-" * len(header))

    best_val = None
    best_cell = (None, None)
    for a in ALPHA_GRID:
        for m in MIN_LEN_GRID:
            v = pivot[a][m]
            if v is None:
                continue
            if best_val is None or v > best_val:
                best_val, best_cell = v, (a, m)

    for a in ALPHA_GRID:
        cells = []
        for m in MIN_LEN_GRID:
            v = pivot[a][m]
            if v is None:
                cells.append(f"{'--':>10}")
            else:
                s = value_fmt.format(v)
                marker = '*' if (a, m) == best_cell else ' '
                cells.append(f"{marker}{s:>9}")
        print(f"α={a:<8}" + "".join(cells))

    if best_val is not None:
        print(f"\n  Best: α={best_cell[0]}, MIN={best_cell[1]} -> {value_fmt.format(best_val).strip()}")


def write_pivot_csv(pivot, file_path, value_label):
    """Ghi pivot ra CSV: cột đầu là α, các cột sau là MIN_LEN_GRID."""
    with open(file_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([f'alpha\\{value_label}'] + [f'MIN_{m}' for m in MIN_LEN_GRID])
        for a in ALPHA_GRID:
            row = [a]
            for m in MIN_LEN_GRID:
                v = pivot[a][m]
                row.append('' if v is None else v)
            writer.writerow(row)


# =====================================================================
# MAIN
# =====================================================================

def main():
    print("╔════════════════════════════════════════════════════════╗")
    print("║  PARAM TUNING STRING SIMILARITY                      ║")
    print("║  Grid search ALPHA × MIN_LENGTH                      ║")
    print("║  Baseline + LCS/Jaccard configs                      ║")
    print("╚════════════════════════════════════════════════════════╝")

    print(f"\nTổng số config sẽ chạy: {len(configs)}")
    print(f"  - 1 Baseline")
    print(f"  - {len(ALPHA_GRID)} alpha × {len(MIN_LEN_GRID)} min_len = {len(ALPHA_GRID) * len(MIN_LEN_GRID)} configs cải tiến")

    all_results = []

    # Doc du lieu MOT LAN duy nhat. Moi config se deepcopy de co state sach.
    # Deepcopy ~5-10s vs re-read ~40s/scenario * 8 = ~320s -> tiet kiem ~1.5h tong runtime
    print(f"\nĐang đọc dữ liệu (1 lần duy nhất, {len(files)} scenarios)...")
    t0 = time.time()
    groups_dict_original = read_input.read_input(files, deltas, input_type)
    n_groups = sum(len(g) for fi, dd in groups_dict_original.items() for d, g in dd.items())
    print(f"Đọc xong: {time.time() - t0:.1f}s ({n_groups} groups tổng)")

    for index, (alpha, min_len, max_len, name) in enumerate(configs, start=1):
        print(f"\n\n### RUN {index}/{len(configs)}: {name}")

        # Deepcopy de co state sach cho moi config (groups bi mutate trong pipeline)
        t0 = time.time()
        groups_dict_fresh = copy.deepcopy(groups_dict_original)
        print(f"Deepcopy: {time.time() - t0:.1f}s")

        results = run_one_config(
            groups_dict_fresh,
            alpha,
            min_len,
            max_len,
            name
        )

        all_results.extend(results)
        gc.collect()

    if not all_results:
        print("Không có kết quả nào để ghi.")
        return

    # =================================================================
    # GHI DETAIL CSV
    # =================================================================

    base_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(base_dir, 'data', 'out', 'evaluation')
    os.makedirs(output_dir, exist_ok=True)

    detail_file = os.path.join(output_dir, 'param_tuning_results.csv')

    with open(detail_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=all_results[0].keys())
        writer.writeheader()
        writer.writerows(all_results)

    # =================================================================
    # IN + GHI SUMMARY CSV
    # =================================================================

    summary_rows = summarize_results(all_results)

    summary_file = os.path.join(output_dir, 'param_tuning_summary.csv')

    if summary_rows:
        with open(summary_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=summary_rows[0].keys())
            writer.writeheader()
            writer.writerows(summary_rows)

    # =================================================================
    # HEATMAP PIVOT α × MIN_LEN
    # =================================================================
    pivot_files = {}
    if summary_rows:
        # Baseline avg để in tham chiếu
        baseline = next((r for r in summary_rows if r['config'] == 'Baseline'), None)
        if baseline is not None:
            print(f"\n{'=' * 80}")
            print("BASELINE (string_sim OFF) — tham chiếu")
            print(f"{'=' * 80}")
            print(f"  AvgPrec={baseline['avg_precision']:.4f}  "
                  f"AvgRec={baseline['avg_recall']:.4f}  "
                  f"AvgF1={baseline['avg_f1']:.4f}  "
                  f"Meta={baseline['meta_alerts']}")

        for value_key, title, fname, fmt in [
            ('avg_f1',       'PIVOT α × MIN_LEN — Avg F1',        'pivot_avg_f1.csv',     "{:>7.4f}"),
            ('avg_precision','PIVOT α × MIN_LEN — Avg Precision', 'pivot_avg_precision.csv', "{:>7.4f}"),
            ('avg_recall',   'PIVOT α × MIN_LEN — Avg Recall',    'pivot_avg_recall.csv', "{:>7.4f}"),
            ('meta_alerts',  'PIVOT α × MIN_LEN — Meta-alerts (so luong, thap = nen tot)', 'pivot_meta_alerts.csv', "{:>7.0f}"),
        ]:
            pivot = build_pivot(summary_rows, value_key)
            print_pivot(pivot, title, value_fmt=fmt)
            path = os.path.join(output_dir, fname)
            write_pivot_csv(pivot, path, value_key)
            pivot_files[value_key] = path

    print(f"\n{'=' * 80}")
    print("HOÀN THÀNH")
    print(f"{'=' * 80}")
    print(f"Detail CSV : {detail_file}")
    print(f"Summary CSV: {summary_file}")
    for k, p in pivot_files.items():
        print(f"Pivot {k:<14}: {p}")
    print(f"Tổng số config đã chạy: {len(configs)}")



if __name__ == "__main__":
    main()