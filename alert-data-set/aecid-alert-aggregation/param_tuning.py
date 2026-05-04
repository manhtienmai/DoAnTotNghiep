import time
import csv
import importlib

from preprocessing import label
from preprocessing import read_input
from merging.objects import MetaAlertManager, KnowledgeBase

# === CHẾ ĐỘ CHẠY ===
# True  = chỉ 4 scenario nhỏ (~35K alerts, nhanh ~5-10 phút/config)
# False = full 8 scenario (~1.7M alerts, chậm ~30-40 phút/config)
FAST_MODE = True

files_small = [
    ['../alerts_filtered/russellmitchell_wazuh.json', '../alerts_filtered/russellmitchell_aminer.json'],
    ['../alerts_filtered/santos_wazuh.json', '../alerts_filtered/santos_aminer.json'],
    ['../alerts_filtered/shaw_wazuh.json', '../alerts_filtered/shaw_aminer.json'],
    ['../alerts_filtered/wardbeck_wazuh.json', '../alerts_filtered/wardbeck_aminer.json'],
]

files_full = [
    ['../alerts_filtered/russellmitchell_wazuh.json', '../alerts_filtered/russellmitchell_aminer.json'],
    ['../alerts_filtered/santos_wazuh.json', '../alerts_filtered/santos_aminer.json'],
    ['../alerts_filtered/shaw_wazuh.json', '../alerts_filtered/shaw_aminer.json'],
    ['../alerts_filtered/wardbeck_wazuh.json', '../alerts_filtered/wardbeck_aminer.json'],
    ['../alerts_filtered/fox_wazuh.json', '../alerts_filtered/fox_aminer.json'],
    ['../alerts_filtered/harrison_wazuh.json', '../alerts_filtered/harrison_aminer.json'],
    ['../alerts_filtered/wheeler_wazuh.json', '../alerts_filtered/wheeler_aminer.json'],
    ['../alerts_filtered/wilson_wazuh.json', '../alerts_filtered/wilson_aminer.json'],
]

files = files_small if FAST_MODE else files_full

input_type = None
deltas = [2]
threshold = 0.55
max_val_limit = 5                  # Giống aggregate_config.py (tác giả)
min_key_occurrence = 0.1
min_val_occurrence = 0.1
alignment_weight = 0.1
max_groups_per_meta_alert = 25
min_alert_match_similarity = 0.5   # Giống aggregate_config.py (tác giả)
w = {
    'timestamp': 0, 'Timestamp': 0, 'timestamps': 0, 'Timestamps': 0,
    'DetectionTimestamp': 0, '@timestamp': 0
}

labels = [
    'network_scans', 'service_scans', 'dirb', 'wpscan', 'webshell',
    'cracking', 'reverse_shell', 'privilege_escalation', 'service_stop',
    'dnsteal', 'non-attack', 'multiple'
]

# =====================================================================
# CÁC CẤU HÌNH CẦN THỬ
# =====================================================================

configs = [
    # (ALPHA, MIN_LENGTH_THRESHOLD, MAX_LENGTH_THRESHOLD, tên config)
    # --- Nhóm 1: Baseline ---
    (None,  None, None, "Baseline"),                   # Không dùng string sim

    # --- Nhóm 2: Thay đổi ALPHA (cố định MIN=20) ---
    (0.0,   20,   500,  "A0.0_MIN20"),                # Chỉ Jaccard
    (0.3,   20,   500,  "A0.3_MIN20"),                # Thiên Jaccard
    (0.5,   20,   500,  "A0.5_MIN20"),                # Cân bằng (mặc định)
    (0.7,   20,   500,  "A0.7_MIN20"),                # Thiên LCS
    (1.0,   20,   500,  "A1.0_MIN20"),                # Chỉ LCS

    # --- Nhóm 3: Thay đổi MIN_LENGTH (cố định ALPHA=0.5) ---
    (0.5,   10,   500,  "A0.5_MIN10"),                # Ngưỡng thấp
    (0.5,   30,   500,  "A0.5_MIN30"),                # Ngưỡng cao
]

# =====================================================================
# HÀM CHẠY PIPELINE VÀ EVALUATE CHO 1 CẤU HÌNH
# =====================================================================

def run_one_config(groups_dict, alpha, min_len, max_len, config_name):
    """
    Chạy pipeline + evaluate cho 1 cấu hình tham số.
    Trả về dict chứa kết quả.
    """
    print(f"\n{'='*60}")
    print(f"  Config: {config_name}")
    if alpha is not None:
        print(f"  ALPHA={alpha}, MIN_LEN={min_len}, MAX_LEN={max_len}")
    else:
        print(f"  Baseline — không dùng string similarity")
    print(f"{'='*60}")

    # Cập nhật tham số trong module string_similarity
    import similarity.string_similarity as ss
    import similarity.similarity as sim_module  # Patch trực tiếp module dùng hàm
    if alpha is not None:
        ss.ALPHA = alpha
        ss.MIN_LENGTH_THRESHOLD = min_len
        if hasattr(ss, 'MAX_LENGTH_THRESHOLD'):
            ss.MAX_LENGTH_THRESHOLD = max_len
        if hasattr(ss, '_cached_similarity'):
            ss._cached_similarity.cache_clear()

    # Điều khiển bật/tắt string similarity
    # QUAN TRỌNG: phải patch sim_module (nơi dùng hàm), không chỉ ss (nơi định nghĩa)
    original_should_use = sim_module.should_use_string_similarity
    if alpha is None:
        # Baseline: tắt string similarity
        sim_module.should_use_string_similarity = lambda a, b, t=None: False
    else:
        # Khôi phục hàm gốc nếu bị patch từ vòng trước
        sim_module.should_use_string_similarity = ss.should_use_string_similarity

    # Chạy pipeline
    min_sim_val = min_alert_match_similarity if min_alert_match_similarity is not None else threshold
    kb = KnowledgeBase(max_groups_per_meta_alert, evaluate=True)
    mam = MetaAlertManager(kb)
    runtime = 0.0

    for file_group_index, delta_dicts in groups_dict.items():
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
                    group, delta, threshold,
                    min_alert_match_similarity=min_sim_val,
                    max_val_limit=max_val_limit,
                    min_key_occurrence=min_key_occurrence,
                    min_val_occurrence=min_val_occurrence,
                    w=w,
                    alignment_weight=alignment_weight
                )
                kb.add_group_delta(group, delta)
                runtime += time.time() - start

    # Evaluate
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
                o_label = str(list(g_outer.attacks)[0]) if len(g_outer.attacks) == 1 else 'multiple'
                i_label = str(list(g_inner.attacks)[0]) if len(g_inner.attacks) == 1 else 'multiple'

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

        num_meta_alerts = len(mam.meta_alerts[delta])

        for l in labels:
            tpr = tp[l] / (tp[l] + fn[l]) if (tp[l] + fn[l]) > 0 else 0.0
            fpr_val = fp[l] / (fp[l] + tn[l]) if (fp[l] + tn[l]) > 0 else 0.0
            prec = tp[l] / (tp[l] + fp[l]) if (tp[l] + fp[l]) > 0 else 0.0
            f1 = tp[l] / (tp[l] + 0.5 * (fp[l] + fn[l])) if (tp[l] + fp[l] + fn[l]) > 0 else 0.0

            results.append({
                'config': config_name,
                'alpha': alpha if alpha is not None else 'N/A',
                'min_len': min_len if min_len is not None else 'N/A',
                'max_len': max_len if max_len is not None else 'N/A',
                'delta': delta,
                'attack': l,
                'tp': tp[l],
                'fp': fp[l],
                'fn': fn[l],
                'tn': tn[l],
                'recall': round(tpr, 4),
                'fpr': round(fpr_val, 4),
                'precision': round(prec, 4),
                'f1': round(f1, 4),
                'meta_alerts': num_meta_alerts,
                'groups': len(groups),
                'runtime': round(runtime, 1)
            })

            if tp[l] > 0 or fp[l] > 0 or fn[l] > 0:
                print(f"  {l:<25} Prec={prec:.3f}  Recall={tpr:.3f}  F1={f1:.3f}")

    print(f"  Meta-alerts: {num_meta_alerts} | Runtime: {runtime:.1f}s")

    # Khôi phục hàm gốc — cả 2 nơi
    sim_module.should_use_string_similarity = original_should_use
    ss.should_use_string_similarity = original_should_use

    return results


# =====================================================================
# MAIN
# =====================================================================

def main():
    print("╔════════════════════════════════════════════════════════╗")
    print("║  TINH CHỈNH THAM SỐ STRING SIMILARITY               ║")
    print("║  Thử nghiệm nhiều cấu hình ALPHA + MIN_LENGTH       ║")
    print("╚════════════════════════════════════════════════════════╝")

    # Đọc dữ liệu 1 lần duy nhất (tốn thời gian nhất)
    print("\nĐang đọc dữ liệu...")
    groups_dict = read_input.read_input(files, deltas, input_type)
    print("Đọc xong.\n")

    all_results = []

    for alpha, min_len, max_len, name in configs:
        # Mỗi config cần reload groups vì pipeline thay đổi state
        groups_dict_fresh = read_input.read_input(files, deltas, input_type)
        results = run_one_config(groups_dict_fresh, alpha, min_len, max_len, name)
        all_results.extend(results)

    # Ghi kết quả ra CSV
    suffix = '_fast' if FAST_MODE else '_full'
    output_file = f'data/out/evaluation/param_tuning_results{suffix}.csv'
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=all_results[0].keys())
        writer.writeheader()
        writer.writerows(all_results)

    print(f"\n{'='*60}")
    print(f"HOÀN THÀNH! Kết quả lưu tại: {output_file}")
    print(f"Tổng số config đã thử: {len(configs)}")
    print(f"{'='*60}")

    # In bảng tóm tắt F1 trung bình cho mỗi config
    print(f"\n{'='*60}")
    print("BẢNG TÓM TẮT — F1 TRUNG BÌNH (chỉ attack có dữ liệu)")
    print(f"{'='*60}")
    print(f"{'Config':<30} {'F1 TB':<8} {'Meta-alerts':<12} {'Runtime':<10}")
    print(f"{'-'*30} {'-'*8} {'-'*12} {'-'*10}")

    for alpha, min_len, max_len, name in configs:
        config_results = [r for r in all_results
                         if r['config'] == name
                         and (r['tp'] > 0 or r['fp'] > 0 or r['fn'] > 0)]
        if config_results:
            avg_f1 = sum(r['f1'] for r in config_results) / len(config_results)
            meta = config_results[0]['meta_alerts']
            rt = config_results[0]['runtime']
            print(f"{name:<30} {avg_f1:<8.4f} {meta:<12} {rt:<10.1f}s")


if __name__ == "__main__":
    main()