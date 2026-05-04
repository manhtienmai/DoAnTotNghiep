"""
evaluate_quick.py — Chạy nhanh 2 config quan trọng
  Config 1: Baseline (tắt string similarity)
  Config 2: Cải tiến tốt nhất (ALPHA=0.5, MIN=10)

Dùng cùng tham số với evaluate_aitads.py (chuẩn):
  max_val_limit=10, min_alert_match_similarity=None→threshold
"""

import time
import os
import sys

from preprocessing import label
from preprocessing import read_input
from merging.objects import MetaAlertManager, KnowledgeBase
import similarity.string_similarity as ss
import similarity.similarity as sim_module  # Cần patch trực tiếp module này

# =====================================================================
# CẤU HÌNH CHUNG — giữ đúng như evaluate_aitads.py
# =====================================================================
files = [
    ['../alerts_filtered/fox_wazuh.json',              '../alerts_filtered/fox_aminer.json'],
    ['../alerts_filtered/harrison_wazuh.json',          '../alerts_filtered/harrison_aminer.json'],
    ['../alerts_filtered/russellmitchell_wazuh.json',   '../alerts_filtered/russellmitchell_aminer.json'],
    ['../alerts_filtered/santos_wazuh.json',            '../alerts_filtered/santos_aminer.json'],
    ['../alerts_filtered/shaw_wazuh.json',              '../alerts_filtered/shaw_aminer.json'],
    ['../alerts_filtered/wardbeck_wazuh.json',          '../alerts_filtered/wardbeck_aminer.json'],
    ['../alerts_filtered/wheeler_wazuh.json',           '../alerts_filtered/wheeler_aminer.json'],
    ['../alerts_filtered/wilson_wazuh.json',            '../alerts_filtered/wilson_aminer.json'],
]

input_type          = None
deltas              = [2]
threshold           = 0.55
max_val_limit       = 5         # Giống aggregate_config.py (tác giả)
min_key_occurrence  = 0.1
min_val_occurrence  = 0.1
alignment_weight    = 0.1
max_groups_per_meta = 25
w = {
    'timestamp': 0, 'Timestamp': 0, 'timestamps': 0,
    'Timestamps': 0, 'DetectionTimestamp': 0, '@timestamp': 0
}
# 0.5 → giống aggregate_config.py (tác giả)
min_alert_match_similarity = 0.5

labels = [
    'network_scans', 'service_scans', 'dirb', 'wpscan', 'webshell',
    'cracking', 'reverse_shell', 'privilege_escalation', 'service_stop',
    'dnsteal', 'non-attack', 'multiple'
]

output_dir = r'D:\DoAnTotNghiep\alert-data-set\aecid-alert-aggregation\data\out\evaluation'
os.makedirs(output_dir, exist_ok=True)

# =====================================================================
# 2 CONFIG CẦN CHẠY
# =====================================================================
configs = [
    # (use_string_sim, ALPHA, MIN_LEN, tên)
    (False, None, None, 'Baseline'),
    (True,  0.5,  10,   'A0.5_MIN10'),
]

# =====================================================================
# HÀM EVALUATE
# =====================================================================
def evaluate(kb, mam, delta, labels):
    groups = kb.delta_dict[delta]
    tp = {l: 0 for l in labels}
    fp = {l: 0 for l in labels}
    tn = {l: 0 for l in labels}
    fn = {l: 0 for l in labels}

    for g_out in groups:
        for g_in in groups:
            if g_out == g_in:
                continue
            o_lbl = str(list(g_out.attacks)[0]) if len(g_out.attacks) == 1 else 'multiple'
            i_lbl = str(list(g_in.attacks)[0])  if len(g_in.attacks)  == 1 else 'multiple'
            if g_out.meta_alert == g_in.meta_alert:
                if o_lbl == i_lbl: tp[o_lbl] += 1
                else:              fp[o_lbl] += 1
            else:
                if g_out.attacks == g_in.attacks: fn[o_lbl] += 1
                else:                             tn[o_lbl] += 1

    results = {}
    for l in labels:
        rec  = tp[l]/(tp[l]+fn[l])       if (tp[l]+fn[l]) > 0 else 0.0
        prec = tp[l]/(tp[l]+fp[l])       if (tp[l]+fp[l]) > 0 else 0.0
        f1   = tp[l]/(tp[l]+0.5*(fp[l]+fn[l])) if (tp[l]+fp[l]+fn[l]) > 0 else 0.0
        results[l] = dict(tp=tp[l], fp=fp[l], fn=fn[l], tn=tn[l],
                          rec=rec, prec=prec, f1=f1)
    return results, len(mam.meta_alerts[delta])

# =====================================================================
# MAIN
# =====================================================================
print("=" * 60)
print("  evaluate_quick.py — 2 config quan trọng")
print("=" * 60)

all_results = {}  # config_name → {label → metrics}

for idx, (use_sim, alpha, min_len, name) in enumerate(configs):
    print(f"\n[{idx+1}/{len(configs)+1}] Đang chạy config: {name}")
    t_start = time.time()

    # Cài đặt string similarity
    # QUAN TRỌNG: phải patch cả ss (module gốc) VÀ sim_module (nơi dùng hàm)
    # vì `from .string_similarity import should_use_string_similarity` tạo bản sao reference
    orig_fn = sim_module.should_use_string_similarity
    if use_sim:
        ss.ALPHA = alpha
        ss.MIN_LENGTH_THRESHOLD = min_len
        if hasattr(ss, '_cached_similarity'):
            ss._cached_similarity.cache_clear()
        # Khôi phục hàm gốc nếu bị patch từ vòng trước
        sim_module.should_use_string_similarity = ss.should_use_string_similarity
    else:
        # TẮT string similarity — patch TRỰC TIẾP trong similarity.py
        sim_module.should_use_string_similarity = lambda a, b, t=None: False

    # Đọc lại data (pipeline thay đổi state của groups)
    groups_dict = read_input.read_input(files, deltas, input_type)

    min_sim_val = min_alert_match_similarity if min_alert_match_similarity is not None else threshold

    kb  = KnowledgeBase(max_groups_per_meta, evaluate=True)
    mam = MetaAlertManager(kb)
    runtime = 0.0

    for file_idx, delta_dicts in groups_dict.items():
        sys.stdout.write(f"\r      host {file_idx+1}/8 ...")
        sys.stdout.flush()
        for delta, groups in delta_dicts.items():
            for group in groups:
                label.label_group(group)
                t1 = time.time()
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
                runtime += time.time() - t1

    print(f"\r      host 8/8 ✓  ({time.time()-t_start:.1f}s)")

    # Khôi phục hàm gốc — cả 2 nơi
    sim_module.should_use_string_similarity = orig_fn
    ss.should_use_string_similarity = orig_fn

    # Evaluate
    for delta in deltas:
        results, n_meta = evaluate(kb, mam, delta, labels)
        all_results[name] = (results, n_meta, runtime)

    # In nhanh ra màn hình
    results, n_meta, rt = all_results[name]
    active = {l: v for l, v in results.items() if v['tp']+v['fp']+v['fn'] > 0}
    avg_f1 = sum(v['f1'] for v in active.values()) / len(active) if active else 0
    print(f"      Meta-alerts={n_meta}  AvgF1={avg_f1:.4f}  Runtime={rt:.0f}s")

# =====================================================================
# GHI FILE KẾT QUẢ
# =====================================================================
print(f"\n[{len(configs)+1}/{len(configs)+1}] Ghi file kết quả...")

summary_path = os.path.join(output_dir, 'quick_summary.txt')
detail_path  = os.path.join(output_dir, 'quick_detail.csv')

# File chi tiết CSV
with open(detail_path, 'w', encoding='utf-8') as f:
    f.write('config,attack,tp,fp,fn,tn,prec,rec,f1\n')
    for name, (results, n_meta, rt) in all_results.items():
        for l, v in results.items():
            f.write(f"{name},{l},{v['tp']},{v['fp']},{v['fn']},{v['tn']},"
                    f"{v['prec']:.4f},{v['rec']:.4f},{v['f1']:.4f}\n")

# File tóm tắt so sánh — dạng bảng dễ copy vào LaTeX
with open(summary_path, 'w', encoding='utf-8') as f:
    f.write("=" * 80 + "\n")
    f.write("SO SÁNH BASELINE vs CẢI TIẾN (α=0.5, MIN=10)\n")
    f.write("=" * 80 + "\n\n")

    baseline_r = all_results.get('Baseline',   (None,))[0]
    improved_r = all_results.get('A0.5_MIN10', (None,))[0]
    b_meta     = all_results.get('Baseline',   (None, 0))[1]
    i_meta     = all_results.get('A0.5_MIN10', (None, 0))[1]

    header = f"{'Pha tấn công':<25} {'B_Prec':>7} {'B_Rec':>7} {'B_F1':>7}  {'I_Prec':>7} {'I_Rec':>7} {'I_F1':>7}  {'ΔF1':>8}"
    f.write(header + "\n")
    f.write("-" * len(header) + "\n")

    active_labels = [l for l in labels
                     if baseline_r and (baseline_r[l]['tp']+baseline_r[l]['fp']+baseline_r[l]['fn']) > 0]

    b_f1_sum = 0
    i_f1_sum = 0
    for l in active_labels:
        bv = baseline_r[l]
        iv = improved_r[l] if improved_r else {'prec':0,'rec':0,'f1':0}
        delta_f1 = iv['f1'] - bv['f1']
        b_f1_sum += bv['f1']
        i_f1_sum += iv['f1']
        line = (f"{l:<25} {bv['prec']:>7.3f} {bv['rec']:>7.3f} {bv['f1']:>7.3f}"
                f"  {iv['prec']:>7.3f} {iv['rec']:>7.3f} {iv['f1']:>7.3f}"
                f"  {delta_f1:>+8.3f}")
        f.write(line + "\n")

    f.write("-" * len(header) + "\n")
    n = len(active_labels)
    f.write(f"{'Trung bình':<25} {'':>7} {'':>7} {b_f1_sum/n:>7.3f}"
            f"  {'':>7} {'':>7} {i_f1_sum/n:>7.3f}"
            f"  {(i_f1_sum-b_f1_sum)/n:>+8.3f}\n")
    f.write(f"\nMeta-alerts: Baseline={b_meta}, Cải tiến={i_meta} "
            f"(thay đổi {i_meta-b_meta:+d})\n")

    b_rt = all_results.get('Baseline',   (None,None,0))[2]
    i_rt = all_results.get('A0.5_MIN10', (None,None,0))[2]
    f.write(f"Runtime:     Baseline={b_rt:.0f}s, Cải tiến={i_rt:.0f}s\n")

print(f"  Chi tiết : {detail_path}")
print(f"  Tóm tắt  : {summary_path}")
print("\nHOÀN THÀNH!")