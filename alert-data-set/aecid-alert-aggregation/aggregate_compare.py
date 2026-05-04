"""
aggregate_compare.py
====================
Chạy pipeline tổng hợp cảnh báo 2 lần:
  - Baseline A: read_input gốc (chỉ nhóm theo thời gian)
  - Hệ C: read_input_improved (alert_sim++ + adjacent gating)

So sánh số nhóm, số meta-alert, và purity theo attack label.

CHẠY:
    cd aecid-alert-aggregation/
    python aggregate_compare.py

OUTPUT:
    - In bảng so sánh ra terminal
    - Lưu kết quả chi tiết vào data/out/compare/
"""

import os
import sys
import time
import json
import pickle
from collections import defaultdict

# Fix circular import (giống test_adjacent_gating.py)
import merging.merge

# === Import pipeline ===
from preprocessing import label
from preprocessing import read_input as read_input_original
from preprocessing import read_input_improved
from clustering import time_delta_group
from similarity import similarity
from merging.objects import MetaAlert, MetaAlertManager, KnowledgeBase
import aggregate_config


def run_pipeline(read_input_module, theta_adj=0.0, sim_func=None, label_str=""):
    """
    Chạy pipeline tổng hợp cảnh báo và thu thập metrics.

    Parameters:
        read_input_module: module chứa hàm read_input
        theta_adj: ngưỡng tương đồng kề (0.0 = tắt)
        sim_func: hàm similarity (None = tắt)
        label_str: tên hệ thống để in

    Returns:
        dict chứa metrics cho mỗi delta
    """
    print(f"\n{'=' * 60}")
    print(f" Running: {label_str}")
    print(f" theta_adj={theta_adj}, sim_func={'ON' if sim_func else 'OFF'}")
    print(f"{'=' * 60}")

    min_alert_match_similarity_val = aggregate_config.min_alert_match_similarity
    if min_alert_match_similarity_val is None:
        min_alert_match_similarity_val = aggregate_config.threshold

    start_time = time.time()

    # === Đọc và nhóm cảnh báo ===
    if theta_adj > 0 and sim_func is not None:
        # Hệ cải tiến
        groups_dict = read_input_module.read_input(
            aggregate_config.files,
            aggregate_config.deltas,
            aggregate_config.input_type,
            0.0,
            aggregate_config.group_strategy,
            aggregate_config.group_type,
            theta_adj=theta_adj,
            sim_func=sim_func
        )
    else:
        # Baseline gốc
        groups_dict = read_input_module.read_input(
            aggregate_config.files,
            aggregate_config.deltas,
            aggregate_config.input_type,
            0.0,
            aggregate_config.group_strategy,
            aggregate_config.group_type
        )

    grouping_time = time.time() - start_time

    # === Chạy pipeline: label + metrics + meta-alert trong 1 lượt ===
    # (Giống cấu trúc aggregate.py gốc)
    results = {}

    meta_start = time.time()
    kb = KnowledgeBase(
        aggregate_config.max_groups_per_meta_alert,
        aggregate_config.queue_strategy
    )
    mam = MetaAlertManager(kb)

    for file_group_index, delta_dicts in groups_dict.items():
        for delta, groups in delta_dicts.items():
            if delta not in results:
                results[delta] = {
                    'num_groups': 0,
                    'num_meta_alerts': 0,
                    'total_alerts': 0,
                    'group_sizes': [],
                    'group_purity': [],
                    'pure_groups': 0,
                    'mixed_groups': 0,
                    'attack_labels': defaultdict(int),
                    'grouping_time': grouping_time,
                }

            results[delta]['num_groups'] += len(groups)

            for group in groups:
                # 1. Gán label (giống aggregate.py gốc)
                label.label_group(group)

                # 2. Thu thập metrics nhóm
                group_size = len(group.alerts)
                results[delta]['total_alerts'] += group_size
                results[delta]['group_sizes'].append(group_size)

                attacks = group.attacks
                if len(attacks) <= 1:
                    results[delta]['pure_groups'] += 1
                    purity = 1.0
                else:
                    results[delta]['mixed_groups'] += 1
                    purity = 1.0 / len(attacks) if len(attacks) > 0 else 1.0
                results[delta]['group_purity'].append(purity)

                for atk in attacks:
                    results[delta]['attack_labels'][atk] += 1

                # 3. Tạo bag-of-alerts (giống aggregate.py gốc)
                group.create_bag_of_alerts(
                    min_alert_match_similarity_val,
                    max_val_limit=aggregate_config.max_val_limit,
                    min_key_occurrence=aggregate_config.min_key_occurrence,
                    min_val_occurrence=aggregate_config.min_val_occurrence
                )

                # 4. Thêm vào meta-alert (giống aggregate.py gốc)
                mam.add_to_meta_alerts(
                    group, delta,
                    aggregate_config.threshold,
                    min_alert_match_similarity=min_alert_match_similarity_val,
                    max_val_limit=aggregate_config.max_val_limit,
                    min_key_occurrence=aggregate_config.min_key_occurrence,
                    min_val_occurrence=aggregate_config.min_val_occurrence,
                    w=aggregate_config.w,
                    alignment_weight=aggregate_config.alignment_weight
                )
                kb.add_group_delta(group, delta)

    meta_time = time.time() - meta_start

    for delta, meta_alerts in mam.meta_alerts.items():
        if delta in results:
            results[delta]['num_meta_alerts'] = len(meta_alerts)
            results[delta]['meta_time'] = meta_time

    total_time = time.time() - start_time

    # === In tóm tắt ===
    print(f"\n  Tổng thời gian: {total_time:.1f}s")
    for delta, r in results.items():
        avg_purity = sum(r['group_purity']) / len(r['group_purity']) if r['group_purity'] else 0
        print(f"  δ={delta}: {r['num_groups']} nhóm, "
              f"{r['num_meta_alerts']} meta-alerts, "
              f"{r['total_alerts']} alerts, "
              f"pure={r['pure_groups']}, mixed={r['mixed_groups']}, "
              f"avg_purity={avg_purity:.3f}")

    return results, mam


def compare_results(results_a, results_c, label_a="Baseline A", label_c="Hệ C"):
    """In bảng so sánh giữa 2 hệ thống."""

    print(f"\n{'=' * 80}")
    print(f" SO SÁNH KẾT QUẢ: {label_a} vs {label_c}")
    print(f"{'=' * 80}")

    all_deltas = sorted(set(list(results_a.keys()) + list(results_c.keys())))

    # Header
    print(f"\n{'Delta':>8} | {'Nhóm A':>8} {'Nhóm C':>8} {'Δ%':>7} | "
          f"{'Meta A':>8} {'Meta C':>8} {'Δ%':>7} | "
          f"{'Pure A':>7} {'Pure C':>7} | "
          f"{'Mixed A':>8} {'Mixed C':>8} | "
          f"{'Purity A':>9} {'Purity C':>9}")
    print("-" * 120)

    for delta in all_deltas:
        ra = results_a.get(delta, {})
        rc = results_c.get(delta, {})

        ng_a = ra.get('num_groups', 0)
        ng_c = rc.get('num_groups', 0)
        nm_a = ra.get('num_meta_alerts', 0)
        nm_c = rc.get('num_meta_alerts', 0)
        pu_a = ra.get('pure_groups', 0)
        pu_c = rc.get('pure_groups', 0)
        mx_a = ra.get('mixed_groups', 0)
        mx_c = rc.get('mixed_groups', 0)

        avg_pur_a = sum(ra.get('group_purity', [])) / len(ra['group_purity']) if ra.get('group_purity') else 0
        avg_pur_c = sum(rc.get('group_purity', [])) / len(rc['group_purity']) if rc.get('group_purity') else 0

        # Tính % thay đổi
        dg = ((ng_c - ng_a) / ng_a * 100) if ng_a > 0 else 0
        dm = ((nm_c - nm_a) / nm_a * 100) if nm_a > 0 else 0

        print(f"{delta:>8.2f} | {ng_a:>8} {ng_c:>8} {dg:>+6.1f}% | "
              f"{nm_a:>8} {nm_c:>8} {dm:>+6.1f}% | "
              f"{pu_a:>7} {pu_c:>7} | "
              f"{mx_a:>8} {mx_c:>8} | "
              f"{avg_pur_a:>9.3f} {avg_pur_c:>9.3f}")

    print()
    print("Ghi chú:")
    print("  Nhóm: Số nhóm cảnh báo. C nhiều hơn A → adjacent gating tách nhóm hỗn tạp")
    print("  Meta: Số meta-alert. Ít hơn = tổng hợp tốt hơn")
    print("  Pure: Nhóm chỉ chứa 1 loại attack (tốt)")
    print("  Mixed: Nhóm chứa nhiều loại attack (xấu)")
    print("  Purity: Tỷ lệ thuần chủng trung bình (cao hơn = tốt hơn)")


def save_results(results, filename, label_str):
    """Lưu kết quả ra file JSON."""
    os.makedirs(os.path.dirname(filename), exist_ok=True)

    output = {
        'system': label_str,
        'config': {
            'files': [str(f) for f in aggregate_config.files],
            'deltas': aggregate_config.deltas,
            'threshold': aggregate_config.threshold,
            'min_alert_match_similarity': aggregate_config.min_alert_match_similarity,
            'alignment_weight': aggregate_config.alignment_weight,
        },
        'results': {}
    }

    for delta, r in results.items():
        avg_purity = sum(r['group_purity']) / len(r['group_purity']) if r['group_purity'] else 0
        output['results'][str(delta)] = {
            'num_groups': r['num_groups'],
            'num_meta_alerts': r['num_meta_alerts'],
            'total_alerts': r['total_alerts'],
            'pure_groups': r['pure_groups'],
            'mixed_groups': r['mixed_groups'],
            'avg_purity': round(avg_purity, 4),
            'attack_labels': dict(r['attack_labels']),
            'grouping_time': round(r.get('grouping_time', 0), 2),
        }

    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"  Kết quả lưu tại: {filename}")


# ==============================================================
# BASELINE CACHE — Tránh chạy lại baseline mỗi lần
# ==============================================================

BASELINE_CACHE_PATH = 'data/out/compare/baseline_cache.pkl'


def save_baseline_cache(results, mam):
    """Lưu kết quả baseline ra disk (pickle)."""
    os.makedirs(os.path.dirname(BASELINE_CACHE_PATH), exist_ok=True)
    cache = {
        'results': results,
        'mam': mam,
        'deltas': aggregate_config.deltas,
        'files': [str(f) for f in aggregate_config.files],
        'threshold': aggregate_config.threshold,
    }
    with open(BASELINE_CACHE_PATH, 'wb') as f:
        pickle.dump(cache, f)
    print(f"  Baseline cache saved: {BASELINE_CACHE_PATH}")


def load_baseline_cache():
    """
    Tải baseline từ cache nếu config khớp.
    Trả về (results, mam) hoặc (None, None) nếu cache không hợp lệ.
    """
    if not os.path.exists(BASELINE_CACHE_PATH):
        return None, None

    try:
        with open(BASELINE_CACHE_PATH, 'rb') as f:
            cache = pickle.load(f)

        # Kiểm tra config có khớp không
        if (cache['deltas'] != aggregate_config.deltas or
            cache['files'] != [str(f) for f in aggregate_config.files] or
            cache['threshold'] != aggregate_config.threshold):
            print("  Baseline cache outdated (config changed), re-running...")
            return None, None

        print(f"  Baseline cache loaded from: {BASELINE_CACHE_PATH}")
        return cache['results'], cache['mam']

    except Exception as e:
        print(f"  Baseline cache corrupted ({e}), re-running...")
        return None, None


# ==============================================================
# MAIN
# ==============================================================

if __name__ == '__main__':
    print("=" * 60)
    print(" THỰC NGHIỆM SO SÁNH: Baseline vs Adjacent Gating")
    print(f" Dataset: AIT-LDS v2.0 ({len(aggregate_config.files)} systems)")
    print(f" Deltas: {aggregate_config.deltas}")
    print(f" Threshold: {aggregate_config.threshold}")
    print("=" * 60)

    # ----------------------------------------------------------
    # HỆ A: Baseline gốc — dùng cache nếu có
    # ----------------------------------------------------------
    use_cache = '--no-cache' not in sys.argv

    results_a, mam_a = None, None
    if use_cache:
        results_a, mam_a = load_baseline_cache()

    if results_a is None:
        results_a, mam_a = run_pipeline(
            read_input_original,
            theta_adj=0.0,
            sim_func=None,
            label_str="Baseline A (gốc)"
        )
        save_baseline_cache(results_a, mam_a)
    else:
        # In tóm tắt từ cache
        print(f"\n{'=' * 60}")
        print(f" Baseline A (từ cache)")
        print(f"{'=' * 60}")
        for delta, r in results_a.items():
            avg_p = sum(r['group_purity']) / len(r['group_purity']) if r.get('group_purity') else 0
            print(f"  δ={delta}: {r['num_groups']} nhóm, "
                  f"{r.get('num_meta_alerts', '?')} meta-alerts, "
                  f"pure={r['pure_groups']}, mixed={r['mixed_groups']}, "
                  f"avg_purity={avg_p:.3f}")

    # ----------------------------------------------------------
    # HỆ C: alert_sim++ + adjacent gating
    # ----------------------------------------------------------
    theta_values = [0.4]

    for theta in theta_values:
        results_c, mam_c = run_pipeline(
            read_input_improved,
            theta_adj=theta,
            sim_func=similarity.get_json_similarity,
            label_str=f"Hệ C (theta_adj={theta})"
        )

        compare_results(
            results_a, results_c,
            label_a="Baseline A (gốc)",
            label_c=f"Hệ C (θ={theta})"
        )

        save_results(results_a,
                     'data/out/compare/results_baseline.json',
                     'Baseline A')
        save_results(results_c,
                     f'data/out/compare/results_theta_{theta}.json',
                     f'Hệ C (theta_adj={theta})')

    print("\n" + "=" * 60)
    print(" HOÀN THÀNH!")
    print(" Xem kết quả chi tiết tại: data/out/compare/")
    print(" Tip: Baseline đã được cache, lần sau sẽ nhanh hơn.")
    print(" Dùng --no-cache để chạy lại baseline.")
    print("=" * 60)