"""
compare_grouping_only.py
========================
Script nhẹ: CHỈ chạy bước nhóm cảnh báo + đánh giá purity.
BỎ QUA hoàn toàn create_bag_of_alerts và meta-alert generation.

Thời gian chạy: ~3-5 phút (thay vì 2 tiếng)
Dùng để: tune tham số theta_adj, so sánh nhanh nhiều cấu hình

CHẠY:
    python compare_grouping_only.py
"""

import os
import sys
import time
import json
import pickle
from collections import defaultdict

import merging.merge  # Fix circular import

from preprocessing import label
from preprocessing import read_input as read_input_original
from preprocessing import read_input_improved
from similarity import similarity
import aggregate_config


def run_grouping_only(read_input_module, theta_adj=0.0, sim_func=None, label_str=""):
    """Chỉ chạy read_input + label. Không tạo meta-alert."""

    print(f"\n{'=' * 60}")
    print(f" {label_str}")
    print(f" theta_adj={theta_adj}")
    print(f"{'=' * 60}")

    start = time.time()

    if theta_adj > 0 and sim_func is not None:
        groups_dict = read_input_module.read_input(
            aggregate_config.files, aggregate_config.deltas,
            aggregate_config.input_type, 0.0,
            aggregate_config.group_strategy, aggregate_config.group_type,
            theta_adj=theta_adj, sim_func=sim_func
        )
    else:
        groups_dict = read_input_module.read_input(
            aggregate_config.files, aggregate_config.deltas,
            aggregate_config.input_type, 0.0,
            aggregate_config.group_strategy, aggregate_config.group_type
        )

    grouping_time = time.time() - start

    # Thu thập metrics
    results = {}
    per_system = {}  # Kết quả theo từng system

    system_names = []
    for fg in aggregate_config.files:
        name = fg[0].split('/')[-1].split('_')[0]
        system_names.append(name)

    for file_group_index, delta_dicts in groups_dict.items():
        sys_name = system_names[file_group_index] if file_group_index < len(
            system_names) else f"system_{file_group_index}"

        for delta, groups in delta_dicts.items():
            if delta not in results:
                results[delta] = {
                    'num_groups': 0, 'total_alerts': 0,
                    'pure_groups': 0, 'mixed_groups': 0,
                    'group_purity': [], 'attack_labels': defaultdict(int),
                    'grouping_time': grouping_time,
                }

            # Per-system tracking
            sys_key = f"{sys_name}_d{delta}"
            per_system[sys_key] = {
                'system': sys_name, 'delta': delta,
                'num_groups': len(groups), 'total_alerts': 0,
                'pure': 0, 'mixed': 0, 'attacks': defaultdict(int),
            }

            results[delta]['num_groups'] += len(groups)

            for group in groups:
                if len(group.alerts) == 0:
                    continue

                label.label_group(group)

                group_size = len(group.alerts)
                results[delta]['total_alerts'] += group_size
                per_system[sys_key]['total_alerts'] += group_size

                attacks = group.attacks
                if len(attacks) <= 1:
                    results[delta]['pure_groups'] += 1
                    per_system[sys_key]['pure'] += 1
                    results[delta]['group_purity'].append(1.0)
                else:
                    results[delta]['mixed_groups'] += 1
                    per_system[sys_key]['mixed'] += 1
                    results[delta]['group_purity'].append(1.0 / len(attacks))

                for atk in attacks:
                    results[delta]['attack_labels'][atk] += 1
                    per_system[sys_key]['attacks'][atk] += 1

    # In tóm tắt
    for delta, r in results.items():
        avg_p = sum(r['group_purity']) / len(r['group_purity']) if r['group_purity'] else 0
        print(f"  δ={delta}: {r['num_groups']} nhóm | "
              f"pure={r['pure_groups']} mixed={r['mixed_groups']} | "
              f"purity={avg_p:.4f} | "
              f"alerts={r['total_alerts']} | "
              f"time={grouping_time:.1f}s")

    # In per-system
    print(f"\n  {'System':<20} {'Groups':>7} {'Pure':>6} {'Mixed':>6} {'Alerts':>10}")
    print(f"  {'-' * 55}")
    for key, ps in per_system.items():
        print(f"  {ps['system']:<20} {ps['num_groups']:>7} {ps['pure']:>6} {ps['mixed']:>6} {ps['total_alerts']:>10}")

    return results, per_system


def save_json(data, filename):
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    # Convert defaultdict to dict for JSON
    clean = {}
    for k, v in data.items():
        if isinstance(v, dict):
            clean[str(k)] = {kk: (dict(vv) if isinstance(vv, defaultdict) else vv)
                             for kk, vv in v.items()}
        else:
            clean[str(k)] = v
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(clean, f, indent=2, ensure_ascii=False)
    print(f"  Saved: {filename}")


BASELINE_GROUPING_CACHE = 'data/out/compare/baseline_grouping_cache.pkl'


def save_grouping_cache(results, per_system):
    os.makedirs(os.path.dirname(BASELINE_GROUPING_CACHE), exist_ok=True)
    cache = {
        'results': results, 'per_system': per_system,
        'deltas': aggregate_config.deltas,
        'files': [str(f) for f in aggregate_config.files],
    }
    with open(BASELINE_GROUPING_CACHE, 'wb') as f:
        pickle.dump(cache, f)
    print(f"  Baseline grouping cache saved: {BASELINE_GROUPING_CACHE}")


def load_grouping_cache():
    if not os.path.exists(BASELINE_GROUPING_CACHE):
        return None, None
    try:
        with open(BASELINE_GROUPING_CACHE, 'rb') as f:
            cache = pickle.load(f)
        if (cache['deltas'] != aggregate_config.deltas or
            cache['files'] != [str(f) for f in aggregate_config.files]):
            print("  Baseline grouping cache outdated, re-running...")
            return None, None
        print(f"  Baseline grouping cache loaded from: {BASELINE_GROUPING_CACHE}")
        return cache['results'], cache['per_system']
    except Exception as e:
        print(f"  Baseline grouping cache corrupted ({e}), re-running...")
        return None, None


if __name__ == '__main__':
    print("=" * 60)
    print(" SO SÁNH NHANH: Chỉ grouping + purity")
    print(f" Dataset: {len(aggregate_config.files)} systems")
    print(f" Deltas: {aggregate_config.deltas}")
    print("=" * 60)

    # === Baseline A — dùng cache nếu có ===
    use_cache = '--no-cache' not in sys.argv

    res_a, per_a = None, None
    if use_cache:
        res_a, per_a = load_grouping_cache()

    if res_a is None:
        res_a, per_a = run_grouping_only(
            read_input_original,
            label_str="Baseline A (gốc)"
        )
        save_grouping_cache(res_a, per_a)
    else:
        print(f"\n{'=' * 60}")
        print(f" Baseline A (từ cache)")
        print(f"{'=' * 60}")
        for delta, r in res_a.items():
            avg_p = sum(r.get('group_purity', [])) / len(r['group_purity']) if r.get('group_purity') else 0
            print(f"  δ={delta}: {r['num_groups']} nhóm | "
                  f"pure={r['pure_groups']} mixed={r['mixed_groups']} | "
                  f"purity={avg_p:.4f}")

    # === Hệ C: thử nhiều theta_adj ===
    theta_values = [0.4]

    all_results = {'baseline': res_a}

    for theta in theta_values:
        res_c, per_c = run_grouping_only(
            read_input_improved,
            theta_adj=theta,
            sim_func=similarity.get_json_similarity,
            label_str=f"Hệ C (θ={theta})"
        )
        all_results[f'theta_{theta}'] = res_c

    # === Bảng so sánh tổng hợp ===
    print(f"\n{'=' * 80}")
    print(f" BẢNG TỔNG HỢP")
    print(f"{'=' * 80}")

    for delta in aggregate_config.deltas:
        ra = res_a.get(delta, {})
        ng_a = ra.get('num_groups', 0)
        pu_a = ra.get('pure_groups', 0)
        mx_a = ra.get('mixed_groups', 0)
        avg_a = sum(ra.get('group_purity', [])) / len(ra['group_purity']) if ra.get('group_purity') else 0
        t_a = ra.get('grouping_time', 0)

        print(f"\n  δ = {delta}")
        print(f"  {'Hệ thống':<20} {'Nhóm':>7} {'Pure':>6} {'Mixed':>6} {'Purity':>8} {'Time(s)':>8}")
        print(f"  {'-' * 60}")
        print(f"  {'Baseline A':<20} {ng_a:>7} {pu_a:>6} {mx_a:>6} {avg_a:>8.4f} {t_a:>8.1f}")

        for theta in theta_values:
            rc = all_results.get(f'theta_{theta}', {}).get(delta, {})
            ng_c = rc.get('num_groups', 0)
            pu_c = rc.get('pure_groups', 0)
            mx_c = rc.get('mixed_groups', 0)
            avg_c = sum(rc.get('group_purity', [])) / len(rc['group_purity']) if rc.get('group_purity') else 0
            t_c = rc.get('grouping_time', 0)

            dg = f"+{ng_c - ng_a}" if ng_c >= ng_a else f"{ng_c - ng_a}"
            print(f"  {'θ=' + str(theta):<20} {ng_c:>7} {pu_c:>6} {mx_c:>6} {avg_c:>8.4f} {t_c:>8.1f}  ({dg} nhóm)")

    # Lưu kết quả
    save_json(all_results, 'data/out/compare/grouping_comparison.json')

    print(f"\n{'=' * 60}")
    print(
        f" XONG! Tổng ~{sum(r.get(aggregate_config.deltas[0], {}).get('grouping_time', 0) for r in all_results.values()):.0f}s")
    print(f" Tip: Baseline đã cache, lần sau sẽ nhanh hơn. Dùng --no-cache để chạy lại.")
    print(f"{'=' * 60}")