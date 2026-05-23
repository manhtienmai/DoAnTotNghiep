"""
evaluate_combined.py — So sanh tac dong cua cai tien string_similarity (LCS + Jaccard)
=====================================================================================
  Config 1: Baseline        (string_sim OFF)
  Config 2: StringSim_only  (string_sim ON, ALPHA=0.5, MIN_LEN=10)

Dung cung tham so voi aggregate_config.py
"""

import time
import os
import sys
import csv
import pickle

from preprocessing import label
from preprocessing import read_input as read_input_original
from merging.objects import MetaAlertManager, KnowledgeBase
import similarity.string_similarity as ss
import similarity.similarity as sim_module

# =====================================================================
# CAU HINH CHUNG — lay tu aggregate_config.py
# =====================================================================
import aggregate_config

files               = aggregate_config.files
input_type          = aggregate_config.input_type
deltas              = aggregate_config.deltas
threshold           = aggregate_config.threshold
max_val_limit       = aggregate_config.max_val_limit
min_key_occurrence  = aggregate_config.min_key_occurrence
min_val_occurrence  = aggregate_config.min_val_occurrence
alignment_weight    = aggregate_config.alignment_weight
max_groups_per_meta = aggregate_config.max_groups_per_meta_alert
w                   = aggregate_config.w
min_alert_match_similarity = aggregate_config.min_alert_match_similarity

STRING_SIM_ALPHA = 0.5
STRING_SIM_MIN_LEN = 10

labels = [
    'network_scans', 'service_scans', 'dirb', 'wpscan', 'webshell',
    'cracking', 'reverse_shell', 'privilege_escalation', 'service_stop',
    'dnsteal', 'non-attack', 'multiple'
]

output_dir = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    'data', 'out', 'evaluation'
)
os.makedirs(output_dir, exist_ok=True)

# =====================================================================
# 2 CONFIG
# =====================================================================
configs = [
    # (name, string_sim_on)
    ('Baseline',       False),
    ('StringSim_only', True),
]

# =====================================================================
# CACHE
# =====================================================================
CACHE_DIR = output_dir


def get_cache_key():
    return {
        'deltas': deltas,
        'files': [str(f) for f in files],
        'threshold': threshold,
        'max_val_limit': max_val_limit,
        'min_alert_match_similarity': min_alert_match_similarity,
    }


def save_cache(name, eval_results, n_meta, n_groups, runtime):
    os.makedirs(CACHE_DIR, exist_ok=True)
    cache_file = os.path.join(CACHE_DIR, f'combined_cache_{name}.pkl')
    data = {
        'config_key': get_cache_key(),
        'eval_results': eval_results,
        'n_meta': n_meta,
        'n_groups': n_groups,
        'runtime': runtime,
    }
    with open(cache_file, 'wb') as f:
        pickle.dump(data, f)


def load_cache(name):
    cache_file = os.path.join(CACHE_DIR, f'combined_cache_{name}.pkl')
    if not os.path.exists(cache_file):
        return None
    try:
        with open(cache_file, 'rb') as f:
            data = pickle.load(f)
        if data['config_key'] != get_cache_key():
            print(f"    Cache outdated for {name}, re-running...")
            return None
        print(f"    Cache loaded for {name}")
        return data
    except Exception as e:
        print(f"    Cache corrupted for {name} ({e}), re-running...")
        return None


# =====================================================================
# HAM EVALUATE (pairwise)
# =====================================================================
def evaluate_pairwise(kb, mam, delta):
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
            i_lbl = str(list(g_in.attacks)[0]) if len(g_in.attacks) == 1 else 'multiple'
            if g_out.meta_alert == g_in.meta_alert:
                if o_lbl == i_lbl:
                    tp[o_lbl] += 1
                else:
                    fp[o_lbl] += 1
            else:
                if g_out.attacks == g_in.attacks:
                    fn[o_lbl] += 1
                else:
                    tn[o_lbl] += 1

    results = {}
    for l in labels:
        rec  = tp[l] / (tp[l] + fn[l]) if (tp[l] + fn[l]) > 0 else 0.0
        prec = tp[l] / (tp[l] + fp[l]) if (tp[l] + fp[l]) > 0 else 0.0
        f1   = tp[l] / (tp[l] + 0.5 * (fp[l] + fn[l])) if (tp[l] + fp[l] + fn[l]) > 0 else 0.0
        fpr  = fp[l] / (fp[l] + tn[l]) if (fp[l] + tn[l]) > 0 else 0.0
        results[l] = dict(tp=tp[l], fp=fp[l], fn=fn[l], tn=tn[l],
                          rec=rec, prec=prec, f1=f1, fpr=fpr)
    return results, len(mam.meta_alerts[delta]), len(groups)


# =====================================================================
# HAM CHAY 1 CONFIG
# =====================================================================
def run_config(name, string_sim_on, use_cache=True):
    print(f"\n{'=' * 60}")
    print(f"  Config: {name}")
    print(f"  string_sim={'ON' if string_sim_on else 'OFF'}")
    print(f"{'=' * 60}")

    if use_cache:
        cached = load_cache(name)
        if cached is not None:
            return cached['eval_results'], cached['n_meta'], cached['n_groups'], cached['runtime']

    orig_should_use = sim_module.should_use_string_similarity

    if string_sim_on:
        ss.ALPHA = STRING_SIM_ALPHA
        ss.MIN_LENGTH_THRESHOLD = STRING_SIM_MIN_LEN
        if hasattr(ss, '_cached_similarity'):
            ss._cached_similarity.cache_clear()
        sim_module.should_use_string_similarity = ss.should_use_string_similarity
    else:
        sim_module.should_use_string_similarity = lambda a, b, t=None: False

    t_start = time.time()
    groups_dict = read_input_original.read_input(files, deltas, input_type)

    min_sim_val = min_alert_match_similarity if min_alert_match_similarity is not None else threshold
    kb = KnowledgeBase(max_groups_per_meta, evaluate=True)
    mam = MetaAlertManager(kb)
    pipeline_time = 0.0

    for file_idx, delta_dicts in groups_dict.items():
        sys.stdout.write(f"\r    host {file_idx + 1}/{len(files)} ...")
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
                pipeline_time += time.time() - t1

    total_time = time.time() - t_start
    print(f"\r    host {len(files)}/{len(files)} done ({total_time:.1f}s total, pipeline={pipeline_time:.1f}s)")

    sim_module.should_use_string_similarity = orig_should_use

    all_eval = {}
    all_n_meta = {}
    all_n_groups = {}
    for delta in deltas:
        results, n_meta, n_groups = evaluate_pairwise(kb, mam, delta)
        all_eval[delta] = results
        all_n_meta[delta] = n_meta
        all_n_groups[delta] = n_groups

        active = {l: v for l, v in results.items() if v['tp'] + v['fp'] + v['fn'] > 0}
        avg_f1 = sum(v['f1'] for v in active.values()) / len(active) if active else 0
        print(f"    delta={delta}: groups={n_groups}, meta={n_meta}, "
              f"avgF1={avg_f1:.4f}")

    save_cache(name, all_eval, all_n_meta, all_n_groups, total_time)

    return all_eval, all_n_meta, all_n_groups, total_time


# =====================================================================
# MAIN
# =====================================================================
def main():
    print("=" * 70)
    print("  EVALUATE COMBINED — Baseline vs StringSim (LCS + Jaccard)")
    print(f"  Deltas: {deltas}")
    print(f"  Threshold: {threshold}, min_alert_match_sim: {min_alert_match_similarity}")
    print(f"  String sim: ALPHA={STRING_SIM_ALPHA}, MIN_LEN={STRING_SIM_MIN_LEN}")
    print("=" * 70)

    use_cache = '--no-cache' not in sys.argv

    all_results = {}
    for name, str_sim in configs:
        eval_res, n_meta, n_groups, rt = run_config(name, str_sim, use_cache)
        all_results[name] = {
            'eval': eval_res,
            'n_meta': n_meta,
            'n_groups': n_groups,
            'runtime': rt,
        }

    # =====================================================================
    # GHI FILE CHI TIET CSV
    # =====================================================================
    detail_path = os.path.join(output_dir, 'combined_detail.csv')
    with open(detail_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['config', 'delta', 'attack', 'tp', 'fp', 'fn', 'tn',
                         'precision', 'recall', 'f1', 'fpr',
                         'groups', 'meta_alerts', 'runtime'])
        for name, data in all_results.items():
            for delta in deltas:
                ev = data['eval'][delta]
                for l in labels:
                    v = ev[l]
                    writer.writerow([
                        name, delta, l,
                        v['tp'], v['fp'], v['fn'], v['tn'],
                        f"{v['prec']:.4f}", f"{v['rec']:.4f}",
                        f"{v['f1']:.4f}", f"{v['fpr']:.4f}",
                        data['n_groups'][delta], data['n_meta'][delta],
                        f"{data['runtime']:.1f}"
                    ])

    # =====================================================================
    # BANG TOM TAT
    # =====================================================================
    summary_path = os.path.join(output_dir, 'combined_summary.txt')
    with open(summary_path, 'w', encoding='utf-8') as f:
        for delta in deltas:
            f.write(f"\n{'=' * 90}\n")
            f.write(f"  DELTA = {delta}\n")
            f.write(f"{'=' * 90}\n\n")

            header = (f"{'Config':<20} {'Groups':>7} {'Meta':>6} "
                      f"{'AvgPrec':>8} {'AvgRec':>8} {'AvgF1':>8} {'Runtime':>8}")
            f.write(header + "\n")
            f.write("-" * len(header) + "\n")

            for name, _ in configs:
                data = all_results[name]
                ev = data['eval'][delta]
                active = {l: v for l, v in ev.items()
                          if v['tp'] + v['fp'] + v['fn'] > 0}
                if active:
                    avg_p = sum(v['prec'] for v in active.values()) / len(active)
                    avg_r = sum(v['rec'] for v in active.values()) / len(active)
                    avg_f = sum(v['f1'] for v in active.values()) / len(active)
                else:
                    avg_p = avg_r = avg_f = 0.0

                f.write(f"{name:<20} {data['n_groups'][delta]:>7} "
                        f"{data['n_meta'][delta]:>6} "
                        f"{avg_p:>8.4f} {avg_r:>8.4f} {avg_f:>8.4f} "
                        f"{data['runtime']:>7.1f}s\n")

            f.write(f"\n  {'Attack':<25}")
            for name, _ in configs:
                f.write(f" {name:>15}")
            f.write("\n")
            f.write(f"  {'-' * 25}" + f" {'-' * 15}" * len(configs) + "\n")

            baseline_ev = all_results['Baseline']['eval'][delta]
            for l in labels:
                bv = baseline_ev[l]
                if bv['tp'] + bv['fp'] + bv['fn'] == 0:
                    any_active = any(
                        all_results[n]['eval'][delta][l]['tp'] +
                        all_results[n]['eval'][delta][l]['fp'] +
                        all_results[n]['eval'][delta][l]['fn'] > 0
                        for n, _ in configs
                    )
                    if not any_active:
                        continue

                f.write(f"  {l:<25}")
                for name, _ in configs:
                    v = all_results[name]['eval'][delta][l]
                    f.write(f" {v['f1']:>15.4f}")
                f.write("\n")

            f.write("\n")

    # =====================================================================
    # IN RA MAN HINH
    # =====================================================================
    print(f"\n{'=' * 70}")
    print("  KET QUA TONG HOP")
    print(f"{'=' * 70}")

    for delta in deltas:
        print(f"\n  --- Delta = {delta} ---")
        print(f"  {'Config':<20} {'Groups':>7} {'Meta':>6} "
              f"{'AvgF1':>8} {'Runtime':>8}")
        print(f"  {'-' * 55}")

        baseline_f1 = None
        for name, _ in configs:
            data = all_results[name]
            ev = data['eval'][delta]
            active = {l: v for l, v in ev.items()
                      if v['tp'] + v['fp'] + v['fn'] > 0}
            avg_f1 = sum(v['f1'] for v in active.values()) / len(active) if active else 0

            if name == 'Baseline':
                baseline_f1 = avg_f1
                delta_str = ""
            else:
                delta_str = f" ({avg_f1 - baseline_f1:+.4f})" if baseline_f1 is not None else ""

            print(f"  {name:<20} {data['n_groups'][delta]:>7} "
                  f"{data['n_meta'][delta]:>6} "
                  f"{avg_f1:>8.4f}{delta_str:>12} "
                  f"{data['runtime']:>7.1f}s")

    print(f"\n  Chi tiet: {detail_path}")
    print(f"  Tom tat:  {summary_path}")
    print(f"\n{'=' * 70}")
    print("  HOAN THANH!")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    main()
