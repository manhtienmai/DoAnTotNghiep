import argparse
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path = [str(ROOT)] + [p for p in sys.path if p != str(ROOT)]

from evaluation.compare_versions import (
    run_worker, backup_current, restore_backup, write_table,
)

HOSTS = ['cup', 'spiral', 'onion', 'insect']

CONFIGS = [
    ('Baseline Pair-F1', 'orig', 'best', None, None),
    ('LCS+Jaccard',      'new',  'best', 0.5,  None),
    ('Sinkhorn OT',      'orig', 'ot',   None, 0.01),
    ('Combined',         'new',  'ot',   0.5,  0.01),
]


def run_one(host, version, pair_strategy, alpha, epsilon, delta, threshold):
    cfg = {
        'version': version,
        'files': [[f'data/ossec/ossec_{host}.json', f'data/aminer/aminer_{host}.txt']],
        'deltas': [delta],
        'threshold': threshold,
        'pair_strategy': pair_strategy,
    }
    if alpha is not None:
        cfg['alpha'] = alpha
    if epsilon is not None:
        cfg['epsilon'] = epsilon
    d = run_worker(cfg)['per_delta'][0]
    return d['pair_f1'], d['num_groups']


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--delta', type=float, default=0.5)
    ap.add_argument('--threshold', type=float, default=0.3)
    ap.add_argument('--repeats', type=int, default=1)
    args = ap.parse_args()

    print(f'>>> Hosts: {HOSTS} | delta={args.delta}, threshold={args.threshold}, repeats={args.repeats}')

    results = {h: {label: [] for label, *_ in CONFIGS} for h in HOSTS}
    num_groups_by_host = {}

    backup_current()
    t_start = time.time()
    try:
        for host in HOSTS:
            print(f'\n=== Host: {host} ===')
            for label, version, ps, alpha, epsilon in CONFIGS:
                print(f'  ▶ {label}')
                for i in range(args.repeats):
                    pair_f1, num_groups = run_one(host, version, ps, alpha, epsilon,
                                                  args.delta, args.threshold)
                    results[host][label].append(pair_f1)
                    if label == CONFIGS[0][0]:
                        num_groups_by_host[host] = num_groups
                    print(f'      run {i+1}/{args.repeats}: pair_f1={pair_f1:.4f}')
    finally:
        restore_backup()

    # === Tạo bảng kết quả ===
    header = ['Host', '#groups'] + [label for label, *_ in CONFIGS]
    rows = []
    per_config_values = {label: [] for label, *_ in CONFIGS}

    for host in HOSTS:
        row = [host, num_groups_by_host.get(host, '-')]
        for label, *_ in CONFIGS:
            mean_val = statistics.mean(results[host][label])
            per_config_values[label].append(mean_val)
            row.append(mean_val)
        rows.append(row)

    summary = ['Mean ± SD', '—']
    for label, *_ in CONFIGS:
        vals = per_config_values[label]
        if len(vals) >= 2:
            summary.append(f'{statistics.mean(vals):.4f} ± {statistics.stdev(vals):.4f}')
        else:
            summary.append(f'{vals[0]:.4f}')
    rows.append(summary)

    write_table('per_host_pairf1', header, rows,
                title='So sánh Pair-F1 theo Host × Phương pháp',
                note=f'delta={args.delta}, threshold={args.threshold}, '
                     f'repeats={args.repeats}, alpha=0.5 (LCS+Jaccard), '
                     f'epsilon=0.01 (Sinkhorn OT). Mean ± SD tính qua {len(HOSTS)} host.')

    print(f'\nTổng thời gian: {time.time() - t_start:.1f} s')


if __name__ == '__main__':
    main()
