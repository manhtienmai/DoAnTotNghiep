#So sánh Sinkhorn OT với Greedy
import argparse
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path = [str(ROOT)] + [p for p in sys.path if p != str(ROOT)]

from evaluation.compare_versions import (
    run_worker, backup_current, restore_backup, write_table,
    DEFAULT_FILES, DEFAULT_DELTAS, DEFAULT_THRESHOLD,
)

DEFAULT_EPSILONS = [0.01, 0.05, 0.1, 0.5, 1.0]

OT3_CONFIGS = [
    ('Greedy (baseline)',         'orig', 'best', None, None),
    ('LCS+Jaccard only',          'new',  'best', 0.5,  None),
    ('Sinkhorn OT only',          'orig', 'ot',   None, 0.01),
    ('LCS+Jaccard + Sinkhorn OT', 'new',  'ot',   0.5,  0.01),
]


def table_OT1(files, deltas, threshold):
    print('\n[OT1] Greedy vs Sinkhorn OT (Trước/Sau)')
    runs = {}
    for label, ps in [('greedy', 'best'), ('ot', 'ot')]:
        runs[label] = run_worker({
            'version': 'orig', 'files': files, 'deltas': deltas,
            'threshold': threshold, 'pair_strategy': ps,
        })

    g = runs['greedy']['per_delta'][0]
    o = runs['ot']['per_delta'][0]
    t_g = runs['greedy']['total_time']
    t_o = runs['ot']['total_time']

    def pct(before, after):
        if before == 0:
            return '—'
        return f'{(after - before) / before * 100:+.1f}%'

    header = ['Chỉ số', 'Trước (Greedy)', 'Sau (Sinkhorn OT ε=0.1)', 'Thay đổi']
    rows = [
        ['Số meta-alert', g['num_meta_alerts'], o['num_meta_alerts'],
         pct(g['num_meta_alerts'], o['num_meta_alerts'])],
        ['NMI ↑', g['nmi'], o['nmi'], pct(g['nmi'], o['nmi'])],
        ['ARI ↑', g['ari'], o['ari'], pct(g['ari'], o['ari'])],
        ['Pair-Precision ↑', g['pair_precision'], o['pair_precision'],
         pct(g['pair_precision'], o['pair_precision'])],
        ['Pair-Recall ↑', g['pair_recall'], o['pair_recall'],
         pct(g['pair_recall'], o['pair_recall'])],
        ['Pair-F1 ↑', g['pair_f1'], o['pair_f1'],
         pct(g['pair_f1'], o['pair_f1'])],
        ['Thời gian (s)', t_g, t_o, pct(t_g, t_o)],
    ]
    write_table('OT1_truoc_sau', header, rows,
                title='Bảng 4.4 — So sánh kết quả trước và sau khi thay đổi cấu hình',
                note=f'Sinkhorn OT tại ε=0.1 (chưa điều chỉnh) so với Greedy baseline. δ={deltas[0]}, θ={threshold}.')
    return runs


def table_OT2(files, deltas, threshold, epsilons):
    print('\n[OT2] Quét ε Sinkhorn')
    print('  ▶ baseline Greedy (để tính ΔF1)')
    baseline = run_worker({
        'version': 'orig', 'files': files, 'deltas': deltas,
        'threshold': threshold, 'pair_strategy': 'best',
    })
    base_pf1 = {d['delta']: d['pair_f1'] for d in baseline['per_delta']}

    header = ['Epsilon', '#MA', 'NMI', 'ARI', 'PairF1',
              'ΔF1 vs Greedy (%)', 'Time(s)']
    rows = []
    for eps in epsilons:
        r = run_worker({
            'version': 'orig', 'files': files, 'deltas': deltas,
            'threshold': threshold,
            'pair_strategy': 'ot', 'epsilon': eps,
        })
        for d in r['per_delta']:
            base = base_pf1.get(d['delta'], 0.0)
            delta_pct = ((d['pair_f1'] - base) / base * 100) if base > 0 else 0.0
            rows.append([eps, d['num_meta_alerts'],
                         d['nmi'], d['ari'], d['pair_f1'],
                         delta_pct, r['total_time']])
    write_table('OT2_epsilon_sweep', header, rows,
                title='OT2 — Ảnh hưởng của ε',
                note=f'threshold={threshold}. ΔF1 (%) so với Greedy baseline (PairF1={list(base_pf1.values())[0]:.4f}).')


def table_OT3_combined(files, deltas, threshold):
    print('\n[OT3] 4 cấu hình Bảng 5.6')

    runs = {}
    for label, version, ps, alpha, epsilon in OT3_CONFIGS:
        print(f'  ▶ {label}')
        cfg = {'version': version, 'files': files, 'deltas': deltas,
               'threshold': threshold, 'pair_strategy': ps}
        if alpha is not None:
            cfg['alpha'] = alpha
        if epsilon is not None:
            cfg['epsilon'] = epsilon
        r = run_worker(cfg)
        runs[label] = r
        print(f'      time={r["total_time"]:.2f}s')

    baseline_label = 'Greedy (baseline)'
    baseline_pf1 = {d['delta']: d['pair_f1']
                    for d in runs[baseline_label]['per_delta']}

    header = ['Cấu hình', '#MA', 'NMI', 'ARI', 'Pair-F1',
              'ΔF1', 'Time(s)']
    rows = []
    for label, *_ in OT3_CONFIGS:
        r = runs[label]
        for d in r['per_delta']:
            base = baseline_pf1.get(d['delta'], 0.0)
            if label == baseline_label:
                df1 = '—'
            else:
                pct = ((d['pair_f1'] - base) / base * 100) if base > 0 else 0.0
                df1 = f'{pct:+.1f}%'
            rows.append([label, d['num_meta_alerts'],
                         d['nmi'], d['ari'], d['pair_f1'],
                         df1, r['total_time']])
    write_table('OT3_combined', header, rows,
                title='OT3 — 4 cấu hình Bảng 5.6',
                note=f'threshold={threshold}, α=0.5, ε=0.01. ΔF1 = (Pair-F1 − Greedy baseline) / Greedy baseline.')
    return runs


OT_TABLES = ['OT1', 'OT2', 'OT3']

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--threshold', type=float, default=DEFAULT_THRESHOLD)
    ap.add_argument('--deltas', type=float, nargs='+', default=DEFAULT_DELTAS)
    ap.add_argument('--epsilons', type=float, nargs='+', default=DEFAULT_EPSILONS)
    ap.add_argument('--only', nargs='*', choices=OT_TABLES, default=None)
    args = ap.parse_args()

    def should_run(name):
        return args.only is None or name in args.only

    backup_current()
    t_start = time.time()
    try:
        if should_run('OT1'):
            table_OT1(DEFAULT_FILES, args.deltas, args.threshold)
        if should_run('OT2'):
            table_OT2(DEFAULT_FILES, args.deltas, args.threshold, args.epsilons)
        if should_run('OT3'):
            table_OT3_combined(DEFAULT_FILES, args.deltas, args.threshold)
    finally:
        restore_backup()
    print(f'\nTổng: {time.time() - t_start:.1f}s')

if __name__ == '__main__':
    main()
