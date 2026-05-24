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

DEFAULT_ALPHAS = [0.0, 0.25, 0.5, 0.75, 1.0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--alphas', type=float, nargs='+', default=DEFAULT_ALPHAS)
    ap.add_argument('--threshold', type=float, default=DEFAULT_THRESHOLD)
    args = ap.parse_args()

    print(f'>>> Alphas: {args.alphas} | threshold={args.threshold} | deltas={DEFAULT_DELTAS}')

    header = ['Alpha', 'Delta', '#MetaAlerts', 'Reduction', 'NMI', 'ARI', 'PairF1', 'Time(s)']
    rows = []

    backup_current()
    t_start = time.time()
    try:
        for alpha in args.alphas:
            print(f'\n=== alpha={alpha} ===')
            r = run_worker({
                'version': 'new',
                'files': DEFAULT_FILES,
                'deltas': DEFAULT_DELTAS,
                'threshold': args.threshold,
                'alpha': alpha,
            })
            for d in r['per_delta']:
                rows.append([alpha, d['delta'], d['num_meta_alerts'], d['reduction'],
                             d['nmi'], d['ari'], d['pair_f1'], r['total_time']])
                print(f'  delta={d["delta"]}: #MA={d["num_meta_alerts"]}, '
                      f'NMI={d["nmi"]:.4f}, ARI={d["ari"]:.4f}, PairF1={d["pair_f1"]:.4f}')
    finally:
        restore_backup()

    write_table('alpha_sweep', header, rows,
                title='Quét alpha (LCS ↔ Jaccard)',
                note=f'alpha=0 ⇒ chỉ Jaccard; alpha=1 ⇒ chỉ LCS. threshold={args.threshold}, '
                     f'deltas={DEFAULT_DELTAS}.')

    print(f'\nTổng thời gian: {time.time() - t_start:.1f} s')


if __name__ == '__main__':
    main()
