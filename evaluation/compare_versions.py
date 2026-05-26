import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')

ROOT = Path(__file__).resolve().parent.parent
sys.path = [str(ROOT)] + [p for p in sys.path if p != str(ROOT)]

SIM_DIR = ROOT / 'similarity'
ACTIVE = SIM_DIR / 'similarity.py'
ORIG_FILE = SIM_DIR / 'similarity_original.py'
NEW_FILE = SIM_DIR / 'similarity_modified.py'
BACKUP = SIM_DIR / 'similarity.py.bak_compare'

OUT_DIR = ROOT / 'data' / 'out' / 'comparison'
OUT_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_FILES = [
    ['data/ossec/ossec_cup.json',    'data/aminer/aminer_cup.txt'],
    ['data/ossec/ossec_onion.json',  'data/aminer/aminer_onion.txt'],
    ['data/ossec/ossec_insect.json', 'data/aminer/aminer_insect.txt'],
    ['data/ossec/ossec_spiral.json', 'data/aminer/aminer_spiral.txt'],
]

DEFAULT_DELTAS = [0.5]
DEFAULT_THRESHOLD = 0.3

PHASE_ORDER = ['nmap', 'nikto', 'vrfy', 'hydra', 'upload',
               'exploit', 'non-attack', 'multiple', 'noise']
ATTACK_PHASES = ['nmap', 'nikto', 'vrfy', 'hydra', 'upload', 'exploit']
EMPTY_PHASE_METRICS = {'tp': 0, 'fp': 0, 'fn': 0, 'tn': 0,
                       'precision': 0, 'recall': 0, 'f1': 0, 'support_groups': 0}

def swap_to(version):
    src = ORIG_FILE if version == 'orig' else NEW_FILE
    if not src.exists():
        raise FileNotFoundError(
            f'Không tìm thấy {src}. Cần có 2 file similarity_original.py và similarity_modified.py.'
        )
    shutil.copyfile(src, ACTIVE)


def backup_current():
    if ACTIVE.exists():
        shutil.copyfile(ACTIVE, BACKUP)


def restore_backup():
    if BACKUP.exists():
        shutil.copyfile(BACKUP, ACTIVE)
        BACKUP.unlink()


def run_worker(config):
    swap_to(config['version'])
    env = os.environ.copy()
    env['PYTHONIOENCODING'] = 'utf-8'
    existing_pp = env.get('PYTHONPATH', '')
    env['PYTHONPATH'] = str(ROOT) + (os.pathsep + existing_pp if existing_pp else '')
    payload = json.dumps(config)
    try:
        proc = subprocess.run(
            [sys.executable, '-m', 'evaluation._worker'],
            input=payload,
            capture_output=True,
            text=True,
            cwd=str(ROOT),
            env=env,
            timeout=7200,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f'Worker timeout với config {config}')
    if proc.returncode != 0:
        sys.stderr.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        raise RuntimeError(f'Worker thất bại (returncode={proc.returncode})')
    # Trích phần JSON giữa 2 marker
    text = proc.stdout
    try:
        b = text.index('===RESULT_BEGIN===') + len('===RESULT_BEGIN===')
        e = text.index('===RESULT_END===')
        return json.loads(text[b:e].strip())
    except ValueError:
        sys.stderr.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        raise RuntimeError('Không tìm thấy marker RESULT trong stdout của worker')

def write_table(name, header, rows, *, title=None, note=None):
    md_path = OUT_DIR / f'{name}.md'
    with open(md_path, 'w', encoding='utf-8') as f:
        if title:
            f.write(f'# {title}\n\n')
        if note:
            f.write(f'> {note}\n\n')
        f.write('| ' + ' | '.join(header) + ' |\n')
        f.write('|' + '|'.join(['---'] * len(header)) + '|\n')
        for r in rows:
            f.write('| ' + ' | '.join(_fmt(c) for c in r) + ' |\n')
    print(f'  → {md_path.name} ({len(rows)} dòng) ')


def _fmt(v):
    if isinstance(v, float):
        return f'{v:.4f}'
    return str(v)

def _iter_phase_compare(left_pp, right_pp):
    delta_strs = sorted(set(list(left_pp.keys()) + list(right_pp.keys())))
    for delta_str in delta_strs:
        lp = left_pp.get(delta_str, {})
        rp = right_pp.get(delta_str, {})
        for phase in [p for p in PHASE_ORDER if p in lp or p in rp]:
            ml = lp.get(phase, EMPTY_PHASE_METRICS)
            mr = rp.get(phase, EMPTY_PHASE_METRICS)
            sup = max(ml['support_groups'], mr['support_groups'])
            if sup == 0 and ml['f1'] == 0 and mr['f1'] == 0:
                continue
            yield delta_str, phase, sup, ml, mr

def table_A1(files, deltas, threshold):
    print('\n[A1] So sánh chất lượng clustering tổng thể …')
    runs = {
        v: run_worker({'version': v, 'files': files,
                       'deltas': deltas, 'threshold': threshold})
        for v in ('orig', 'new')
    }
    _write_A1_clustering(runs, files, deltas, threshold)
    _write_A2b_compare(runs, threshold)
    return runs


def _write_A1_clustering(runs, files, deltas, threshold):
    orig = runs['orig']['per_delta'][0]
    new = runs['new']['per_delta'][0]

    def pct(before, after):
        if before == 0:
            return '—'
        p = (after - before) / before * 100
        if abs(p) < 1:
            return f'{p:+.2f}%'
        return f'{p:+.1f}%'

    header = ['Chỉ số', 'Bản gốc', 'LCS+Jaccard', 'Thay đổi']
    rows = [
        ['Số meta-alert', orig['num_meta_alerts'], new['num_meta_alerts'],
         pct(orig['num_meta_alerts'], new['num_meta_alerts'])],
        ['Purity ↑', orig['purity'], new['purity'],
         pct(orig['purity'], new['purity'])],
        ['NMI ↑', orig['nmi'], new['nmi'], pct(orig['nmi'], new['nmi'])],
        ['ARI ↑', orig['ari'], new['ari'], pct(orig['ari'], new['ari'])],
        ['Pair-Precision ↑', orig['pair_precision'], new['pair_precision'],
         pct(orig['pair_precision'], new['pair_precision'])],
        ['Pair-Recall ↑', orig['pair_recall'], new['pair_recall'],
         pct(orig['pair_recall'], new['pair_recall'])],
        ['Pair-F1 ↑', orig['pair_f1'], new['pair_f1'],
         pct(orig['pair_f1'], new['pair_f1'])],
    ]
    scenarios = [f[0].split('_')[-1].split('.')[0] for f in files]
    write_table('A1_clustering_quality', header, rows,
                title='A1 — So sánh chất lượng tổng hợp cảnh báo tổng thể',
                note=f'δ={deltas[0]}, θ={threshold}, datasets={scenarios}. Mũi tên ↑ biểu thị giá trị càng cao càng tốt.')


def _write_A2b_compare(runs, threshold):
    orig_pp = runs['orig'].get('per_phase', {})
    new_pp = runs['new'].get('per_phase', {})
    delta_str = next(iter(orig_pp), None)
    if delta_str is None:
        return

    rows = []
    for phase in ATTACK_PHASES:
        mo = orig_pp[delta_str].get(phase, EMPTY_PHASE_METRICS)
        mn = new_pp.get(delta_str, {}).get(phase, EMPTY_PHASE_METRICS)
        sup = max(mo['support_groups'], mn['support_groups'])
        if sup == 0:
            continue
        rows.append([phase, sup,
                     mo['recall'], mn['recall'],
                     mo['precision'], mn['precision'],
                     mo['f1'], mn['f1']])
    rows.sort(key=lambda r: r[1], reverse=True)

    header = ['Giai đoạn', 'Support',
              'Recall Orig', 'Recall New',
              'Precision Orig', 'Precision New',
              'F1 Orig', 'F1 New']
    write_table('A2b_per_phase_compare', header, rows,
                title='A2b — So sánh F1/Recall/Precision per-phase (Orig vs New)',
                note=f'δ={delta_str}, θ={threshold}. Sắp xếp theo Support giảm dần.')

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--threshold', type=float, default=DEFAULT_THRESHOLD)
    ap.add_argument('--deltas', type=float, nargs='+', default=DEFAULT_DELTAS)
    args = ap.parse_args()

    print(f'>>> Output dir: {OUT_DIR}')
    print(f'>>> threshold={args.threshold}, deltas={args.deltas}')
    backup_current()
    t_start = time.time()
    try:
        table_A1(DEFAULT_FILES, args.deltas, args.threshold)
    finally:
        restore_backup()
        print('\n Đã restore similarity.py về trạng thái ban đầu.')
    print(f'Tổng time: {time.time() - t_start:.1f} s')

if __name__ == '__main__':
    main()
