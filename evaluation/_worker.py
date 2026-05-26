import json
import os
import sys
import time
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
except AttributeError:
    pass

ROOT = Path(__file__).resolve().parent.parent
root_str = str(ROOT)
sys.path = [root_str] + [p for p in sys.path if p != root_str]  # tránh đụng package trùng tên

def label_of(group):
    s = group.attacks
    if not s:
        return 'non-attack'
    if len(s) > 1:
        return 'multiple'
    return next(iter(s))

def scenario_of(group):
    if not group.files or not group.files[0]:
        return 'unknown'
    parts = group.files[0].split('/')[-1].split('.')[0].split('_')
    if parts[0] in ('aminer', 'wazuh', 'ossec', 'test'):
        return parts[1] if len(parts) > 1 else 'unknown'  # Lấy tên scenario từ tên file (cup/onion/insect/spiral)
    return parts[0]

def main():
    config = json.loads(sys.stdin.read())
    version = config['version']

    if version == 'new':
        try:
            from similarity import string_similarity as ss
            if 'alpha' in config and config['alpha'] is not None:
                ss.ALPHA = config['alpha']
            if 'min_length' in config and config['min_length'] is not None:
                ss.MIN_LENGTH_THRESHOLD = config['min_length']
            if 'max_length' in config and config['max_length'] is not None:
                ss.MAX_LENGTH_THRESHOLD = config['max_length']
            ss._cached_similarity.cache_clear()
        except Exception as e:
            print(f'cannot patch string_similarity ({e})', file=sys.stderr)

    pair_strategy = config.get('pair_strategy', 'best')

    if pair_strategy == 'ot':
        try:
            from similarity import optimal_transport as ot
            if 'epsilon' in config and config['epsilon'] is not None:
                ot.EPSILON = config['epsilon']
            if 'max_iter' in config and config['max_iter'] is not None:
                ot.MAX_ITER = config['max_iter']
        except Exception as e:
            print(f'[worker] WARNING: cannot patch optimal_transport ({e})', file=sys.stderr)

    from preprocessing import label as lab
    from preprocessing import read_input
    from merging.objects import MetaAlertManager, KnowledgeBase

    threshold = config['threshold']
    min_alert_match_similarity = config.get('min_alert_match_similarity')
    if min_alert_match_similarity is None:
        min_alert_match_similarity = threshold
    max_val_limit = config.get('max_val_limit', 10)
    min_key_occurrence = config.get('min_key_occurrence', 0.1)
    min_val_occurrence = config.get('min_val_occurrence', 0.1)
    alignment_weight = config.get('alignment_weight', 0.1)
    max_groups = config.get('max_groups_per_meta_alert', 25)
    w = config.get('w', {'timestamp': 0, 'Timestamp': 0, 'timestamps': 0, 'Timestamps': 0})

    # === 1. Đọc input ===
    t_start = time.perf_counter()
    groups_dict = read_input.read_input(config['files'], list(config['deltas']), None)
    read_time = time.perf_counter() - t_start

    # === 2. Build bag-of-alerts + incremental clustering ===
    kb = KnowledgeBase(max_groups, evaluate=True)
    mam = MetaAlertManager(kb)
    bag_time = 0.0
    cluster_time = 0.0

    for file_idx, delta_dicts in groups_dict.items():
        for delta, groups in delta_dicts.items():
            for group in groups:
                lab.label_group(group)
                t1 = time.perf_counter()
                group.create_bag_of_alerts(
                    min_alert_match_similarity,
                    max_val_limit=max_val_limit,
                    min_key_occurrence=min_key_occurrence,
                    min_val_occurrence=min_val_occurrence,
                )
                t2 = time.perf_counter()
                mam.add_to_meta_alerts(
                    group, delta, threshold,
                    min_alert_match_similarity=min_alert_match_similarity,
                    max_val_limit=max_val_limit,
                    min_key_occurrence=min_key_occurrence,
                    min_val_occurrence=min_val_occurrence,
                    w=w,
                    alignment_weight=alignment_weight,
                    pair_strategy=pair_strategy,
                )
                t3 = time.perf_counter()
                bag_time += (t2 - t1)
                cluster_time += (t3 - t2)
                kb.add_group_delta(group, delta)

    total_time = time.perf_counter() - t_start

    # === 3. Tính metrics theo delta ===
    from evaluation._eval_metrics import all_metrics

    per_delta = []
    for delta, groups in kb.delta_dict.items():
        y_true = [label_of(g) for g in groups]
        y_pred = [g.meta_alert.id if g.meta_alert is not None else -1 for g in groups]
        metrics = all_metrics(y_true, y_pred)
        metrics['delta'] = delta
        metrics['num_groups'] = len(groups)
        n_ma = len(mam.meta_alerts.get(delta, []))
        metrics['num_meta_alerts'] = n_ma
        metrics['reduction'] = (1 - n_ma / len(groups)) if groups else 0.0
        # Reduction theo alert (so với tổng số alert thô)
        total_alerts = sum(len(g.alerts) for g in groups)
        total_ma_alerts = sum(len(m.alert_group.alerts) for m in mam.meta_alerts.get(delta, []))
        metrics['total_alerts'] = total_alerts
        metrics['total_ma_alerts'] = total_ma_alerts
        metrics['reduction_alerts'] = (1 - total_ma_alerts / total_alerts) if total_alerts else 0.0
        per_delta.append(metrics)

    #   same meta_alert + same label  → TP, same meta_alert + diff label  → FP
    #   diff meta_alert + same attacks → FN, diff meta_alert + diff attacks → TN
    PHASE_LABELS = ['nmap', 'nikto', 'vrfy', 'hydra', 'upload',
                    'exploit', 'non-attack', 'multiple', 'noise']

    per_phase = {}
    for delta, groups in kb.delta_dict.items():
        counts = {l: {'tp': 0, 'fp': 0, 'fn': 0, 'tn': 0} for l in PHASE_LABELS}
        for go in groups:
            ol = label_of(go)
            if ol not in counts:
                counts[ol] = {'tp': 0, 'fp': 0, 'fn': 0, 'tn': 0}
            for gi in groups:
                if go is gi:
                    continue
                il = label_of(gi)
                same_ma = (go.meta_alert is not None
                           and gi.meta_alert is not None
                           and go.meta_alert is gi.meta_alert)
                if same_ma:
                    if ol == il:
                        counts[ol]['tp'] += 1
                    else:
                        counts[ol]['fp'] += 1
                else:
                    if go.attacks == gi.attacks:
                        counts[ol]['fn'] += 1
                    else:
                        counts[ol]['tn'] += 1

        # Tính precision/recall/F1 cho từng label
        phase_metrics = {}
        for l, d in counts.items():
            tp, fp, fn, tn = d['tp'], d['fp'], d['fn'], d['tn']
            prec = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
            rec = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
            f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0
            tpr = rec
            fpr = (fp / (fp + tn)) if (fp + tn) > 0 else 0.0
            support_groups = sum(1 for g in groups if label_of(g) == l)
            phase_metrics[l] = {
                'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
                'precision': prec, 'recall': rec, 'f1': f1,
                'tpr': tpr, 'fpr': fpr,
                'support_groups': support_groups,
            }
        per_phase[str(delta)] = phase_metrics

    # Per-scenario
    per_scenario = {}
    if kb.delta_dict:
        any_delta = next(iter(kb.delta_dict))
        for g in kb.delta_dict[any_delta]:
            sc = scenario_of(g)
            if sc not in per_scenario:
                per_scenario[sc] = {'num_groups': 0, 'num_alerts': 0, 'meta_alerts_ids': set()}
            per_scenario[sc]['num_groups'] += 1
            per_scenario[sc]['num_alerts'] += len(g.alerts)
            if g.meta_alert is not None:
                per_scenario[sc]['meta_alerts_ids'].add(g.meta_alert.id)
        for sc, d in per_scenario.items():
            d['num_meta_alerts'] = len(d.pop('meta_alerts_ids'))

    # Cache info
    cache_info = None
    if version == 'new':
        try:
            from similarity.string_similarity import _cached_similarity
            info = _cached_similarity.cache_info()
            cache_info = {
                'hits': info.hits,
                'misses': info.misses,
                'currsize': info.currsize,
                'maxsize': info.maxsize,
                'hit_rate': (info.hits / (info.hits + info.misses)) if (info.hits + info.misses) > 0 else 0.0,
            }
        except Exception:
            cache_info = None

    result = {
        'version': version,
        'config': {
            'threshold': threshold,
            'deltas': list(config['deltas']),
            'alpha': config.get('alpha'),
            'min_length': config.get('min_length'),
            'max_length': config.get('max_length'),
            'pair_strategy': pair_strategy,
            'gap': config.get('gap'),
            'epsilon': config.get('epsilon'),
            'files': config['files'],
        },
        'read_time': read_time,
        'bag_time': bag_time,
        'cluster_time': cluster_time,
        'total_time': total_time,
        'per_delta': per_delta,
        'per_phase': per_phase,
        'per_scenario': per_scenario,
        'cache_info': cache_info,
    }

    print(json.dumps(result))

if __name__ == '__main__':
    main()
