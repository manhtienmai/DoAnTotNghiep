"""
dataset_statistics.py — Thong ke du lieu AIT-ADS
=================================================
Thong ke so luong alerts theo:
  - Scenario (8 he thong)
  - IDS (AMiner vs Wazuh)
  - Pha tan cong (10 pha)
  - Thoi gian tan cong

Ket qua ghi ra: data/out/evaluation/dataset_statistics.txt
                 data/out/evaluation/dataset_statistics.csv

Chay:
    cd aecid-alert-aggregation
    python dataset_statistics.py
"""

import os
import sys
import time
import json
from datetime import datetime
from collections import defaultdict

from dateutil import parser as dateparser
import pytz

from attacktimes import phase as attack_phases, get_phase
import aggregate_config

# =====================================================================
# CAU HINH
# =====================================================================
output_dir = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    'data', 'out', 'evaluation'
)
os.makedirs(output_dir, exist_ok=True)

labels_order = [
    'network_scans', 'service_scans', 'dirb', 'wpscan', 'webshell',
    'cracking', 'reverse_shell', 'privilege_escalation', 'service_stop',
    'dnsteal',
    'false_positive_same_day', 'false_positive_test', 'false_positive_other_day'
]

# =====================================================================
# DOC ALERTS TU FILE JSON
# =====================================================================
def read_alerts_from_file(filepath):
    """Doc alerts tu file JSON, tra ve list cac (timestamp_float, alert_dict)."""
    alerts = []
    filename = filepath.split('/')[-1].split('\\')[-1]
    parts = filename.split('.')[0].split('_')

    # Xac dinh IDS type
    if parts[0] in ('aminer', 'wazuh', 'ossec'):
        ids_type = parts[0]
    elif len(parts) > 1 and parts[1] in ('aminer', 'wazuh', 'ossec'):
        ids_type = parts[1]
    else:
        ids_type = 'unknown'

    if ids_type == 'ossec':
        ids_type = 'wazuh'

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read().strip()

        # Try JSON array first
        if content.startswith('['):
            data = json.loads(content)
            for item in data:
                ts = extract_timestamp(item, ids_type)
                alerts.append((ts, item, ids_type))
        else:
            # JSONL (one object per line)
            for line in content.split('\n'):
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                    ts = extract_timestamp(item, ids_type)
                    alerts.append((ts, item, ids_type))
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        print(f"  Loi doc {filepath}: {e}")

    return alerts


def extract_timestamp(d, ids_type):
    """Trich timestamp (float) tu alert dict."""
    if ids_type == 'aminer':
        if 'LogData' in d and 'Timestamps' in d['LogData']:
            ts_list = d['LogData']['Timestamps']
            if isinstance(ts_list, list) and len(ts_list) > 0:
                return float(ts_list[0])
        if 'LogData' in d and 'DetectionTimestamp' in d['LogData']:
            return float(d['LogData']['DetectionTimestamp'])
    else:
        # Wazuh
        if '@timestamp' in d:
            return dateparser.isoparse(d['@timestamp']).timestamp()
        if 'timestamp' in d:
            return dateparser.parse(d['timestamp']).timestamp()
    return 0.0


# =====================================================================
# MAIN
# =====================================================================
def main():
    print("=" * 70)
    print("  THONG KE DU LIEU AIT-ADS")
    print(f"  {len(aggregate_config.files)} scenarios x 2 IDS (AMiner + Wazuh)")
    print("=" * 70)

    # Thu thap du lieu
    # stats[scenario][ids_type][phase] = count
    stats = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
    total_by_scenario = defaultdict(int)
    total_by_ids = defaultdict(int)
    total_by_phase = defaultdict(int)
    grand_total = 0

    # Thoi gian tan cong
    attack_durations = {}

    for filegroup in aggregate_config.files:
        # Xac dinh scenario name
        sample_file = filegroup[0]
        name_parts = sample_file.split('/')[-1].split('\\')[-1].split('.')[0].split('_')
        if name_parts[0] in ('aminer', 'wazuh', 'ossec'):
            scenario = name_parts[1]
        else:
            scenario = name_parts[0]

        print(f"\n  Scenario: {scenario}")

        # Tinh thoi gian tan cong
        if scenario in attack_phases:
            phases_info = attack_phases[scenario]
            attack_start = None
            attack_end = None
            for p_name, interval in phases_info.items():
                if p_name in ('false_positive_test', 'false_positive_same_day',
                              'false_positive_other_day'):
                    continue
                if attack_start is None or interval[0] < attack_start:
                    attack_start = interval[0]
                if attack_end is None or interval[1] > attack_end:
                    attack_end = interval[1]
            if attack_start and attack_end:
                attack_durations[scenario] = {
                    'start': attack_start,
                    'end': attack_end,
                    'duration_sec': (attack_end - attack_start).total_seconds(),
                    'phases': {
                        p: (iv[1] - iv[0]).total_seconds()
                        for p, iv in phases_info.items()
                        if p not in ('false_positive_test', 'false_positive_same_day',
                                     'false_positive_other_day')
                    }
                }

        for filepath in filegroup:
            print(f"    Doc: {filepath} ... ", end='', flush=True)
            t0 = time.time()
            alerts = read_alerts_from_file(filepath)
            print(f"{len(alerts)} alerts ({time.time()-t0:.1f}s)")

            for ts, alert_dict, ids_type in alerts:
                p = get_phase(scenario, ts)
                stats[scenario][ids_type][p] += 1
                total_by_scenario[scenario] += 1
                total_by_ids[ids_type] += 1
                total_by_phase[p] += 1
                grand_total += 1

    # =====================================================================
    # IN KET QUA
    # =====================================================================
    txt_path = os.path.join(output_dir, 'dataset_statistics.txt')
    csv_path = os.path.join(output_dir, 'dataset_statistics.csv')

    with open(txt_path, 'w', encoding='utf-8') as f, \
         open(csv_path, 'w', encoding='utf-8') as csv_f:

        csv_f.write('scenario,ids,phase,count\n')

        def pr(line):
            print(line)
            f.write(line + '\n')

        pr(f"\n{'=' * 90}")
        pr(f"  THONG KE DU LIEU AIT-ADS (AIT Log Data Set V2.0)")
        pr(f"  Tong: {grand_total:,} alerts | {len(aggregate_config.files)} scenarios | 2 IDS")
        pr(f"{'=' * 90}")

        # --- Bang 1: Tong quan theo scenario ---
        pr(f"\n  1. TONG QUAN THEO SCENARIO")
        pr(f"  {'Scenario':<20} {'AMiner':>10} {'Wazuh':>10} {'Tong':>12} {'%':>7}")
        pr(f"  {'-' * 62}")
        for fg in aggregate_config.files:
            name_parts = fg[0].split('/')[-1].split('\\')[-1].split('.')[0].split('_')
            sc = name_parts[0] if name_parts[0] not in ('aminer','wazuh','ossec') else name_parts[1]
            a = sum(stats[sc]['aminer'].values())
            w = sum(stats[sc]['wazuh'].values())
            t = a + w
            pct = t / grand_total * 100 if grand_total > 0 else 0
            pr(f"  {sc:<20} {a:>10,} {w:>10,} {t:>12,} {pct:>6.1f}%")
        pr(f"  {'-' * 62}")
        pr(f"  {'TONG':<20} {total_by_ids.get('aminer',0):>10,} "
           f"{total_by_ids.get('wazuh',0):>10,} {grand_total:>12,} {'100.0':>6}%")

        # --- Bang 2: Phan bo theo pha tan cong ---
        pr(f"\n  2. PHAN BO THEO PHA TAN CONG")
        pr(f"  {'Pha tan cong':<25} {'Alerts':>10} {'%':>7}  So scenario")
        pr(f"  {'-' * 55}")

        for phase_name in labels_order:
            cnt = total_by_phase.get(phase_name, 0)
            if cnt == 0:
                continue
            pct = cnt / grand_total * 100
            # Dem so scenario co pha nay
            n_sc = sum(1 for sc in stats if stats[sc]['aminer'].get(phase_name, 0) +
                       stats[sc]['wazuh'].get(phase_name, 0) > 0)
            pr(f"  {phase_name:<25} {cnt:>10,} {pct:>6.1f}%  {n_sc}/8")

        # Alerts khong thuoc pha nao (non-attack trong thoi gian tan cong)
        other_phases = set(total_by_phase.keys()) - set(labels_order)
        for phase_name in sorted(other_phases):
            cnt = total_by_phase[phase_name]
            pct = cnt / grand_total * 100
            pr(f"  {phase_name:<25} {cnt:>10,} {pct:>6.1f}%")

        # --- Bang 3: Chi tiet scenario x phase ---
        pr(f"\n  3. CHI TIET: SO ALERTS THEO SCENARIO x PHA TAN CONG")

        # Header
        active_phases = [p for p in labels_order if total_by_phase.get(p, 0) > 0]
        # Short names for display
        short_names = {
            'network_scans': 'net_scan', 'service_scans': 'svc_scan',
            'dirb': 'dirb', 'wpscan': 'wpscan', 'webshell': 'webshell',
            'cracking': 'crack', 'reverse_shell': 'rev_sh',
            'privilege_escalation': 'priv_esc', 'service_stop': 'svc_stp',
            'dnsteal': 'dnsteal',
            'false_positive_same_day': 'fp_day',
            'false_positive_test': 'fp_test',
            'false_positive_other_day': 'fp_other',
        }

        header = f"  {'Scenario':<16}"
        for p in active_phases:
            header += f" {short_names.get(p, p[:8]):>9}"
        header += f" {'TONG':>10}"
        pr(header)
        pr(f"  {'-' * (len(header) - 2)}")

        for fg in aggregate_config.files:
            name_parts = fg[0].split('/')[-1].split('\\')[-1].split('.')[0].split('_')
            sc = name_parts[0] if name_parts[0] not in ('aminer','wazuh','ossec') else name_parts[1]
            line = f"  {sc:<16}"
            row_total = 0
            for p in active_phases:
                cnt = stats[sc]['aminer'].get(p, 0) + stats[sc]['wazuh'].get(p, 0)
                row_total += cnt
                line += f" {cnt:>9,}" if cnt > 0 else f" {'-':>9}"
            line += f" {row_total:>10,}"
            pr(line)

        # --- Bang 4: Thoi gian tan cong ---
        pr(f"\n  4. THOI GIAN TAN CONG")
        pr(f"  {'Scenario':<16} {'Bat dau':>22} {'Ket thuc':>22} {'Tong (phut)':>12}")
        pr(f"  {'-' * 75}")

        for fg in aggregate_config.files:
            name_parts = fg[0].split('/')[-1].split('\\')[-1].split('.')[0].split('_')
            sc = name_parts[0] if name_parts[0] not in ('aminer','wazuh','ossec') else name_parts[1]
            if sc in attack_durations:
                ad = attack_durations[sc]
                pr(f"  {sc:<16} {str(ad['start'].strftime('%Y-%m-%d %H:%M:%S')):>22} "
                   f"{str(ad['end'].strftime('%Y-%m-%d %H:%M:%S')):>22} "
                   f"{ad['duration_sec']/60:>11.1f}")

        # --- Bang 5: Thoi luong tung pha ---
        pr(f"\n  5. THOI LUONG TUNG PHA TAN CONG (giay)")

        attack_only = [p for p in labels_order if p not in
                       ('false_positive_same_day', 'false_positive_test', 'false_positive_other_day')]

        header5 = f"  {'Scenario':<16}"
        for p in attack_only:
            header5 += f" {short_names.get(p, p[:8]):>9}"
        pr(header5)
        pr(f"  {'-' * (len(header5) - 2)}")

        for fg in aggregate_config.files:
            name_parts = fg[0].split('/')[-1].split('\\')[-1].split('.')[0].split('_')
            sc = name_parts[0] if name_parts[0] not in ('aminer','wazuh','ossec') else name_parts[1]
            if sc in attack_durations:
                line = f"  {sc:<16}"
                for p in attack_only:
                    dur = attack_durations[sc]['phases'].get(p, 0)
                    if dur > 0:
                        line += f" {dur:>9.0f}"
                    else:
                        line += f" {'-':>9}"
                pr(line)

        # Ghi CSV chi tiet
        for sc in stats:
            for ids_type in stats[sc]:
                for phase_name, count in stats[sc][ids_type].items():
                    csv_f.write(f"{sc},{ids_type},{phase_name},{count}\n")

        pr(f"\n{'=' * 90}")
        pr(f"  Files:")
        pr(f"    TXT: {txt_path}")
        pr(f"    CSV: {csv_path}")
        pr(f"{'=' * 90}")


if __name__ == '__main__':
    main()
