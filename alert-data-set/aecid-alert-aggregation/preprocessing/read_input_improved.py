"""
read_input_improved.py — PHIÊN BẢN SỬA LỖI
=============================================
Thay đổi so với bản trước:
  - Gọi get_groups_with_sim() trả về Groups trực tiếp
  - Không qua trung gian group_times → get_groups nữa
  - Mỗi alert thuộc đúng 1 nhóm, không bị mất

ĐẶT FILE: preprocessing/read_input_improved.py
"""

from preprocessing import preprocess
from clustering import time_delta_group
import random


def fuse_groups(groups_unsorted, times_unsorted, delta):
    """Hàm gốc — KHÔNG SỬA."""
    fused_groups = []
    fused_group = None
    fused_times = []
    fused_time = ()
    prev_time = None
    for group, times in sorted(zip(groups_unsorted, times_unsorted),
                                key=lambda pair: pair[1][0]):
        if prev_time is None:
            fused_group = group
            fused_time = times
        elif times[0] < prev_time + delta:
            fused_group.add_to_group(group.alerts)
            fused_time = (fused_time[0], times[1])
        else:
            fused_groups.append(fused_group)
            fused_group = group
            fused_times.append(fused_time)
            fused_time = times
        prev_time = times[0]
    fused_groups.append(fused_group)
    return fused_groups, fused_times


def read_input(files, deltas, input_type, noise=0.0,
               group_strategy='delta', group_type=[],
               theta_adj=0.0, sim_func=None):
    """
    Đọc và nhóm cảnh báo từ file.

    Khi theta_adj > 0 và sim_func != None:
      → Gọi get_groups_with_sim() trả về Groups trực tiếp
      → Không qua group_times + get_groups

    Khi theta_adj = 0 (default):
      → Hoạt động GIỐNG HỆT file gốc
    """
    groups_dict = {}

    for filegroup in files:
        alerts = []
        timestamps = []

        for f in filegroup:
            f_parts = f.split('/')[-1].split('.')[0].split('_')
            if f_parts[0] in ("aminer", "wazuh", "ossec"):
                file_type = f_parts[0]
            else:
                file_type = f_parts[1]

            if input_type == 'aminer' or file_type == 'aminer':
                file_alerts, file_timestamps = preprocess.read_aminer_json(f)
            elif input_type in ('ossec', 'wazuh') or file_type in ('ossec', 'wazuh'):
                file_alerts, file_timestamps = preprocess.read_ossec_full_json(f)
            else:
                print('Unknown file type ' + str(file_type) +
                      '. Please specify input_type. Aborting.')
                break

            if len(file_alerts) != len(file_timestamps):
                print('Alerts and timestamps are diverging!')
                break

            alerts.extend(file_alerts)
            timestamps.extend(file_timestamps)

        if noise != 0.0:
            max_ts = max(timestamps)
            min_ts = min(timestamps)
            number_to_inject = (max_ts - min_ts) / 60.0 * noise
            sample_alerts = random.sample(alerts, min(100, len(alerts)))
            while number_to_inject > 0:
                number_to_inject -= 1
                new_alert = random.choice(sample_alerts).get_alert_clone()
                new_alert.noise = True
                alerts.append(new_alert)
                timestamps.append(random.uniform(min_ts, max_ts))

        deltas_sorted = sorted(deltas)
        delta_dict = {}
        prev_groups = None

        if group_strategy == 'delta':
            for delta in deltas_sorted:

                if theta_adj > 0 and sim_func is not None:
                    # ===== CẢI TIẾN: trả về Groups trực tiếp =====
                    groups = time_delta_group.get_groups_with_sim(
                        timestamps, alerts, delta, theta_adj, sim_func
                    )
                else:
                    # ===== GỐC: group_times → get_groups =====
                    group_times = time_delta_group.get_time_delta_group_times(
                        timestamps, delta
                    )
                    groups = time_delta_group.get_groups(
                        alerts, timestamps, group_times
                    )

                if prev_groups is None:
                    prev_groups = groups
                else:
                    time_delta_group.find_group_connections(
                        prev_groups, groups
                    )
                    prev_groups = groups

                print('delta = ' + str(delta) + ': ' +
                      str(len(groups)) + ' groups in ' + str(filegroup))
                delta_dict[delta] = groups

        elif group_strategy == 'type':
            alerts_type = {}
            timestamps_type = {}
            for i, alert in enumerate(alerts):
                for group_type_path in group_type:
                    parts = group_type_path.split('.')
                    alert_obj = alert.d
                    not_found = False
                    for part in parts:
                        if part in alert_obj:
                            alert_obj = alert_obj[part]
                        else:
                            not_found = True
                            break
                    if not_found:
                        continue
                    if alert_obj not in alerts_type:
                        alerts_type[alert_obj] = []
                        timestamps_type[alert_obj] = []
                    alerts_type[alert_obj].append(alert)
                    timestamps_type[alert_obj].append(timestamps[i])
                    break

            for delta in deltas_sorted:
                group_times_list = []
                groups_list = []
                for alert_type, ts_type in timestamps_type.items():
                    group_times = time_delta_group.get_time_delta_group_times(
                        ts_type, delta
                    )
                    groups = time_delta_group.get_groups(
                        alerts_type[alert_type], ts_type, group_times
                    )
                    group_times_list.extend(group_times)
                    groups_list.extend(groups)
                fused_groups, fused_times = fuse_groups(
                    groups_list, group_times_list, delta
                )
                print('delta = ' + str(delta) + ': ' +
                      str(len(fused_groups)) + ' groups in ' + str(filegroup))
                delta_dict[delta] = fused_groups

        elif group_strategy == 'bayes':
            group_times = time_delta_group.get_time_bayes_group_times(
                timestamps
            )
            groups = time_delta_group.get_groups(
                alerts, timestamps, group_times
            )
            print(' * ' + str(len(groups)) + ' groups in ' + str(filegroup))
            delta_dict[-1] = groups
        else:
            print('WARNING: Unknown group_strategy ' +
                  str(group_strategy) + '. Aborting.')

        groups_dict[files.index(filegroup)] = delta_dict

    return groups_dict