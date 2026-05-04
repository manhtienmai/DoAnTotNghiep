from clustering.objects import Group
from astropy import stats

def get_time_delta_group_times(timestamps, delta):
  # Cannot assume that alerts are chronologically ordered, especially when multiple files/ids are used.
  # This code is not implemented for online analysis, only forensic analysis supported.
  group_times = []
  for ts in timestamps:
    group_found = False
    for i in reversed(range(len(group_times))): # Reverse, because most likely last group is most recent and thus fits
      if ts >= group_times[i][0] - delta and ts <= group_times[i][1] + delta:
        group_times[i] = (min(group_times[i][0], ts), max(group_times[i][1], ts))
        group_found = True
        break
    if group_found is False:
      group_times.append((ts, ts))

  # Sort groups by start time
  start_times = []
  for group_time in group_times:
    start_times.append(group_time[0])
  sorted_group_times = [x for _, x in sorted(zip(start_times, group_times))]

  merged_group_times = [sorted_group_times[0]] # Initialize with first group
  for group_time in sorted_group_times:
    if group_time[0] <= merged_group_times[-1][1] + delta:
      merged_group_times[-1] = (merged_group_times[-1][0], max(merged_group_times[-1][1], group_time[1]))
    else:
      merged_group_times.append(group_time)

  return merged_group_times

def get_time_bayes_group_times(timestamps_unsorted):
  timestamps = sorted(timestamps_unsorted)
  group_times = []
  group_time = (timestamps[0], timestamps[0])
  blocks = stats.bayesian_blocks(timestamps, fitness='events')
  current_block_index = 0
  prev_time = None
  for timestamp in timestamps:
    # Since many timestamps are integers, this method will produce groups for each second during high-frequency alerts; avoid by forcing that groups are larger than 1 second
    if prev_time is None or timestamp < blocks[current_block_index] or abs(timestamp - prev_time) < 1.001:
      group_time = (group_time[0], timestamp)
    else:
      group_times.append((group_time[0], timestamp))
      group_time = (timestamp, timestamp)
    prev_time = timestamp
  return group_times

def get_group_indices(timestamps, group_times):
  group_indices = []
  for group_time in group_times:
    group_indices.append([])
  i = 0
  for ts in timestamps:
    j = 0
    for group_time in group_times:
      # Alert could be part of multiple groups
      if ts >= group_time[0] and ts <= group_time[1]:
        group_indices[j].append(i)
      j += 1
    i += 1

  return group_indices

def get_groups(alerts, timestamps, group_times):
  groups = []
  for group_time in group_times:
    groups.append(Group())
  i = 0
  for alert in alerts:
    ts = timestamps[i]
    j = 0
    for group_time in group_times:
      # Alert could be part of multiple groups
      if ts >= group_time[0] and ts <= group_time[1]:
        groups[j].add_to_group(alert)
      j += 1
    i += 1

  return groups

def find_group_connections(groups_small_delta, groups_large_delta):
  # This could be improved by finding common group ids allocated to each alert
  # This could be more efficiently solved when group_times is used instead of iterating over all alerts.
  for group_small_delta in groups_small_delta:
    supergroup = None
    for alert in group_small_delta.alerts:
      if supergroup is not None and alert in supergroup.alerts:
        # Alert is in same supergroup as previous alert, skip since supergroup already added.
        continue
      for group_large_delta in groups_large_delta:
        if alert in group_large_delta.alerts:
          supergroup = group_large_delta
          break
      if supergroup is not None:
        group_small_delta.supergroups.append(supergroup)
        if group_small_delta not in supergroup.subgroups:
          supergroup.subgroups.append(group_small_delta)
      else:
        print('No supergroup found, something went wrong!')

def _get_alert_type(alert):
  if alert is None or not hasattr(alert, 'd'):
    return None
  d = alert.d

  # AMiner alert
  if 'AnalysisComponent' in d:
    ac = d['AnalysisComponent']
    if isinstance(ac, dict) and 'AnalysisComponentName' in ac:
      return ('aminer', str(ac['AnalysisComponentName']))
    return ('aminer', str(ac))

  # Wazuh/OSSEC alert
  if 'rule' in d:
    rule = d['rule']
    if isinstance(rule, dict) and 'description' in rule:
      return ('wazuh', str(rule['description']))
    return ('wazuh', str(rule))

  return None


def _safe_sim(alert_a, alert_b, sim_func):
  """
  So sánh nhanh 2 alert dựa trên loại cảnh báo (O(1)).
  - Cùng source + cùng type → 1.0 (gộp)
  - Cùng source + khác type → 0.0 (tách)
  - Khác source (cross-IDS) → 1.0 (cho gộp vì không so sánh được)
  - Không xác định được type → fallback gọi sim_func
  """
  if alert_a is None or alert_b is None:
    return 1.0

  type_a = _get_alert_type(alert_a)
  type_b = _get_alert_type(alert_b)

  # Không trích xuất được type → fallback
  if type_a is None or type_b is None:
    try:
      return sim_func(alert_a.d, alert_b.d)
    except Exception:
      return 1.0

  # Cross-IDS (AMiner vs Wazuh) → cho gộp
  if type_a[0] != type_b[0]:
    return 1.0

  # Cùng source: so sánh type string
  if type_a[1] == type_b[1]:
    return 1.0  # Cùng loại
  else:
    return 0.0  # Khác loại


def get_groups_with_sim(timestamps, alerts, delta, theta_adj, sim_func):
  """
  Nhóm cảnh báo theo thời gian + điều kiện tương đồng kề.
  Trả về list[Group] trực tiếp — mỗi alert thuộc đúng 1 nhóm.

  Khác biệt với phiên bản cũ:
    - Cũ: tính group_times → get_groups gán theo thời gian → overlap → mất alert
    - Mới: gán alert vào Group ngay khi duyệt → không bao giờ mất alert

  Parameters:
      timestamps: list[float]
      alerts:     list[Alert]
      delta:      float — ngưỡng thời gian
      theta_adj:  float — ngưỡng tương đồng (>0)
      sim_func:   callable(dict, dict) → float

  Returns:
      list[Group] — mỗi alert thuộc đúng 1 nhóm
  """
  # ===== BƯỚC 1: Gán alert vào nhóm =====
  # Mỗi nhóm theo dõi: Group object, khoảng thời gian, alert cuối
  groups = []  # list[Group]
  group_ranges = []  # list[(start, end)] — chỉ dùng để kiểm tra thời gian
  group_last_alerts = []  # list[Alert] — alert cuối mỗi nhóm

  for idx, ts in enumerate(timestamps):
    alert = alerts[idx]
    group_found = False

    # Duyệt ngược — nhóm gần nhất thường phù hợp nhất
    for i in reversed(range(len(groups))):
      # Kiểm tra thời gian (giống gốc)
      if ts >= group_ranges[i][0] - delta and ts <= group_ranges[i][1] + delta:

        # Kiểm tra tương đồng nội dung (CẢI TIẾN)
        sim = _safe_sim(alert, group_last_alerts[i], sim_func)
        if sim < theta_adj:
          continue  # Nội dung khác → thử nhóm tiếp

        # Gán alert vào nhóm này
        groups[i].add_to_group(alert)
        group_ranges[i] = (min(group_ranges[i][0], ts),
                           max(group_ranges[i][1], ts))
        group_last_alerts[i] = alert
        group_found = True
        break

    if not group_found:
      # Tạo nhóm mới
      new_group = Group()
      new_group.add_to_group(alert)
      groups.append(new_group)
      group_ranges.append((ts, ts))
      group_last_alerts.append(alert)

  # ===== BƯỚC 2: Merge nhóm chồng thời gian + nội dung giống =====
  # Sắp xếp theo thời gian bắt đầu
  paired = sorted(zip(group_ranges, group_last_alerts, groups),
                  key=lambda x: x[0][0])

  if len(paired) == 0:
    return []

  merged_groups = [paired[0][2]]
  merged_ranges = [paired[0][0]]
  merged_last_alerts = [paired[0][1]]

  for k in range(1, len(paired)):
    gt, la, grp = paired[k]

    time_overlap = (gt[0] <= merged_ranges[-1][1] + delta)

    if time_overlap:
      sim = _safe_sim(la, merged_last_alerts[-1], sim_func)
      if sim >= theta_adj:
        # Merge: chuyển alert từ grp sang nhóm hiện tại
        merged_groups[-1].add_to_group(grp.alerts)
        merged_ranges[-1] = (merged_ranges[-1][0],
                             max(merged_ranges[-1][1], gt[1]))
        merged_last_alerts[-1] = la
      else:
        # Nội dung khác → giữ tách
        merged_groups.append(grp)
        merged_ranges.append(gt)
        merged_last_alerts.append(la)
    else:
      # Xa thời gian → giữ tách
      merged_groups.append(grp)
      merged_ranges.append(gt)
      merged_last_alerts.append(la)

  # Lọc bỏ nhóm rỗng (phòng trường hợp edge case)
  merged_groups = [g for g in merged_groups if len(g.alerts) > 0]

  return merged_groups