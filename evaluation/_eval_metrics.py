import math

def count_labels(labels):
    counts = {}
    for label in labels:
        if label not in counts:
            counts[label] = 0
        counts[label] += 1
    return counts

def _build_contingency(y_true, y_pred):
    cm = {}
    for i in range(len(y_true)):
        t = y_true[i]
        p = y_pred[i]
        if t not in cm:
            cm[t] = {}
        if p not in cm[t]:
            cm[t][p] = 0
        cm[t][p] += 1
    return cm

# ---------- Purity ----------

def purity(y_true, y_pred):
    """Tỉ lệ mẫu được gán đúng class chiếm đa số trong cluster của nó."""
    n = len(y_true)
    if n == 0:
        return 0.0

    cm_by_cluster = {}
    for i in range(n):
        t = y_true[i]
        p = y_pred[i]
        if p not in cm_by_cluster:
            cm_by_cluster[p] = {}
        if t not in cm_by_cluster[p]:
            cm_by_cluster[p][t] = 0
        cm_by_cluster[p][t] += 1

    # Mỗi cluster lấy số mẫu thuộc lớp đông nhất
    total_correct = 0
    for cluster_label in cm_by_cluster:
        true_counts = cm_by_cluster[cluster_label]
        max_count = max(true_counts.values())
        total_correct += max_count

    return total_correct / n

def _entropy(counts, total):
    entropy = 0.0
    for c in counts:
        if c > 0:
            p = c / total
            entropy -= p * math.log(p)
    return entropy


def _mutual_info(cm, true_count, pred_count, n):
    """MI(Y_true, Y_pred) tính trên bảng contingency."""
    mi = 0.0
    for t in cm:
        for p in cm[t]:
            c = cm[t][p]
            if c > 0:
                mi += (c / n) * math.log((c * n) / (true_count[t] * pred_count[p]))
    return mi

def homogeneity_completeness(y_true, y_pred):
    n = len(y_true)
    if n == 0:
        return 0.0, 0.0

    true_count = count_labels(y_true)
    pred_count = count_labels(y_pred)
    cm = _build_contingency(y_true, y_pred)

    H_true = _entropy(true_count.values(), n)
    H_pred = _entropy(pred_count.values(), n)
    mi = _mutual_info(cm, true_count, pred_count, n)

    if H_true > 0:
        h = mi / H_true
    else:
        h = 1.0

    if H_pred > 0:
        c = mi / H_pred
    else:
        c = 1.0

    return h, c

def nmi(y_true, y_pred):
    n = len(y_true)
    if n == 0:
        return 0.0

    true_count = count_labels(y_true)
    pred_count = count_labels(y_pred)
    cm = _build_contingency(y_true, y_pred)

    H_true = _entropy(true_count.values(), n)
    H_pred = _entropy(pred_count.values(), n)
    mi = _mutual_info(cm, true_count, pred_count, n)

    denom = (H_true + H_pred) / 2
    if denom > 0:
        return mi / denom # nmi = 1 thì cluster khớp pergect với nhãn thật
    return 0.0


# ARI & Pair-based metrics
def _comb2(x):
    return x * (x - 1) / 2.0 # số cặp có thể tạo ra từ x ptu

def _sum_comb2(counts):
    total = 0.0
    for c in counts:
        total += _comb2(c) # tổng số cặp
    return total

def ari(y_true, y_pred):
    """Adjusted Rand Index. Trả về [-0.5, 1]; 0 ≈ random, 1 = trùng khớp."""
    n = len(y_true)
    if n < 2:
        return 0.0

    true_count = count_labels(y_true)
    pred_count = count_labels(y_pred)
    cm = _build_contingency(y_true, y_pred)

    sum_comb_c = _sum_comb2(true_count.values())
    sum_comb_k = _sum_comb2(pred_count.values())

    sum_comb = 0.0
    for t in cm:
        for p in cm[t]:
            sum_comb += _comb2(cm[t][p]) # số cặp vừa cùng lớp thật, vừa cùng cluster dự đoán

    comb_n = _comb2(n)
    if comb_n > 0:
        expected = (sum_comb_c * sum_comb_k) / comb_n
    else:
        expected = 0.0
    max_index = (sum_comb_c + sum_comb_k) / 2.0

    if max_index == expected:
        return 0.0
    return (sum_comb - expected) / (max_index - expected) # ari = (index - exprect)/ (main index - exprec)


def pair_metrics(y_true, y_pred):
    """Precision / Recall / F1 dựa trên cặp"""
    true_count = count_labels(y_true)
    pred_count = count_labels(y_pred)
    cm = _build_contingency(y_true, y_pred)

    sum_comb_c = _sum_comb2(true_count.values())   # tổng cặp cùng lớp thật
    sum_comb_k = _sum_comb2(pred_count.values())   # tổng cặp cùng cluster dự đoán

    # TP = số cặp vừa cùng lớp thật vừa cùng cluster dự đoán
    tp = 0.0
    for t in cm:
        for p in cm[t]:
            tp += _comb2(cm[t][p])

    fn = sum_comb_c - tp   # cùng lớp thật nhưng bị tách ra khác cluster
    fp = sum_comb_k - tp   # cùng cluster dự đoán nhưng khác lớp thật

    if (tp + fp) > 0:
        prec = tp / (tp + fp)
    else:
        prec = 0.0

    if (tp + fn) > 0:
        rec = tp / (tp + fn)
    else:
        rec = 0.0

    if (prec + rec) > 0:
        f1 = 2 * prec * rec / (prec + rec)
    else:
        f1 = 0.0

    return prec, rec, f1 # pair recall cao nghiax là cảnh báo đáng lẽ cùng nhóm thật thì gom chung tốt

def all_metrics(y_true, y_pred):
    h, c = homogeneity_completeness(y_true, y_pred)
    p, r, f1 = pair_metrics(y_true, y_pred)
    return {
        'purity': purity(y_true, y_pred),
        'nmi': nmi(y_true, y_pred),
        'ari': ari(y_true, y_pred),
        'homogeneity': h,
        'completeness': c,
        'pair_precision': p,
        'pair_recall': r,
        'pair_f1': f1,
    }