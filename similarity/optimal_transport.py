import numpy as np
from similarity.similarity import get_json_similarity
EPSILON = 0.1
MAX_ITER = 100
MAX_PRODUCT = 50_000

def get_group_similarity_ot(group_a, group_b,
                            early_stopping_threshold=0.0,
                            w=None,
                            min_alert_match_similarity=0.0,
                            epsilon=None,
                            max_iter=None,
                            partial=False):
    if epsilon is None:
        epsilon = EPSILON
    if max_iter is None:
        max_iter = MAX_ITER

    alerts_a = group_a.alerts
    alerts_b = group_b.alerts
    m, n = len(alerts_a), len(alerts_b)

    if m == 0 or n == 0:
        return 0.0
    if m * n > MAX_PRODUCT:
        return None
    if min(m, n) / max(m, n) < early_stopping_threshold:
        return 0.0

    # 1. Cost matrix: C[i, j] = 1 - sim(a_i, b_j)
    C = np.empty((m, n), dtype=np.float64)
    for i in range(m):
        a_d = alerts_a[i].d
        for j in range(n):
            s = get_json_similarity(a_d, alerts_b[j].d, w)
            if s < min_alert_match_similarity:
                s = 0.0
            C[i, j] = 1.0 - s

    # 2. Sinkhorn iteration
    a = np.full(m, 1.0 / m, dtype=np.float64)
    b = np.full(n, 1.0 / n, dtype=np.float64)
    K = np.exp(-C / epsilon)
    u = np.ones(m, dtype=np.float64)
    v = np.ones(n, dtype=np.float64)
    for _ in range(max_iter):
        u = a / (K @ v + 1e-30)
        v = b / (K.T @ u + 1e-30)

    # Tính Transport plan
    T = u[:, None] * K * v[None, :]

    transport_cost = float(np.sum(T * C))
    return max(0.0, min(1.0, 1.0 - transport_cost)) #Similarity = 1 - <T, C>
