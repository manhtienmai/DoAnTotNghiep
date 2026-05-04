"""
Module string_similarity v2 — Phiên bản tối ưu tốc độ
Thay đổi so với v1:
  1. Thêm MAX_LENGTH_THRESHOLD: chuỗi quá dài dùng == (tránh O(n²) chậm)
  2. Thêm LRU cache: cặp chuỗi giống nhau không tính lại
  3. Dùng quick_ratio() trước ratio() để loại nhanh cặp khác xa
"""

import re
from difflib import SequenceMatcher
from functools import lru_cache

# === CẤU HÌNH ===
MIN_LENGTH_THRESHOLD = 10
MAX_LENGTH_THRESHOLD = 500
ALPHA = 0.5
QUICK_REJECT_THRESHOLD = 0.1 # Nếu quick_ratio < ngưỡng này → trả 0 luôn

TOKEN_DELIMITERS = r'[\s\[\]\(\)\{\}:;,="\'/\\|<>@#$%^&*!?+\-]+'
_TOKEN_RE = re.compile(TOKEN_DELIMITERS)  # Compile 1 lần, dùng lại


def sim_lcs(s1, s2):
    """LCS ratio với quick reject để tăng tốc"""
    if s1 == s2:
        return 1.0
    if not s1 or not s2:
        return 0.0
    # autojunk=False: tắt auto-junk detection → nhanh hơn cho chuỗi ngắn
    matcher = SequenceMatcher(None, s1, s2, autojunk=False)
    # quick_ratio() chạy O(n) — nếu kết quả quá thấp thì bỏ qua
    # ratio() chạy O(n²) — chỉ gọi khi quick_ratio đủ cao
    quick = matcher.quick_ratio()
    if quick < QUICK_REJECT_THRESHOLD:
        return quick  # Trả quick_ratio luôn, không cần tính chính xác
    return matcher.ratio()


def sim_jaccard(s1, s2):
    """Jaccard token similarity"""
    if s1 == s2:
        return 1.0
    if not s1 or not s2:
        return 0.0

    tokens_a = set(t for t in _TOKEN_RE.split(s1) if t)
    tokens_b = set(t for t in _TOKEN_RE.split(s2) if t)

    if not tokens_a and not tokens_b:
        return 1.0
    if not tokens_a or not tokens_b:
        return 0.0

    intersection = tokens_a & tokens_b
    union = tokens_a | tokens_b

    return len(intersection) / len(union)


def string_similarity(s1, s2, alpha=None):
    """
    Phép đo tương đồng kết hợp LCS + Jaccard
    Phiên bản v2: dùng cache để tránh tính lại cùng cặp chuỗi
    """
    if alpha is None:
        alpha = ALPHA

    if s1 == s2:
        return 1.0
    if not s1 or not s2:
        return 0.0

    # Dùng cached version nếu chuỗi đủ ngắn để hash
    # (chuỗi rất dài thì hash cũng tốn thời gian)
    if len(s1) <= MAX_LENGTH_THRESHOLD and len(s2) <= MAX_LENGTH_THRESHOLD:
        return _cached_similarity(s1, s2, alpha)
    else:
        # Chuỗi quá dài — tính trực tiếp không cache
        lcs = sim_lcs(s1, s2)
        jac = sim_jaccard(s1, s2)
        return alpha * lcs + (1 - alpha) * jac


@lru_cache(maxsize=10000)
def _cached_similarity(s1, s2, alpha):
    """Phiên bản có cache — tự động lưu kết quả đã tính"""
    lcs = sim_lcs(s1, s2)
    jac = sim_jaccard(s1, s2)
    return alpha * lcs + (1 - alpha) * jac


def should_use_string_similarity(val_a, val_b, threshold=None):
    """
    Kiểm tra có nên dùng string similarity không
    v2: thêm giới hạn MAX_LENGTH_THRESHOLD
    """
    if threshold is None:
        threshold = MIN_LENGTH_THRESHOLD

    if not isinstance(val_a, str) or not isinstance(val_b, str):
        return False

    len_a = len(val_a)
    len_b = len(val_b)

    # Quá ngắn → dùng ==
    if len_a < threshold or len_b < threshold:
        return False

    # Quá dài → dùng == (tránh O(n²) chậm)
    if len_a > MAX_LENGTH_THRESHOLD or len_b > MAX_LENGTH_THRESHOLD:
        return False

    return True


if __name__ == "__main__":
    print("=" * 60)
    print("TEST MODULE STRING_SIMILARITY v2 (tối ưu tốc độ)")
    print("=" * 60)
    print(f"  MIN_LENGTH_THRESHOLD = {MIN_LENGTH_THRESHOLD}")
    print(f"  MAX_LENGTH_THRESHOLD = {MAX_LENGTH_THRESHOLD}")
    print(f"  ALPHA = {ALPHA}")
    print(f"  QUICK_REJECT_THRESHOLD = {QUICK_REJECT_THRESHOLD}")

    test_cases = [
        (
            "2020-03-04 18:19:49 no host name found for IP address 192.168.10.81",
            "2020-03-04 19:21:55 no host name found for IP address 192.168.10.238",
            "AMiner RawLogData: khác thời gian + IP"
        ),
        (
            '10.35.35.202 - - [15/Jan/2022:06:20:14 +0000] "GET / HTTP/1.1" 200 6128',
            '10.35.35.202 - - [15/Jan/2022:06:20:15 +0000] "GET / HTTP/1.1" 200 6128',
            "Apache log: khác 1 giây"
        ),
        (
            "Jan 15 06:26:59 mail dovecot: imap-login: Login: user=<daniel.morgan>, method=PLAIN, rip=127.0.0.1",
            "Jan 15 06:27:00 mail dovecot: imap-login: Login: user=<sarah.wilson>, method=PLAIN, rip=127.0.0.1",
            "Wazuh full_log: khác user"
        ),
        (
            "type=USER_ACCT msg=audit(1642204801.159:657): pid=5790 uid=0",
            "Jan 15 02:32:32 mail freshclam[29266]: ClamAV update process started",
            "Hoàn toàn khác"
        ),
        (
            "GET",
            "POST",
            "Chuỗi ngắn"
        ),
        (
            "A" * 600,
            "A" * 599 + "B",
            "Chuỗi quá dài (>500) — nên bị chặn"
        ),
    ]

    import time
    for s1, s2, desc in test_cases:
        start = time.time()
        combined = string_similarity(s1, s2)
        elapsed = time.time() - start
        should = should_use_string_similarity(s1, s2)
        eq = 1 if s1 == s2 else 0
        print(f"\n--- {desc} ---")
        print(f"  len={len(s1)},{len(s2)} | =="
              f"{eq} | sim={combined:.3f} | "
              f"dùng={'Có' if should else 'Không'} | "
              f"time={elapsed*1000:.1f}ms")

    # Test cache hit
    print(f"\n--- Test cache ---")
    s1 = "2020-03-04 18:19:49 no host name found for IP address 192.168.10.81"
    s2 = "2020-03-04 19:21:55 no host name found for IP address 192.168.10.238"
    start = time.time()
    for _ in range(10000):
        string_similarity(s1, s2)
    elapsed = time.time() - start
    print(f"  10,000 lần gọi cùng cặp: {elapsed*1000:.0f}ms "
          f"({elapsed/10000*1000000:.1f}μs/call)")
    print(f"  Cache info: {_cached_similarity.cache_info()}")