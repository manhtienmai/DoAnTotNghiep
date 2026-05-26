import re
from functools import lru_cache
import pylcs

MIN_LENGTH_THRESHOLD = 10
MAX_LENGTH_THRESHOLD = 500
ALPHA = 0.5

_TOKEN_RE = re.compile(
    r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    r'|[a-zA-Z]+'
    r'|\d+(?:\.\d+)*'
)

def sim_lcs(s1, s2):
    if s1 == s2:
        return 1.0
    if not s1 or not s2:
        return 0.0
    lcs_len = pylcs.lcs_sequence_length(s1, s2)
    return lcs_len / max(len(s1), len(s2))

def sim_jaccard(s1, s2):
    if s1 == s2:
        return 1.0
    if not s1 or not s2:
        return 0.0

    tokens_a = set(_TOKEN_RE.findall(s1.lower()))
    tokens_b = set(_TOKEN_RE.findall(s2.lower()))

    if not tokens_a and not tokens_b:
        return 1.0
    if not tokens_a or not tokens_b:
        return 0.0

    intersection = tokens_a & tokens_b
    union = tokens_a | tokens_b

    return len(intersection) / len(union)

def string_similarity(s1, s2, alpha=None):
    if alpha is None:
        alpha = ALPHA

    if s1 == s2:
        return 1.0
    if not s1 or not s2:
        return 0.0

    if len(s1) <= MAX_LENGTH_THRESHOLD and len(s2) <= MAX_LENGTH_THRESHOLD:
        return _cached_similarity(s1, s2, alpha)
    else:
        return _compute_similarity(s1, s2, alpha)


def _compute_similarity(s1, s2, alpha):
    if alpha == 0.0:
        return sim_jaccard(s1, s2)
    if alpha == 1.0:
        return sim_lcs(s1, s2)
    return alpha * sim_lcs(s1, s2) + (1 - alpha) * sim_jaccard(s1, s2)


@lru_cache(maxsize=100000)
def _cached_similarity(s1, s2, alpha):
    return _compute_similarity(s1, s2, alpha)


def should_use_string_similarity(val_a, val_b, threshold=None):
    if threshold is None:
        threshold = MIN_LENGTH_THRESHOLD

    if not isinstance(val_a, str) or not isinstance(val_b, str):
        return False

    len_a = len(val_a)
    len_b = len(val_b)

    if len_a < threshold or len_b < threshold:
        return False

    if len_a > MAX_LENGTH_THRESHOLD or len_b > MAX_LENGTH_THRESHOLD:
        return False

    return True