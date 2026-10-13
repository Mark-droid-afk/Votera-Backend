"""Votera credibility checker and tallying (Chapter 3 algorithms).

1. TF-IDF + Cosine Similarity -> Originality Score (100 - highest similarity x 100)
2. Weighted Sum Model         -> Credibility Score (35/30/20/15)
3. Hash Map tally + Quick Sort -> ranked results (highest to lowest votes)
"""
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

FLAG_THRESHOLD = 0.70  # highest similarity at or above this is flagged for administrator review

# Weighted Sum Model weights (Chapter 3). Each criterion is scored 0-100.
WEIGHTS = {"originality": 0.35, "achievements": 0.30, "leadership": 0.20, "community": 0.15}


def compute_similarities(manifestos: list[str]) -> list[float]:
    """For each manifesto, the highest cosine similarity against the OTHER candidates'
    manifestos in the same election (the reference set). TF-IDF vectors are built over
    the whole set of manifestos, so common words weigh little and distinctive words weigh more."""
    n = len(manifestos)
    if n < 2:
        return [0.0] * n
    try:
        vectors = TfidfVectorizer(lowercase=True, stop_words="english").fit_transform(manifestos)
    except ValueError:  # all manifestos empty or only stop words
        return [0.0] * n
    sim = cosine_similarity(vectors)  # n x n matrix, values 0..1 for TF-IDF vectors
    result = []
    for i in range(n):
        result.append(max(float(sim[i][j]) for j in range(n) if j != i))
    return result


def compute_similarities_detailed(manifestos: list[str]) -> list[tuple[float, int | None]]:
    """Same as compute_similarities, but also returns the index of the most similar other manifesto
    (used to show the administrator WHICH candidate a flagged manifesto resembles)."""
    n = len(manifestos)
    if n < 2:
        return [(0.0, None)] * n
    try:
        vectors = TfidfVectorizer(lowercase=True, stop_words="english").fit_transform(manifestos)
    except ValueError:
        return [(0.0, None)] * n
    sim = cosine_similarity(vectors)
    out = []
    for i in range(n):
        j = max((j for j in range(n) if j != i), key=lambda j: float(sim[i][j]))
        s = float(sim[i][j])
        out.append((s, j if s > 0 else None))
    return out


def originality_score(highest_similarity: float) -> float:
    """Originality = 100 - (highest cosine similarity x 100)."""
    return round(100 - highest_similarity * 100, 2)


def is_flagged(highest_similarity: float) -> bool:
    return highest_similarity >= FLAG_THRESHOLD


def credibility_score(originality: float, achievements: float, leadership: float, community: float) -> float:
    """Weighted Sum Model: sum of each criterion score x its weight."""
    total = (originality * WEIGHTS["originality"] + achievements * WEIGHTS["achievements"]
             + leadership * WEIGHTS["leadership"] + community * WEIGHTS["community"])
    return round(total, 2)


# ---------------- Vote counting ----------------
def count_votes(candidate_ids: list[int], votes: list[int]) -> dict[int, int]:
    """Hash map tally: key = candidate id, value = vote count (O(1) lookup and update per vote)."""
    tally = {cid: 0 for cid in candidate_ids}  # candidates with no votes still appear
    for cid in votes:
        tally[cid] = tally.get(cid, 0) + 1
    return tally


def quick_sort(items: list, key) -> list:
    """Quick Sort (written by hand, not the built-in sort). Sorts ascending by key(item)."""
    if len(items) <= 1:
        return items
    pivot = key(items[len(items) // 2])
    smaller = [x for x in items if key(x) < pivot]
    equal = [x for x in items if key(x) == pivot]
    larger = [x for x in items if key(x) > pivot]
    return quick_sort(smaller, key) + equal + quick_sort(larger, key)


def ranked_results(tally: dict[int, int]) -> list[tuple[int, int]]:
    """Arrange tallied results from most votes to fewest (ties broken by lower candidate id)."""
    pairs = list(tally.items())  # (candidate_id, votes)
    return quick_sort(pairs, key=lambda p: (-p[1], p[0]))