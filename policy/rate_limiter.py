import time
from collections import defaultdict, deque

request_store = defaultdict(lambda: deque())

LIMITS = {
    "HIGH_TRUST": 100,     
    "MEDIUM_TRUST": 50,
    "LOW_TRUST": 10
}

TIME_WINDOW = 1.0  


def check_rate_limit(source_id: str, trust_state: str):
    now = time.time()
    window = request_store[source_id]

    while window and now - window[0] > TIME_WINDOW:
        window.popleft()

    limit = LIMITS.get(trust_state, 50)

    if len(window) >= limit:
        return False  # BLOCK

    window.append(now)
    return True  # ALLOW