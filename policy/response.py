import time

blocked_sources = {}
BLOCK_TIMEOUT = 30  

def block_source(source):
    if source not in blocked_sources:
        blocked_sources[source] = time.time()
        print(f"⛔ BLOCKED SOURCE: {source}")

def is_blocked(source):
    if source not in blocked_sources:
        return False

    # auto-unblock after timeout
    if time.time() - blocked_sources[source] > BLOCK_TIMEOUT:
        print(f"✅ UNBLOCKED SOURCE: {source}")
        del blocked_sources[source]
        return False

    return True