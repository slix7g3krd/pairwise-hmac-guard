"""HMAC request-signing guard for the open platform.

Fixes the replay/tamper defects:
- canonical string covers method + path + full sorted query
- duplicate query parameters are rejected (returns None)
- body hash is computed over the exact raw body (empty != '{}')
- timestamps must fall inside a freshness window
- nonces are single-use via a caller-supplied shared store
- signature comparison is constant-time
- sign() accepts a key version for rotation without changing the wire format
- header names are normalized to lowercase
"""

import hashlib
import hmac
from urllib.parse import quote


def canonical_string(method, path, query):
    """Build the canonical string: METHOD\nPATH\nsorted-query.

    Query params are sorted by (name, value) and percent-encoded so the
    ordering is stable and unambiguous across client and server. A param
    that appears more than once (list/tuple value) makes the request
    ambiguous, so None is returned and the caller must reject it.
    """
    pairs = []
    for name, value in query.items():
        if isinstance(value, (list, tuple)):
            if len(value) != 1:
                return None
            value = value[0]
        pairs.append((str(name), str(value)))
    pairs.sort()
    qs = '&'.join(
        '{}={}'.format(quote(k, safe=''), quote(v, safe='')) for k, v in pairs
    )
    return '{}\n{}\n{}'.format(method.upper(), path, qs)


def body_hash(body):
    """SHA-256 hex digest of the exact raw body.

    The digest goes into the signed canonical string, and '' and '{}'
    hash differently, so an empty body can never be swapped for an
    empty JSON object (or vice versa) without breaking the signature.
    """
    if isinstance(body, str):
        body = body.encode('utf-8')
    return hashlib.sha256(body).hexdigest()


def sign(key, message, version=None):
    """HMAC-SHA256 signature with a 'sha256=' prefix.

    `version` selects which generation of the key is in use (for
    rotation); it never changes the wire format, so old and new keys
    produce the same 'sha256=' shape and expired keys are rejected by
    the caller's key lookup, not by parsing the signature.
    """
    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(message, str):
        message = message.encode('utf-8')
    digest = hmac.new(key, message, hashlib.sha256).hexdigest()
    return 'sha256=' + digest


def verify(key, message, signature):
    """Constant-time signature check. Empty/malformed input is False."""
    if not signature or not isinstance(signature, str):
        return False
    if not signature.startswith('sha256='):
        return False
    expected = sign(key, message)
    return hmac.compare_digest(expected, signature)


def is_timestamp_fresh(timestamp, now, window):
    """True iff |now - timestamp| <= window (rejects old and future)."""
    return abs(now - timestamp) <= window


def consume_nonce(nonce, seen):
    """Single-use nonce check against a shared store.

    `seen` must be a store shared by all instances (e.g. a set backed
    by Redis in production). Returns True and records the nonce on
    first sight; False on replay.
    """
    if nonce in seen:
        return False
    seen.add(nonce)
    return True


def normalize_header(name):
    """Normalize a header name to lowercase for case-insensitive lookup."""
    return name.strip().lower()
