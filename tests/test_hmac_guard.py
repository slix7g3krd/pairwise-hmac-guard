from security.hmac_guard import (
    canonical_string,
    body_hash,
    sign,
    verify,
    is_timestamp_fresh,
    consume_nonce,
    normalize_header
)


def test_canonical():
    assert canonical_string('GET', '/a', {'b': '2', 'a': '1'}) == 'GET\n/a\na=1&b=2'

def test_duplicate():
    assert canonical_string('GET', '/a', {'a': ['1', '2']}) is None

def test_empty_body():
    assert body_hash('') != body_hash('{}')

def test_hash_det():
    assert body_hash('x') == body_hash('x')

def test_sign_prefix():
    assert sign('k', 'msg').startswith('sha256=')

def test_verify_ok():
    assert verify('k', 'msg', sign('k', 'msg')) is True

def test_verify_bad():
    assert verify('k', 'msg', 'sha256=deadbeef') is False

def test_fresh():
    assert is_timestamp_fresh(1000, 1001, 30) is True

def test_stale():
    assert is_timestamp_fresh(1000, 1100, 30) is False

def test_nonce_first():
    assert consume_nonce('n1', set()) is True

def test_nonce_reuse():
    assert consume_nonce('n1', {'n1'}) is False

def test_header():
    assert normalize_header('X-Signature') == 'x-signature'

def test_empty_sig():
    assert verify('k', 'm', '') is False

def test_version():
    assert sign('k', 'm', version=2).startswith('v2:') is False

def test_safe():
    assert canonical_string('GET', '/a', {}) == 'GET\n/a\n'
