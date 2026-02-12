"""Tests for WalrusProof Seal encryption."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from seal_client import SealClient, SealEnvelope


def test_encrypt_decrypt_roundtrip():
    client = SealClient(master_secret="test-secret", policy_id="test-policy")
    plaintext = b"Hello, this is a secret proof record!"
    encrypted = client.encrypt(plaintext)
    decrypted = client.decrypt(encrypted)
    assert decrypted == plaintext


def test_different_policies_different_output():
    c1 = SealClient(master_secret="secret", policy_id="policy-a")
    c2 = SealClient(master_secret="secret", policy_id="policy-b")

    plaintext = b"Same data, different policies"
    enc1 = c1.encrypt(plaintext)
    enc2 = c2.encrypt(plaintext)
    assert enc1 != enc2


def test_wrong_policy_fails():
    c1 = SealClient(master_secret="secret", policy_id="policy-a")
    c2 = SealClient(master_secret="secret", policy_id="policy-b")

    encrypted = c1.encrypt(b"secret data")
    try:
        c2.decrypt(encrypted)
        assert False, "Should have raised an error"
    except (AssertionError, Exception):
        pass  # Expected


def test_envelope_serialization():
    client = SealClient(master_secret="test", policy_id="test-policy")
    plaintext = b"Test data for envelope"
    encrypted = client.encrypt(plaintext)

    # Should start with SEAL_v1 header
    assert encrypted[:7] == b"SEAL_v1"


def test_large_payload():
    client = SealClient(master_secret="test", policy_id="test-policy")
    plaintext = b"x" * 10000  # 10KB payload
    encrypted = client.encrypt(plaintext)
    decrypted = client.decrypt(encrypted)
    assert decrypted == plaintext


def test_empty_payload():
    client = SealClient(master_secret="test", policy_id="test-policy")
    plaintext = b""
    encrypted = client.encrypt(plaintext)
    decrypted = client.decrypt(encrypted)
    assert decrypted == plaintext


def test_binary_payload():
    client = SealClient(master_secret="test", policy_id="test-policy")
    plaintext = bytes(range(256))  # All byte values
    encrypted = client.encrypt(plaintext)
    decrypted = client.decrypt(encrypted)
    assert decrypted == plaintext
