"""Live integration tests for Walrus testnet storage.

These tests require internet access and hit the real Walrus testnet.
Run with: pytest tests/test_walrus_live.py -v
"""
import sys, os
import json
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from walrus_client import WalrusClient


@pytest.fixture
def client():
    return WalrusClient(epochs=1)


def test_walrus_health(client):
    """Check Walrus testnet is reachable."""
    assert client.health_check(), "Walrus testnet unreachable"


def test_store_and_read_text(client):
    """Store text blob and read it back."""
    data = b"WalrusProof integration test - hello walrus!"
    result = client.store_blob(data)
    assert result.blob_id
    assert result.status in ("new", "certified")

    retrieved = client.read_blob(result.blob_id)
    assert retrieved == data


def test_store_and_read_json(client):
    """Store JSON and read it back."""
    obj = {"test": True, "proofs": [1, 2, 3], "agent": "walrusproof"}
    result = client.store_json(obj)
    assert result.blob_id

    retrieved = client.read_json(result.blob_id)
    assert retrieved == obj


def test_store_encrypted_proof(client):
    """Store encrypted bytes (simulating a Seal envelope)."""
    fake_encrypted = os.urandom(256)  # Random bytes
    result = client.store_proof(fake_encrypted)
    assert result.blob_id

    retrieved = client.read_blob(result.blob_id)
    assert retrieved == fake_encrypted


def test_already_certified(client):
    """Storing the same data twice returns alreadyCertified."""
    data = b"walrusproof-dedup-test-fixed-content"
    r1 = client.store_blob(data)
    r2 = client.store_blob(data)
    assert r1.blob_id == r2.blob_id  # Same content = same blob ID
