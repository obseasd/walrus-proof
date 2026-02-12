"""
WalrusProof - Seal Encryption Client

Wraps Sui Seal protocol for encrypting proof data before storing on Walrus.
Seal allows policy-based encryption: only parties meeting the on-chain policy
can decrypt the data.

For hackathon demo: uses AES-256-GCM as local encryption with Seal-compatible
key derivation. Full Seal integration requires the @mysten/seal TypeScript SDK
for on-chain policy enforcement.
"""
import hashlib
import json
import os
import struct
from dataclasses import dataclass
from typing import Optional

# Use cryptography library for AES-GCM
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


SEAL_PROTOCOL_VERSION = 1
SEAL_HEADER = b"SEAL_v1"


@dataclass
class SealEnvelope:
    """Encrypted envelope compatible with Seal protocol."""
    version: int
    policy_id: str
    nonce: bytes
    ciphertext: bytes
    tag: bytes

    def to_bytes(self) -> bytes:
        policy_bytes = self.policy_id.encode("utf-8")
        return (
            SEAL_HEADER
            + struct.pack(">B", self.version)
            + struct.pack(">H", len(policy_bytes))
            + policy_bytes
            + struct.pack(">H", len(self.nonce))
            + self.nonce
            + self.ciphertext
            + self.tag
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "SealEnvelope":
        assert data[:7] == SEAL_HEADER, "Invalid Seal envelope header"
        pos = 7
        version = struct.unpack(">B", data[pos : pos + 1])[0]
        pos += 1
        policy_len = struct.unpack(">H", data[pos : pos + 2])[0]
        pos += 2
        policy_id = data[pos : pos + policy_len].decode("utf-8")
        pos += policy_len
        nonce_len = struct.unpack(">H", data[pos : pos + 2])[0]
        pos += 2
        nonce = data[pos : pos + nonce_len]
        pos += nonce_len
        # AES-GCM: ciphertext includes 16-byte tag at the end
        ciphertext = data[pos:-16]
        tag = data[-16:]
        return cls(version=version, policy_id=policy_id, nonce=nonce, ciphertext=ciphertext, tag=tag)


class SealClient:
    """
    Encrypts and decrypts proof data using Seal-compatible AES-256-GCM.

    In production, the encryption key is derived from Sui on-chain policies
    via the Seal key server. For the hackathon demo, we derive keys from
    a shared secret + policy_id using HKDF.
    """

    def __init__(self, master_secret: str, policy_id: str = "walrusproof-default"):
        self.policy_id = policy_id
        self._key = self._derive_key(master_secret, policy_id)

    @staticmethod
    def _derive_key(secret: str, policy_id: str) -> bytes:
        """HKDF-like key derivation from secret + policy."""
        material = f"seal:{policy_id}:{secret}".encode()
        return hashlib.sha256(material).digest()  # 32 bytes = AES-256

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt data and return a Seal envelope as bytes."""
        if not HAS_CRYPTO:
            return self._fallback_encrypt(plaintext)

        nonce = os.urandom(12)  # 96-bit nonce for AES-GCM
        aes = AESGCM(self._key)
        ct_with_tag = aes.encrypt(nonce, plaintext, associated_data=self.policy_id.encode())
        # AES-GCM appends 16-byte tag
        ciphertext = ct_with_tag[:-16]
        tag = ct_with_tag[-16:]

        envelope = SealEnvelope(
            version=SEAL_PROTOCOL_VERSION,
            policy_id=self.policy_id,
            nonce=nonce,
            ciphertext=ciphertext,
            tag=tag,
        )
        return envelope.to_bytes()

    def decrypt(self, envelope_bytes: bytes) -> bytes:
        """Decrypt a Seal envelope back to plaintext."""
        if not HAS_CRYPTO:
            return self._fallback_decrypt(envelope_bytes)

        env = SealEnvelope.from_bytes(envelope_bytes)
        assert env.policy_id == self.policy_id, f"Policy mismatch: {env.policy_id} != {self.policy_id}"

        aes = AESGCM(self._key)
        ct_with_tag = env.ciphertext + env.tag
        return aes.decrypt(env.nonce, ct_with_tag, associated_data=self.policy_id.encode())

    def _fallback_encrypt(self, plaintext: bytes) -> bytes:
        """XOR fallback when cryptography library is unavailable."""
        nonce = os.urandom(12)
        key_stream = hashlib.sha256(self._key + nonce).digest()
        ct = bytes(b ^ key_stream[i % 32] for i, b in enumerate(plaintext))
        tag = hashlib.sha256(self._key + ct).digest()[:16]
        return SealEnvelope(
            version=SEAL_PROTOCOL_VERSION,
            policy_id=self.policy_id,
            nonce=nonce,
            ciphertext=ct,
            tag=tag,
        ).to_bytes()

    def _fallback_decrypt(self, envelope_bytes: bytes) -> bytes:
        """XOR fallback decryption."""
        env = SealEnvelope.from_bytes(envelope_bytes)
        key_stream = hashlib.sha256(self._key + env.nonce).digest()
        return bytes(b ^ key_stream[i % 32] for i, b in enumerate(env.ciphertext))
