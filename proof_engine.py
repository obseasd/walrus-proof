"""
WalrusProof - Cryptographic Proof-of-Reasoning Engine

Generates an immutable, hash-linked chain of proof records for every
action an AI agent takes. Each proof is encrypted, stored on Walrus
(Sui's decentralized blob store), and anchored on-chain via a Move contract.
"""
import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class ProofRecord:
    """A single proof in the chain."""
    proof_id: str
    chain_position: int
    action_type: str
    action_summary: str
    input_hash: str
    output_hash: str
    prev_proof_hash: str
    timestamp: float
    agent_id: str
    nonce: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    walrus_blob_id: Optional[str] = None
    sui_tx_digest: Optional[str] = None

    def to_bytes(self) -> bytes:
        return json.dumps(asdict(self), sort_keys=True).encode("utf-8")

    def compute_hash(self) -> str:
        payload = (
            f"{self.proof_id}|{self.chain_position}|{self.action_type}|"
            f"{self.input_hash}|{self.output_hash}|{self.prev_proof_hash}|"
            f"{self.timestamp}|{self.nonce}"
        )
        return hashlib.sha256(payload.encode()).hexdigest()


class ProofEngine:
    """Builds and manages the proof chain for a single agent session."""

    GENESIS_HASH = "0" * 64

    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.chain: list[ProofRecord] = []
        self._position = 0

    @property
    def latest_hash(self) -> str:
        if not self.chain:
            return self.GENESIS_HASH
        return self.chain[-1].compute_hash()

    def record_action(
        self,
        action_type: str,
        action_summary: str,
        input_data: str | bytes = "",
        output_data: str | bytes = "",
    ) -> ProofRecord:
        if isinstance(input_data, str):
            input_data = input_data.encode()
        if isinstance(output_data, str):
            output_data = output_data.encode()

        proof = ProofRecord(
            proof_id=uuid.uuid4().hex,
            chain_position=self._position,
            action_type=action_type,
            action_summary=action_summary,
            input_hash=hashlib.sha256(input_data).hexdigest(),
            output_hash=hashlib.sha256(output_data).hexdigest(),
            prev_proof_hash=self.latest_hash,
            timestamp=time.time(),
            agent_id=self.agent_id,
        )
        self.chain.append(proof)
        self._position += 1
        return proof

    def verify_chain(self) -> tuple[bool, str]:
        if not self.chain:
            return True, "Empty chain"

        if self.chain[0].prev_proof_hash != self.GENESIS_HASH:
            return False, "Genesis proof has wrong prev_hash"

        for i, proof in enumerate(self.chain):
            if proof.chain_position != i:
                return False, f"Position mismatch at index {i}"
            if i > 0:
                expected_prev = self.chain[i - 1].compute_hash()
                if proof.prev_proof_hash != expected_prev:
                    return False, f"Hash chain broken at position {i}"

        return True, f"Chain valid: {len(self.chain)} proofs verified"

    def export_chain(self) -> list[dict]:
        return [asdict(p) for p in self.chain]

    @classmethod
    def verify_exported(cls, chain_data: list[dict]) -> tuple[bool, str]:
        if not chain_data:
            return True, "Empty chain"

        prev_hash = cls.GENESIS_HASH
        for i, rec in enumerate(chain_data):
            proof = ProofRecord(**rec)
            if proof.chain_position != i:
                return False, f"Position mismatch at {i}"
            if proof.prev_proof_hash != prev_hash:
                return False, f"Hash chain broken at {i}"
            prev_hash = proof.compute_hash()

        return True, f"Chain valid: {len(chain_data)} proofs verified"
