"""
WalrusProof - OpenClaw Middleware

Integrates all WalrusProof components into a single middleware that
intercepts agent actions, generates proofs, and stores them securely.

Usage:
    wp = WalrusProofMiddleware(agent_id="my-agent", seal_secret="secret")

    # Before processing a prompt
    result = wp.check_prompt(user_prompt, source="telegram")
    if not result.allowed:
        print(f"BLOCKED: {result.reasons}")

    # After an action
    wp.record_action("file_read", "Read /etc/hosts", input_data, output_data)

    # Verify the chain
    valid, msg = wp.verify()
"""
import json
import logging
import time
from typing import Optional

from proof_engine import ProofEngine, ProofRecord
from walrus_client import WalrusClient
from seal_client import SealClient
from prompt_firewall import PromptFirewall, FirewallResult, ThreatLevel
from sui_client import SuiClient

log = logging.getLogger("walrusproof")


class WalrusProofMiddleware:
    """Main middleware that ties all WalrusProof components together."""

    def __init__(
        self,
        agent_id: str,
        seal_secret: str = "walrusproof-demo-secret",
        seal_policy: str = "walrusproof-default",
        walrus_publisher: Optional[str] = None,
        walrus_aggregator: Optional[str] = None,
        sui_rpc: Optional[str] = None,
        sui_package_id: Optional[str] = None,
        sui_chain_object: Optional[str] = None,
        block_threshold: float = 0.7,
        store_on_walrus: bool = True,
        anchor_on_chain: bool = True,
    ):
        self.agent_id = agent_id
        self.store_on_walrus = store_on_walrus
        self.anchor_on_chain = anchor_on_chain

        # Initialize components
        self.engine = ProofEngine(agent_id)
        self.firewall = PromptFirewall(block_threshold=block_threshold)
        self.seal = SealClient(master_secret=seal_secret, policy_id=seal_policy)

        walrus_kwargs = {}
        if walrus_publisher:
            walrus_kwargs["publisher_url"] = walrus_publisher
        if walrus_aggregator:
            walrus_kwargs["aggregator_url"] = walrus_aggregator
        self.walrus = WalrusClient(**walrus_kwargs)

        sui_kwargs = {}
        if sui_rpc:
            sui_kwargs["rpc_url"] = sui_rpc
        if sui_package_id:
            sui_kwargs["package_id"] = sui_package_id
        if sui_chain_object:
            sui_kwargs["chain_object_id"] = sui_chain_object
        self.sui = SuiClient(**sui_kwargs)

        self._action_count = 0
        log.info(f"WalrusProof initialized for agent: {agent_id}")

    def check_prompt(self, prompt: str, source: str = "unknown") -> FirewallResult:
        """Check a prompt through the firewall and log the result."""
        result = self.firewall.analyze(prompt, source=source)

        # Record the firewall check as a proof action
        self.record_action(
            action_type="firewall_check",
            action_summary=f"Prompt from {source}: {result.level.value} (score={result.score:.2f})",
            input_data=prompt,
            output_data=json.dumps({"level": result.level.value, "reasons": result.reasons}),
        )

        if result.level == ThreatLevel.BLOCKED:
            log.warning(f"BLOCKED prompt from {source}: {result.reasons}")
        elif result.level == ThreatLevel.SUSPICIOUS:
            log.info(f"SUSPICIOUS prompt from {source}: score={result.score:.2f}")

        return result

    def record_action(
        self,
        action_type: str,
        action_summary: str,
        input_data: str | bytes = "",
        output_data: str | bytes = "",
    ) -> ProofRecord:
        """Record an agent action, encrypt, store on Walrus, anchor on-chain."""
        # 1. Generate proof
        proof = self.engine.record_action(action_type, action_summary, input_data, output_data)
        self._action_count += 1

        # 2. Encrypt with Seal
        proof_bytes = proof.to_bytes()
        encrypted = self.seal.encrypt(proof_bytes)

        # 3. Store on Walrus
        if self.store_on_walrus:
            try:
                blob_result = self.walrus.store_proof(encrypted)
                proof.walrus_blob_id = blob_result.blob_id
                log.info(f"Proof stored on Walrus: {blob_result.blob_id}")
            except Exception as e:
                log.error(f"Walrus storage failed: {e}")

        # 4. Anchor on Sui
        if self.anchor_on_chain:
            try:
                tx = self.sui.anchor_proof(
                    action_hash=proof.compute_hash(),
                    walrus_blob_id=proof.walrus_blob_id or "local",
                    chain_position=proof.chain_position,
                    timestamp=int(proof.timestamp),
                )
                if tx:
                    proof.sui_tx_digest = tx.digest
                    log.info(f"Proof anchored on Sui: {tx.digest}")
            except Exception as e:
                log.error(f"Sui anchoring failed: {e}")

        return proof

    def verify(self) -> tuple[bool, str]:
        """Verify the integrity of the local proof chain."""
        return self.engine.verify_chain()

    def verify_from_walrus(self, blob_ids: list[str]) -> tuple[bool, str]:
        """Retrieve proofs from Walrus, decrypt, and verify the chain."""
        chain_data = []
        for blob_id in blob_ids:
            try:
                encrypted = self.walrus.read_blob(blob_id)
                decrypted = self.seal.decrypt(encrypted)
                proof_dict = json.loads(decrypted)
                chain_data.append(proof_dict)
            except Exception as e:
                return False, f"Failed to retrieve/decrypt blob {blob_id}: {e}"

        chain_data.sort(key=lambda p: p["chain_position"])
        return ProofEngine.verify_exported(chain_data)

    def export_audit_report(self) -> dict:
        """Export a full audit report of the proof chain."""
        valid, msg = self.verify()
        return {
            "agent_id": self.agent_id,
            "total_actions": self._action_count,
            "chain_length": len(self.engine.chain),
            "chain_valid": valid,
            "verification_message": msg,
            "firewall_stats": self.firewall.get_stats(),
            "proofs": self.engine.export_chain(),
        }

    def get_stats(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "actions_recorded": self._action_count,
            "chain_length": len(self.engine.chain),
            "chain_valid": self.verify()[0],
            "firewall": self.firewall.get_stats(),
        }
