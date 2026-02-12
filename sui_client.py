"""
WalrusProof - Sui Blockchain Client

Interacts with the WalrusProof Move smart contract on Sui to anchor
proof records on-chain. Uses Sui JSON-RPC API directly.
"""
import hashlib
import json
import requests
import logging
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger("walrusproof.sui")

SUI_TESTNET_RPC = "https://fullnode.testnet.sui.io:443"
SUI_DEVNET_RPC = "https://fullnode.devnet.sui.io:443"

# Deployed contract addresses (Sui Testnet)
WALRUSPROOF_PACKAGE_ID = "0xb9d87d8952e3bad53a1538d8bf5c262fc796c5416be6eeaf8800261b18c521d6"


@dataclass
class SuiTransaction:
    digest: str
    status: str
    gas_used: Optional[int] = None
    events: Optional[list] = None


class SuiClient:
    """Client for Sui JSON-RPC API interactions."""

    def __init__(
        self,
        rpc_url: str = SUI_TESTNET_RPC,
        package_id: Optional[str] = None,
        chain_object_id: Optional[str] = None,
        keypair: Optional[dict] = None,
    ):
        self.rpc_url = rpc_url
        self.package_id = package_id
        self.chain_object_id = chain_object_id
        self.keypair = keypair
        self.session = requests.Session()
        self._req_id = 0

    def _rpc(self, method: str, params: list) -> dict:
        self._req_id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": self._req_id,
            "method": method,
            "params": params,
        }
        resp = self.session.post(self.rpc_url, json=payload, timeout=30)
        resp.raise_for_status()
        result = resp.json()
        if "error" in result:
            raise RuntimeError(f"Sui RPC error: {result['error']}")
        return result.get("result", {})

    def get_object(self, object_id: str) -> dict:
        return self._rpc("sui_getObject", [
            object_id,
            {"showContent": True, "showType": True, "showOwner": True}
        ])

    def get_balance(self, address: str) -> int:
        result = self._rpc("suix_getBalance", [address, "0x2::sui::SUI"])
        return int(result.get("totalBalance", 0))

    def get_chain_state(self) -> Optional[dict]:
        """Read the on-chain proof chain state."""
        if not self.chain_object_id:
            log.warning("No chain_object_id configured")
            return None
        try:
            obj = self.get_object(self.chain_object_id)
            content = obj.get("data", {}).get("content", {})
            return content.get("fields", {})
        except Exception as e:
            log.error(f"Failed to read chain state: {e}")
            return None

    def anchor_proof(
        self,
        action_hash: str,
        walrus_blob_id: str,
        chain_position: int,
        timestamp: int,
    ) -> Optional[SuiTransaction]:
        """
        Anchor a proof record on-chain by calling the Move contract.
        Returns the transaction result.

        In production, this constructs and signs a MoveCall transaction.
        For demo, we log the intent and return a simulated result.
        """
        if not self.package_id:
            log.info(
                f"[DRY-RUN] anchor_proof: hash={action_hash[:16]}... "
                f"blob={walrus_blob_id} pos={chain_position}"
            )
            return SuiTransaction(
                digest=f"sim_{hashlib.sha256(action_hash.encode()).hexdigest()[:32]}",
                status="dry_run",
            )

        # Real transaction construction
        tx_bytes = self._build_move_call(
            package=self.package_id,
            module="proof_chain",
            function="add_proof",
            arguments=[
                self.chain_object_id,
                list(bytes.fromhex(action_hash)),
                walrus_blob_id,
                timestamp,
            ],
        )
        return self._sign_and_execute(tx_bytes)

    def create_proof_chain(self, agent_id: str) -> Optional[SuiTransaction]:
        """Create a new on-chain proof chain for an agent."""
        if not self.package_id:
            log.info(f"[DRY-RUN] create_proof_chain: agent_id={agent_id}")
            return SuiTransaction(digest="sim_create_chain", status="dry_run")

        tx_bytes = self._build_move_call(
            package=self.package_id,
            module="proof_chain",
            function="create_chain",
            arguments=[agent_id],
        )
        return self._sign_and_execute(tx_bytes)

    def _build_move_call(
        self,
        package: str,
        module: str,
        function: str,
        arguments: list,
    ) -> dict:
        """Build a MoveCall transaction using sui_moveCall."""
        sender = self.keypair.get("address") if self.keypair else None
        return self._rpc("unsafe_moveCall", [
            sender,
            package,
            module,
            function,
            [],  # type_arguments
            arguments,
            None,  # gas object
            "10000000",  # gas budget
        ])

    def _sign_and_execute(self, tx_data: dict) -> SuiTransaction:
        """Sign and execute a transaction."""
        result = self._rpc("sui_executeTransactionBlock", [
            tx_data.get("txBytes"),
            [tx_data.get("signature", "")],
            {"showEffects": True, "showEvents": True},
            "WaitForLocalExecution",
        ])
        effects = result.get("effects", {})
        return SuiTransaction(
            digest=result.get("digest", ""),
            status=effects.get("status", {}).get("status", "unknown"),
            gas_used=int(effects.get("gasUsed", {}).get("computationCost", 0)),
            events=result.get("events", []),
        )

    def health_check(self) -> bool:
        try:
            result = self._rpc("sui_getLatestCheckpointSequenceNumber", [])
            return result is not None
        except Exception:
            return False
