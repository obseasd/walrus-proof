"""
WalrusProof - Walrus Decentralized Blob Storage Client

Stores and retrieves encrypted proof blobs on Walrus, Sui's decentralized
storage layer. Each blob is content-addressed and permanently available.
"""
import requests
import json
import logging
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger("walrusproof.walrus")

WALRUS_TESTNET_PUBLISHER = "https://publisher.walrus-testnet.walrus.space"
WALRUS_TESTNET_AGGREGATOR = "https://aggregator.walrus-testnet.walrus.space"


@dataclass
class BlobResult:
    blob_id: str
    sui_object_id: Optional[str] = None
    cost: Optional[int] = None
    status: str = "stored"


class WalrusClient:
    """Client for Walrus decentralized blob storage."""

    def __init__(
        self,
        publisher_url: str = WALRUS_TESTNET_PUBLISHER,
        aggregator_url: str = WALRUS_TESTNET_AGGREGATOR,
        epochs: int = 5,
    ):
        self.publisher = publisher_url.rstrip("/")
        self.aggregator = aggregator_url.rstrip("/")
        self.epochs = epochs
        self.session = requests.Session()

    def store_blob(self, data: bytes, content_type: str = "application/octet-stream") -> BlobResult:
        """Store a blob on Walrus. Returns blob_id for retrieval."""
        url = f"{self.publisher}/v1/blobs"
        params = {"epochs": self.epochs}
        headers = {"Content-Type": content_type}

        resp = self.session.put(url, data=data, params=params, headers=headers, timeout=30)
        resp.raise_for_status()
        result = resp.json()

        if "newlyCreated" in result:
            info = result["newlyCreated"]["blobObject"]
            return BlobResult(
                blob_id=info["blobId"],
                sui_object_id=info.get("id"),
                cost=result["newlyCreated"].get("cost"),
                status="new",
            )
        elif "alreadyCertified" in result:
            info = result["alreadyCertified"]
            return BlobResult(
                blob_id=info["blobId"],
                sui_object_id=info.get("event", {}).get("txDigest"),
                status="certified",
            )
        else:
            raise ValueError(f"Unexpected Walrus response: {result}")

    def read_blob(self, blob_id: str) -> bytes:
        """Retrieve a blob from Walrus by its blob_id."""
        url = f"{self.aggregator}/v1/blobs/{blob_id}"
        resp = self.session.get(url, timeout=30)
        resp.raise_for_status()
        return resp.content

    def store_json(self, obj: dict | list) -> BlobResult:
        """Store a JSON-serializable object on Walrus."""
        data = json.dumps(obj, sort_keys=True, ensure_ascii=False).encode("utf-8")
        return self.store_blob(data, content_type="application/json")

    def read_json(self, blob_id: str) -> dict | list:
        """Read a JSON blob from Walrus."""
        data = self.read_blob(blob_id)
        return json.loads(data)

    def store_proof(self, proof_bytes: bytes) -> BlobResult:
        """Store an encrypted proof blob on Walrus."""
        log.info(f"Storing proof blob ({len(proof_bytes)} bytes)")
        result = self.store_blob(proof_bytes)
        log.info(f"Stored: blob_id={result.blob_id} status={result.status}")
        return result

    def health_check(self) -> bool:
        """Check if Walrus endpoints are reachable."""
        try:
            # Try storing a tiny test blob - most reliable check
            resp = self.session.put(
                f"{self.publisher}/v1/blobs",
                data=b"healthcheck",
                params={"epochs": 1},
                timeout=10,
            )
            return resp.status_code == 200
        except Exception:
            return False
