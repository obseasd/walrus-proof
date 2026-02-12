# WalrusProof - Cryptographic Proof-of-Reasoning for AI Agents

> **Track 1: Safety & Security** - DeepSurge x OpenClaw Hackathon on Sui

## What is WalrusProof?

WalrusProof is a security middleware that creates an **immutable, verifiable audit trail** of every action an AI agent takes. It combines:

- **Cryptographic proof chain** - SHA-256 hash-linked records of every agent action
- **Walrus storage** - Encrypted proofs stored on Sui's decentralized blob store
- **Seal encryption** - Policy-based encryption so only authorized parties can audit
- **On-chain anchoring** - Move smart contract on Sui for tamper-proof verification
- **Prompt injection firewall** - Detects and blocks prompt injection attacks before they reach the agent

## Why?

AI agents with system access (browser, terminal, wallet) can go rogue. WalrusProof ensures that:

1. **Every action is recorded** - nothing happens without a cryptographic proof
2. **Proofs are tamper-proof** - hash-linked chain + Walrus storage + Sui anchoring
3. **Privacy is preserved** - Seal encryption means only authorized auditors can read proofs
4. **Injections are caught** - firewall blocks prompt manipulation before it causes damage

## Architecture

```
                    ┌──────────────────┐
  User Prompt ──────► Prompt Firewall  │
                    │ (detect inject.) │
                    └────────┬─────────┘
                             │ allowed
                    ┌────────▼─────────┐
  Agent Action ─────► Proof Engine     │
                    │ (hash chain)     │
                    └────────┬─────────┘
                             │ proof record
                    ┌────────▼─────────┐
                    │ Seal Encryption  │
                    │ (AES-256-GCM)    │
                    └────────┬─────────┘
                             │ encrypted blob
              ┌──────────────┴──────────────┐
              │                             │
     ┌────────▼─────────┐        ┌─────────▼────────┐
     │  Walrus Storage   │        │  Sui Blockchain  │
     │  (blob store)     │        │  (Move contract) │
     └──────────────────┘        └──────────────────┘
```

## Sui Integration

| Component | Sui Technology | Purpose |
|-----------|---------------|---------|
| Proof storage | **Walrus** | Permanent decentralized blob storage for encrypted proofs |
| Data privacy | **Seal** | Policy-based encryption for proof confidentiality |
| Chain anchoring | **Move contract** | Tamper-proof on-chain record of proof chain state |
| Verification | **Sui Events** | Indexable events for audit trail queries |

## Quick Start

```bash
pip install -r requirements.txt
python demo.py                  # Local demo (no blockchain)
python demo.py --walrus         # + Walrus testnet storage
python demo.py --walrus --sui   # + Sui testnet anchoring
```

## Components

| File | Description |
|------|-------------|
| `proof_engine.py` | Hash-linked proof chain generation and verification |
| `walrus_client.py` | Walrus decentralized blob storage client |
| `seal_client.py` | Seal-compatible AES-256-GCM encryption |
| `prompt_firewall.py` | Multi-layer prompt injection detection |
| `sui_client.py` | Sui JSON-RPC client for on-chain anchoring |
| `middleware.py` | Unified middleware tying all components together |
| `contracts/` | Move smart contract for on-chain proof chain |
| `demo.py` | Interactive demo showing the full pipeline |

## Move Smart Contract

The `proof_chain.move` contract provides:

- `create_chain(agent_id)` - Initialize a proof chain for an agent
- `add_proof(chain, action_hash, walrus_blob_id, timestamp)` - Anchor a proof
- `log_injection(chain, threat_score, source)` - Log detected injection attempts
- Events: `ChainCreated`, `ProofAnchored`, `InjectionDetected`

## Prompt Firewall Detection Methods

1. **Pattern matching** - 14+ known injection signatures
2. **Structural analysis** - Delimiter injection, ChatML tags, role hijacking
3. **Entropy analysis** - Detects obfuscated/encoded payloads
4. **Unicode homographs** - Mixed-script attacks (Cyrillic, Greek, Armenian)
5. **Nested prompts** - Meta-prompt detection

## License

MIT
