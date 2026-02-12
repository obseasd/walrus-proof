---
name: walrus-proof
description: Cryptographic proof-of-reasoning middleware for AI agents. Generates hash-linked proof chains, detects prompt injections, encrypts proofs with Seal, stores on Walrus decentralized storage, and anchors on Sui blockchain. Use when you need to audit agent actions, verify reasoning integrity, or detect prompt injection attacks.
user-invocable: true
metadata: {"openclaw":{"emoji":"🔐","os":["win32","darwin","linux"],"requires":{"bins":["python3"]}}}
---

# WalrusProof - Cryptographic Proof-of-Reasoning

Security middleware that creates an immutable, verifiable audit trail for every AI agent action.

## When to Use

- When you need to record and verify agent actions cryptographically
- When you want to detect prompt injection attacks
- When you need to store encrypted proof chains on Walrus (Sui's decentralized storage)
- When you need to anchor proofs on the Sui blockchain
- When auditing agent behavior or reasoning steps

## Setup (First Run)

```bash
pip install -r {baseDir}/requirements.txt
```

## Commands

### Run Full Demo
Shows the complete pipeline: proof generation, firewall, encryption, Walrus storage, and Sui anchoring.
```bash
python3 {baseDir}/demo.py --walrus --sui
```

### Check a Prompt for Injection
Analyze a prompt through the multi-layer firewall.
```bash
python3 {baseDir}/cli.py firewall --prompt "<the prompt to check>"
```

### Record an Agent Action
Record an action to the proof chain with optional Walrus storage.
```bash
python3 {baseDir}/cli.py record --type "<action_type>" --summary "<description>" --walrus
```

### Verify Proof Chain
Verify the integrity of the local proof chain.
```bash
python3 {baseDir}/cli.py verify
```

### Export Audit Report
Generate a full JSON audit report.
```bash
python3 {baseDir}/cli.py export --output audit_report.json
```

### Check Walrus Health
Test connectivity to Walrus testnet endpoints.
```bash
python3 {baseDir}/cli.py health
```

## Output Format

All commands output structured text. The `export` command generates a JSON file containing:
- Agent ID, total actions, chain validity
- Full proof chain with hashes
- Firewall statistics (blocked, suspicious, safe counts)

## Architecture

```
Prompt → Firewall → ProofEngine → Seal Encrypt → Walrus Store → Sui Anchor
                         ↓
                   SHA-256 Hash Chain
                   (tamper-evident)
```

## Sui Integration

- **Package ID**: `0xb9d87d8952e3bad53a1538d8bf5c262fc796c5416be6eeaf8800261b18c521d6`
- **Contract**: `proof_chain.move` (create_chain, add_proof, log_injection)
- **Events**: ChainCreated, ProofAnchored, InjectionDetected
