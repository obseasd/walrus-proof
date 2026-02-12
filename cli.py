"""
WalrusProof - CLI Interface for OpenClaw Integration

Provides command-line access to all WalrusProof features.
Designed to be called by OpenClaw agent via SKILL.md instructions.

Usage:
    python cli.py firewall --prompt "check this prompt"
    python cli.py record --type "file_read" --summary "Read config"
    python cli.py verify
    python cli.py export --output report.json
    python cli.py health
"""
import sys
import json
import argparse
import logging

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

logging.basicConfig(level=logging.WARNING, format="%(name)s | %(message)s")

from middleware import WalrusProofMiddleware
from prompt_firewall import PromptFirewall, ThreatLevel
from walrus_client import WalrusClient
from sui_client import SuiClient


def cmd_firewall(args):
    """Analyze a prompt for injection attacks."""
    fw = PromptFirewall(block_threshold=args.threshold)
    result = fw.analyze(args.prompt, source=args.source)

    print(f"Threat Level: {result.level.value.upper()}")
    print(f"Score: {result.score:.2f}")
    print(f"Allowed: {result.allowed}")

    if result.reasons:
        print(f"Detections:")
        for r in result.reasons:
            print(f"  - {r}")

    if result.sanitized_prompt and result.sanitized_prompt != args.prompt:
        print(f"Sanitized: {result.sanitized_prompt[:200]}")

    # Exit code reflects threat level
    sys.exit(0 if result.allowed else 1)


def cmd_record(args):
    """Record an agent action to the proof chain."""
    wp = WalrusProofMiddleware(
        agent_id=args.agent or "openclaw-agent",
        store_on_walrus=args.walrus,
        anchor_on_chain=args.sui,
    )

    proof = wp.record_action(
        action_type=args.type,
        action_summary=args.summary,
        input_data=args.input or "",
        output_data=args.output or "",
    )

    print(f"Proof ID: {proof.proof_id}")
    print(f"Position: {proof.chain_position}")
    print(f"Hash: {proof.compute_hash()}")
    if proof.walrus_blob_id:
        print(f"Walrus Blob: {proof.walrus_blob_id}")
    if proof.sui_tx_digest:
        print(f"Sui TX: {proof.sui_tx_digest}")


def cmd_verify(args):
    """Verify proof chain integrity."""
    wp = WalrusProofMiddleware(
        agent_id=args.agent or "openclaw-agent",
        store_on_walrus=False,
        anchor_on_chain=False,
    )

    # If a report file exists, verify from that
    try:
        with open("audit_report.json", "r") as f:
            report = json.load(f)
        chain = report.get("proofs", [])
        if chain:
            from proof_engine import ProofEngine
            valid, msg = ProofEngine.verify_exported(chain)
            print(f"Status: {'VALID' if valid else 'INVALID'}")
            print(f"Proofs: {len(chain)}")
            print(f"Message: {msg}")
            sys.exit(0 if valid else 1)
    except FileNotFoundError:
        pass

    print("No proof chain found. Run 'record' first or provide audit_report.json")
    sys.exit(1)


def cmd_export(args):
    """Export audit report as JSON."""
    wp = WalrusProofMiddleware(
        agent_id=args.agent or "openclaw-agent",
        store_on_walrus=False,
        anchor_on_chain=False,
    )

    report = wp.export_audit_report()
    output = args.output or "audit_report.json"

    with open(output, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)

    print(f"Audit report exported to: {output}")
    print(f"Actions: {report['total_actions']}")
    print(f"Chain valid: {report['chain_valid']}")


def cmd_health(args):
    """Check health of Walrus and Sui endpoints."""
    print("Checking Walrus testnet...")
    wc = WalrusClient()
    walrus_ok = wc.health_check()
    print(f"  Walrus: {'OK' if walrus_ok else 'UNREACHABLE'}")

    print("Checking Sui testnet...")
    sc = SuiClient()
    sui_ok = sc.health_check()
    print(f"  Sui RPC: {'OK' if sui_ok else 'UNREACHABLE'}")

    # Quick Walrus round-trip test
    if walrus_ok:
        print("Testing Walrus store/read...")
        try:
            blob = wc.store_blob(b"walrusproof-health-check")
            data = wc.read_blob(blob.blob_id)
            print(f"  Store/Read: OK (blob_id={blob.blob_id[:20]}...)")
        except Exception as e:
            print(f"  Store/Read: FAILED ({e})")

    all_ok = walrus_ok and sui_ok
    print(f"\nOverall: {'ALL SYSTEMS GO' if all_ok else 'DEGRADED'}")
    sys.exit(0 if all_ok else 1)


def main():
    parser = argparse.ArgumentParser(description="WalrusProof CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    # firewall
    fw = sub.add_parser("firewall", help="Analyze prompt for injections")
    fw.add_argument("--prompt", required=True, help="Prompt to analyze")
    fw.add_argument("--source", default="user", help="Prompt source")
    fw.add_argument("--threshold", type=float, default=0.7, help="Block threshold")

    # record
    rec = sub.add_parser("record", help="Record an agent action")
    rec.add_argument("--type", required=True, help="Action type")
    rec.add_argument("--summary", required=True, help="Action summary")
    rec.add_argument("--input", default="", help="Input data")
    rec.add_argument("--output", default="", help="Output data")
    rec.add_argument("--agent", default="", help="Agent ID")
    rec.add_argument("--walrus", action="store_true", help="Store on Walrus")
    rec.add_argument("--sui", action="store_true", help="Anchor on Sui")

    # verify
    ver = sub.add_parser("verify", help="Verify proof chain")
    ver.add_argument("--agent", default="", help="Agent ID")

    # export
    exp = sub.add_parser("export", help="Export audit report")
    exp.add_argument("--output", default="audit_report.json", help="Output file")
    exp.add_argument("--agent", default="", help="Agent ID")

    # health
    sub.add_parser("health", help="Check endpoint health")

    args = parser.parse_args()
    commands = {
        "firewall": cmd_firewall,
        "record": cmd_record,
        "verify": cmd_verify,
        "export": cmd_export,
        "health": cmd_health,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
