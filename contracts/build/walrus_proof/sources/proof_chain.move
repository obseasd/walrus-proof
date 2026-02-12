/// WalrusProof - On-Chain Proof Chain for AI Agent Reasoning
///
/// Anchors cryptographic proofs of every agent action on-chain.
/// Proof data is encrypted via Seal and stored on Walrus.
/// This contract maintains the hash-linked chain and emits events for indexing.
module walrus_proof::proof_chain {
    use std::string::String;
    use sui::event;

    /// A proof chain registry for a single agent.
    public struct ProofChain has key, store {
        id: UID,
        agent_id: String,
        proof_count: u64,
        latest_action_hash: vector<u8>,
        latest_walrus_blob_id: String,
        created_at: u64,
    }

    /// Individual proof record stored as a shared object.
    public struct ProofRecord has key, store {
        id: UID,
        chain_id: address,
        position: u64,
        action_hash: vector<u8>,
        walrus_blob_id: String,
        prev_action_hash: vector<u8>,
        timestamp: u64,
    }

    /// Emitted when a new proof chain is created.
    public struct ChainCreated has copy, drop {
        chain_id: address,
        agent_id: String,
    }

    /// Emitted when a new proof is anchored.
    public struct ProofAnchored has copy, drop {
        chain_id: address,
        proof_id: address,
        position: u64,
        action_hash: vector<u8>,
        walrus_blob_id: String,
    }

    /// Emitted when an injection attempt is detected.
    public struct InjectionDetected has copy, drop {
        chain_id: address,
        threat_score: u64,
        source: String,
    }

    /// Create a new proof chain for an agent.
    public entry fun create_chain(
        agent_id: String,
        clock_timestamp: u64,
        ctx: &mut TxContext,
    ) {
        let chain = ProofChain {
            id: object::new(ctx),
            agent_id,
            proof_count: 0,
            latest_action_hash: vector::empty(),
            latest_walrus_blob_id: std::string::utf8(b""),
            created_at: clock_timestamp,
        };
        let chain_addr = object::uid_to_address(&chain.id);
        event::emit(ChainCreated {
            chain_id: chain_addr,
            agent_id: chain.agent_id,
        });
        transfer::public_share_object(chain);
    }

    /// Anchor a new proof record in the chain.
    public entry fun add_proof(
        chain: &mut ProofChain,
        action_hash: vector<u8>,
        walrus_blob_id: String,
        timestamp: u64,
        ctx: &mut TxContext,
    ) {
        let proof = ProofRecord {
            id: object::new(ctx),
            chain_id: object::uid_to_address(&chain.id),
            position: chain.proof_count,
            action_hash,
            walrus_blob_id,
            prev_action_hash: chain.latest_action_hash,
            timestamp,
        };
        let proof_addr = object::uid_to_address(&proof.id);

        // Update chain state
        chain.proof_count = chain.proof_count + 1;
        chain.latest_action_hash = proof.action_hash;
        chain.latest_walrus_blob_id = proof.walrus_blob_id;

        event::emit(ProofAnchored {
            chain_id: proof.chain_id,
            proof_id: proof_addr,
            position: proof.position,
            action_hash: proof.action_hash,
            walrus_blob_id: proof.walrus_blob_id,
        });

        transfer::public_share_object(proof);
    }

    /// Log an injection detection event on-chain.
    public entry fun log_injection(
        chain: &mut ProofChain,
        threat_score: u64,
        source: String,
    ) {
        event::emit(InjectionDetected {
            chain_id: object::uid_to_address(&chain.id),
            threat_score,
            source,
        });
    }

    /// Read the current proof count.
    public fun proof_count(chain: &ProofChain): u64 {
        chain.proof_count
    }

    /// Read the latest action hash.
    public fun latest_hash(chain: &ProofChain): vector<u8> {
        chain.latest_action_hash
    }
}
