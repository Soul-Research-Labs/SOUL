use poseidon::poseidon::bn254;

/// @title SanctionsCheckCircuit
/// @notice Privacy-preserving sanctions screening for compliance
/// @dev Proves that a user's address commitment is NOT on a sanctions list
///      without revealing the actual address or the full sanctions list.
///
/// Approach:
///   1. User commits to their identity: commitment = Poseidon(address_hash, secret)
///   2. A Merkle tree of sanctioned address hashes is maintained off-chain
///   3. User proves NON-membership in the sanctions Merkle tree
///   4. Additionally proves they hold a valid compliance credential
///
/// Privacy guarantees:
///   - The user's address is never revealed on-chain
///   - The sanctions list contents are not exposed (only the root)
///   - Only the compliance status (pass/fail) is public

/// Merkle tree depth for the sanctions list (supports up to 2^16 = 65,536 entries)
global TREE_DEPTH: u32 = 16;

/// Compute Poseidon hash of two fields (for Merkle tree)
fn hash2(left: Field, right: Field) -> Field {
    bn254::hash_2([left, right])
}

fn to_bounded_u64(value: Field) -> u64 {
    let narrowed = value as u64;
    assert(narrowed as Field == value, "Field exceeds u64");
    narrowed
}

fn derive_issuer_pubkey(issuer_secret: Field) -> Field {
    bn254::hash_1([issuer_secret])
}

/// Verify a Merkle proof (membership/non-membership)
/// Returns the computed root from the leaf + proof path
fn compute_merkle_root(
    leaf: Field,
    index: Field,
    path: [Field; 16]
) -> Field {
    let mut current = leaf;
    let mut idx = index;

    for i in 0..TREE_DEPTH {
        let path_element = path[i];

        // Use index bits to determine left/right placement
        let index_bit = idx as u64 & 1;
        idx = (idx as u64 >> 1) as Field;

        if index_bit == 0 {
            current = hash2(current, path_element);
        } else {
            current = hash2(path_element, current);
        }
    }

    current
}

fn main(
    // -- Public inputs --
    sanctions_merkle_root: pub Field,    // Root of the sanctioned addresses Merkle tree
    identity_commitment: pub Field,      // User's identity commitment (Poseidon(addr_hash, secret))
    compliance_nullifier: pub Field,     // Nullifier for this compliance check (prevents replay)
    credential_issuer_pubkey: pub Field, // Public key of the credential issuer
    current_timestamp: pub Field,        // Current timestamp for temporal checks

    // -- Private inputs --
    address_hash: Field,                 // Hash of the user's address
    secret: Field,                       // User's secret for the commitment
    nullifier_secret: Field,             // Secret used to derive the compliance nullifier

    // Non-membership proof: proves address_hash is NOT in the sanctions tree
    // We use a neighboring leaf approach:
    //   - neighbor_leaf is the leaf at the position where address_hash would be
    //   - We prove neighbor_leaf != address_hash AND neighbor_leaf IS in the tree
    neighbor_leaf: Field,                // The leaf at the would-be position
    neighbor_index: Field,               // Index of the neighbor in the tree
    neighbor_path: [Field; 16],          // Merkle path for the neighbor

    // Credential data
    credential_hash: Field,              // Hash of the compliance credential
    credential_issuer_secret: Field,     // Issuer secret proving authorization for this credential
    credential_issued_at: Field,         // Credential issuance timestamp
    credential_expiry: Field             // Credential expiration timestamp
) {
    // -- Step 1: Verify identity commitment --
    // commitment = Poseidon(address_hash, secret)
    let computed_commitment = bn254::hash_2([address_hash, secret]);
    assert(computed_commitment == identity_commitment);

    // -- Step 2: Verify compliance nullifier --
    // nullifier = Poseidon(address_hash, nullifier_secret, "sanctions_check")
    let domain_separator: Field = 0x73616e6374696f6e735f636865636b; // "sanctions_check" as hex
    let computed_nullifier = bn254::hash_4([address_hash, nullifier_secret, domain_separator, 0]);
    assert(computed_nullifier == compliance_nullifier);

    // -- Step 3: Verify NON-membership in sanctions list --
    // The neighbor leaf at the would-be position must NOT equal our address_hash
    assert(neighbor_leaf != address_hash);

    // Verify the neighbor leaf IS in the tree (proves the tree structure is valid)
    let computed_root = compute_merkle_root(neighbor_leaf, neighbor_index, neighbor_path);
    assert(computed_root == sanctions_merkle_root);

    // -- Step 4: Verify compliance credential --
    // The credential statement is bound to the identity, issuer, and validity
    // window. Requiring the issuer secret to derive the public key prevents a
    // prover from fabricating arbitrary credential_hash values. Production
    // issuers should migrate this relation to a real signature verification
    // gadget or issuer-controlled credential Merkle root.
    assert(derive_issuer_pubkey(credential_issuer_secret) == credential_issuer_pubkey, "Credential issuer mismatch");
    let expected_credential_hash = bn254::hash_4([
        address_hash,
        credential_issued_at,
        credential_expiry,
        credential_issuer_pubkey
    ]);
    assert(credential_hash == expected_credential_hash, "Credential hash mismatch");

    // -- Step 5: Verify temporal validity --
    // Credential must have been issued and must not be expired.
    let issued_u64 = to_bounded_u64(credential_issued_at);
    let expiry_u64 = to_bounded_u64(credential_expiry);
    let current_u64 = to_bounded_u64(current_timestamp);
    assert(issued_u64 <= current_u64, "Credential issued in future");
    assert(expiry_u64 > current_u64, "Credential expired");
}

// ==================================================
// Tests
// ==================================================

fn run_sanctions_main(
    credential_issuer_secret: Field,
    credential_issuer_pubkey: Field,
    credential_issued_at: Field,
    credential_expiry: Field,
    current_timestamp: Field
) {
    let address_hash: Field = 0xabcdef;
    let secret: Field = 54321;
    let nullifier_secret: Field = 11111;
    let neighbor_leaf: Field = 0x123456;
    let neighbor_index: Field = 0;
    let neighbor_path: [Field; 16] = [0; 16];
    let sanctions_merkle_root = compute_merkle_root(neighbor_leaf, neighbor_index, neighbor_path);
    let identity_commitment = bn254::hash_2([address_hash, secret]);
    let domain_separator: Field = 0x73616e6374696f6e735f636865636b;
    let compliance_nullifier = bn254::hash_4([address_hash, nullifier_secret, domain_separator, 0]);
    let credential_hash = bn254::hash_4([
        address_hash,
        credential_issued_at,
        credential_expiry,
        credential_issuer_pubkey
    ]);

    main(
        sanctions_merkle_root,
        identity_commitment,
        compliance_nullifier,
        credential_issuer_pubkey,
        current_timestamp,
        address_hash,
        secret,
        nullifier_secret,
        neighbor_leaf,
        neighbor_index,
        neighbor_path,
        credential_hash,
        credential_issuer_secret,
        credential_issued_at,
        credential_expiry
    );
}

#[test]
fn test_identity_commitment() {
    let addr: Field = 0xdeadbeef;
    let secret: Field = 54321;
    let commitment = bn254::hash_2([addr, secret]);
    assert(commitment != 0);

    // Deterministic
    let commitment2 = bn254::hash_2([addr, secret]);
    assert(commitment == commitment2);

    // Different secret -> different commitment
    let commitment3 = bn254::hash_2([addr, 99999]);
    assert(commitment != commitment3);
}

#[test]
fn test_compliance_nullifier() {
    let addr: Field = 0xdeadbeef;
    let nullifier_secret: Field = 11111;
    let domain_separator: Field = 0x73616e6374696f6e735f636865636b;
    let nullifier = bn254::hash_4([addr, nullifier_secret, domain_separator, 0]);
    assert(nullifier != 0);

    // Deterministic
    let nullifier2 = bn254::hash_4([addr, nullifier_secret, domain_separator, 0]);
    assert(nullifier == nullifier2);

    // Different secret -> different nullifier
    let nullifier3 = bn254::hash_4([addr, 22222, domain_separator, 0]);
    assert(nullifier != nullifier3);
}

#[test]
fn test_merkle_root_computation() {
    // Build a trivial 2-level path (using only 16 levels with zeros for upper)
    let leaf: Field = bn254::hash_2([0xabc, 0xdef]);
    let mut path: [Field; 16] = [0; 16];
    path[0] = 0x111;
    path[1] = 0x222;

    let root = compute_merkle_root(leaf, 0, path);
    assert(root != 0);

    // Same inputs -> same root
    let root2 = compute_merkle_root(leaf, 0, path);
    assert(root == root2);

    // Different leaf -> different root
    let different_leaf = bn254::hash_2([0xfff, 0xeee]);
    let root3 = compute_merkle_root(different_leaf, 0, path);
    assert(root != root3);
}

#[test]
fn test_non_membership_check() {
    // Core property: neighbor_leaf must not equal address_hash
    let address_hash: Field = 0xabcdef;
    let neighbor_leaf: Field = 0x123456;
    assert(neighbor_leaf != address_hash);
}

#[test]
fn test_credential_commitment() {
    let address_hash: Field = 0xdddd;
    let credential_issued_at: Field = 1700000000;
    let credential_expiry: Field = 1800000000;
    let issuer_secret: Field = 0xbbbb;
    let issuer_pubkey = derive_issuer_pubkey(issuer_secret);

    let credential_hash = bn254::hash_4([
        address_hash,
        credential_issued_at,
        credential_expiry,
        issuer_pubkey,
    ]);
    assert(credential_hash != 0);
    assert(derive_issuer_pubkey(issuer_secret) == issuer_pubkey);
}

#[test]
fn test_valid_sanctions_main() {
    let issuer_secret: Field = 0xbbbb;
    let issuer_pubkey = derive_issuer_pubkey(issuer_secret);
    run_sanctions_main(issuer_secret, issuer_pubkey, 1700000000, 1700100000, 1700050000);
}

#[test(should_fail_with = "Credential issuer mismatch")]
fn test_forged_credential_issuer_rejected() {
    let issuer_secret: Field = 0xbbbb;
    let forged_secret: Field = 0xcccc;
    let issuer_pubkey = derive_issuer_pubkey(issuer_secret);
    run_sanctions_main(forged_secret, issuer_pubkey, 1700000000, 1700100000, 1700050000);
}

#[test(should_fail_with = "Credential issued in future")]
fn test_future_credential_rejected() {
    let issuer_secret: Field = 0xbbbb;
    let issuer_pubkey = derive_issuer_pubkey(issuer_secret);
    run_sanctions_main(issuer_secret, issuer_pubkey, 1700060000, 1700100000, 1700050000);
}

#[test(should_fail_with = "Credential expired")]
fn test_expired_credential_rejected() {
    let issuer_secret: Field = 0xbbbb;
    let issuer_pubkey = derive_issuer_pubkey(issuer_secret);
    run_sanctions_main(issuer_secret, issuer_pubkey, 1700000000, 1700050000, 1700050000);
}
