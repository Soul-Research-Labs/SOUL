use poseidon::poseidon::bn254;

/// @title LiquidityProofCircuit
/// @notice ZK circuit proving liquidity backing for cross-chain private transfers
/// @dev Proves that a lock on the source-chain vault has sufficient LP backing
///      on the destination-chain vault WITHOUT revealing exact amounts or LP identities.
///
/// What this circuit proves (public statement):
///   1. A liquidity lock exists for a given request on the source chain.
///   2. The destination vault has sufficient available liquidity to cover the transfer.
///   3. The lock amount and destination amount are consistent (after optional fee deduction).
///   4. The lock has not expired.
///   5. A valid nullifier prevents double-release.
///
/// Private inputs (known only to the relayer / prover):
///   - Exact lock amount, LP pool sizes, fee rates
///   - Lock details (token, timestamps)
///   - Nullifier secret
///
/// Public inputs (verified on-chain):
///   - Lock commitment (Poseidon hash of lock details)
///   - Destination pool commitment (Poseidon hash of pool state)
///   - Nullifier (prevents double-spend)
///   - Minimum available liquidity flag (boolean)
///   - Current timestamp bound
///
/// Constraint budget: ~3,500 constraints

// --- Constants --------------------------------------------------------

global FEE_DENOMINATOR: Field = 10000; // Basis points denominator
global FEE_DENOMINATOR_U64: u64 = 10000;
global MAX_TIMESTAMP_DRIFT: u64 = 2592000; // 30 days

// --- Structs ----------------------------------------------------------

/// Source-chain lock details (private witness)
struct LockWitness {
    request_id: Field,       // Unique relay request identifier
    token: Field,            // Token address (as Field)  
    amount: Field,           // Locked amount
    source_chain_id: Field,  // Source chain
    dest_chain_id: Field,    // Destination chain
    lock_timestamp: Field,   // When the lock was created
    expiry: Field,           // Lock expiration timestamp
    salt: Field,             // Random salt for commitment hiding
}

/// Destination-chain pool state (private witness)
struct PoolWitness {
    total_deposited: Field,   // Total LP deposits in destination vault
    total_locked: Field,      // Already locked on destination chain
    fee_bps: Field,           // Fee in basis points
    pool_salt: Field,         // Salt for pool commitment hiding
}

/// Prover context
struct ProverContext {
    relayer_secret: Field,    // Relayer's secret for nullifier derivation
    current_timestamp: Field, // Current timestamp (for expiry check)
}

// --- Helper functions -------------------------------------------------

/// Compute commitment to a liquidity lock
/// commitment = H(request_id, token, amount, source_chain, dest_chain, lock_timestamp, expiry, salt)
fn compute_lock_commitment(lock: LockWitness) -> Field {
    // Hash in two rounds due to Poseidon arity limits
    let h1 = bn254::hash_4([
        lock.request_id,
        lock.token,
        lock.amount,
        lock.source_chain_id
    ]);
    let h2 = bn254::hash_4([
        lock.dest_chain_id,
        lock.lock_timestamp,
        lock.expiry,
        lock.salt
    ]);
    bn254::hash_2([h1, h2])
}

/// Compute commitment to the destination pool state
/// pool_commitment = H(total_deposited, total_locked, fee_bps, pool_salt)
fn compute_pool_commitment(pool: PoolWitness) -> Field {
    bn254::hash_4([
        pool.total_deposited,
        pool.total_locked,
        pool.fee_bps,
        pool.pool_salt
    ])
}

/// Derive nullifier for this lock (prevents double-release)
/// nullifier = H(relayer_secret, request_id, dest_chain_id)
fn derive_release_nullifier(
    relayer_secret: Field,
    request_id: Field,
    dest_chain_id: Field
) -> Field {
    bn254::hash_4([relayer_secret, request_id, dest_chain_id, 0])
}

/// Compute the amount after fee deduction
/// net_amount = amount - (amount * fee_bps / FEE_DENOMINATOR)
/// Note: We verify this relationship in-circuit rather than compute it with division
fn verify_fee_deduction(
    gross_amount: Field,
    net_amount: Field,
    fee_bps: Field
) -> bool {
    // net_amount * FEE_DENOMINATOR == gross_amount * (FEE_DENOMINATOR - fee_bps)
    // This avoids division in the circuit
    let lhs = net_amount * FEE_DENOMINATOR;
    let rhs = gross_amount * (FEE_DENOMINATOR - fee_bps);
    lhs == rhs
}

/// Constrain a field witness to be exactly representable as a u64 before using
/// integer ordering. This prevents field wraparound from satisfying timestamp,
/// amount, and liquidity comparisons.
fn to_bounded_u64(value: Field) -> u64 {
    let narrowed = value as u64;
    assert(narrowed as Field == value, "Field exceeds u64");
    narrowed
}

// --- Main circuit -----------------------------------------------------

/// Main entry point for the liquidity proof circuit
///
/// Public inputs:
///   lock_commitment      - Poseidon commitment to the source lock
///   pool_commitment      - Poseidon commitment to the destination pool state
///   nullifier            - Release nullifier (prevents double-spend)
///   transfer_amount_hash - H(net_amount) for amount binding without revealing exact value
///   timestamp_bound      - Upper bound on current timestamp (for freshness)
///
/// Private inputs:
///   lock    - Source chain lock details
///   pool    - Destination pool state
///   ctx     - Prover context (relayer secret, current timestamp)
///   net_amount - Amount after fee that will be released on destination
fn main(
    // Public inputs
    lock_commitment: pub Field,
    pool_commitment: pub Field,
    nullifier: pub Field,
    transfer_amount_hash: pub Field,
    timestamp_bound: pub Field,

    // Private inputs (witness)
    lock: LockWitness,
    pool: PoolWitness,
    ctx: ProverContext,
    net_amount: Field
) {
    // -- 1. Verify lock commitment matches witness --------------
    let computed_lock_commitment = compute_lock_commitment(lock);
    assert(computed_lock_commitment == lock_commitment, "Lock commitment mismatch");

    // -- 2. Verify pool commitment matches witness --------------
    let computed_pool_commitment = compute_pool_commitment(pool);
    assert(computed_pool_commitment == pool_commitment, "Pool commitment mismatch");

    // -- 3. Verify nullifier derivation -------------------------
    let computed_nullifier = derive_release_nullifier(
        ctx.relayer_secret,
        lock.request_id,
        lock.dest_chain_id
    );
    assert(computed_nullifier == nullifier, "Nullifier mismatch");

    let lock_amount_u64 = to_bounded_u64(lock.amount);
    let lock_timestamp_u64 = to_bounded_u64(lock.lock_timestamp);
    let expiry_u64 = to_bounded_u64(lock.expiry);
    let current_u64 = to_bounded_u64(ctx.current_timestamp);
    let timestamp_bound_u64 = to_bounded_u64(timestamp_bound);
    let total_deposited_u64 = to_bounded_u64(pool.total_deposited);
    let total_locked_u64 = to_bounded_u64(pool.total_locked);
    let fee_bps_u64 = to_bounded_u64(pool.fee_bps);
    let net_amount_u64 = to_bounded_u64(net_amount);

    // -- 4. Verify lock has not expired -------------------------
    assert(lock_amount_u64 > 0, "Lock amount must be non-zero");
    assert(net_amount_u64 > 0, "Transfer amount must be non-zero");
    assert(lock_timestamp_u64 <= current_u64, "Lock timestamp in future");
    assert(expiry_u64 > current_u64, "Lock expired");
    assert(expiry_u64 - current_u64 <= MAX_TIMESTAMP_DRIFT, "Expiry too far");
    assert(timestamp_bound_u64 == current_u64, "Timestamp bound mismatch");
    assert(ctx.current_timestamp == timestamp_bound, "Timestamp bound mismatch");

    // -- 5. Verify sufficient destination liquidity -------------
    assert(total_deposited_u64 >= total_locked_u64, "Pool overlocked");
    let available_u64 = total_deposited_u64 - total_locked_u64;
    assert(available_u64 >= net_amount_u64, "Insufficient destination liquidity");

    // -- 6. Verify fee deduction is correct ---------------------
    assert(fee_bps_u64 <= FEE_DENOMINATOR_U64, "Fee bps exceeds denominator");
    let fee_valid = verify_fee_deduction(lock.amount, net_amount, pool.fee_bps);
    assert(fee_valid, "Fee deduction invalid");

    // -- 7. Verify transfer amount hash -------------------------
    let computed_amount_hash = bn254::hash_1([net_amount]);
    assert(computed_amount_hash == transfer_amount_hash, "Transfer amount hash mismatch");

    // -- 8. Cross-chain sanity: source != destination -----------
    assert(lock.source_chain_id != lock.dest_chain_id, "Source and destination must differ");
}

// --- Test module ------------------------------------------------------

#[test]
fn test_valid_liquidity_proof() {
    // Setup test values
    let lock = LockWitness {
        request_id: 12345,
        token: 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE, // ETH placeholder
        amount: 1000,
        source_chain_id: 1,     // Ethereum
        dest_chain_id: 42161,   // Arbitrum
        lock_timestamp: 1700000000,
        expiry: 1700604800,     // +7 days
        salt: 99999,
    };

    let pool = PoolWitness {
        total_deposited: 50000,
        total_locked: 10000,     // 40000 available
        fee_bps: 0,             // No fee for simplicity
        pool_salt: 88888,
    };

    let ctx = ProverContext {
        relayer_secret: 777,
        current_timestamp: 1700100000, // Well before expiry
    };

    let net_amount: Field = 1000; // No fee, so net == gross

    // Compute expected public inputs
    let expected_lock_commitment = compute_lock_commitment(lock);
    let expected_pool_commitment = compute_pool_commitment(pool);
    let expected_nullifier = derive_release_nullifier(777, 12345, 42161);
    let expected_amount_hash = bn254::hash_1([net_amount]);

    // This should not panic
    main(
        expected_lock_commitment,
        expected_pool_commitment,
        expected_nullifier,
        expected_amount_hash,
        1700100000, // timestamp_bound
        lock,
        pool,
        ctx,
        net_amount
    );
}

#[test]
fn test_with_fee_deduction() {
    let lock = LockWitness {
        request_id: 54321,
        token: 1,
        amount: 10000,
        source_chain_id: 1,
        dest_chain_id: 10,    // Optimism
        lock_timestamp: 1700000000,
        expiry: 1700604800,
        salt: 11111,
    };

    // 50 bps (0.5%) fee
    let pool = PoolWitness {
        total_deposited: 100000,
        total_locked: 20000,
        fee_bps: 50,
        pool_salt: 22222,
    };

    let ctx = ProverContext {
        relayer_secret: 555,
        current_timestamp: 1700050000,
    };

    // net_amount = 10000 * (10000 - 50) / 10000 = 10000 * 9950 / 10000 = 9950
    let net_amount: Field = 9950;

    let expected_lock_commitment = compute_lock_commitment(lock);
    let expected_pool_commitment = compute_pool_commitment(pool);
    let expected_nullifier = derive_release_nullifier(555, 54321, 10);
    let expected_amount_hash = bn254::hash_1([net_amount]);

    main(
        expected_lock_commitment,
        expected_pool_commitment,
        expected_nullifier,
        expected_amount_hash,
        1700050000,
        lock,
        pool,
        ctx,
        net_amount
    );
}

#[test(should_fail_with = "Source and destination must differ")]
fn test_same_chain_rejected() {
    let lock = LockWitness {
        request_id: 99,
        token: 1,
        amount: 1000,
        source_chain_id: 1,
        dest_chain_id: 1, // Same chain - should fail
        lock_timestamp: 1700000000,
        expiry: 1700604800,
        salt: 33333,
    };

    let pool = PoolWitness {
        total_deposited: 50000,
        total_locked: 0,
        fee_bps: 0,
        pool_salt: 44444,
    };

    let ctx = ProverContext {
        relayer_secret: 111,
        current_timestamp: 1700100000,
    };

    let expected_lock_commitment = compute_lock_commitment(lock);
    let expected_pool_commitment = compute_pool_commitment(pool);
    let expected_nullifier = derive_release_nullifier(111, 99, 1);
    let expected_amount_hash = bn254::hash_1([1000]);

    main(
        expected_lock_commitment,
        expected_pool_commitment,
        expected_nullifier,
        expected_amount_hash,
        1700100000,
        lock,
        pool,
        ctx,
        1000
    );
}

#[test(should_fail_with = "Transfer amount must be non-zero")]
fn test_zero_amount_rejected() {
    let lock = LockWitness {
        request_id: 88,
        token: 1,
        amount: 1000,
        source_chain_id: 1,
        dest_chain_id: 42161,
        lock_timestamp: 1700000000,
        expiry: 1700604800,
        salt: 55555,
    };

    let pool = PoolWitness {
        total_deposited: 50000,
        total_locked: 0,
        fee_bps: 0,
        pool_salt: 66666,
    };

    let ctx = ProverContext {
        relayer_secret: 222,
        current_timestamp: 1700100000,
    };

    let expected_lock_commitment = compute_lock_commitment(lock);
    let expected_pool_commitment = compute_pool_commitment(pool);
    let expected_nullifier = derive_release_nullifier(222, 88, 42161);
    let expected_amount_hash = bn254::hash_1([0]);

    main(
        expected_lock_commitment,
        expected_pool_commitment,
        expected_nullifier,
        expected_amount_hash,
        1700100000,
        lock,
        pool,
        ctx,
        0 // Zero amount - should fail
    );
}

#[test(should_fail_with = "Fee bps exceeds denominator")]
fn test_fee_bps_above_denominator_rejected() {
    let lock = LockWitness {
        request_id: 77,
        token: 1,
        amount: 1000,
        source_chain_id: 1,
        dest_chain_id: 42161,
        lock_timestamp: 1700000000,
        expiry: 1700100100,
        salt: 77777,
    };

    let pool = PoolWitness {
        total_deposited: 50000,
        total_locked: 0,
        fee_bps: 10001,
        pool_salt: 77778,
    };

    let ctx = ProverContext {
        relayer_secret: 333,
        current_timestamp: 1700100000,
    };

    let expected_lock_commitment = compute_lock_commitment(lock);
    let expected_pool_commitment = compute_pool_commitment(pool);
    let expected_nullifier = derive_release_nullifier(333, 77, 42161);
    let expected_amount_hash = bn254::hash_1([1000]);

    main(
        expected_lock_commitment,
        expected_pool_commitment,
        expected_nullifier,
        expected_amount_hash,
        1700100000,
        lock,
        pool,
        ctx,
        1000
    );
}

#[test(should_fail_with = "Lock expired")]
fn test_expired_lock_rejected() {
    let lock = LockWitness {
        request_id: 66,
        token: 1,
        amount: 1000,
        source_chain_id: 1,
        dest_chain_id: 42161,
        lock_timestamp: 1700000000,
        expiry: 1700100000,
        salt: 66666,
    };

    let pool = PoolWitness {
        total_deposited: 50000,
        total_locked: 0,
        fee_bps: 0,
        pool_salt: 66667,
    };

    let ctx = ProverContext {
        relayer_secret: 444,
        current_timestamp: 1700100000,
    };

    let expected_lock_commitment = compute_lock_commitment(lock);
    let expected_pool_commitment = compute_pool_commitment(pool);
    let expected_nullifier = derive_release_nullifier(444, 66, 42161);
    let expected_amount_hash = bn254::hash_1([1000]);

    main(
        expected_lock_commitment,
        expected_pool_commitment,
        expected_nullifier,
        expected_amount_hash,
        1700100000,
        lock,
        pool,
        ctx,
        1000
    );
}

#[test(should_fail_with = "Insufficient destination liquidity")]
fn test_insufficient_liquidity_rejected() {
    let lock = LockWitness {
        request_id: 55,
        token: 1,
        amount: 600,
        source_chain_id: 1,
        dest_chain_id: 42161,
        lock_timestamp: 1700000000,
        expiry: 1700100100,
        salt: 55555,
    };

    let pool = PoolWitness {
        total_deposited: 1000,
        total_locked: 500,
        fee_bps: 0,
        pool_salt: 55556,
    };

    let ctx = ProverContext {
        relayer_secret: 555,
        current_timestamp: 1700100000,
    };

    let expected_lock_commitment = compute_lock_commitment(lock);
    let expected_pool_commitment = compute_pool_commitment(pool);
    let expected_nullifier = derive_release_nullifier(555, 55, 42161);
    let expected_amount_hash = bn254::hash_1([600]);

    main(
        expected_lock_commitment,
        expected_pool_commitment,
        expected_nullifier,
        expected_amount_hash,
        1700100000,
        lock,
        pool,
        ctx,
        600
    );
}
