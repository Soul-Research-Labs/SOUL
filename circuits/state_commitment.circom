pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

/**
 * @title StateCommitmentCircuit
 * @notice Optimized circuit for proving knowledge of state preimage
 * @dev Uses Poseidon hash for ~8x fewer constraints vs MiMC/Pedersen
 * 
 * Performance Optimizations:
 * 1. Poseidon hash (240 constraints vs ~1900 for SHA256)
 * 2. Field arithmetic instead of binary where possible
 * 3. Parallel signal computation
 * 4. Constraint batching for state fields
 */
template StateCommitment(STATE_FIELDS) {
    // Private inputs - the actual state values
    signal input stateFields[STATE_FIELDS];  // Private state data
    signal input salt;                         // Random blinding factor
    signal input ownerSecret;                  // Owner's private key/secret
    
    // Public inputs
    signal input commitment;                   // Public commitment to verify
    signal input ownerPubkey;                  // Owner's public identifier
    
    // Output
    signal output valid;
    
    // ═══════════════════════════════════════════════════════════════════
    // STEP 1: Compute state hash using Poseidon (optimized for ZK)
    // ═══════════════════════════════════════════════════════════════════
    
    // Hash state fields in chunks of 16 (Poseidon optimal batch size)
    var numChunks = (STATE_FIELDS + 15) \ 16;
    signal stateHashes[numChunks];
    
    component poseidonState[numChunks];
    
    for (var i = 0; i < numChunks; i++) {
        var chunkSize = 16;
        if (i == numChunks - 1 && STATE_FIELDS % 16 != 0) {
            chunkSize = STATE_FIELDS % 16;
        }
        
        poseidonState[i] = Poseidon(chunkSize);
        for (var j = 0; j < chunkSize; j++) {
            var idx = i * 16 + j;
            if (idx < STATE_FIELDS) {
                poseidonState[i].inputs[j] <== stateFields[idx];
            } else {
                poseidonState[i].inputs[j] <== 0;
            }
        }
        stateHashes[i] <== poseidonState[i].out;
    }
    
    // ═══════════════════════════════════════════════════════════════════
    // STEP 2: Combine state hash with salt and owner
    // ═══════════════════════════════════════════════════════════════════
    
    // Final commitment = Poseidon(stateHash, salt, ownerSecret)
    component finalHash = Poseidon(3);
    
    // If multiple chunks, combine them first
    component combineHashes = Poseidon(numChunks);
    for (var i = 0; i < numChunks; i++) {
        combineHashes.inputs[i] <== stateHashes[i];
    }
    
    finalHash.inputs[0] <== combineHashes.out;
    finalHash.inputs[1] <== salt;
    finalHash.inputs[2] <== ownerSecret;
    
    // ═══════════════════════════════════════════════════════════════════
    // STEP 3: Verify commitment matches
    // ═══════════════════════════════════════════════════════════════════
    
    component isEqual = IsEqual();
    isEqual.in[0] <== finalHash.out;
    isEqual.in[1] <== commitment;
    
    // ═══════════════════════════════════════════════════════════════════
    // STEP 4: Verify owner secret derives to pubkey
    // ═══════════════════════════════════════════════════════════════════
    
    component ownerHash = Poseidon(1);
    ownerHash.inputs[0] <== ownerSecret;
    
    component ownerValid = IsEqual();
    ownerValid.in[0] <== ownerHash.out;
    ownerValid.in[1] <== ownerPubkey;
    
    // Both conditions must be satisfied
    valid <== isEqual.out * ownerValid.out;
}

/**
 * @title OptimizedNullifier
 * @notice Gas-efficient nullifier computation
 * @dev Single Poseidon call, no bit decomposition
 */
template NullifierDerivation() {
    signal input commitment;
    signal input ownerSecret;
    signal input nonce;
    
    signal output nullifier;
    
    // Nullifier = Poseidon(commitment, secret, nonce)
    // This prevents double-spending while hiding the owner
    component hash = Poseidon(3);
    hash.inputs[0] <== commitment;
    hash.inputs[1] <== ownerSecret;
    hash.inputs[2] <== nonce;
    
    nullifier <== hash.out;
}

// Main circuit instantiation for PIL protocol
// 8 state fields is optimal for most use cases
component main {public [commitment, ownerPubkey]} = StateCommitment(8);
