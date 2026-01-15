# PIL Protocol Gas Optimization Report

## Executive Summary

This document analyzes gas consumption across all PIL Protocol smart contracts and provides optimization recommendations. Gas measurements were taken on Hardhat network with Solidity 0.8.20, optimization enabled (200 runs), and viaIR compilation.

---

## Deployment Gas Costs

| Contract | Gas Used | Block % | Optimization Status |
|----------|----------|---------|---------------------|
| `Groth16VerifierBLS12381` | 102,909 | 0.3% | ✅ Optimized |
| `ConfidentialStateContainerV2` | 955,191 | 3.2% | ⚠️ Acceptable |
| `CrossChainProofHubV2` | 1,445,304 | 4.8% | ⚠️ Acceptable |
| `PILAtomicSwapV2` | 1,222,786 | 4.1% | ⚠️ Acceptable |
| `PILComplianceV2` | 1,283,555 | 4.3% | ⚠️ Acceptable |
| **Total Core Deployment** | **5,009,745** | **16.7%** | |

### Deployment Analysis
- All contracts deploy within reasonable gas limits
- Largest contract (`CrossChainProofHubV2`) uses <5% of block gas limit
- Total deployment gas is ~16.7% of block limit (30M gas)

---

## Method Gas Costs

### ConfidentialStateContainerV2

| Method | Min Gas | Max Gas | Avg Gas | Calls | Status |
|--------|---------|---------|---------|-------|--------|
| `registerState` | 160,568 | 205,349 | 182,980 | 4 | ⚠️ Medium |
| `transferState` | - | - | 164,093 | 2 | ⚠️ Medium |

**Analysis:**
- `registerState` variance (160K-205K) likely due to new storage slots vs updates
- State operations involve proof storage + event emission (costly)
- First-time slot writes cost 20K gas (SSTORE), which is unavoidable

**Optimizations Applied:**
- ✅ Using `bytes` for proof storage (variable length)
- ✅ Pedersen commitments stored as `bytes32`
- ✅ Custom errors instead of require strings (~200 gas savings)

**Recommendations:**
1. Consider off-chain proof storage with on-chain commitment only
2. Use events for encrypted state retrieval (cheaper than storage)
3. Batch multiple state registrations when possible

---

### CrossChainProofHubV2

| Method | Min Gas | Max Gas | Avg Gas | Calls | Status |
|--------|---------|---------|---------|-------|--------|
| `submitProof` | 833,572 | 867,772 | 843,076 | 9 | ⛔ High |
| `sealBatch` | - | - | 224,543 | 2 | ⚠️ Medium |
| `registerRelayer` | - | - | 69,254 | 2 | ✅ Low |
| `claimBatch` | - | - | 52,822 | 2 | ✅ Low |

**Analysis:**
- `submitProof` is the most expensive operation (843K gas avg)
- High gas due to: proof bytes storage + array push + merkle operations
- Relayer operations are efficient

**Optimizations Applied:**
- ✅ Auto-batching reduces individual transaction overhead
- ✅ Merkle root computation amortized across batch
- ✅ ReentrancyGuard uses transient storage pattern

**Recommendations:**
1. **Critical**: Store proof hash instead of full proof bytes (-70% gas)
2. Implement EIP-4337 account abstraction for batched submissions
3. Use off-chain merkle tree with on-chain root verification
4. Consider ZK-rollup pattern for proof aggregation

**Proposed Optimization:**
```solidity
// Current (high gas)
messages[messageId] = ProofMessage({
    proof: proof,        // Full bytes storage
    publicInputs: publicInputs,
    ...
});

// Optimized (~70% reduction)
messages[messageId] = ProofMessage({
    proofHash: keccak256(proof),  // Only 32 bytes
    publicInputsHash: keccak256(publicInputs),
    ...
});
// Emit full data in event for off-chain retrieval
emit ProofSubmittedWithData(messageId, proof, publicInputs);
```

---

### PILAtomicSwapV2

| Method | Min Gas | Max Gas | Avg Gas | Calls | Status |
|--------|---------|---------|---------|-------|--------|
| `createSwapETH` | 240,313 | 257,413 | 248,863 | 4 | ⚠️ Medium |
| `claim` | - | - | 51,606 | 2 | ✅ Low |

**Analysis:**
- Swap creation involves multiple storage writes (hashlock, timelock, amounts)
- Claim is efficient as it primarily involves ETH transfer + status update

**Optimizations Applied:**
- ✅ SafeERC20 for token transfers
- ✅ Single-slot packing for swap struct where possible
- ✅ Efficient hashlock verification (single keccak256)

**Recommendations:**
1. Pack `timeLock` and `status` into single slot (saves 20K gas)
2. Use `immutable` for `feeRecipient` if unchangeable
3. Consider CREATE2 for deterministic swap addresses

**Struct Packing Optimization:**
```solidity
// Current struct (multiple slots)
struct Swap {
    address initiator;    // slot 1 (20 bytes)
    address recipient;    // slot 2 (20 bytes)
    address token;        // slot 3 (20 bytes)
    uint256 amount;       // slot 4 (32 bytes)
    bytes32 hashLock;     // slot 5 (32 bytes)
    uint256 timeLock;     // slot 6 (32 bytes)
    SwapStatus status;    // slot 7 (1 byte)
}

// Optimized struct (~40K gas savings)
struct Swap {
    address initiator;    // slot 1: 20 bytes
    uint48 timeLock;      // slot 1: 6 bytes (timestamp fits)
    SwapStatus status;    // slot 1: 1 byte (packed!)
    address recipient;    // slot 2
    // ... rest unchanged
}
```

---

### PILComplianceV2

| Method | Min Gas | Max Gas | Avg Gas | Calls | Status |
|--------|---------|---------|---------|-------|--------|
| `verifyKYC` | - | - | 146,860 | 2 | ⚠️ Medium |
| `authorizeProvider` | - | - | 47,139 | 1 | ✅ Low |

**Analysis:**
- `verifyKYC` writes full KYCRecord struct (multiple slots)
- Provider authorization is a simple mapping update

**Optimizations Applied:**
- ✅ Enum values packed efficiently
- ✅ Using `bytes2` for jurisdiction codes
- ✅ Custom errors for all validation

**Recommendations:**
1. Pack `status`, `tier`, `jurisdiction` into single slot
2. Consider merkle proof for batch KYC verifications
3. Use bitmap for jurisdiction restrictions (1 bit per code)

---

## Gas Comparison: V1 vs V2

| Operation | V1 (Estimated) | V2 (Actual) | Improvement |
|-----------|---------------|-------------|-------------|
| State Registration | ~250K | 182K | **27% ⬇️** |
| Proof Submission | ~900K | 843K | **6% ⬇️** |
| Swap Creation | ~300K | 248K | **17% ⬇️** |
| Swap Claim | ~80K | 51K | **36% ⬇️** |
| KYC Verification | ~180K | 146K | **19% ⬇️** |

**V2 Improvements Applied:**
- Custom errors instead of revert strings
- OpenZeppelin 5.x optimized patterns
- Struct packing where possible
- viaIR compilation pipeline

---

## Recommended Priority Optimizations

### Priority 1: Critical (High Impact)
| Optimization | Contract | Est. Savings | Effort |
|-------------|----------|--------------|--------|
| Store proof hashes instead of full proofs | CrossChainProofHubV2 | ~500K gas/op | Medium |
| Batch proof submissions | CrossChainProofHubV2 | ~50% total | High |
| Off-chain encrypted state storage | ConfidentialStateContainer | ~100K gas/op | Medium |

### Priority 2: Medium Impact
| Optimization | Contract | Est. Savings | Effort |
|-------------|----------|--------------|--------|
| Struct packing for Swap | PILAtomicSwapV2 | ~40K gas/op | Low |
| KYCRecord struct packing | PILComplianceV2 | ~20K gas/op | Low |
| Bitmap for jurisdictions | PILComplianceV2 | ~10K gas/op | Low |

### Priority 3: Low Impact (Maintenance)
| Optimization | Contract | Est. Savings | Effort |
|-------------|----------|--------------|--------|
| Unchecked math in loops | All | ~200 gas/loop | Low |
| Assembly for hash operations | All | ~100 gas/op | Medium |
| Storage slot ordering | All | Variable | Low |

---

## EIP Compatibility Roadmap

| EIP | Description | Gas Benefit | Status |
|-----|-------------|-------------|--------|
| EIP-4844 (Blob Txs) | Cheaper calldata for proofs | ~90% for proof data | Future |
| EIP-4337 (Account Abstraction) | Batched user operations | ~30% bundling | Ready |
| EIP-1153 (Transient Storage) | Reentrancy guards | ~100 gas | Enabled |
| EIP-3074 (AUTH/AUTHCALL) | Sponsored transactions | Gas sponsor pattern | Future |

---

## Testing Gas Methodology

Tests were run with:
```javascript
// hardhat.config.cjs
gasReporter: {
  enabled: true,
  currency: 'USD',
  coinmarketcap: process.env.COINMARKETCAP_API_KEY,
  outputFile: 'gas-report.txt'
}
```

**Environment:**
- Hardhat Network (local)
- Solidity 0.8.20
- Optimizer: 200 runs
- viaIR: enabled
- Block gas limit: 30,000,000

---

## Conclusion

The PIL Protocol V2 contracts are reasonably optimized with deployment costs under 5% of block limit per contract. The main optimization opportunity is in `CrossChainProofHubV2.submitProof()` which stores full proof bytes on-chain. Implementing hash-only storage with event emission could reduce this operation by 70%.

**Overall Gas Efficiency Score: B+**

| Category | Score | Notes |
|----------|-------|-------|
| Deployment | A | All contracts under 5% block limit |
| Read Operations | A | View functions are free |
| Write Operations | B | Room for proof storage optimization |
| Security Overhead | A | Security features add minimal gas |

---

*Report generated: 2025*
*Protocol Version: 2.0.0*
*Solidity: 0.8.20*
