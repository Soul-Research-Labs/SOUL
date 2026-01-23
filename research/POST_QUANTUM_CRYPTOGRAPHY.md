# PIL Protocol - Post-Quantum Cryptography Research

## Overview

This document outlines the research and implementation roadmap for post-quantum cryptographic primitives in the Privacy Interoperability Layer (PIL) protocol. As quantum computers advance, the cryptographic foundations of blockchain systems face potential threats. PIL is proactively researching quantum-resistant alternatives to ensure long-term security.

## Quantum Threat Analysis

### Current Cryptographic Primitives at Risk

| Primitive | Algorithm | Threat Level | Timeline |
|-----------|-----------|--------------|----------|
| Digital Signatures | ECDSA (secp256k1) | HIGH | 10-15 years |
| Key Exchange | ECDH | HIGH | 10-15 years |
| Hash Functions | Keccak-256 | LOW | 20+ years |
| ZK-SNARKs (Groth16) | Elliptic Curves | HIGH | 10-15 years |
| Commitment Schemes | Pedersen | HIGH | 10-15 years |

### Shor's Algorithm Impact
- Breaks ECDSA signatures in polynomial time
- Compromises all elliptic curve-based key exchanges
- Threatens current ZK-SNARK constructions

### Grover's Algorithm Impact
- Reduces hash function security by half
- 256-bit hashes provide ~128-bit quantum security
- Acceptable for most use cases

## Post-Quantum Candidates for PIL

### 1. Digital Signatures

#### SPHINCS+ (Stateless Hash-Based)
- **Status**: NIST PQC Standard
- **Security**: Based on hash functions (quantum-resistant)
- **Signature Size**: 8-50 KB (configurable)
- **Verification Time**: Fast
- **Key Generation**: Moderate

```
Parameters for PIL:
- SPHINCS+-256s: Balanced security/size
- Signature: ~29 KB
- Public Key: 64 bytes
- Security Level: 128-bit post-quantum
```

#### Dilithium (Lattice-Based)
- **Status**: NIST PQC Standard (ML-DSA)
- **Security**: Based on Module-LWE
- **Signature Size**: 2.4-4.6 KB
- **Verification Time**: Very fast
- **Key Generation**: Fast

```
Parameters for PIL:
- Dilithium3: Recommended
- Signature: 3.3 KB
- Public Key: 1.9 KB
- Security Level: 192-bit classical, 128-bit quantum
```

### 2. Key Encapsulation Mechanisms (KEM)

#### Kyber (Lattice-Based)
- **Status**: NIST PQC Standard (ML-KEM)
- **Security**: Based on Module-LWE
- **Ciphertext Size**: 1-1.6 KB
- **Performance**: Excellent

```
Parameters for PIL:
- Kyber768: Recommended for general use
- Ciphertext: 1088 bytes
- Shared Secret: 32 bytes
- Security Level: 192-bit classical
```

### 3. Zero-Knowledge Proofs

#### STARKs (Hash-Based)
- **Status**: Production-ready
- **Security**: Post-quantum (hash-based)
- **Proof Size**: ~50-100 KB
- **Verification Time**: Moderate
- **Trusted Setup**: NO (transparent)

#### Lattice-Based SNARKs
- **Status**: Research phase
- **Security**: Post-quantum (lattice-based)
- **Proof Size**: 10-50 KB (estimated)
- **Verification Time**: TBD
- **Trusted Setup**: May be required

## Implementation Strategy

### Phase 1: Hybrid Signatures (Q2 2025)
- Implement dual-signature scheme
- ECDSA + Dilithium combined
- Backwards compatible
- Gradual migration path

### Phase 2: PQ KEMs (Q3 2025)
- Replace ECDH with Kyber
- Update privacy pool key exchanges
- Hybrid mode during transition

### Phase 3: PQ ZK-Proofs (Q4 2025)
- Evaluate STARK-based alternatives
- Prototype recursive STARKs
- Performance benchmarking

### Phase 4: Full Migration (2026)
- Complete PQ transition
- Deprecate classical-only paths
- Audit and verification

## Technical Specifications

### Hybrid Signature Scheme

```solidity
// Conceptual hybrid signature structure
struct HybridSignature {
    bytes classicalSig;      // ECDSA signature (65 bytes)
    bytes postQuantumSig;    // Dilithium signature (~3.3 KB)
    uint8 version;           // Scheme version
    uint8 flags;             // Validation flags
}

// Verification logic
function verifyHybrid(
    bytes32 messageHash,
    HybridSignature memory sig,
    address classicalAddress,
    bytes memory pqPublicKey
) internal view returns (bool) {
    // Verify classical ECDSA
    bool classicalValid = ecrecover(...) == classicalAddress;
    
    // Verify post-quantum (via precompile or external verifier)
    bool pqValid = verifyDilithium(messageHash, sig.postQuantumSig, pqPublicKey);
    
    // Both must be valid for full security
    return classicalValid && pqValid;
}
```

### Post-Quantum Account Binding

```solidity
struct PQAccount {
    address classicalAddress;    // Current Ethereum address
    bytes32 pqPublicKeyHash;     // Hash of PQ public key
    bytes pqPublicKey;           // Full Dilithium public key (stored separately)
    uint64 registeredAt;         // Registration timestamp
    bool pqEnabled;              // PQ verification enabled
}

mapping(address => PQAccount) public pqAccounts;
```

### ZK-STARK Migration Path

Current Groth16 proof structure:
```
Proof Size: 128 bytes (a, b, c points)
Verification: ~200K gas
Trusted Setup: Required
```

Future STARK proof structure:
```
Proof Size: ~50 KB (FRI + query phases)
Verification: ~500K gas (with batching: ~100K amortized)
Trusted Setup: None (transparent)
```

## Gas Cost Analysis

| Operation | Current (ECDSA) | Hybrid | PQ-Only |
|-----------|-----------------|--------|---------|
| Signature Verify | 3,000 gas | 350,000 gas | 300,000 gas |
| Key Register | 20,000 gas | 100,000 gas | 80,000 gas |
| ZK Verify (Groth16) | 200,000 gas | - | - |
| ZK Verify (STARK) | - | - | 500,000 gas |

*Note: Gas costs for PQ operations assume EIP proposals for precompiles are adopted.*

## EIP Proposals to Monitor

### EIP-XXXX: Dilithium Precompile
- Adds native Dilithium verification
- Reduces gas cost significantly
- Status: Draft

### EIP-XXXX: Kyber Precompile
- Adds native Kyber encapsulation/decapsulation
- Enables efficient PQ key exchange
- Status: Proposal

### EIP-XXXX: STARK Verifier
- Native FRI verification
- Enables practical on-chain STARKs
- Status: Research

## Compatibility Considerations

### Backwards Compatibility
1. Classical addresses remain valid
2. Existing locks/proofs continue to work
3. Gradual opt-in for PQ features

### Cross-Chain Implications
1. Bridge adapters need PQ signature support
2. Proof relay must handle larger STARK proofs
3. Message format versioning required

### Storage Implications
1. PQ signatures increase calldata by ~3 KB
2. Consider blob transactions (EIP-4844)
3. Compression strategies for repeated keys

## Security Considerations

### Transition Period Risks
- "Harvest now, decrypt later" attacks
- Timing of migration is critical
- Need sufficient quantum threat visibility

### Implementation Risks
- New cryptographic primitives are less battle-tested
- Side-channel vulnerabilities in PQ implementations
- Larger attack surface during hybrid phase

### Recommendations
1. Monitor NIST PQC standardization progress
2. Track quantum computing development (IBM, Google)
3. Begin hybrid implementation before critical threat
4. Engage with Ethereum PQ working groups

## References

1. NIST Post-Quantum Cryptography Standardization
   https://csrc.nist.gov/Projects/post-quantum-cryptography

2. Ethereum Post-Quantum Research
   https://ethresear.ch/tag/post-quantum

3. SPHINCS+ Specification
   https://sphincs.org/

4. Dilithium (ML-DSA) Specification
   https://pq-crystals.org/dilithium/

5. Kyber (ML-KEM) Specification
   https://pq-crystals.org/kyber/

6. STARKs Overview
   https://starkware.co/stark/

## Appendix: Prototype Implementation

See `/contracts/experimental/PostQuantumSignatures.sol` for a prototype implementation of the hybrid signature scheme.

See `/research/pq-benchmarks/` for performance benchmarks of various PQ candidates.

---

*Last Updated: 2025*
*Status: Research Phase*
*Next Review: Q2 2025*
