# PIL Security Invariants

> **Version:** 1.0  
> **Last Updated:** January 2026  
> **Classification:** Security Critical

This document defines all security invariants for the Privacy Interoperability Layer. Each invariant is verified through multiple testing methodologies.

---

## Overview

Security invariants are properties that must **always** hold true throughout the lifetime of the protocol. Violation of any invariant constitutes a critical security vulnerability.

### Verification Matrix Key

| Symbol | Meaning |
|--------|---------|
| ✅ | Verified |
| 🔄 | In Progress |
| ⏳ | Planned |
| N/A | Not Applicable |

---

## 1. Nullifier Invariants

### INV-NULL-001: Nullifier Uniqueness

**Property:** A nullifier can only be marked as used exactly once.

**Rationale:** Prevents double-spending attacks in confidential transfers.

**Verification:**

| Method | Status | Location |
|--------|--------|----------|
| Unit Tests | ✅ | `test/ZKBoundStateLocks.test.ts` |
| Fuzz Tests | ✅ | `test/fuzz/ZKSlocksFuzz.t.sol` |
| Certora | ✅ | `certora/specs/ZKBoundStateLocks.spec` |
| Echidna | ✅ | `contracts/test/EchidnaTests.sol` |
| Symbolic | ✅ | `test/symbolic/ZKSlocksSymbolic.t.sol` |

**Code Location:** `contracts/primitives/ZKBoundStateLocks.sol`

```solidity
// Invariant enforced in _consumeNullifier
function _consumeNullifier(bytes32 nullifier) internal {
    require(!nullifierUsed[nullifier], "Nullifier already used");
    nullifierUsed[nullifier] = true;
}
```

---

### INV-NULL-002: Nullifier Permanence

**Property:** Once a nullifier is marked as used, it can never become unused.

**Rationale:** Prevents resurrection attacks where spent state is re-enabled.

**Verification:**

| Method | Status | Location |
|--------|--------|----------|
| Unit Tests | ✅ | `test/ZKBoundStateLocks.test.ts` |
| Fuzz Tests | ✅ | `test/fuzz/ZKSlocksFuzz.t.sol` |
| Certora | ✅ | `certora/specs/ZKBoundStateLocks.spec` |
| Echidna | ✅ | `contracts/test/echidna/EchidnaZKSlocksAdvanced.sol` |

**Certora Rule:**

```cvl
rule nullifierPermanence(bytes32 nullifier) {
    require nullifierUsed[nullifier];
    
    env e;
    calldataarg args;
    f(e, args);
    
    assert nullifierUsed[nullifier], "Nullifier must remain used";
}
```

---

### INV-NULL-003: Cross-Domain Nullifier Isolation

**Property:** Nullifiers from different domains cannot collide.

**Rationale:** Prevents cross-chain replay attacks.

**Verification:**

| Method | Status | Location |
|--------|--------|----------|
| Unit Tests | ✅ | `test/V3Contracts.test.ts` |
| Certora | ✅ | `certora/specs/CDNA.spec` |
| Symbolic | ✅ | `test/symbolic/ZKSlocksSymbolic.t.sol` |

**Implementation:**

```solidity
// Domain-scoped nullifier computation
nullifier = keccak256(abi.encodePacked(domainSeparator, secret, salt));
```

---

## 2. State Machine Invariants

### INV-SM-001: Terminal State Finality

**Property:** Terminal states (UNLOCKED, DISPUTED, CONSUMED) cannot transition to any other state.

**Rationale:** Prevents state manipulation after finalization.

**Verification:**

| Method | Status | Location |
|--------|--------|----------|
| Unit Tests | ✅ | `test/ZKBoundStateLocks.test.ts` |
| Fuzz Tests | ✅ | `test/fuzz/ZKSlocksFuzz.t.sol` |
| Certora | ✅ | `certora/specs/ZKBoundStateLocks.spec` |
| Echidna | ✅ | `contracts/test/EchidnaTests.sol` |

**State Machine:**

```
PENDING ──────┬──────> UNLOCKED (Terminal)
              │
              ├──────> DISPUTED (Terminal)
              │
              └──────> EXPIRED ──> RECOVERED
```

---

### INV-SM-002: State Monotonicity

**Property:** State can only progress forward, never backward.

**Rationale:** Prevents reverting committed transactions.

**Verification:**

| Method | Status | Location |
|--------|--------|----------|
| Certora | ✅ | `certora/specs/ZKBoundStateLocks.spec` |
| Echidna | ✅ | `contracts/test/echidna/EchidnaZKSlocksAdvanced.sol` |

---

### INV-SM-003: Exchange Completion Terminal

**Property:** Once a Kyber exchange is completed, it cannot be completed again or reversed.

**Rationale:** Prevents key exchange replay attacks.

**Verification:**

| Method | Status | Location |
|--------|--------|----------|
| Unit Tests | ✅ | `test/pqc/PostQuantumCrypto.t.sol` |
| Certora | ✅ | `certora/specs/KyberKEM.spec` |
| Symbolic | ✅ | `test/symbolic/PQCSymbolic.t.sol` |

---

## 3. Access Control Invariants

### INV-AC-001: Role-Based Authorization

**Property:** Privileged functions can only be executed by authorized roles.

**Rationale:** Prevents unauthorized administrative actions.

**Protected Functions:**

| Function | Required Role | Contract |
|----------|---------------|----------|
| `pause()` | `PAUSER_ROLE` | All pausable contracts |
| `unpause()` | `PAUSER_ROLE` | All pausable contracts |
| `transitionPhase()` | `ADMIN_ROLE` | PQCRegistry |
| `scheduleOperation()` | `PROPOSER_ROLE` | PILTimelock |
| `executeOperation()` | `EXECUTOR_ROLE` | PILTimelock |

**Verification:**

| Method | Status | Location |
|--------|--------|----------|
| Unit Tests | ✅ | `test/SecurityTests.test.ts` |
| Slither | ✅ | Automated check |
| Certora | ✅ | `certora/specs/SecurityInvariants.spec` |

---

### INV-AC-002: Ownership Non-Transferable (Without Timelock)

**Property:** Contract ownership cannot be transferred without going through the timelock.

**Rationale:** Prevents hostile takeovers.

**Verification:**

| Method | Status | Location |
|--------|--------|----------|
| Certora | ✅ | `certora/specs/Timelock.spec` |
| Unit Tests | ✅ | `test/SecurityTests.test.ts` |

---

## 4. Timelock Invariants

### INV-TL-001: Minimum Delay Enforcement

**Property:** No operation can be executed before the minimum delay (48 hours) has passed.

**Rationale:** Provides time for community review and emergency response.

**Verification:**

| Method | Status | Location |
|--------|--------|----------|
| Unit Tests | ✅ | `test/SecurityTests.test.ts` |
| Certora | ✅ | `certora/specs/Timelock.spec` |

---

### INV-TL-002: Delay Immutability

**Property:** The minimum delay cannot be reduced below the configured threshold.

**Rationale:** Prevents bypass of security delay.

**Verification:**

| Method | Status | Location |
|--------|--------|----------|
| Certora | ✅ | `certora/specs/Timelock.spec` |

---

### INV-TL-003: Operation Ordering

**Property:** Operations with predecessors cannot execute before their predecessors.

**Rationale:** Ensures correct dependency ordering.

**Verification:**

| Method | Status | Location |
|--------|--------|----------|
| Unit Tests | ✅ | `test/SecurityTests.test.ts` |
| Certora | ✅ | `certora/specs/Timelock.spec` |

---

## 5. Cryptographic Invariants

### INV-CRYPTO-001: Signature Size Validation

**Property:** Signatures with incorrect sizes are always rejected.

| Algorithm | Expected Signature Size | Expected PK Size |
|-----------|------------------------|------------------|
| Dilithium3 | 3,293 bytes | 1,952 bytes |
| Dilithium5 | 4,595 bytes | 2,592 bytes |
| SPHINCS+-128s | 7,856 bytes | 32 bytes |
| SPHINCS+-256s | 29,792 bytes | 64 bytes |

**Verification:**

| Method | Status | Location |
|--------|--------|----------|
| Unit Tests | ✅ | `test/pqc/PostQuantumCrypto.t.sol` |
| Symbolic | ✅ | `test/symbolic/PQCSymbolic.t.sol` |
| Certora | ✅ | `certora/specs/DilithiumVerifier.spec` |

---

### INV-CRYPTO-002: Key Size Validation

**Property:** Public keys with incorrect sizes are always rejected.

| Algorithm | Expected Key Size |
|-----------|------------------|
| Kyber512 | 800 bytes |
| Kyber768 | 1,184 bytes |
| Kyber1024 | 1,568 bytes |

**Verification:**

| Method | Status | Location |
|--------|--------|----------|
| Unit Tests | ✅ | `test/pqc/PostQuantumCrypto.t.sol` |
| Symbolic | ✅ | `test/symbolic/PQCSymbolic.t.sol` |
| Certora | ✅ | `certora/specs/KyberKEM.spec` |

---

### INV-CRYPTO-003: Domain Separator Determinism

**Property:** Domain separators are deterministic for the same inputs.

**Verification:**

| Method | Status | Location |
|--------|--------|----------|
| Fuzz Tests | ✅ | `test/fuzz/ZKSlocksFuzz.t.sol` |
| Symbolic | ✅ | `test/symbolic/ZKSlocksSymbolic.t.sol` |
| Echidna | ✅ | `contracts/test/echidna/EchidnaZKSlocksAdvanced.sol` |

---

### INV-CRYPTO-004: Domain Separator Uniqueness

**Property:** Different chain/app/epoch combinations produce different domain separators.

**Verification:**

| Method | Status | Location |
|--------|--------|----------|
| Fuzz Tests | ✅ | `test/fuzz/ZKSlocksFuzz.t.sol` |
| Symbolic | ✅ | `test/symbolic/ZKSlocksSymbolic.t.sol` |
| Echidna | ✅ | `contracts/test/echidna/EchidnaZKSlocksAdvanced.sol` |

---

## 6. Reentrancy Invariants

### INV-REENT-001: State Changes Before External Calls

**Property:** All state changes occur before any external calls.

**Rationale:** Prevents reentrancy attacks.

**Verification:**

| Method | Status | Location |
|--------|--------|----------|
| Slither | ✅ | Automated detection |
| Code Review | ✅ | All contracts |
| Echidna | ✅ | `contracts/test/EchidnaTests.sol` |

**Protected Functions:**

All functions using `nonReentrant` modifier:
- `consumeContainer()`
- `unlock()`
- `dispute()`
- `executeSwap()`
- `refundSwap()`

---

## 7. Overflow/Underflow Invariants

### INV-OVERFLOW-001: Arithmetic Safety

**Property:** All arithmetic operations are overflow-safe.

**Implementation:** Solidity 0.8+ default checked arithmetic, with explicit `unchecked` only for provably safe operations.

**Verification:**

| Method | Status | Location |
|--------|--------|----------|
| Slither | ✅ | Automated check |
| Mythril | ✅ | Symbolic execution |
| Code Review | ✅ | All unchecked blocks |

**Allowed Unchecked Operations:**

```solidity
// Only for loop counters where overflow is impossible
unchecked { ++i; }

// Only for statistics that cannot realistically overflow
unchecked { ++stats.totalAccounts; }
```

---

## 8. Statistics Invariants

### INV-STAT-001: Monotonic Statistics

**Property:** Statistics counters only increase (or remain constant).

| Statistic | Can Increase | Can Decrease |
|-----------|--------------|--------------|
| `totalCreated` | ✅ | ❌ |
| `totalUnlocked` | ✅ | ❌ |
| `totalSignatureVerifications` | ✅ | ❌ |
| `totalKeyEncapsulations` | ✅ | ❌ |

**Verification:**

| Method | Status | Location |
|--------|--------|----------|
| Fuzz Tests | ✅ | `test/fuzz/ZKSlocksFuzz.t.sol` |
| Echidna | ✅ | `contracts/test/echidna/*.sol` |
| Certora | ✅ | `certora/specs/PQCRegistry.spec` |

---

### INV-STAT-002: Bounded Statistics

**Property:** Sub-statistics never exceed total statistics.

- `dilithiumAccounts + sphincsAccounts <= totalAccounts`
- `kyberAccounts <= totalAccounts`
- `completedExchanges <= totalExchanges`
- `disputed <= optimisticUnlocks`

**Verification:**

| Method | Status | Location |
|--------|--------|----------|
| Echidna | ✅ | `contracts/test/echidna/*.sol` |
| Certora | ✅ | `certora/specs/PQCRegistry.spec` |

---

## 9. Upgrade Safety Invariants

### INV-UPG-001: Storage Layout Preservation

**Property:** Contract upgrades preserve storage layout.

**Rationale:** Prevents storage collision bugs.

**Verification:**

| Method | Status | Location |
|--------|--------|----------|
| OpenZeppelin Plugin | ✅ | Hardhat upgrade checks |
| Manual Review | ✅ | `STORAGE_LAYOUT.md` |

---

### INV-UPG-002: Initializer Single-Use

**Property:** Initializers can only be called once.

**Rationale:** Prevents re-initialization attacks.

**Verification:**

| Method | Status | Location |
|--------|--------|----------|
| Unit Tests | ✅ | Upgrade tests |
| Slither | ✅ | Initializer detection |

---

## 10. PQC Account Invariants

### INV-PQC-001: Account Configuration Immutability

**Property:** Active accounts cannot be reconfigured without deactivation.

**Verification:**

| Method | Status | Location |
|--------|--------|----------|
| Unit Tests | ✅ | `test/pqc/PostQuantumCrypto.t.sol` |
| Symbolic | ✅ | `test/symbolic/PQCSymbolic.t.sol` |
| Certora | ✅ | `certora/specs/PQCRegistry.spec` |

---

### INV-PQC-002: Hybrid Mandatory Enforcement

**Property:** In HybridMandatory phase, accounts must enable hybrid mode.

**Verification:**

| Method | Status | Location |
|--------|--------|----------|
| Unit Tests | ✅ | `test/integration/PQCIntegration.t.sol` |
| Certora | ✅ | `certora/specs/PQCRegistry.spec` |

---

### INV-PQC-003: Account Isolation

**Property:** Operations on one account do not affect other accounts.

**Verification:**

| Method | Status | Location |
|--------|--------|----------|
| Symbolic | ✅ | `test/symbolic/PQCSymbolic.t.sol` |
| Certora | ✅ | `certora/specs/PQCRegistry.spec` |

---

## Invariant Test Coverage Summary

| Category | Total Invariants | Verified | Coverage |
|----------|-----------------|----------|----------|
| Nullifier | 3 | 3 | 100% |
| State Machine | 3 | 3 | 100% |
| Access Control | 2 | 2 | 100% |
| Timelock | 3 | 3 | 100% |
| Cryptographic | 4 | 4 | 100% |
| Reentrancy | 1 | 1 | 100% |
| Overflow | 1 | 1 | 100% |
| Statistics | 2 | 2 | 100% |
| Upgrade | 2 | 2 | 100% |
| PQC Account | 3 | 3 | 100% |
| **TOTAL** | **24** | **24** | **100%** |

---

## Adding New Invariants

When adding new security invariants:

1. Document the invariant in this file
2. Add unit tests
3. Add fuzz tests (if applicable)
4. Add Certora specification
5. Add Echidna invariant (if stateful)
6. Update verification matrix
7. Run all verification methods
8. Get security review approval

---

## Appendix: Quick Verification Commands

```bash
# Run all unit tests
npm test

# Run fuzz tests
npm run test:fuzz

# Run invariant tests
npm run test:invariant

# Run Certora verification
npm run certora:full

# Run Slither analysis
npm run slither

# Run all security checks
npm run security:all
```
