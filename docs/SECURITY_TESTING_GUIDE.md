# PIL Security Testing Guide

> **Version:** 1.0  
> **Last Updated:** January 2026

This guide provides comprehensive instructions for running all security tests in the Privacy Interoperability Layer.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start](#quick-start)
3. [Static Analysis](#static-analysis)
4. [Fuzz Testing](#fuzz-testing)
5. [Invariant Testing](#invariant-testing)
6. [Symbolic Execution](#symbolic-execution)
7. [Formal Verification](#formal-verification)
8. [Property Testing (Echidna)](#property-testing-echidna)
9. [CI/CD Integration](#cicd-integration)
10. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required Tools

```bash
# Node.js 20+
node --version  # Should be 20.x or higher

# Foundry
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Slither (Python 3.8+)
pip install slither-analyzer

# Halmos (Symbolic Execution)
pip install halmos

# Echidna
# macOS
brew install echidna

# Linux
curl -L https://github.com/crytic/echidna/releases/latest/download/echidna-x86_64-linux.tar.gz | tar xz
sudo mv echidna /usr/local/bin/

# Certora CLI (requires license key)
pip install certora-cli
export CERTORAKEY=<your-key>
```

### Project Setup

```bash
# Clone and install
git clone <repo-url>
cd privacy-interoperability-layer
npm install

# Install Foundry dependencies
forge install

# Build contracts
forge build
```

---

## Quick Start

### Run All Security Checks

```bash
# Quick security check (< 5 minutes)
npm run security:quick

# Full security suite (30+ minutes)
npm run security:all

# CI-compatible suite
npm run security:ci
```

### Individual Checks

```bash
# Linting only
npm run lint

# Static analysis only
npm run slither

# Fuzz tests only
npm run test:fuzz

# Invariant tests only
npm run test:invariant
```

---

## Static Analysis

### Solhint Linting

```bash
# Run linting
npm run lint

# Auto-fix issues
npm run lint:fix
```

**Configuration:** [.solhint.json](../.solhint.json)

Key security rules enabled:
- `reentrancy` - Detect reentrancy vulnerabilities
- `avoid-tx-origin` - Prevent tx.origin usage
- `state-visibility` - Require explicit visibility
- `func-visibility` - Require function visibility

### Slither Analysis

```bash
# Standard analysis
npm run slither

# Generate JSON report
npm run slither:json

# Interactive triage mode
npm run slither:triage
```

**Configuration:** [slither.config.json](../slither.config.json)

**Expected Output:**
- No HIGH severity issues
- Review MEDIUM severity manually
- LOW and INFO are typically false positives

### Mythril Deep Analysis

```bash
# Standard analysis (1 hour timeout)
npm run mythril

# Quick analysis (5 minutes)
npm run mythril:quick

# PQC contracts
npm run mythril:pqc
```

---

## Fuzz Testing

### Foundry Fuzzing

```bash
# Standard fuzz testing (10k runs)
npm run test:fuzz

# Deep fuzz testing (100k runs)
npm run test:fuzz:deep

# Specific test file
forge test --match-path "test/fuzz/ZKSlocksFuzz.t.sol" --fuzz-runs 10000 -vvv
```

**Configuration (foundry.toml):**
```toml
[fuzz]
runs = 10000
max_test_rejects = 65536
seed = "0x42"
```

### Interpreting Fuzz Results

```
[PASS] testFuzz_createLock(uint256,bytes32,address,uint256) (runs: 10000, μ: 124532, ~: 123891)
         ↑                                                          ↑         ↑        ↑
    Test name                                                   Runs    Mean gas  Median gas
```

**Common Issues:**
- `EvmError: Revert` - Check require conditions
- `Assumption too strong` - Loosen `vm.assume()` bounds
- `Max test rejects exceeded` - Reduce constraints

---

## Invariant Testing

### Foundry Invariants

```bash
# Standard invariant testing
npm run test:invariant

# Deep invariant testing
npm run test:invariant:deep

# Specific handler
forge test --match-contract ZKSlocksInvariantTest -vvvv
```

**Key Files:**
- [test/invariant/ZKSlocksInvariant.t.sol](../test/invariant/ZKSlocksInvariant.t.sol)
- [test/invariant/handlers/ZKSlocksHandler.sol](../test/invariant/handlers/ZKSlocksHandler.sol)

**Best Practices:**
1. Define ghost variables to track state
2. Use handler contracts to constrain calls
3. Run with high depth for complex state

---

## Symbolic Execution

### Halmos

```bash
# Run all symbolic tests
npm run halmos

# PQC-specific tests
npm run halmos:pqc

# ZKSlocks-specific tests  
npm run halmos:zkslocks

# Specific test
halmos --match-test "check_nullifier_uniqueness" --solver-timeout-assertion 600000
```

**Key Files:**
- [test/symbolic/PQCSymbolic.t.sol](../test/symbolic/PQCSymbolic.t.sol)
- [test/symbolic/ZKSlocksSymbolic.t.sol](../test/symbolic/ZKSlocksSymbolic.t.sol)

**Test Naming Convention:**
- `check_*` - Symbolic tests (run by Halmos)
- `test_*` - Unit tests (run by Forge)

**Interpreting Results:**
```
[PASS] check_nullifier_uniqueness(bytes32) (paths: 12)
                                              ↑
                                      Paths explored
```

### Solver Timeout

For complex tests, increase timeout:
```bash
halmos --solver-timeout-assertion 600000 --solver-timeout-branching 60000
```

---

## Formal Verification

### Certora Prover

```bash
# Verify ZKBoundStateLocks
npm run certora:zkslocks

# Verify all PQC contracts
npm run certora:dilithium
npm run certora:kyber
npm run certora:pqc

# Full verification
npm run certora:full

# Check compilation only (no verification)
npm run certora:check
```

**Key Files:**
- [certora/specs/ZKBoundStateLocks.spec](../certora/specs/ZKBoundStateLocks.spec)
- [certora/specs/DilithiumVerifier.spec](../certora/specs/DilithiumVerifier.spec)
- [certora/specs/KyberKEM.spec](../certora/specs/KyberKEM.spec)
- [certora/specs/PQCRegistry.spec](../certora/specs/PQCRegistry.spec)

**Understanding Results:**
- ✅ `[PASS]` - Rule verified
- ❌ `[FAIL]` - Counter-example found (bug!)
- ⏰ `[TIMEOUT]` - Increase timeout or simplify
- 🔄 `[UNKNOWN]` - Solver inconclusive

---

## Property Testing (Echidna)

### Running Echidna

```bash
# Basic Echidna tests
npm run echidna

# PQC invariants
npm run echidna:pqc

# ZKSlocks advanced
npm run echidna:zkslocks

# Long-running fuzzing campaign
npm run echidna:long
```

**Key Files:**
- [contracts/test/EchidnaTests.sol](../contracts/test/EchidnaTests.sol)
- [contracts/test/echidna/EchidnaPQC.sol](../contracts/test/echidna/EchidnaPQC.sol)
- [contracts/test/echidna/EchidnaZKSlocksAdvanced.sol](../contracts/test/echidna/EchidnaZKSlocksAdvanced.sol)

**Configuration:** [echidna.yaml](../echidna.yaml)

**Invariant Naming:**
```solidity
// Echidna looks for functions starting with echidna_
function echidna_nullifier_uniqueness() public view returns (bool) {
    // Return true if invariant holds
    return totalNullifiersUsed >= 0; 
}
```

**Coverage Report:**
```bash
echidna . --contract EchidnaTests --config echidna.yaml --format text
# Open echidna-corpus/coverage.html for visual coverage
```

---

## CI/CD Integration

### GitHub Actions

The security pipeline runs automatically on:
- Push to `main` or `develop`
- Pull requests
- Daily scheduled run (2 AM UTC)

**Workflow:** [.github/workflows/security.yml](../.github/workflows/security.yml)

**Jobs:**
| Job | Duration | Blocking |
|-----|----------|----------|
| slither | ~2 min | Yes (on HIGH) |
| solhint | ~1 min | Yes |
| foundry-fuzz | ~10 min | Yes |
| foundry-invariant | ~15 min | Yes |
| echidna | ~20 min | No |
| halmos | ~30 min | No |
| certora | ~45 min | No |
| mythril | ~60 min | No |

### Pre-commit Hooks

```bash
# Install pre-commit
npm run precommit:install

# Run manually
pre-commit run --all-files
```

**Configuration:** [.pre-commit-config.yaml](../.pre-commit-config.yaml)

---

## Troubleshooting

### Common Issues

#### Slither: "Compilation failed"
```bash
# Ensure Foundry build works first
forge build

# Check Solidity version
solc --version
```

#### Halmos: "Solver timeout"
```bash
# Increase timeout
halmos --solver-timeout-assertion 600000

# Reduce loop bounds
halmos --loop 3 --depth 10
```

#### Echidna: "Contract not found"
```bash
# Ensure contract is in scope
forge build

# Check contract name matches
echidna . --contract ExactContractName
```

#### Certora: "Compilation error"
```bash
# Check with compilation-only
certoraRun certora/conf/verify.conf --compilation_steps_only

# Verify remappings
cat foundry.toml | grep remappings
```

### Performance Tips

1. **Parallel Execution**
   ```bash
   # Run independent checks in parallel
   npm run lint & npm run slither & wait
   ```

2. **Incremental Testing**
   ```bash
   # Only test changed files
   forge test --match-path "test/**/$(git diff --name-only)"
   ```

3. **Caching**
   ```bash
   # Use Foundry cache
   forge test --cache-path .forge-cache
   ```

---

## Security Test Matrix

| Contract | Unit | Fuzz | Invariant | Symbolic | Certora | Echidna |
|----------|------|------|-----------|----------|---------|---------|
| ZKBoundStateLocks | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| DilithiumVerifier | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| KyberKEM | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| PQCRegistry | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| PILTimelock | ✅ | ✅ | ✅ | ⏳ | ✅ | ✅ |
| AtomicSwap | ✅ | ✅ | ✅ | ⏳ | ✅ | ✅ |

---

## Resources

- [Foundry Book](https://book.getfoundry.sh/)
- [Slither Documentation](https://github.com/crytic/slither/wiki)
- [Certora Documentation](https://docs.certora.com/)
- [Echidna Tutorial](https://github.com/crytic/echidna/wiki)
- [Halmos Documentation](https://github.com/a16z/halmos)
- [Security Invariants](./SECURITY_INVARIANTS.md)
- [Security Roadmap](./SECURITY_ROADMAP.md)
