# Code Coverage for PIL Project

## Overview

The PIL project has comprehensive test coverage, but generating automated coverage reports using `forge coverage` faces technical limitations due to the complex ZK verifier contracts.

## The Problem

Running `forge coverage` fails with:

```
Error: Yul exception: Cannot swap Slot RET with Variable value9: 
too deep in the stack by 2 slots
```

### Root Cause

This is a known limitation with Foundry's coverage tool (see [foundry-rs/foundry#3357](https://github.com/foundry-rs/foundry/issues/3357)):

1. **Coverage instrumentation adds variables**: When forge instruments code for coverage, it adds additional local variables to track branch/line coverage.

2. **YUL stack limit**: The EVM/YUL has a stack limit of 16 slots. Complex functions (especially those with inline assembly, large structs, or many local variables) can exceed this limit when instrumented.

3. **No compile-time exclusion**: Foundry's `--no-match-coverage` only filters the coverage *report*, not the *compilation*. All contracts are still compiled with instrumentation.

4. **via_ir doesn't help**: Even with `--ir-minimum` flag, the stack depth issue persists in complex contracts.

### Affected Contracts

The following contracts use extensive inline assembly for cryptographic operations:

- `contracts/verifiers/Groth16VerifierBLS12381.sol` (12 assembly blocks)
- `contracts/verifiers/GasOptimizedVerifier.sol` (9 assembly blocks)
- `contracts/verifiers/OptimizedGroth16Verifier.sol` (7 assembly blocks)
- `contracts/verifiers/PLONKVerifier.sol` (3 assembly blocks)
- `contracts/verifiers/Groth16VerifierBN254.sol` (3 assembly blocks)
- `contracts/verifiers/FRIVerifier.sol` (1 assembly block)
- `contracts/core/Groth16VerifierBLS12381V2.sol` (4 assembly blocks)

## Current Test Coverage Status

The PIL project has been thoroughly tested through:

### Unit & Integration Tests
- **1,080+ test functions** across all major components:
  - 401 Foundry test functions (test/*.t.sol)
  - 679 TypeScript test functions (test/*.test.ts)
- Comprehensive test coverage documented in test files

### Security Testing
- **Halmos symbolic testing**: 27/27 tests passing
- **Echidna fuzzing**: 21+ invariant properties verified (5114 calls, 944 unique instructions)
- **Slither static analysis**: Reviewed and annotated (using Foundry framework)
- **Attack simulations**: 44 attack tests
- **Stress tests**: 24 load tests
- **PQC integration tests**: 15 post-quantum crypto tests

### Manual Coverage Tracking

Given the automated coverage limitations, coverage is tracked manually:

| Component | Test File(s) | Key Coverage Areas |
|-----------|--------------|-------------------|
| Core Verifiers | `test/verifiers/*.sol` | Proof verification, batch verification |
| Bridge Adapters | `test/*.test.ts` | Cross-chain messaging, state verification |
| PQC Components | `test/pqc/*.sol` | Dilithium, SPHINCS+, hybrid signatures |
| Governance | `test/governance/*.sol` | Token, governance, timelock |
| Security | `test/security/*.sol` | Emergency recovery, access control |
| Staking | `test/staking/*.sol` | Stake, unstake, rewards |

## Workarounds Attempted

### 1. Contract Stubs (Partial Success)

Created simplified stub versions of complex verifier contracts without assembly:

```
coverage-stubs/
├── core/
│   └── Groth16VerifierBLS12381V2.sol
└── verifiers/
    ├── FRIVerifier.sol
    ├── GasOptimizedVerifier.sol
    ├── Groth16VerifierBLS12381.sol
    ├── Groth16VerifierBN254.sol
    ├── OptimizedGroth16Verifier.sol
    └── PLONKVerifier.sol
```

**Script**: `scripts/run_coverage.py` - Swaps stubs in/out during coverage run.

**Status**: Other contracts in the codebase still exceed stack limits during instrumentation.

### 2. Hardhat Coverage

The project uses Hardhat 3, which is incompatible with `solidity-coverage` (requires Hardhat 2).

### 3. Profile Configuration

Added coverage profile in `foundry.toml`:

```toml
[profile.coverage]
via_ir = true
optimizer = true
optimizer_runs = 1
```

**Status**: Does not resolve the stack depth issue.

## Future Solutions

The Foundry team is working on:

1. **Solar compiler integration**: A new Solidity compiler written in Rust
2. **Bytecode-level instrumentation**: Instead of source-level, which will avoid stack issues
3. **Better IR coverage support**: Improved source maps with via_ir

See: [foundry-rs/foundry#3357](https://github.com/foundry-rs/foundry/issues/3357)

## Running Available Coverage

To attempt coverage (may fail on this codebase):

```bash
# Standard (will fail with stack-too-deep)
forge coverage --report summary

# With IR minimum (still fails but better debugging)
forge coverage --ir-minimum --report summary

# Using stub script (partial coverage)
python scripts/run_coverage.py --report=summary
```

## Recommendations

1. **Continue with current test suite**: 380+ tests provide comprehensive coverage
2. **Use security tools**: Halmos, Echidna, and Slither provide security assurance beyond line coverage
3. **Monitor Foundry updates**: When Solar/new coverage is released, re-enable automated coverage
4. **External audit**: Recommend professional security audit for production deployment

## Test Execution

Run the full test suite to verify coverage:

```bash
# Foundry tests
forge test

# Symbolic testing
halmos

# Fuzz testing  
echidna . --config echidna.yaml

# Hardhat integration tests
npx hardhat test
```

## Related Documentation

- [DEPLOYMENT_CHECKLIST.md](./DEPLOYMENT_CHECKLIST.md) - Production deployment guide
- [SECURITY.md](./SECURITY.md) - Security considerations
- [TEST_COVERAGE.md](./TEST_COVERAGE.md) - Detailed test documentation
