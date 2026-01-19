# Security Tools Setup Guide

This guide explains how to install and run the security analysis tools for PIL.

## Prerequisites

- Node.js 18+
- Python 3.10+
- Hardhat (already installed)

---

## 1. Slither (Static Analysis)

### Installation

```bash
# macOS
brew install slither-analyzer

# Linux/pip
pip3 install slither-analyzer

# Verify installation
slither --version
```

### Running Slither

```bash
# Analyze key contracts
npm run slither

# Or analyze individual contracts
slither contracts/bridge/PILAtomicSwapV2.sol \
  --solc-remaps '@openzeppelin/=node_modules/@openzeppelin/'

slither contracts/primitives/ZKBoundStateLocks.sol \
  --solc-remaps '@openzeppelin/=node_modules/@openzeppelin/'

slither contracts/security/EmergencyRecovery.sol \
  --solc-remaps '@openzeppelin/=node_modules/@openzeppelin/'
```

### Known Issues

- **Hardhat v3 Compatibility**: Slither's crytic-compile may not fully support Hardhat v3. Use direct solc compilation mode.
- **Stack too deep**: Some complex contracts require `--via-ir` compilation. Analyze individual files instead of the whole project.

---

## 2. Echidna (Fuzzing)

### Installation

```bash
# macOS
brew install echidna

# Linux (using Docker recommended)
docker pull trailofbits/eth-security-toolbox
docker run -it -v $(pwd):/code trailofbits/eth-security-toolbox

# Verify installation
echidna --version
```

### Running Echidna

```bash
# Run atomic swap fuzzing (when Hardhat v3 compatibility is fixed)
npm run echidna:swap

# Or use Hardhat-based fuzzing (works now)
npm run test:fuzzing
```

### Echidna Test Contracts

Located at `contracts/test/EchidnaTests.sol`:

- **EchidnaConfidentialStateTest**: Tests state container invariants
- **EchidnaAtomicSwapTest**: Tests atomic swap state machine

### Invariants Tested

| Contract | Property | Description |
|----------|----------|-------------|
| ConfidentialState | `echidna_nullifier_uniqueness` | Nullifiers can only be used once |
| ConfidentialState | `echidna_state_consistency` | Active states have valid data |
| ConfidentialState | `echidna_counter_monotonicity` | Active ≤ Total states |
| AtomicSwap | `echidna_swap_mutual_exclusion` | Can't be completed AND refunded |
| AtomicSwap | `echidna_swap_id_uniqueness` | All swap IDs are unique |

---

## 3. Certora Prover (Formal Verification)

### Installation

```bash
# Install Certora CLI
pip3 install certora-cli

# Set up API key (get from https://prover.certora.com)
export CERTORAKEY=your_api_key_here

# Add to .bashrc/.zshrc for persistence
echo 'export CERTORAKEY=your_api_key' >> ~/.zshrc

# Verify installation
certoraRun --version
```

### Running Certora

```bash
# Run verification
npm run certora

# Or directly
certoraRun certora/conf/verify.conf
```

### Specification Files

Located at `certora/specs/`:

| Spec File | Contract | Key Properties |
|-----------|----------|----------------|
| `ConfidentialStateContainer.spec` | ConfidentialStateContainerV3 | Nullifier uniqueness, no double nullification, state resurrection prevention |
| `ZKBoundStateLocks.spec` | ZKBoundStateLocks | Lock state machine, terminal state finality, domain separator safety |
| `PILAtomicSwap.spec` | PILAtomicSwapV2 | Mutual exclusion, no double completion/refund, fee bounds |

### Configuration

Edit `certora/conf/verify.conf` to:
- Change target contracts
- Adjust loop iteration limits
- Enable/disable rule sanity checks

---

## 4. Hardhat Fuzzing (Alternative)

For immediate fuzzing without external dependencies:

```bash
# Run property-based fuzzing tests
npm run test:fuzzing
```

Tests 14 properties including:
- Random input handling (50 iterations each)
- Boundary value testing
- Nullifier uniqueness
- State monotonicity
- Race condition simulation

---

## 5. Running All Security Checks

```bash
# 1. Static Analysis
npm run slither

# 2. Fuzzing Tests
npm run test:fuzzing

# 3. Full Test Suite
npm test

# 4. Formal Verification (requires Certora key)
npm run certora
```

---

## 6. CI/CD Integration

Add to `.github/workflows/security.yml`:

```yaml
name: Security Analysis

on: [push, pull_request]

jobs:
  slither:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: crytic/slither-action@v0.4.0
        with:
          target: 'contracts/'
          slither-args: '--exclude-dependencies'

  fuzzing:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm ci
      - run: npm run test:fuzzing

  certora:
    runs-on: ubuntu-latest
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install certora-cli
      - run: npm run certora
        env:
          CERTORAKEY: ${{ secrets.CERTORAKEY }}
```

---

## 7. Interpreting Results

### Slither Severity Levels

| Level | Action Required |
|-------|-----------------|
| High | Must fix before deployment |
| Medium | Review and justify if accepted |
| Low | Consider fixing |
| Informational | Optional optimization |

### Common Accepted Findings

1. **Timestamp comparisons**: Required for HTLC/lock expiry logic
2. **Arbitrary ETH send**: Intentional in slashing/refund mechanisms
3. **Reentrancy-events**: CEI pattern followed, only event emission after call

---

## 8. External Audit Checklist

Before external audit:

- [ ] Run all security tools locally
- [ ] Document all accepted findings with justification
- [ ] Ensure 100% test coverage on critical paths
- [ ] Prepare threat model documentation
- [ ] Create attack scenario documentation
- [ ] Freeze code (no changes during audit)

---

## Support

For security tool issues:
- Slither: https://github.com/crytic/slither/issues
- Echidna: https://github.com/crytic/echidna/issues
- Certora: https://discord.gg/certora
