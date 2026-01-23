# Mutation Testing Configuration

## Vertigo-RS Setup

### Installation

```bash
# Install Rust if not already installed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install vertigo-rs
cargo install vertigo-rs
```

### Configuration File

```toml
# vertigo.toml

[project]
# Contracts to mutate
contracts = [
    "contracts/primitives/ZKBoundStateLocks.sol",
    "contracts/primitives/ProofCarryingContainer.sol",
    "contracts/pqc/DilithiumVerifier.sol",
    "contracts/pqc/KyberKEM.sol",
    "contracts/pqc/PQCRegistry.sol",
    "contracts/bridge/PILAtomicSwapV2.sol",
    "contracts/core/ConfidentialStateContainerV3.sol",
    "contracts/core/NullifierRegistryV3.sol"
]

# Test files
tests = [
    "test/**/*.t.sol",
    "test/**/*.test.ts"
]

# Exclude patterns
exclude = [
    "contracts/test/**",
    "contracts/mocks/**",
    "node_modules/**"
]

[mutations]
# Mutation operators to apply
operators = [
    "BinaryOpMutation",           # Replace binary operators (+, -, *, /)
    "RequireMutation",            # Modify require conditions
    "SwapArgumentsMutation",      # Swap function arguments
    "DeleteExpressionMutation",   # Delete expressions
    "IfStatementMutation",        # Modify if conditions
    "AssignmentMutation",         # Modify assignments
    "UnaryOpMutation",            # Replace unary operators
    "LiteralMutation",            # Modify literals
    "BoundaryMutation",           # Test boundary conditions
    "ReturnValueMutation"         # Modify return values
]

# Maximum mutations per file
max_mutations_per_file = 50

# Timeout per test run (seconds)
test_timeout = 300

[output]
# Output format
format = "json"
output_file = "mutation-report.json"

# Generate HTML report
html_report = true
html_output = "mutation-report.html"
```

---

## Gambit Setup (Alternative)

### Installation

```bash
pip install gambit-sol
```

### Running Gambit

```bash
# Generate mutants for a specific contract
gambit mutate contracts/primitives/ZKBoundStateLocks.sol \
    --outdir mutants/zkslocks

# Generate mutants for all PQC contracts
gambit mutate contracts/pqc/*.sol \
    --outdir mutants/pqc

# Run tests against mutants
gambit test \
    --test-command "forge test --match-path 'test/fuzz/*'" \
    --mutant-dir mutants/zkslocks
```

### Gambit Configuration

```yaml
# gambit.yaml

# Solidity compiler settings
solc_remappings:
  - "@openzeppelin/=node_modules/@openzeppelin/"

# Mutation operators
mutations:
  - binary_op_replacement   # Replace +, -, *, /, %, etc.
  - require_mutation        # Flip require conditions
  - if_statement_mutation   # Flip if conditions
  - swap_arguments          # Swap function call arguments
  - unary_op_mutation       # Replace ++, --, !, ~
  - literal_mutation        # Change numeric/boolean literals
  - delete_expression       # Remove statements
  - swap_lines              # Swap adjacent statements

# Contracts to mutate
contracts:
  - contracts/primitives/ZKBoundStateLocks.sol
  - contracts/pqc/DilithiumVerifier.sol
  - contracts/pqc/KyberKEM.sol
  - contracts/pqc/PQCRegistry.sol
  - contracts/bridge/PILAtomicSwapV2.sol

# Test command
test_cmd: "forge test --fuzz-runs 1000"

# Timeout per mutant (seconds)
timeout: 120

# Output settings
output_dir: "mutation-results"
report_format: "html"
```

---

## NPM Scripts

Add to `package.json`:

```json
{
  "scripts": {
    "mutate:zkslocks": "gambit mutate contracts/primitives/ZKBoundStateLocks.sol --outdir mutants/zkslocks",
    "mutate:pqc": "gambit mutate contracts/pqc/*.sol --outdir mutants/pqc",
    "mutate:test": "gambit test --test-command 'forge test' --mutant-dir mutants",
    "mutate:report": "gambit report --input mutation-results --output mutation-report.html"
  }
}
```

---

## Mutation Score Targets

| Contract | Target Score | Priority |
|----------|--------------|----------|
| ZKBoundStateLocks | >85% | Critical |
| ProofCarryingContainer | >90% | Critical |
| DilithiumVerifier | >90% | Critical |
| KyberKEM | >85% | Critical |
| PQCRegistry | >85% | High |
| PILAtomicSwapV2 | >85% | High |
| NullifierRegistryV3 | >90% | Critical |
| ConfidentialStateContainerV3 | >85% | High |

---

## Interpreting Results

### Mutation Score Calculation

```
Mutation Score = (Killed Mutants / Total Mutants) × 100%
```

### Mutant States

| State | Description |
|-------|-------------|
| **Killed** | Tests failed when mutant applied (GOOD) |
| **Survived** | Tests passed with mutant (BAD - weak tests) |
| **Equivalent** | Mutant has same behavior as original (neutral) |
| **Timeout** | Test execution exceeded time limit |
| **Error** | Mutant caused compilation error |

### Common Survived Mutants

1. **Boundary off-by-one**: Tests don't check exact boundaries
2. **Operator replacement**: `>` vs `>=` not distinguished
3. **Dead code**: Unreachable code paths not tested
4. **Error handling**: Revert conditions not tested

### Fixing Low Scores

1. Add boundary value tests
2. Add negative test cases (expected reverts)
3. Test edge cases explicitly
4. Increase fuzz iterations
5. Add assertion density

---

## CI Integration

```yaml
# .github/workflows/mutation.yml
name: Mutation Testing

on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly on Sunday
  workflow_dispatch:

jobs:
  mutation:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Gambit
        run: pip install gambit-sol
        
      - name: Install Foundry
        uses: foundry-rs/foundry-toolchain@v1
        
      - name: Generate Mutants
        run: |
          gambit mutate contracts/primitives/ZKBoundStateLocks.sol --outdir mutants
          
      - name: Run Mutation Tests
        run: |
          gambit test --test-command "forge test" --mutant-dir mutants
          
      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: mutation-report
          path: mutation-results/
```

---

## Quick Start

```bash
# 1. Install Gambit
pip install gambit-sol

# 2. Generate mutants for critical contract
gambit mutate contracts/primitives/ZKBoundStateLocks.sol

# 3. Run tests against mutants
gambit test --test-command "forge test --match-path 'test/fuzz/ZKSlocksFuzz*'"

# 4. View report
open mutation-results/report.html
```
