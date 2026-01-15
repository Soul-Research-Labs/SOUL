# Privacy Interoperability Layer (PIL)

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.20-blue.svg)](https://docs.soliditylang.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue.svg)](https://www.typescriptlang.org/)

**Cross-Chain Private State & ZK Proof Middleware for Web3**

</div>

---

## 🌟 Overview

The Privacy Interoperability Layer (PIL) is a next-generation middleware protocol that enables secure, private transfer of confidential state and zero-knowledge proofs across heterogeneous blockchain networks. PIL bridges the gap between different ZK proof systems and privacy-preserving technologies, creating a unified privacy layer for the multi-chain ecosystem.

### Key Features

- 🔐 **Confidential State Management**: AES-256-GCM encrypted state containers with ZK proof verification
- 🌉 **Cross-Chain ZK Bridge**: Transfer proofs between different ZK systems (Groth16, PLONK, FRI-based)
- 🛡️ **Privacy-First Relayer Network**: Mixnet-style routing with decoy traffic and timing obfuscation
- ⚡ **Atomic Swaps**: HTLC-based private cross-chain swaps with stealth commitments
- 📋 **Compliance Layer**: Optional KYC/AML with zero-knowledge audit proofs

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Privacy Interoperability Layer                     │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 4: Execution Sandbox                                          │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐                 │
│  │ PILAtomicSwap│ │PILCompliance │ │   PILOracle  │                 │
│  └──────────────┘ └──────────────┘ └──────────────┘                 │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 3: Relayer Network                                            │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │        CrossChainProofHub + Staking + Slashing                │   │
│  └──────────────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 2: Proof Translation                                          │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐       │
│  │  Groth16   │ │   PLONK    │ │    FRI     │ │   Native   │       │
│  │  BLS12381  │ │  Verifier  │ │  Verifier  │ │  Adapter   │       │
│  └────────────┘ └────────────┘ └────────────┘ └────────────┘       │
├─────────────────────────────────────────────────────────────────────┤
│  Layer 1: Confidential State                                         │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │   ConfidentialStateContainer + NullifierRegistry              │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### Protocol Layers

| Layer | Component | Description |
|-------|-----------|-------------|
| 1 | Confidential State | Encrypted state storage with Pedersen commitments and nullifier tracking |
| 2 | Proof Translation | Verifiers for different ZK systems with proof format conversion |
| 3 | Relayer Network | Decentralized relayer infrastructure with staking and slashing |
| 4 | Execution Sandbox | High-level applications (swaps, compliance, oracles) |

---

## 📦 Project Structure

```
Privacy Interoperability Layer/
├── contracts/              # Solidity smart contracts
│   ├── core/              # Core protocol (state container, verifiers)
│   ├── bridge/            # Cross-chain infrastructure
│   ├── compliance/        # KYC/AML modules
│   ├── infrastructure/    # Oracles, rate limiting
│   ├── primitives/        # Cryptographic primitives (TEE, VDF)
│   └── mocks/             # Test mocks
├── sdk/                   # TypeScript SDK
│   └── src/
│       ├── client/        # Main SDK client
│       ├── crypto/        # Encryption & proof generation
│       └── types/         # TypeScript interfaces
├── relayer/               # Relayer node service
│   └── src/
│       ├── network/       # P2P networking
│       ├── bridge/        # Bridge message handling
│       └── staking/       # Stake management
├── compliance/            # Compliance service
├── test/                  # Test suites
│   └── contracts/         # Contract tests
└── docs/                  # Documentation
```

---

## 🚀 Quick Start

### Prerequisites

- Node.js >= 18.0.0
- npm >= 9.0.0

### Installation

```bash
# Clone repository
git clone https://github.com/your-org/privacy-interoperability-layer.git
cd privacy-interoperability-layer

# Install dependencies
npm install

# Compile contracts
npm run compile
```

### Running Tests

```bash
# Run all contract tests
npm test

# Run specific test file
npx hardhat test --config hardhat.config.cjs test/contracts/ConfidentialStateContainerV2.test.js

# Run with gas reporting
REPORT_GAS=true npm test
```

### Deployment

```bash
# Deploy to local network
npx hardhat run scripts/deploy.js --config hardhat.config.cjs --network localhost

# Deploy to testnet (Sepolia)
npx hardhat run scripts/deploy.js --config hardhat.config.cjs --network sepolia
```

---

## 📚 Core Contracts

### ConfidentialStateContainer

The main state management contract for encrypted confidential states.

```solidity
// Register encrypted state with ZK proof
function registerState(
    bytes calldata encryptedState,
    bytes32 commitment,
    bytes32 nullifier,
    bytes calldata proof,
    bytes calldata publicInputs
) external;

// Transfer state to new owner with proof
function transferState(
    bytes32 oldCommitment,
    bytes calldata newEncryptedState,
    bytes32 newCommitment,
    bytes32 newNullifier,
    bytes calldata proof,
    bytes calldata publicInputs,
    address newOwner
) external;
```

### Groth16VerifierBLS12381

Production-ready Groth16 verifier for BLS12-381 curve.

```solidity
// Verify a single proof
function verifyProof(
    bytes32 circuitId,
    Proof calldata proof,
    uint256[] calldata publicInputs
) external returns (bool);

// Verify batch of proofs (gas efficient)
function batchVerifyProofs(
    bytes32 circuitId,
    Proof[] calldata proofs,
    uint256[][] calldata publicInputsArray
) external returns (bool);
```

### PILAtomicSwap

HTLC-based atomic swaps with privacy features.

```solidity
// Initiate ETH swap
function initiateEthSwap(
    address recipient,
    bytes32 hashlock,
    uint256 timelock,
    bytes32 stealthCommitment
) external payable returns (bytes32 swapId);

// Redeem with secret
function redeem(bytes32 swapId, bytes calldata secret) external;
```

---

## 🔧 SDK Usage

### Basic Setup

```typescript
import { PILSDK } from '@pil/sdk';

const sdk = new PILSDK({
  rpcUrl: 'https://mainnet.infura.io/v3/YOUR_KEY',
  contracts: {
    stateContainer: '0x...',
    proofHub: '0x...',
    atomicSwap: '0x...'
  }
});

await sdk.initialize();
```

### Send Private State

```typescript
// Encrypt and send state cross-chain
const receipt = await sdk.sendPrivateState({
  targetChain: 137, // Polygon
  encryptedState: await sdk.encrypt(mySecretData, recipientPubKey),
  proof: await sdk.generateProof('state_transfer', inputs)
});

console.log('State sent:', receipt.commitment);
```

### Receive Private State

```typescript
// Receive and decrypt state
const state = await sdk.receivePrivateState(commitment, myPrivateKey);
const decryptedData = await sdk.decrypt(state.encryptedState);
```

---

## 🔒 Security Considerations

### Cryptographic Security

- **Encryption**: AES-256-GCM for state encryption
- **Key Exchange**: ECIES for secure key derivation
- **Commitments**: Pedersen commitments with hiding/binding properties
- **Nullifiers**: Unique nullifiers prevent double-spending

### Smart Contract Security

- OpenZeppelin security patterns (Ownable, ReentrancyGuard, Pausable)
- Custom error types for gas-efficient reverts
- Input validation on all external functions
- Emergency pause functionality

### Relayer Security

- Proof-of-stake with slashing for malicious behavior
- Decoy traffic to prevent traffic analysis
- Timing obfuscation against timing attacks
- Reputation system for relayer selection

---

## 🧪 Testing

### Test Coverage

| Contract | Tests | Passing |
|----------|-------|---------|
| ConfidentialStateContainerV2 | 12 | ✅ 12 |
| Groth16VerifierBLS12381 | 5 | ✅ 5 |
| NullifierRegistryV2 | 8 | 🔄 Pending |
| PILAtomicSwapV2 | 15 | 🔄 Pending |
| PILComplianceV2 | 12 | 🔄 Pending |

### Run Tests

```bash
# All tests
npm test

# With coverage
npm run coverage

# Gas report
REPORT_GAS=true npm test
```

---

## 📈 Gas Optimization

### Estimated Gas Costs

| Function | Gas (Avg) | USD* |
|----------|-----------|------|
| registerState | ~160,000 | ~$0.80 |
| transferState | ~164,000 | ~$0.82 |
| verifyProof | ~85,000 | ~$0.43 |
| initiateSwap | ~120,000 | ~$0.60 |

*Estimated at 50 gwei gas price, $2000 ETH

### Optimization Techniques

- `viaIR` compiler optimization enabled
- Packed storage slots for related variables
- `calldata` for read-only parameters
- Custom errors instead of require strings
- Batch operations for multiple proofs

---

## 🗺️ Roadmap

### Phase 1 - Core Protocol ✅
- [x] Confidential state container
- [x] Groth16 verifier (BLS12-381)
- [x] Nullifier registry
- [x] Basic TypeScript SDK

### Phase 2 - Cross-Chain Infrastructure ✅
- [x] Cross-chain proof hub
- [x] Relayer staking/slashing
- [x] Atomic swaps
- [x] Compliance layer

### Phase 3 - Advanced Features 🔄
- [ ] PLONK verifier
- [ ] FRI verifier (StarkNet compatibility)
- [ ] TEE attestation integration
- [ ] VDF for randomness

### Phase 4 - Production Readiness 📋
- [ ] Security audits
- [ ] Mainnet deployment
- [ ] Developer documentation
- [ ] SDK packages (npm)

---

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🔗 Links

- [Documentation](docs/README.md)
- [API Reference](docs/api/README.md)
- [Architecture Guide](docs/architecture.md)
- [Security Model](docs/security.md)

---

<div align="center">

**Built with ❤️ by the PIL Protocol Team**

</div>
