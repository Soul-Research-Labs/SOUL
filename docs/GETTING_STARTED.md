# Getting Started with PIL Network

This guide will help you set up and start using the Privacy Interoperability Layer (PIL) for cross-chain privacy-preserving operations.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Core Concepts](#core-concepts)
5. [Your First Private Transaction](#your-first-private-transaction)
6. [Next Steps](#next-steps)

---

## Prerequisites

Before you begin, ensure you have the following installed:

- **Node.js** >= 18.0.0
- **npm** >= 9.0.0 or **yarn** >= 1.22.0
- **Git** for version control
- **Docker** (optional, for local development)

### Blockchain Requirements

For development, you'll need access to:
- A local Hardhat/Anvil node, or
- Testnet RPC endpoints (Sepolia, Goerli, etc.)

---

## Installation

### Using npm

```bash
npm install @pil/sdk
```

### Using yarn

```bash
yarn add @pil/sdk
```

### From source

```bash
git clone https://github.com/pil-network/pil-protocol.git
cd pil-protocol
npm install
npm run build
```

---

## Quick Start

### 1. Initialize the SDK

```typescript
import { PILSDK } from '@pil/sdk';

// Initialize with your configuration
const pil = new PILSDK({
  rpcUrl: 'https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY',
  privateKey: process.env.PRIVATE_KEY,
  network: 'sepolia'
});

// Connect to PIL contracts
await pil.connect();
```

### 2. Create a ZK-Bound State Lock

```typescript
import { ZKBoundStateLocks } from '@pil/sdk';

// Create a state lock with privacy
const lockResult = await pil.zkSlocks.createLock({
  oldStateCommitment: '0x...',
  transitionPredicateHash: '0x...',
  policyHash: '0x...',
  domainSeparator: await pil.zkSlocks.generateDomainSeparator('ethereum', 1),
  unlockDeadline: Math.floor(Date.now() / 1000) + 3600 // 1 hour
});

console.log('Lock created:', lockResult.lockId);
```

### 3. Bridge Assets Privately

```typescript
import { BridgeFactory } from '@pil/sdk/bridges';

// Create a bridge adapter for Cardano
const bridge = BridgeFactory.create('cardano', {
  evmRpcUrl: 'https://eth-sepolia...',
  cardanoRpcUrl: 'https://cardano-preprod...'
});

// Bridge with privacy
const transfer = await bridge.bridgeWithPrivacy({
  amount: '1000000000000000000', // 1 ETH
  recipient: 'addr_test1...',
  proofParams: {
    nullifier: '0x...',
    commitment: '0x...'
  }
});
```

---

## Core Concepts

### ZK-Bound State Locks (ZK-SLocks)

ZK-SLocks provide atomic state transitions with zero-knowledge proofs:

```
┌─────────────────────────────────────────────────────────────┐
│                    ZK-SLock Lifecycle                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. CREATE LOCK                                             │
│     ┌─────────────┐     ┌─────────────┐                    │
│     │ Old State   │────►│   LOCKED    │                    │
│     │ Commitment  │     │    STATE    │                    │
│     └─────────────┘     └──────┬──────┘                    │
│                                │                            │
│  2. PROVE TRANSITION           │                            │
│                         ┌──────▼──────┐                    │
│                         │  ZK Proof   │                    │
│                         │ Verification│                    │
│                         └──────┬──────┘                    │
│                                │                            │
│  3. UNLOCK                     │                            │
│     ┌─────────────┐     ┌──────▼──────┐                    │
│     │ New State   │◄────│  UNLOCKED   │                    │
│     │ Commitment  │     │    STATE    │                    │
│     └─────────────┘     └─────────────┘                    │
└─────────────────────────────────────────────────────────────┘
```

### Cross-Domain Nullifiers

Prevent double-spending across chains:

```typescript
// Register a nullifier that works across all supported chains
const nullifier = await pil.cdna.registerNullifier({
  domain: 'ethereum-mainnet',
  secret: privateSecret,
  chainScope: 'global' // Works on all chains
});

// Check if nullifier is used on any chain
const isUsed = await pil.cdna.isNullifierUsed(nullifier.hash);
```

### Privacy Pools

Join privacy sets for enhanced anonymity:

```typescript
// Deposit into privacy pool
await pil.privacyPool.deposit({
  amount: '1000000000000000000',
  commitment: commitment,
  merkleRoot: await pil.privacyPool.getCurrentRoot()
});

// Withdraw with proof
await pil.privacyPool.withdraw({
  proof: zkProof,
  nullifier: nullifier,
  recipient: recipientAddress
});
```

---

## Your First Private Transaction

Here's a complete example of a private cross-chain transfer:

```typescript
import { PILSDK, BridgeFactory } from '@pil/sdk';
import { generateProof } from '@pil/sdk/zkprover';

async function privateTransfer() {
  // 1. Initialize SDK
  const pil = new PILSDK({
    rpcUrl: process.env.RPC_URL,
    privateKey: process.env.PRIVATE_KEY
  });
  await pil.connect();

  // 2. Generate commitment and nullifier
  const secret = pil.crypto.randomBytes(32);
  const nullifier = pil.crypto.poseidon([secret, 0]);
  const commitment = pil.crypto.poseidon([secret, 1]);

  // 3. Create privacy-preserving lock
  const lock = await pil.zkSlocks.createLock({
    oldStateCommitment: commitment,
    transitionPredicateHash: pil.crypto.keccak256('transfer'),
    policyHash: pil.crypto.keccak256('default'),
    domainSeparator: await pil.zkSlocks.generateDomainSeparator('ethereum', 1),
    unlockDeadline: Math.floor(Date.now() / 1000) + 7200
  });

  // 4. Generate ZK proof for state transition
  const proof = await generateProof({
    circuit: 'transfer',
    inputs: {
      secret,
      nullifier,
      recipient: '0x...',
      amount: '1000000000000000000'
    }
  });

  // 5. Unlock with proof
  const unlockResult = await pil.zkSlocks.unlock({
    lockId: lock.lockId,
    zkProof: proof.proof,
    newStateCommitment: proof.publicInputs.newCommitment,
    nullifier: nullifier,
    verifierKeyHash: proof.verifierKeyHash,
    auxiliaryData: '0x'
  });

  console.log('Private transfer complete:', unlockResult.txHash);
}
```

---

## Next Steps

1. **[Integration Guide](./INTEGRATION_GUIDE.md)** - Deep dive into PIL integration
2. **[API Reference](./API_REFERENCE.md)** - Complete API documentation
3. **[Bridge Integration](./BRIDGE_INTEGRATION.md)** - Cross-chain bridge setup
4. **[Security Best Practices](./SECURITY_AUDIT_CHECKLIST.md)** - Security guidelines
5. **[Architecture Overview](./architecture.md)** - System design documentation

---

## Support

- **Discord**: [Join our community](https://discord.gg/pil-network)
- **GitHub Issues**: [Report bugs](https://github.com/pil-network/pil-protocol/issues)
- **Documentation**: [Full docs](https://docs.pil.network)
