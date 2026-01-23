# PIL SDK Examples

This directory contains comprehensive examples demonstrating PIL Network functionality.

## Quick Links

- [Basic Usage](#basic-usage)
- [ZK-SLocks](#zk-slocks)
- [Cross-Chain Bridges](#cross-chain-bridges)
- [Privacy Pools](#privacy-pools)
- [MPC Operations](#mpc-operations)
- [React Integration](#react-integration)

---

## Basic Usage

### Initialize the SDK

```typescript
import { PILSDK } from '@pil/sdk';

const config = {
  // Network configuration
  rpcUrl: 'https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY',
  privateKey: process.env.PRIVATE_KEY,
  network: 'sepolia',
  
  // Contract addresses (auto-detected for known networks)
  contracts: {
    zkSlocks: '0x...',
    privacyPool: '0x...',
    nullifierRegistry: '0x...'
  },
  
  // Optional: Custom proof verifier
  proofVerifier: '0x...'
};

const pil = new PILSDK(config);
await pil.connect();

// Check connection
console.log('Connected to network:', pil.network);
console.log('Block number:', await pil.provider.getBlockNumber());
```

---

## ZK-SLocks

### Create and Manage State Locks

```typescript
import { PILSDK } from '@pil/sdk';

async function zkSlocksExample() {
  const pil = new PILSDK({ /* config */ });
  await pil.connect();

  // Generate cryptographic primitives
  const secret = pil.crypto.randomBytes(32);
  const stateCommitment = pil.crypto.poseidon([secret]);
  const policyHash = pil.crypto.keccak256('compliance-policy-v1');
  
  // Create domain separator for cross-chain uniqueness
  const domainSeparator = await pil.zkSlocks.generateDomainSeparator(
    'ethereum',
    1 // Chain ID
  );

  // Create a lock
  const lock = await pil.zkSlocks.createLock({
    oldStateCommitment: stateCommitment,
    transitionPredicateHash: pil.crypto.keccak256('state-transition'),
    policyHash: policyHash,
    domainSeparator: domainSeparator,
    unlockDeadline: Math.floor(Date.now() / 1000) + 3600 // 1 hour
  });

  console.log('Lock ID:', lock.lockId);
  console.log('Transaction:', lock.txHash);

  // Check lock status
  const lockInfo = await pil.zkSlocks.getLock(lock.lockId);
  console.log('Lock Info:', {
    oldStateCommitment: lockInfo.oldStateCommitment,
    lockedBy: lockInfo.lockedBy,
    createdAt: new Date(Number(lockInfo.createdAt) * 1000),
    unlockDeadline: new Date(Number(lockInfo.unlockDeadline) * 1000),
    isUnlocked: lockInfo.isUnlocked
  });

  // Generate ZK proof for unlock
  const proof = await pil.prover.generateProof({
    circuit: 'state-transition',
    inputs: {
      oldState: stateCommitment,
      secret: secret,
      newState: pil.crypto.poseidon([secret, 1])
    }
  });

  // Unlock with proof
  const unlockResult = await pil.zkSlocks.unlock({
    lockId: lock.lockId,
    zkProof: proof.proof,
    newStateCommitment: proof.publicInputs.newState,
    nullifier: pil.crypto.poseidon([secret, 0]),
    verifierKeyHash: proof.verifierKeyHash,
    auxiliaryData: '0x'
  });

  console.log('Unlock successful:', unlockResult.txHash);
}
```

### Optimistic Unlock with Economic Security

```typescript
async function optimisticUnlockExample() {
  const pil = new PILSDK({ /* config */ });
  await pil.connect();

  // Initiate optimistic unlock (faster, requires bond)
  const optimisticResult = await pil.zkSlocks.optimisticUnlock({
    lockId: existingLockId,
    zkProof: proof.proof,
    newStateCommitment: newCommitment,
    nullifier: nullifier,
    verifierKeyHash: verifierKey,
    auxiliaryData: '0x',
    bondAmount: pil.utils.parseEther('0.1') // Bond required
  });

  console.log('Optimistic unlock initiated');
  console.log('Dispute window ends:', optimisticResult.finalizeAfter);

  // Wait for dispute window to pass, then finalize
  // (or challenger can dispute with conflicting proof)
  
  // After dispute window...
  const finalizeResult = await pil.zkSlocks.finalizeOptimisticUnlock(
    existingLockId
  );

  console.log('Finalized:', finalizeResult.txHash);
}
```

---

## Cross-Chain Bridges

### Cardano Bridge

```typescript
import { BridgeFactory, CardanoBridgeAdapterSDK } from '@pil/sdk/bridges';

async function cardanoBridgeExample() {
  // Create Cardano bridge adapter
  const bridge = BridgeFactory.create('cardano', {
    evmRpcUrl: process.env.ETH_RPC_URL,
    cardanoRpcUrl: process.env.CARDANO_RPC_URL,
    privateKey: process.env.PRIVATE_KEY
  });

  // Check bridge status
  const status = await bridge.getStatus();
  console.log('Bridge Status:', {
    operational: status.operational,
    totalBridged: status.totalValueBridged,
    pendingTransfers: status.pendingTransfers
  });

  // Get fees
  const fees = await bridge.getFees('1000000000000000000'); // 1 ETH
  console.log('Bridge Fees:', {
    baseFee: fees.baseFee,
    percentageFee: fees.percentageFee,
    totalFee: fees.totalFee
  });

  // Bridge ETH to Cardano
  const transfer = await bridge.bridgeToCardano({
    amount: '1000000000000000000', // 1 ETH worth
    recipient: 'addr_test1qz...', // Cardano address
    metadata: {
      purpose: 'cross-chain-privacy'
    }
  });

  console.log('Transfer initiated:', transfer.transferId);

  // Track transfer status
  const trackResult = await bridge.trackTransfer(transfer.transferId);
  console.log('Transfer status:', trackResult.status);
}
```

### Polkadot Bridge

```typescript
import { BridgeFactory } from '@pil/sdk/bridges';

async function polkadotBridgeExample() {
  const bridge = BridgeFactory.create('polkadot', {
    evmRpcUrl: process.env.ETH_RPC_URL,
    polkadotRpcUrl: process.env.POLKADOT_RPC_URL,
    privateKey: process.env.PRIVATE_KEY
  });

  // Bridge to Polkadot parachain
  const transfer = await bridge.bridgeToPolkadot({
    amount: '5000000000000000000', // 5 DOT equivalent
    paraId: 2000, // Target parachain
    recipient: '5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY',
    xcmMessage: {
      // Optional: custom XCM message
      instruction: 'DepositAsset'
    }
  });

  console.log('XCM Transfer:', transfer);
}
```

### Cosmos Bridge (IBC)

```typescript
import { BridgeFactory } from '@pil/sdk/bridges';

async function cosmosBridgeExample() {
  const bridge = BridgeFactory.create('cosmos', {
    evmRpcUrl: process.env.ETH_RPC_URL,
    cosmosRpcUrl: 'https://rpc.cosmos.network',
    privateKey: process.env.PRIVATE_KEY
  });

  // Bridge via IBC
  const transfer = await bridge.bridgeToCosmos({
    amount: '1000000', // 1 ATOM (6 decimals)
    denom: 'uatom',
    channel: 'channel-0',
    recipient: 'cosmos1...',
    timeout: 3600 // 1 hour timeout
  });

  console.log('IBC Transfer:', transfer);
}
```

---

## Privacy Pools

### Deposit and Withdraw

```typescript
import { PILSDK } from '@pil/sdk';

async function privacyPoolExample() {
  const pil = new PILSDK({ /* config */ });
  await pil.connect();

  // Generate commitment for deposit
  const secret = pil.crypto.randomBytes(32);
  const nullifier = pil.crypto.poseidon([secret, 0]);
  const commitment = pil.crypto.poseidon([nullifier, secret]);

  // Deposit into privacy pool
  const deposit = await pil.privacyPool.deposit({
    amount: pil.utils.parseEther('1'),
    commitment: commitment
  });

  console.log('Deposited:', deposit.txHash);
  console.log('Leaf index:', deposit.leafIndex);

  // Save these for withdrawal!
  const withdrawalData = {
    secret,
    nullifier,
    leafIndex: deposit.leafIndex,
    commitment
  };

  // --- Later: Withdraw with privacy ---

  // Get current Merkle root and path
  const merkleData = await pil.privacyPool.getMerklePath(withdrawalData.leafIndex);
  
  // Generate withdrawal proof
  const proof = await pil.prover.generateProof({
    circuit: 'withdraw',
    inputs: {
      root: merkleData.root,
      nullifierHash: pil.crypto.poseidon([withdrawalData.nullifier]),
      recipient: recipientAddress,
      secret: withdrawalData.secret,
      nullifier: withdrawalData.nullifier,
      pathElements: merkleData.pathElements,
      pathIndices: merkleData.pathIndices
    }
  });

  // Withdraw
  const withdrawal = await pil.privacyPool.withdraw({
    proof: proof.proof,
    root: merkleData.root,
    nullifierHash: pil.crypto.poseidon([withdrawalData.nullifier]),
    recipient: recipientAddress,
    relayer: '0x0000000000000000000000000000000000000000', // No relayer
    fee: 0
  });

  console.log('Withdrawal complete:', withdrawal.txHash);
}
```

---

## MPC Operations

### Threshold Signatures

```typescript
import { MPC } from '@pil/sdk';

async function mpcExample() {
  // Initialize MPC client
  const mpc = new MPC.ThresholdSignatureClient({
    threshold: 2,
    totalParties: 3,
    rpcEndpoints: [
      'https://mpc-node-1.pil.network',
      'https://mpc-node-2.pil.network',
      'https://mpc-node-3.pil.network'
    ]
  });

  // Distributed key generation
  const keyShare = await mpc.generateKeyShare({
    keyId: 'my-threshold-key',
    partyIndex: 0
  });

  console.log('Key share generated:', keyShare.publicKey);

  // Sign message with threshold
  const signature = await mpc.thresholdSign({
    keyId: 'my-threshold-key',
    message: '0x1234...',
    signingParties: [0, 1] // Any 2 of 3
  });

  console.log('Threshold signature:', signature);
}
```

---

## React Integration

### Using PIL Hooks

```tsx
import { 
  PILProvider, 
  useZKSlocks, 
  usePrivacyPool,
  useBridge 
} from '@pil/sdk/react';

// Wrap your app
function App() {
  return (
    <PILProvider config={{ rpcUrl: '...', network: 'sepolia' }}>
      <YourApp />
    </PILProvider>
  );
}

// Use hooks in components
function PrivacyDashboard() {
  const { createLock, locks, isLoading } = useZKSlocks();
  const { deposit, balance, pendingWithdrawals } = usePrivacyPool();
  const { bridge, transfers, fees } = useBridge('cardano');

  const handleCreateLock = async () => {
    await createLock({
      oldStateCommitment: '0x...',
      // ... other params
    });
  };

  return (
    <div>
      <h2>My Locks: {locks.length}</h2>
      <h2>Privacy Pool Balance: {balance}</h2>
      <h2>Pending Transfers: {transfers.length}</h2>
      
      <button onClick={handleCreateLock} disabled={isLoading}>
        Create Lock
      </button>
    </div>
  );
}
```

### Transaction Status Hook

```tsx
import { useTransactionStatus } from '@pil/sdk/react';

function TransactionTracker({ txHash }: { txHash: string }) {
  const { status, confirmations, error } = useTransactionStatus(txHash);

  return (
    <div>
      <p>Status: {status}</p>
      <p>Confirmations: {confirmations}</p>
      {error && <p className="error">{error}</p>}
    </div>
  );
}
```

---

## Running Examples

```bash
# Clone the repository
git clone https://github.com/pil-network/pil-protocol.git
cd pil-protocol/examples

# Install dependencies
npm install

# Set up environment
cp .env.example .env
# Edit .env with your keys

# Run examples
npx ts-node basic-usage.ts
npx ts-node zk-slocks.ts
npx ts-node bridges/cardano.ts
```

---

## Need Help?

- **Documentation**: https://docs.pil.network
- **Discord**: https://discord.gg/pil-network
- **GitHub Issues**: https://github.com/pil-network/pil-protocol/issues
