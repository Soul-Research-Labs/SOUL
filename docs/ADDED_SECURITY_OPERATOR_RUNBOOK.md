# PIL Added Security Operator Runbook

## Overview

This runbook provides operational guidance for PIL security operators managing the Added Security stack. It covers deployment, configuration, monitoring, and incident response procedures.

**Version**: 1.0  
**Last Updated**: January 2026  
**Audience**: Security operators, DevOps, SREs

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Component Overview](#component-overview)
3. [Deployment Guide](#deployment-guide)
4. [Configuration](#configuration)
5. [Monitoring](#monitoring)
6. [Incident Response](#incident-response)
7. [Troubleshooting](#troubleshooting)
8. [Maintenance](#maintenance)

---

## Quick Start

### Prerequisites

- Node.js 18+
- Hardhat 3.x
- Access to Ethereum RPC endpoints
- Wallet with sufficient ETH for deployment

### Deploy Added Security Stack

```bash
# 1. Install dependencies
npm install

# 2. Configure environment
cp .env.example .env
# Edit .env with your RPC URLs and private keys

# 3. Deploy to Sepolia (testnet)
npx hardhat run scripts/deploy-added-security.ts --network sepolia

# 4. Verify contracts
./scripts/verify-sepolia.sh
```

### Start Monitoring

```bash
# Start watchtower services
cd monitoring
docker-compose -f docker-compose.watchtower.yml up -d

# Check status
docker-compose -f docker-compose.watchtower.yml ps
```

---

## Component Overview

### Added Security Modules

| Component | Purpose | Status Check |
|-----------|---------|--------------|
| **RuntimeSecurityMonitor** | Bytecode analysis, invariant checking | `isContractMonitored()` |
| **FormalBugBounty** | On-chain bug bounty program | `getBountyCount()` |
| **CryptographicAttestation** | TEE attestation for nodes | `isAttested()` |
| **EmergencyResponseAutomation** | Incident management & runbooks | `getIncidentCount()` |
| **ZKFraudProof** | Zero-knowledge fraud proofs | `getBatchCount()` |
| **ThresholdSignature** | Multi-party threshold signatures | `getGroupCount()` |

### Integration Layer

| Component | Purpose | Dependency |
|-----------|---------|------------|
| **AddedSecurityOrchestrator** | Unified security coordination | All added security modules |

---

## Deployment Guide

### Network Requirements

| Network | Chain ID | Recommended Gas | Required ETH |
|---------|----------|-----------------|--------------|
| Sepolia | 11155111 | 20 gwei | 0.5 ETH |
| Mainnet | 1 | Market rate | 2-5 ETH |
| Arbitrum | 42161 | 0.1 gwei | 0.01 ETH |
| Optimism | 10 | Market rate | 0.1 ETH |

### Step-by-Step Deployment

#### 1. Deploy Added Security Contracts

```bash
# Compile all contracts
npx hardhat compile

# Deploy to target network
npx hardhat run scripts/deploy-added-security.ts --network <network>

# Output will show:
# - RuntimeSecurityMonitor: 0x...
# - FormalBugBounty: 0x...
# - CryptographicAttestation: 0x...
# - EmergencyResponseAutomation: 0x...
# - ZKFraudProof: 0x...
# - ThresholdSignature: 0x...
```

#### 2. Deploy Orchestrator

```bash
# Deploy orchestrator with added security addresses
npx hardhat run scripts/deploy-orchestrator.ts --network <network>
```

#### 3. Configure Roles

```typescript
// Grant OPERATOR_ROLE to monitoring service
await runtimeMonitor.grantRole(OPERATOR_ROLE, watchtowerAddress);

// Grant RESPONDER_ROLE to incident responders
await emergencyResponse.grantRole(RESPONDER_ROLE, responder1Address);
await emergencyResponse.grantRole(RESPONDER_ROLE, responder2Address);

// Grant JUDGE_ROLE to bug bounty judges
await bugBounty.grantRole(JUDGE_ROLE, judge1Address);
await bugBounty.grantRole(JUDGE_ROLE, judge2Address);
await bugBounty.grantRole(JUDGE_ROLE, judge3Address);
```

#### 4. Verify Contracts

```bash
# Verify on Etherscan
npx hardhat verify --network sepolia <contract_address> [constructor_args]
```

---

## Configuration

### RuntimeSecurityMonitor

#### Register Contracts for Monitoring

```typescript
// Risk levels: 0=NONE, 1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL
await runtimeMonitor.monitorContract(bridgeAddress, 3); // HIGH risk
await runtimeMonitor.monitorContract(vaultAddress, 4);  // CRITICAL risk
```

#### Configure Invariants

```typescript
// Invariant types:
// 0 = BALANCE_CONSERVATION
// 1 = OWNERSHIP_IMMUTABLE
// 2 = SUPPLY_CAP
// 3 = TVL_BOUNDS
// 4 = RATE_LIMIT

await runtimeMonitor.registerInvariant(
  bridgeAddress,
  3,                          // TVL_BOUNDS
  parseEther("1000000"),      // Max TVL threshold
  true                        // enabled
);
```

#### Create State Snapshots

```typescript
// Manual snapshot
await runtimeMonitor.createSnapshot(bridgeAddress);

// Automated snapshots via cron job (recommended)
```

### EmergencyResponseAutomation

#### Create Runbooks

```typescript
// Action types:
// 0 = PAUSE_CONTRACT
// 1 = TRIGGER_CIRCUIT_BREAKER
// 2 = BLACKLIST_ADDRESS
// 3 = ENABLE_RATE_LIMIT
// 4 = TRIGGER_WITHDRAWAL_DELAY
// 5 = NOTIFY_TEAM
// 6 = ESCALATE
// 7 = CUSTOM

await emergencyResponse.createRunbook(
  "Critical Bridge Incident",  // name
  4,                           // CRITICAL severity trigger
  [0, 1, 5],                   // actions: pause, circuit breaker, notify
  [bridgeAddress, breakerAddress, zeroAddress],  // targets
  true                         // enabled
);
```

#### Auto-Response Thresholds

```typescript
await emergencyResponse.setAutoResponseThreshold(
  3,      // HIGH severity
  true    // enable auto-response
);
```

### ThresholdSignature

#### Create Signing Groups

```typescript
// Signature types: 0=ECDSA, 1=BLS, 2=SCHNORR, 3=FROST

const signers = [signer1, signer2, signer3, signer4, signer5];

await thresholdSignature.createGroup(
  "Bridge Governance Signers",  // name
  3n,                           // threshold (3-of-5)
  signers,                      // signer addresses
  0                             // ECDSA_THRESHOLD
);

// Start DKG ceremony
await thresholdSignature.startDKG(groupId);
```

#### DKG Ceremony Procedure

1. **Commitment Phase** (24 hours)
   ```typescript
   // Each signer submits commitment
   await thresholdSignature.submitDKGCommitment(groupId, commitment);
   ```

2. **Share Phase** (24 hours)
   ```typescript
   // Each signer submits encrypted shares
   await thresholdSignature.submitDKGShares(groupId, shares);
   ```

3. **Finalization**
   ```typescript
   // Admin finalizes DKG
   await thresholdSignature.finalizeDKG(groupId);
   ```

### CryptographicAttestation

#### Register Trusted Measurements

```typescript
// For SGX enclaves
await attestation.registerTrustedMeasurement(
  mrenclave,           // MRENCLAVE value
  "Production v1.0"    // description
);
```

#### Configure TCB Levels

```typescript
// Set minimum acceptable TCB level (0-4)
await attestation.setMinTCBLevel(2);  // Require level 2+
```

### ZKFraudProof

#### Configure Dispute Periods

```typescript
// Standard: 7 days, Expedited: 1 day
await zkFraudProof.setDisputePeriod(
  7 * 24 * 60 * 60,   // standard (7 days)
  1 * 24 * 60 * 60    // expedited (1 day)
);
```

#### Register Provers

```typescript
// Provers must bond ETH
await zkFraudProof.registerProver({ value: parseEther("10") });
```

---

## Monitoring

### Watchtower Dashboard

Access Grafana dashboard at: `http://localhost:3000/d/watchtower`

Key metrics to monitor:

| Metric | Alert Threshold | Description |
|--------|-----------------|-------------|
| `security_score` | < 70 | Contract security score |
| `active_incidents` | > 0 | Unresolved incidents |
| `attestation_expiry` | < 1 hour | Node attestation expiring |
| `unfinalized_batches` | > 10 | ZK batch backlog |
| `pending_signatures` | > 5 | Threshold signature requests |

### Alert Configuration

Edit `monitoring/config/watchtower_alerts.yml`:

```yaml
alerts:
  - name: "LowSecurityScore"
    condition: "security_score < 70"
    severity: "high"
    channel: "slack-security"
    
  - name: "CriticalIncident"
    condition: "incident_severity >= 4"
    severity: "critical"
    channel: "pagerduty"
```

### Log Aggregation

```bash
# View added security logs
docker-compose logs -f watchtower

# Filter by component
docker-compose logs -f watchtower | grep "RuntimeSecurityMonitor"
```

### Health Checks

```typescript
// Check all components
const healthCheck = {
  runtimeMonitor: await runtimeMonitor.read.getMonitoredContractCount(),
  incidents: await emergencyResponse.read.getIncidentCount(),
  attestations: await attestation.read.getAttestationCount(),
  batches: await zkFraudProof.read.getBatchCount(),
  groups: await thresholdSignature.read.getGroupCount(),
  bounties: await bugBounty.read.getBountyCount()
};

console.log("Health Check:", healthCheck);
```

---

## Incident Response

### Severity Levels

| Level | Name | Response Time | Escalation |
|-------|------|---------------|------------|
| 0 | INFORMATIONAL | 1 week | None |
| 1 | LOW | 3 days | After 3 days |
| 2 | MEDIUM | 24 hours | After 24 hours |
| 3 | HIGH | 4 hours | After 4 hours |
| 4 | CRITICAL | 15 minutes | Immediate |

### Incident Workflow

```
DETECTED → ACKNOWLEDGED → INVESTIGATING → REMEDIATING → RESOLVED → CLOSED
```

#### 1. Detection

Incidents are detected via:
- RuntimeSecurityMonitor alerts
- Watchtower anomaly detection
- Manual reporting

#### 2. Acknowledgment

```typescript
// Responder acknowledges incident
await emergencyResponse.acknowledgeIncident(incidentId);
```

#### 3. Investigation

```typescript
// Add investigation notes
await emergencyResponse.addNote(incidentId, "Investigating root cause...");
```

#### 4. Remediation

```typescript
// Execute runbook
await emergencyResponse.executeRunbook(incidentId, runbookId);

// Or manual actions
await circuitBreaker.tripBreaker(targetContract, "Manual response");
```

#### 5. Resolution

```typescript
// Mark as resolved
await emergencyResponse.resolveIncident(incidentId, "Root cause addressed");
```

#### 6. Post-Mortem

```typescript
// Close with post-mortem
await emergencyResponse.closeIncident(incidentId, postMortemHash);
```

### Emergency Contacts

| Role | Contact | Availability |
|------|---------|--------------|
| On-call Security | +1-XXX-XXX-XXXX | 24/7 |
| Security Lead | security-lead@pil.network | Business hours |
| Escalation | escalation@pil.network | Immediate |

---

## Troubleshooting

### Common Issues

#### "ContractAlreadyMonitored" Error

```typescript
// Check if already monitored
const isMonitored = await runtimeMonitor.isContractMonitored(target);
if (isMonitored) {
  await runtimeMonitor.stopMonitoring(target);
  await runtimeMonitor.monitorContract(target, newRiskLevel);
}
```

#### DKG Timeout

```typescript
// Check DKG status
const status = await thresholdSignature.getDKGStatus(groupId);
console.log("Commitments:", status.commitmentCount);
console.log("Shares:", status.shareCount);

// If stuck, abort and restart
await thresholdSignature.abortDKG(groupId);
await thresholdSignature.startDKG(groupId);
```

#### Attestation Expired

```typescript
// Nodes must re-attest
await attestation.submitAttestation(
  attestationType,
  newQuote,
  measurement,
  tcbLevel,
  validityPeriod
);
```

#### Batch Not Finalizing

```typescript
// Check dispute status
const batch = await zkFraudProof.getBatch(batchIndex);
if (batch.disputed) {
  console.log("Batch is under dispute");
  // Wait for dispute resolution
} else {
  // Check if dispute period passed
  const now = Math.floor(Date.now() / 1000);
  if (now > batch.submittedAt + disputePeriod) {
    await zkFraudProof.finalizeBatch(batchIndex);
  }
}
```

### Recovery Procedures

#### Full System Recovery

```bash
# 1. Pause all contracts
npx hardhat run scripts/emergency-pause.ts --network mainnet

# 2. Assess damage
npx hardhat run scripts/security-audit.ts --network mainnet

# 3. Apply fixes
# Deploy patched contracts if needed

# 4. Resume operations
npx hardhat run scripts/emergency-unpause.ts --network mainnet
```

---

## Maintenance

### Daily Tasks

- [ ] Review watchtower alerts
- [ ] Check security scores for all monitored contracts
- [ ] Verify attestation status of all nodes
- [ ] Review pending bug bounty submissions

### Weekly Tasks

- [ ] Audit incident response metrics
- [ ] Review threshold signature group health
- [ ] Check ZK batch finalization status
- [ ] Update runbooks if needed

### Monthly Tasks

- [ ] Rotate signing keys if needed
- [ ] Review and update trusted measurements
- [ ] Conduct security drills
- [ ] Review and update this runbook

### Quarterly Tasks

- [ ] External security audit
- [ ] Penetration testing
- [ ] Update dependencies
- [ ] Review access control matrix

---

## Appendix

### Environment Variables

```bash
# Required
ETH_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/xxx
SEPOLIA_RPC_URL=https://eth-sepolia.g.alchemy.com/v2/xxx
DEPLOYER_PRIVATE_KEY=0x...

# Optional
ETHERSCAN_API_KEY=xxx
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
PAGERDUTY_KEY=xxx
```

### Contract Addresses

See `deployments/added-security-<chainId>.json` for deployed addresses.

### Useful Commands

```bash
# Compile
npx hardhat compile

# Run tests
npx hardhat test test/security/AddedSecurityTests.test.ts

# Deploy
npx hardhat run scripts/deploy-added-security.ts --network <network>

# Verify
npx hardhat verify --network <network> <address> [args]

# Console
npx hardhat console --network <network>
```

---

*Document Version: 1.0*  
*Last Updated: January 22, 2026*
