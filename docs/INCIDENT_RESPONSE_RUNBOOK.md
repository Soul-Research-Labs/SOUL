# PIL Incident Response Runbook

## Overview

This runbook provides step-by-step procedures for responding to security incidents affecting the Privacy Interoperability Layer (PIL) protocol. All team members with operational responsibilities must be familiar with these procedures.

---

## Table of Contents

1. [Incident Classification](#incident-classification)
2. [Response Team Structure](#response-team-structure)
3. [Communication Protocols](#communication-protocols)
4. [Incident Response Procedures](#incident-response-procedures)
5. [Specific Incident Playbooks](#specific-incident-playbooks)
6. [Recovery Procedures](#recovery-procedures)
7. [Post-Incident Activities](#post-incident-activities)

---

## Incident Classification

### Severity Levels

| Level | Name | Description | Response Time | Example |
|-------|------|-------------|---------------|---------|
| **P0** | Critical | Active exploitation, fund loss imminent | < 15 min | Drain attack in progress |
| **P1** | High | Vulnerability discovered, exploit possible | < 1 hour | Critical bug found |
| **P2** | Medium | Security issue, no immediate exploit | < 4 hours | Access control weakness |
| **P3** | Low | Minor issue, no user impact | < 24 hours | Information disclosure |
| **P4** | Info | Security improvement opportunity | < 1 week | Best practice suggestion |

### Classification Matrix

```
┌─────────────────────────────────────────────────────────────────────┐
│                    INCIDENT CLASSIFICATION MATRIX                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Impact Assessment:                                                  │
│                                                                      │
│                    │ Exploitability                                 │
│                    │ None    Low     Med     High    Active         │
│  ──────────────────┼──────────────────────────────────────          │
│  Impact            │                                                │
│  ──────────────────┼──────────────────────────────────────          │
│  Critical (>$1M)   │  P2      P1      P0      P0      P0            │
│  High ($100K-$1M)  │  P3      P2      P1      P0      P0            │
│  Medium ($10K-$100K│  P3      P3      P2      P1      P0            │
│  Low (<$10K)       │  P4      P3      P3      P2      P1            │
│  None              │  P4      P4      P3      P3      P2            │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Response Team Structure

### Roles & Responsibilities

| Role | Primary | Backup | Responsibilities |
|------|---------|--------|------------------|
| **Incident Commander** | @lead | @backup-lead | Overall coordination, decisions |
| **Technical Lead** | @tech-lead | @senior-dev | Technical investigation, fixes |
| **Communications Lead** | @comms | @pm | User/public communication |
| **Operations Lead** | @ops | @devops | System access, deployments |
| **Legal/Compliance** | @legal | External | Regulatory, legal guidance |

### Escalation Path

```
┌──────────────────────────────────────────────────────────────────────┐
│                       ESCALATION PATH                                 │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  Detector (anyone)                                                    │
│       │                                                               │
│       ▼                                                               │
│  On-Call Engineer (15 min SLA)                                        │
│       │                                                               │
│       ├─────────────────────────────────┐                            │
│       ▼                                 ▼                            │
│  P3/P4: Handle                     P0/P1/P2: Escalate                │
│  independently                          │                            │
│                                         ▼                            │
│                               Incident Commander                      │
│                                         │                            │
│                     ┌───────────────────┼───────────────────┐        │
│                     ▼                   ▼                   ▼        │
│              Technical Lead      Communications      Operations      │
│                     │                   │                   │        │
│                     ▼                   ▼                   ▼        │
│              Investigation        Announcements       System Access  │
│                     │                                       │        │
│                     └───────────────────┬───────────────────┘        │
│                                         ▼                            │
│                                 P0 Only: CEO/Board                   │
│                                                                       │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Communication Protocols

### Internal Channels

| Channel | Purpose | SLA |
|---------|---------|-----|
| #incident-war-room | Active incident coordination | Real-time |
| #security-alerts | Automated monitoring alerts | 5 min |
| @security-oncall | Direct escalation | 15 min |
| Incident Call | Voice coordination for P0/P1 | Immediate |

### External Communication

| Audience | Channel | Timing | Approver |
|----------|---------|--------|----------|
| Users | Status page | Every 30 min during P0/P1 | Comms Lead |
| Community | Discord/Twitter | After initial assessment | Incident Commander |
| Partners | Direct email | Within 1 hour of P0 | CEO |
| Regulators | Formal notice | As required by law | Legal |
| Media | Press release | Only for major incidents | CEO + Legal |

### Communication Templates

#### Status Page Update (During Incident)
```
[INCIDENT] - Bridge Operations Temporarily Paused

We are currently investigating an issue affecting [COMPONENT].
As a precaution, we have paused [OPERATIONS].

User funds are safe. We will provide updates every 30 minutes.

Next update: [TIME]

Questions: support@pil-protocol.io
```

#### Resolution Announcement
```
[RESOLVED] - Issue with [COMPONENT] Resolved

The issue affecting [COMPONENT] has been resolved.
All operations have resumed normal functionality.

Summary:
- Duration: [TIME]
- Impact: [DESCRIPTION]
- Cause: [BRIEF EXPLANATION]
- Resolution: [ACTIONS TAKEN]

A detailed post-mortem will be published within 48 hours.
```

---

## Incident Response Procedures

### Phase 1: Detection & Triage (0-15 minutes)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    PHASE 1: DETECTION & TRIAGE                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Step 1: Acknowledge Alert                                           │
│  □ Respond to alert in #security-alerts                             │
│  □ Claim incident in PagerDuty/OpsGenie                             │
│  □ Start incident log with timestamp                                │
│                                                                      │
│  Step 2: Initial Assessment                                          │
│  □ Identify affected component(s)                                   │
│  □ Determine if funds are at risk                                   │
│  □ Classify severity (P0-P4)                                        │
│  □ Check if exploit is active                                       │
│                                                                      │
│  Step 3: Escalate if P0/P1/P2                                        │
│  □ Page Incident Commander                                          │
│  □ Create #incident-YYYY-MM-DD-NNN channel                          │
│  □ Post initial assessment                                          │
│                                                                      │
│  Step 4: Initial Containment (if active exploit)                     │
│  □ Execute emergency pause (see Playbook 1)                         │
│  □ Document all actions taken                                       │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Phase 2: Containment (15-60 minutes)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    PHASE 2: CONTAINMENT                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Step 1: Assemble Response Team                                      │
│  □ Incident Commander online                                        │
│  □ Technical Lead identified                                        │
│  □ Communications Lead notified                                     │
│  □ Operations Lead on standby                                       │
│                                                                      │
│  Step 2: Isolate Affected Systems                                    │
│  □ Pause affected contracts if not already done                     │
│  □ Disable external integrations                                    │
│  □ Rate limit suspicious addresses                                  │
│  □ Blacklist known attacker addresses                               │
│                                                                      │
│  Step 3: Preserve Evidence                                           │
│  □ Snapshot current state                                           │
│  □ Export relevant logs                                             │
│  □ Record attacker transactions                                     │
│  □ Document timeline                                                │
│                                                                      │
│  Step 4: Initial Communication                                       │
│  □ Update status page                                               │
│  □ Post in Discord #announcements                                   │
│  □ Prepare holding statement                                        │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Phase 3: Investigation (1-4 hours)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    PHASE 3: INVESTIGATION                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Step 1: Root Cause Analysis                                         │
│  □ Identify vulnerability type                                      │
│  □ Determine attack vector                                          │
│  □ Analyze attacker transactions                                    │
│  □ Identify affected addresses/contracts                            │
│                                                                      │
│  Step 2: Impact Assessment                                           │
│  □ Calculate funds at risk                                          │
│  □ Calculate funds lost (if any)                                    │
│  □ Identify affected users                                          │
│  □ Assess data exposure                                             │
│                                                                      │
│  Step 3: Develop Fix                                                 │
│  □ Design patch/fix                                                 │
│  □ Review with 2+ senior engineers                                  │
│  □ Test in forked environment                                       │
│  □ Prepare deployment plan                                          │
│                                                                      │
│  Step 4: Validate Other Components                                   │
│  □ Check for similar vulnerabilities                                │
│  □ Review related code paths                                        │
│  □ Verify other contracts not affected                              │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Phase 4: Eradication & Recovery (4-24 hours)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    PHASE 4: ERADICATION & RECOVERY                   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Step 1: Deploy Fix                                                  │
│  □ Execute upgrade through timelock (or emergency if P0)            │
│  □ Verify fix deployed correctly                                    │
│  □ Run integration tests                                            │
│  □ Verify attacker cannot exploit again                             │
│                                                                      │
│  Step 2: Restore Services                                            │
│  □ Gradually re-enable operations                                   │
│  □ Monitor for anomalies                                            │
│  □ Verify user access restored                                      │
│  □ Confirm cross-chain operations working                           │
│                                                                      │
│  Step 3: Fund Recovery (if applicable)                               │
│  □ Contact exchanges to freeze attacker funds                       │
│  □ Coordinate with on-chain sleuths                                 │
│  □ Engage law enforcement if appropriate                            │
│  □ Consider white-hat negotiation                                   │
│                                                                      │
│  Step 4: User Communication                                          │
│  □ Announce resolution                                              │
│  □ Provide detailed impact summary                                  │
│  □ Outline compensation plan (if needed)                            │
│  □ Share timeline for post-mortem                                   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Specific Incident Playbooks

### Playbook 1: Emergency Contract Pause

**Trigger**: Active exploit detected, funds at risk

**Authority**: Guardian role holder

**Procedure**:

```bash
# 1. Connect to emergency wallet
# Ensure Guardian role wallet is available

# 2. Execute pause on affected contract(s)
# Using Foundry cast command:

cast send $CONTRACT_ADDRESS "pause()" \
  --rpc-url $RPC_URL \
  --private-key $GUARDIAN_PRIVATE_KEY \
  --gas-limit 100000

# For multiple contracts, pause in order:
# 1. CrossChainProofHubV3
# 2. PILAtomicSwapV2
# 3. All bridge adapters
# 4. ZKBoundStateLocks
```

**Verification**:
```bash
# Verify pause state
cast call $CONTRACT_ADDRESS "paused()(bool)" --rpc-url $RPC_URL
# Should return: true
```

**Rollback**:
```bash
# Only after incident resolved and fix deployed
cast send $CONTRACT_ADDRESS "unpause()" \
  --rpc-url $RPC_URL \
  --private-key $GUARDIAN_PRIVATE_KEY
```

### Playbook 2: Circuit Breaker Activation

**Trigger**: Anomaly detected by monitoring

**Authority**: Automatic or Operator role

**Monitoring Thresholds**:
- Volume spike: > 3x average in 1 hour
- Failed transactions: > 10% in 10 minutes
- Large withdrawal: > $100K single tx
- Multiple withdrawals: > $500K in 1 hour

**Procedure**:
```bash
# Manual activation if automatic trigger failed
cast send $CIRCUIT_BREAKER_ADDRESS \
  "triggerCircuitBreaker(string)" \
  "Manual activation: [REASON]" \
  --rpc-url $RPC_URL \
  --private-key $OPERATOR_PRIVATE_KEY
```

### Playbook 3: Malicious Message Block

**Trigger**: Suspected malicious cross-chain message

**Authority**: Operator role

**Procedure**:
```bash
# 1. Block specific source address
cast send $BRIDGE_ADAPTER_ADDRESS \
  "blockSource(uint256,address)" \
  $SOURCE_CHAIN_ID $MALICIOUS_ADDRESS \
  --rpc-url $RPC_URL \
  --private-key $OPERATOR_PRIVATE_KEY

# 2. Block entire source chain (extreme measure)
cast send $BRIDGE_ADAPTER_ADDRESS \
  "setChainBlocked(uint256,bool)" \
  $SOURCE_CHAIN_ID true \
  --rpc-url $RPC_URL \
  --private-key $OPERATOR_PRIVATE_KEY
```

### Playbook 4: Emergency Upgrade

**Trigger**: Critical vulnerability requires immediate fix

**Authority**: Multi-sig (3/7) + Emergency timelock bypass

**Procedure**:
```bash
# 1. Prepare upgrade transaction
# (Fix must already be audited/reviewed)

# 2. Collect multi-sig signatures
# Coordinate through secure channel

# 3. Execute emergency upgrade
cast send $UPGRADE_TIMELOCK_ADDRESS \
  "executeEmergency(address,bytes)" \
  $PROXY_ADDRESS $UPGRADE_CALLDATA \
  --rpc-url $RPC_URL \
  --private-key $MULTISIG_EXECUTION_KEY

# 4. Verify upgrade
cast call $PROXY_ADDRESS "getImplementation()(address)" \
  --rpc-url $RPC_URL
```

### Playbook 5: Key Compromise Response

**Trigger**: Private key suspected or confirmed compromised

**Authority**: Incident Commander + Multi-sig

**Procedure**:

1. **Immediate Actions** (< 5 minutes)
   - Pause all contracts using remaining valid keys
   - Revoke compromised key's roles
   - Monitor for unauthorized transactions

2. **Containment** (< 30 minutes)
   ```bash
   # Revoke compromised address from all roles
   cast send $CONTRACT_ADDRESS \
     "revokeRole(bytes32,address)" \
     $ROLE_HASH $COMPROMISED_ADDRESS \
     --rpc-url $RPC_URL \
     --private-key $ADMIN_PRIVATE_KEY
   ```

3. **Recovery** (< 24 hours)
   - Generate new keys securely
   - Update multi-sig configuration
   - Re-grant roles to new addresses
   - Document key rotation

### Playbook 6: Bridge Drain Attack

**Trigger**: Unauthorized large withdrawals detected

**Authority**: Guardian + Incident Commander

**Procedure**:

1. **Immediate** (< 2 minutes)
   - Pause all bridge adapters
   - Pause central hub contract
   - Alert all exchanges

2. **Containment** (< 15 minutes)
   ```bash
   # Block attacker addresses
   cast send $BRIDGE_ADDRESS \
     "blacklistAddress(address)" \
     $ATTACKER_ADDRESS \
     --rpc-url $RPC_URL \
     --private-key $GUARDIAN_PRIVATE_KEY
   ```

3. **Investigation**
   - Trace attack origin
   - Identify exploited vulnerability
   - Calculate total loss

4. **Recovery**
   - Contact exchanges (Binance, Coinbase, etc.)
   - File law enforcement report
   - Coordinate with on-chain investigators

---

## Recovery Procedures

### Contract Re-enablement Checklist

```
□ Fix verified and deployed
□ Integration tests passing
□ No new vulnerabilities introduced
□ Monitoring enhanced for recurrence
□ Multi-sig approval for unpause
□ Gradual re-enablement plan ready
□ Communication prepared

Re-enablement Order:
1. ZKBoundStateLocks (lowest risk)
2. NullifierRegistry
3. CrossChainProofHubV3
4. Bridge Adapters (one at a time)
5. PILAtomicSwapV2 (highest risk, last)
```

### Service Restoration Verification

```bash
# 1. Verify contract states
for CONTRACT in $CONTRACT_LIST; do
  echo "Checking $CONTRACT..."
  cast call $CONTRACT "paused()(bool)" --rpc-url $RPC_URL
done

# 2. Run smoke tests
npm run test:smoke

# 3. Verify cross-chain functionality
npm run test:crosschain:smoke

# 4. Monitor for 1 hour before announcing resolution
```

---

## Post-Incident Activities

### Post-Mortem Process

**Timeline**: Complete within 48 hours of resolution

**Template**:
```markdown
# Post-Mortem: [INCIDENT NAME]

## Summary
- **Date**: 
- **Duration**: 
- **Severity**: 
- **Impact**: 

## Timeline
- HH:MM - Detection
- HH:MM - Escalation
- HH:MM - Containment
- HH:MM - Root cause identified
- HH:MM - Fix deployed
- HH:MM - Services restored

## Root Cause
[Detailed technical explanation]

## Impact
- Funds lost: 
- Users affected: 
- Downtime: 

## Response Assessment
### What went well
- 
### What could be improved
- 

## Action Items
| Action | Owner | Due Date | Status |
|--------|-------|----------|--------|
|        |       |          |        |

## Lessons Learned
```

### Long-term Improvements

| Category | Action | Timeline |
|----------|--------|----------|
| Prevention | Add automated checks | 2 weeks |
| Detection | Enhance monitoring | 1 week |
| Response | Update runbooks | 3 days |
| Recovery | Improve backup procedures | 2 weeks |
| Training | Conduct incident drill | 1 month |

---

## Appendix

### Emergency Contacts

| Role | Name | Phone | Telegram |
|------|------|-------|----------|
| Primary On-Call | [REDACTED] | [REDACTED] | @[REDACTED] |
| Incident Commander | [REDACTED] | [REDACTED] | @[REDACTED] |
| Legal Counsel | [REDACTED] | [REDACTED] | N/A |

### External Resources

| Resource | Contact | Purpose |
|----------|---------|---------|
| Immunefi | platform@immunefi.com | Bug bounty coordination |
| Chainanalysis | incident@chainalysis.com | Fund tracing |
| AWS Support | Enterprise support line | Infrastructure |

### Multi-Sig Wallet Addresses

| Network | Address | Signers Required |
|---------|---------|------------------|
| Ethereum | [ADDRESS] | 4/7 |
| Arbitrum | [ADDRESS] | 3/5 |
| Optimism | [ADDRESS] | 3/5 |
| Base | [ADDRESS] | 3/5 |

---

*Last Updated: January 2026*
*Version: 1.0.0*
*Review Schedule: Quarterly*
