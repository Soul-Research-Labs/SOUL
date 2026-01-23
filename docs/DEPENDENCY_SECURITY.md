# PIL Protocol - Dependency Security Guidelines

## Overview

This document outlines the dependency management and security practices for the Privacy Interoperability Layer protocol.

---

## Pinned Dependencies

All production dependencies are pinned to exact versions to prevent supply chain attacks.

### Solidity Dependencies

| Package | Version | Security Status | Last Audit |
|---------|---------|-----------------|------------|
| @openzeppelin/contracts | 5.4.0 | ✅ Audited | Dec 2025 |
| @openzeppelin/contracts-upgradeable | 5.4.0 | ✅ Audited | Dec 2025 |
| forge-std | 1.1.2 | ✅ Safe (test only) | N/A |

### JavaScript Dependencies

| Package | Version | Purpose | Security |
|---------|---------|---------|----------|
| hardhat | 3.1.4 | Build tool | ✅ Verified |
| viem | 2.30.0 | Ethereum client | ✅ Verified |
| typescript | 5.9.3 | Type checking | ✅ Verified |
| dotenv | 17.2.3 | Env loading | ✅ Verified |

---

## Security Practices

### 1. Version Pinning

```json
// DO - Exact versions
"@openzeppelin/contracts": "5.4.0"

// DON'T - Range versions in production
"@openzeppelin/contracts": "^5.4.0"
```

### 2. Lock Files

Always commit:
- `package-lock.json` (npm)
- `foundry.lock` (Foundry)

### 3. Audit Commands

```bash
# NPM vulnerability check
npm audit

# Foundry dependency check
forge update --check

# Check for outdated packages
npm outdated
```

### 4. Update Process

1. **Check for CVEs** - Review security advisories
2. **Test in isolation** - Create branch, update, run full test suite
3. **Security review** - Check changelog for security-relevant changes
4. **Staged rollout** - Deploy to testnet before mainnet

---

## Critical Dependencies

### OpenZeppelin Contracts v5.4.0

**Used modules:**
- `AccessControl.sol` - Role-based permissions
- `Pausable.sol` - Emergency pause
- `ReentrancyGuard.sol` - Reentrancy protection
- `TimelockController.sol` - Upgrade timelock
- `ECDSA.sol` - Signature verification

**Known issues:** None at time of deployment

**Upgrade path:** Review OZ changelog, test all contracts

### Viem v2.30.0

**Used for:**
- Ethereum RPC calls
- Transaction encoding
- Contract interactions

**Security:** Client-side only, no fund custody

---

## Supply Chain Security

### 1. Package Verification

```bash
# Verify package integrity
npm ci  # Uses lockfile exactly

# Check package signatures
npm audit signatures
```

### 2. Build Reproducibility

```bash
# Clean build
npm ci && npx hardhat clean && npx hardhat compile

# Verify bytecode matches
forge verify-check --chain-id 1 CONTRACT_ADDRESS
```

### 3. CI/CD Security

- Run `npm audit` in CI
- Block deploys on high severity vulnerabilities
- Use GitHub Dependabot for alerts
- Review all dependency PRs manually

---

## Vulnerability Response

### Severity Levels

| Level | Response Time | Action |
|-------|---------------|--------|
| Critical | 1 hour | Immediate pause, patch |
| High | 24 hours | Assess, prepare patch |
| Medium | 1 week | Schedule update |
| Low | 1 month | Include in next release |

### Response Procedure

1. **Assess impact** - Does vulnerability affect our usage?
2. **Check exploitability** - Is it exploitable in our context?
3. **Prepare mitigation** - Patch or workaround
4. **Test thoroughly** - Full test suite + security review
5. **Deploy** - Via standard upgrade process

---

## Dependency Freeze Policy

### Before Mainnet

- Freeze all dependencies 2 weeks before launch
- Security audit with frozen dependencies
- No updates during audit period

### After Mainnet

- Emergency security updates only during freeze
- Batch non-critical updates quarterly
- Full test suite required for any update

---

## Monitoring

### Automated

- GitHub Dependabot alerts
- Snyk continuous monitoring
- OpenZeppelin Defender dependency scan

### Manual

- Weekly: Check OpenZeppelin security advisories
- Monthly: Review full dependency tree
- Quarterly: Audit dependency licenses

---

## Approved Packages

Only packages from this list may be added:

### Solidity
- OpenZeppelin Contracts
- Solady (gas-optimized)
- forge-std (testing only)

### JavaScript/TypeScript
- Hardhat ecosystem
- Viem/Wagmi
- Ethers.js (legacy support)
- Standard test libraries

### Adding New Dependencies

1. Submit proposal with justification
2. Security team review
3. License compatibility check
4. Audit if handling funds
5. Test integration
6. Document in this file

---

*Last Updated: January 2026*
*Next Review: April 2026*
