# Privacy Interoperability Layer (PIL) Bug Bounty Program

## Overview

The Privacy Interoperability Layer (PIL) Bug Bounty Program rewards security researchers for discovering and responsibly disclosing vulnerabilities in our smart contracts and infrastructure. We believe in working with the security community to ensure the safety of user funds and the integrity of privacy-preserving cross-chain operations.

## Program Scope

### In-Scope Smart Contracts

| Contract | Description | Deployment |
|----------|-------------|------------|
| `SecurityModule.sol` | Core security controls (rate limiting, circuit breaker, flash loan guard) | Core |
| `PILStaking.sol` | Token staking with delegation and rewards | Staking |
| `DualTokenPrivacyEconomics.sol` | Dual token economic model with privacy pools | Economics |
| `PILAtomicSwapV2.sol` | Cross-chain atomic swaps with privacy | Bridge |
| `CrossChainProofHubV3.sol` | ZK proof verification and cross-chain messaging | Bridge |
| `PILCore.sol` | Core protocol logic | Core |
| `PrivacyPoolV2.sol` | Privacy pool with compliance integration | Privacy |
| `ComplianceModule.sol` | On-chain compliance enforcement | Compliance |
| `ZkSlock.sol` | Zero-knowledge lock mechanism | ZK |
| `Groth16Verifier.sol` | ZK proof verifier | Verifier |
| `PlonkVerifier.sol` | ZK proof verifier | Verifier |

### In-Scope Networks

- Ethereum Mainnet
- Arbitrum One
- Base
- Optimism
- Polygon

### Out of Scope

- Frontend applications and web interfaces
- Third-party integrations and dependencies
- Denial of service attacks requiring significant resources
- Issues in test, mock, or development contracts
- Issues already disclosed or known
- Theoretical attacks without proof of concept
- Social engineering attacks
- Attacks requiring compromised keys or privileged access
- Gas optimization suggestions (unless security-related)

## Severity Levels & Rewards

### Critical - Up to $250,000

Impact: Direct loss of funds, permanent freezing of funds, or critical privacy breach affecting multiple users.

Examples:
- Unauthorized withdrawal of staked tokens
- Bypassing SecurityModule protections entirely
- Breaking ZK proof verification to forge proofs
- Cross-chain message manipulation enabling theft
- Circuit breaker bypass enabling market manipulation
- Flash loan attacks draining protocol funds
- Reentrancy attacks on unprotected functions
- Privacy pool deanonymization affecting user privacy

### High - Up to $50,000

Impact: Temporary freezing of funds, bypass of security controls, or significant protocol manipulation.

Examples:
- Rate limit bypass allowing denial of service
- Partial circuit breaker bypass
- Withdrawal limit manipulation
- Cross-chain message replay attacks
- Griefing attacks causing loss to other users
- Governance manipulation or vote buying
- Staking reward calculation errors leading to inflation

### Medium - Up to $10,000

Impact: Contract state manipulation, minor economic exploits, or security control weaknesses.

Examples:
- Flash loan guard timing vulnerabilities
- Incorrect access control on non-critical functions
- Event emission manipulation
- Minor arithmetic issues not leading to fund loss
- Gas manipulation enabling unfair advantages
- Timestamp manipulation exploits

### Low - Up to $2,000

Impact: Non-critical issues that could lead to exploits under specific conditions.

Examples:
- Informational security issues
- Best practice violations with potential impact
- Missing input validation on non-critical parameters
- Documentation discrepancies affecting security

## SecurityModule-Specific Vulnerabilities

We are particularly interested in vulnerabilities related to our SecurityModule protections:

### Rate Limiting
- Bypassing the 50 actions/hour limit
- Window manipulation to reset counters
- Multi-account coordination to exceed limits

### Circuit Breaker
- Triggering false positives to freeze protocol
- Bypassing the 10M token threshold
- Manipulation during cooldown period
- Reset mechanism abuse

### Flash Loan Guard
- Same-block execution exploits
- Multi-contract flash loan coordination
- Price manipulation bypassing guards

### Withdrawal Limits
- Exceeding 100K single withdrawal limit
- Circumventing 1M daily limit
- Day boundary manipulation

## Submission Requirements

### Required Information

1. **Vulnerability Description**: Clear explanation of the vulnerability
2. **Impact Analysis**: Detailed impact assessment with severity justification
3. **Proof of Concept**: Working PoC demonstrating the vulnerability
   - For smart contracts: Foundry test or Hardhat script
   - For multi-step attacks: Step-by-step execution guide
4. **Attack Scenario**: Realistic attack scenario with prerequisites
5. **Affected Code**: Specific file paths, line numbers, and functions
6. **Remediation Suggestions**: Proposed fixes (optional but appreciated)

### Proof of Concept Requirements

```solidity
// Example PoC structure
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../contracts/security/SecurityModule.sol";

contract VulnerabilityPoC is Test {
    SecurityModule public securityModule;
    
    function setUp() public {
        // Setup vulnerable contract state
    }
    
    function testExploit() public {
        // 1. Setup preconditions
        // 2. Execute attack
        // 3. Verify exploit success
        
        // Assert the impact
        assertGt(attacker.balance, initialBalance);
    }
}
```

## Submission Process

1. **Submit via Immunefi**: https://immunefi.com/bounty/pil/
2. **Acknowledgment**: Within 24 hours
3. **Triage**: Within 72 hours
4. **Resolution Timeline**: Varies by severity
   - Critical: 7 days
   - High: 14 days
   - Medium: 30 days
   - Low: 60 days

## Rules of Engagement

### Do:
- ✅ Test on testnets (Sepolia, Arbitrum Sepolia, Base Sepolia, Optimism Sepolia)
- ✅ Use your own accounts and funds for testing
- ✅ Keep vulnerability details confidential until patched
- ✅ Provide detailed, reproducible reports
- ✅ Allow reasonable time for fixes before disclosure

### Don't:
- ❌ Test on mainnet with real user funds
- ❌ Exploit vulnerabilities beyond PoC
- ❌ Access or modify other users' data
- ❌ Perform denial of service attacks
- ❌ Publicly disclose before resolution
- ❌ Submit duplicate or spam reports

## Legal Safe Harbor

We consider security research conducted consistent with this policy to be:
- Authorized and lawful
- Exempt from CFAA provisions
- Exempt from anti-circumvention claims

We will not pursue legal action against researchers who:
- Act in good faith
- Follow responsible disclosure practices
- Avoid privacy violations and data destruction
- Report findings promptly

## Contact Information

- **Security Email**: security@pil.network (PGP key available)
- **Immunefi**: https://immunefi.com/bounty/pil/
- **Discord**: #security channel (for general questions only)

## Response SLA

| Action | Timeline |
|--------|----------|
| First Response | 24 hours |
| Severity Assessment | 72 hours |
| Fix Development | Varies by severity |
| Bounty Payment | 14 days after fix |

## Past Findings

We believe in transparency. After vulnerabilities are patched, we publish:
- Anonymized summary of the finding
- Impact assessment
- Remediation applied
- Bounty paid

See [SECURITY_AUDIT_REPORT.md](../SECURITY_AUDIT_REPORT.md) for past findings.

## Acknowledgments

We thank all security researchers who help keep PIL secure. Notable contributors are recognized in our Security Hall of Fame (coming soon).

---

**Program Version**: 1.0
**Last Updated**: January 2026
**Effective Date**: Upon mainnet launch

*This program is subject to change. Check back regularly for updates.*
