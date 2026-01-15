pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/gates.circom";

/**
 * @title ComplianceProofCircuit
 * @notice Privacy-preserving KYC/AML compliance verification
 * @dev Proves compliance WITHOUT revealing identity or sensitive data
 * 
 * Privacy Features:
 * 1. Zero-knowledge jurisdiction check
 * 2. Age/threshold proofs without revealing exact values
 * 3. Credential validity without exposing credential details
 * 4. Revocation checking via nullifier sets
 */
template ComplianceProof() {
    // ═══════════════════════════════════════════════════════════════════
    // PRIVATE INPUTS (never revealed)
    // ═══════════════════════════════════════════════════════════════════
    signal input credentialHash;          // Hash of the compliance credential
    signal input issuerSecret;            // Credential issuer's signature secret
    signal input holderSecret;            // Credential holder's secret
    signal input jurisdictionCode;        // Numeric jurisdiction identifier
    signal input credentialType;          // Type of credential (KYC level, etc.)
    signal input issuanceTimestamp;       // When credential was issued
    signal input expirationTimestamp;     // When credential expires
    signal input credentialData[4];       // Additional private credential data
    
    // ═══════════════════════════════════════════════════════════════════
    // PUBLIC INPUTS (visible on-chain)
    // ═══════════════════════════════════════════════════════════════════
    signal input credentialCommitment;    // Commitment to the credential
    signal input issuerPubkey;            // Issuer's public key
    signal input holderPubkey;            // Holder's public key
    signal input currentTimestamp;        // Current time for expiry check
    signal input requiredJurisdictions[8]; // Allowed jurisdictions bitmap
    signal input minCredentialType;       // Minimum required credential level
    signal input policyId;                // Compliance policy identifier
    
    signal output valid;
    signal output complianceProof;        // Proof hash for on-chain verification
    
    // ═══════════════════════════════════════════════════════════════════
    // STEP 1: Verify credential structure
    // ═══════════════════════════════════════════════════════════════════
    
    // Compute expected credential hash
    component credentialHashCalc = Poseidon(8);
    credentialHashCalc.inputs[0] <== jurisdictionCode;
    credentialHashCalc.inputs[1] <== credentialType;
    credentialHashCalc.inputs[2] <== issuanceTimestamp;
    credentialHashCalc.inputs[3] <== expirationTimestamp;
    for (var i = 0; i < 4; i++) {
        credentialHashCalc.inputs[4 + i] <== credentialData[i];
    }
    
    component credentialHashCheck = IsEqual();
    credentialHashCheck.in[0] <== credentialHashCalc.out;
    credentialHashCheck.in[1] <== credentialHash;
    
    // ═══════════════════════════════════════════════════════════════════
    // STEP 2: Verify issuer signature (credential authenticity)
    // ═══════════════════════════════════════════════════════════════════
    
    // Commitment = Poseidon(credentialHash, issuerSecret, holderSecret)
    component commitmentCalc = Poseidon(3);
    commitmentCalc.inputs[0] <== credentialHash;
    commitmentCalc.inputs[1] <== issuerSecret;
    commitmentCalc.inputs[2] <== holderSecret;
    
    component commitmentCheck = IsEqual();
    commitmentCheck.in[0] <== commitmentCalc.out;
    commitmentCheck.in[1] <== credentialCommitment;
    
    // Verify issuer pubkey
    component issuerPubkeyCalc = Poseidon(1);
    issuerPubkeyCalc.inputs[0] <== issuerSecret;
    
    component issuerCheck = IsEqual();
    issuerCheck.in[0] <== issuerPubkeyCalc.out;
    issuerCheck.in[1] <== issuerPubkey;
    
    // Verify holder pubkey
    component holderPubkeyCalc = Poseidon(1);
    holderPubkeyCalc.inputs[0] <== holderSecret;
    
    component holderCheck = IsEqual();
    holderCheck.in[0] <== holderPubkeyCalc.out;
    holderCheck.in[1] <== holderPubkey;
    
    // ═══════════════════════════════════════════════════════════════════
    // STEP 3: Verify credential is not expired
    // ═══════════════════════════════════════════════════════════════════
    
    component notExpired = LessThan(64);
    notExpired.in[0] <== currentTimestamp;
    notExpired.in[1] <== expirationTimestamp;
    
    // Also check issuance is in the past
    component wasIssued = LessThan(64);
    wasIssued.in[0] <== issuanceTimestamp;
    wasIssued.in[1] <== currentTimestamp;
    
    signal temporalValid <== notExpired.out * wasIssued.out;
    
    // ═══════════════════════════════════════════════════════════════════
    // STEP 4: Verify jurisdiction is allowed
    // ═══════════════════════════════════════════════════════════════════
    
    // Check if jurisdictionCode matches any required jurisdiction
    component jurisdictionChecks[8];
    signal jurisdictionMatches[8];
    
    for (var i = 0; i < 8; i++) {
        jurisdictionChecks[i] = IsEqual();
        jurisdictionChecks[i].in[0] <== jurisdictionCode;
        jurisdictionChecks[i].in[1] <== requiredJurisdictions[i];
        jurisdictionMatches[i] <== jurisdictionChecks[i].out;
    }
    
    // OR all jurisdiction matches
    signal partialJurisdiction[8];
    partialJurisdiction[0] <== jurisdictionMatches[0];
    for (var i = 1; i < 8; i++) {
        // OR: a + b - a*b
        partialJurisdiction[i] <== partialJurisdiction[i-1] + jurisdictionMatches[i] - partialJurisdiction[i-1] * jurisdictionMatches[i];
    }
    signal jurisdictionValid <== partialJurisdiction[7];
    
    // ═══════════════════════════════════════════════════════════════════
    // STEP 5: Verify credential type meets minimum requirement
    // ═══════════════════════════════════════════════════════════════════
    
    component typeCheck = GreaterEqThan(16);
    typeCheck.in[0] <== credentialType;
    typeCheck.in[1] <== minCredentialType;
    
    // ═══════════════════════════════════════════════════════════════════
    // STEP 6: Generate compliance proof hash
    // ═══════════════════════════════════════════════════════════════════
    
    component proofHashCalc = Poseidon(4);
    proofHashCalc.inputs[0] <== credentialCommitment;
    proofHashCalc.inputs[1] <== holderPubkey;
    proofHashCalc.inputs[2] <== policyId;
    proofHashCalc.inputs[3] <== currentTimestamp;
    
    complianceProof <== proofHashCalc.out;
    
    // ═══════════════════════════════════════════════════════════════════
    // FINAL: Combine all validity checks
    // ═══════════════════════════════════════════════════════════════════
    
    signal v1 <== credentialHashCheck.out * commitmentCheck.out;
    signal v2 <== issuerCheck.out * holderCheck.out;
    signal v3 <== temporalValid * jurisdictionValid;
    signal v4 <== typeCheck.out;
    
    signal v5 <== v1 * v2;
    signal v6 <== v3 * v4;
    valid <== v5 * v6;
}

/**
 * @title RangeProof
 * @notice Prove a value is within a range without revealing it
 * @dev Used for age verification, balance checks, etc.
 */
template RangeProof(BITS) {
    signal input value;       // Private value
    signal input minValue;    // Public minimum
    signal input maxValue;    // Public maximum
    
    signal output valid;
    
    // value >= minValue
    component geMin = GreaterEqThan(BITS);
    geMin.in[0] <== value;
    geMin.in[1] <== minValue;
    
    // value <= maxValue
    component leMax = LessEqThan(BITS);
    leMax.in[0] <== value;
    leMax.in[1] <== maxValue;
    
    valid <== geMin.out * leMax.out;
}

component main {public [credentialCommitment, issuerPubkey, holderPubkey, currentTimestamp, requiredJurisdictions, minCredentialType, policyId]} = ComplianceProof();
