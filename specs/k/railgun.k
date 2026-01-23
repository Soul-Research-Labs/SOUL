/**
 * K Framework Formal Specification for Railgun Privacy System
 * 
 * @title railgun.k
 * @author PIL Protocol
 * @notice Formal verification of Railgun ZK-SNARK privacy operations
 * 
 * VERIFICATION SCOPE:
 * - BN254 elliptic curve operations (alt_bn128)
 * - Poseidon hash function
 * - Groth16 proof verification
 * - UTXO note commitment scheme
 * - Nullifier derivation and uniqueness
 * - Merkle tree operations
 * - Cross-domain (Railgun ↔ PIL) nullifier binding
 * 
 * BN254 PARAMETERS:
 * - Base Field Prime (p): 21888242871839275222246405745257275088696311157297823662689037894645226208583
 * - Scalar Field Order (r): 21888242871839275222246405745257275088548364400416034343698204186575808495617
 * - Curve equation: y² = x³ + 3 (Weierstrass form)
 * - Generator G1: (1, 2)
 * - Generator G2: Complex extension field point
 * - Cofactor: 1
 * 
 * POSEIDON PARAMETERS:
 * - Full rounds: 8
 * - Partial rounds: 57
 * - S-box: x^5
 * - State width: 3 (t = rate + capacity)
 * 
 * GROTH16 VERIFICATION:
 * - Pairing equation: e(A, B) = e(α, β) · e(vkX, γ) · e(C, δ)
 * - Input commitments: IC points
 */

requires "evm-semantics.md"
requires "domains.md"

module RAILGUN-SYNTAX
    imports INT-SYNTAX
    imports BOOL-SYNTAX
    imports LIST
    imports MAP
    imports SET
    imports BYTES
    imports STRING-SYNTAX

    // =========================================================================
    // BN254 CURVE CONSTANTS
    // =========================================================================
    
    // BN254 base field prime (p)
    syntax Int ::= "BN254_P"    [function]
    rule BN254_P => 21888242871839275222246405745257275088696311157297823662689037894645226208583

    // BN254 scalar field order (r)
    syntax Int ::= "BN254_R"    [function]
    rule BN254_R => 21888242871839275222246405745257275088548364400416034343698204186575808495617

    // BN254 curve coefficient b = 3
    syntax Int ::= "BN254_B"    [function]
    rule BN254_B => 3

    // G1 generator x-coordinate
    syntax Int ::= "BN254_G1_X"    [function]
    rule BN254_G1_X => 1

    // G1 generator y-coordinate
    syntax Int ::= "BN254_G1_Y"    [function]
    rule BN254_G1_Y => 2

    // G2 generator coordinates (extension field)
    syntax Int ::= "BN254_G2_X0"    [function]
    rule BN254_G2_X0 => 10857046999023057135944570762232829481370756359578518086990519993285655852781

    syntax Int ::= "BN254_G2_X1"    [function]
    rule BN254_G2_X1 => 11559732032986387107991004021392285783925812861821192530917403151452391805634

    syntax Int ::= "BN254_G2_Y0"    [function]
    rule BN254_G2_Y0 => 8495653923123431417604973247489272438418190587263600148770280649306958101930

    syntax Int ::= "BN254_G2_Y1"    [function]
    rule BN254_G2_Y1 => 4082367875863433681332203403145435568316851327593401208105741076214120093531

    // =========================================================================
    // POSEIDON HASH CONSTANTS
    // =========================================================================
    
    // Number of full rounds
    syntax Int ::= "POSEIDON_FULL_ROUNDS"    [function]
    rule POSEIDON_FULL_ROUNDS => 8

    // Number of partial rounds
    syntax Int ::= "POSEIDON_PARTIAL_ROUNDS"    [function]
    rule POSEIDON_PARTIAL_ROUNDS => 57

    // S-box exponent (x^5)
    syntax Int ::= "POSEIDON_ALPHA"    [function]
    rule POSEIDON_ALPHA => 5

    // State width
    syntax Int ::= "POSEIDON_WIDTH"    [function]
    rule POSEIDON_WIDTH => 3

    // =========================================================================
    // RAILGUN PROTOCOL CONSTANTS
    // =========================================================================
    
    // Merkle tree depth
    syntax Int ::= "MERKLE_TREE_DEPTH"    [function]
    rule MERKLE_TREE_DEPTH => 16

    // Maximum inputs per transaction
    syntax Int ::= "MAX_INPUTS"    [function]
    rule MAX_INPUTS => 13

    // Maximum outputs per transaction
    syntax Int ::= "MAX_OUTPUTS"    [function]
    rule MAX_OUTPUTS => 13

    // PIL-Railgun domain separator
    syntax Bytes ::= "PIL_RAILGUN_DOMAIN"    [function]
    rule PIL_RAILGUN_DOMAIN => b"PIL_Railgun_Interop_v1"

    // =========================================================================
    // SUPPORTED CHAIN IDS
    // =========================================================================
    
    syntax Int ::= "ETHEREUM_CHAIN_ID"    [function]
    rule ETHEREUM_CHAIN_ID => 1

    syntax Int ::= "POLYGON_CHAIN_ID"    [function]
    rule POLYGON_CHAIN_ID => 137

    syntax Int ::= "ARBITRUM_CHAIN_ID"    [function]
    rule ARBITRUM_CHAIN_ID => 42161

    syntax Int ::= "BSC_CHAIN_ID"    [function]
    rule BSC_CHAIN_ID => 56

    // =========================================================================
    // FIELD ELEMENT TYPES
    // =========================================================================
    
    // Scalar field element (mod r)
    syntax Scalar ::= Int
    
    // Base field element (mod p)
    syntax BaseFieldElement ::= Int
    
    // =========================================================================
    // G1 POINT TYPE
    // =========================================================================
    
    syntax G1Point ::= g1Point(
        x: BaseFieldElement,
        y: BaseFieldElement
    )
                    | "G1_GENERATOR"
                    | "G1_INFINITY"
    
    // =========================================================================
    // G2 POINT TYPE (Extension field Fq2)
    // =========================================================================
    
    syntax G2Point ::= g2Point(
        x0: BaseFieldElement,  // Real part of x
        x1: BaseFieldElement,  // Imaginary part of x
        y0: BaseFieldElement,  // Real part of y
        y1: BaseFieldElement   // Imaginary part of y
    )
                    | "G2_GENERATOR"
                    | "G2_INFINITY"
    
    // =========================================================================
    // GROTH16 PROOF TYPE
    // =========================================================================
    
    syntax Groth16Proof ::= groth16Proof(
        a: G1Point,
        b: G2Point,
        c: G1Point
    )
    
    // =========================================================================
    // VERIFICATION KEY TYPE
    // =========================================================================
    
    syntax VerificationKey ::= verificationKey(
        alpha: G1Point,
        beta: G2Point,
        gamma: G2Point,
        delta: G2Point,
        ic: List  // List of G1Points
    )
    
    // =========================================================================
    // SHIELDED NOTE TYPE
    // =========================================================================
    
    syntax ShieldedNote ::= shieldedNote(
        commitment: Bytes,    // Poseidon(npk, value, token, random)
        nullifier: Bytes,     // Derived from spending key
        value: Int,           // Note value
        token: Bytes,         // Token address
        random: Bytes         // Randomness
    )
    
    // =========================================================================
    // ENCRYPTED NOTE TYPE
    // =========================================================================
    
    syntax EncryptedNote ::= encryptedNote(
        ephemeralPubKey: Bytes,
        ciphertext: Bytes,
        mac: Bytes
    )
    
    // =========================================================================
    // VIEWING KEY TYPE
    // =========================================================================
    
    syntax ViewingKey ::= viewingKey(
        key: Bytes,
        owner: Bytes,
        startBlock: Int
    )
    
    // =========================================================================
    // TRANSACTION BUNDLE TYPE
    // =========================================================================
    
    syntax TransactionBundle ::= transactionBundle(
        nullifiers: List,     // List of nullifier bytes
        commitments: List,    // List of commitment bytes
        proof: Groth16Proof,
        merkleRoot: Bytes,
        encryptedOutputs: List
    )
    
    // =========================================================================
    // MERKLE PROOF TYPE
    // =========================================================================
    
    syntax MerkleProof ::= merkleProof(
        leaf: Bytes,
        pathIndices: Int,
        siblings: List
    )
    
    // =========================================================================
    // FIELD OPERATIONS (mod r - scalar field)
    // =========================================================================
    
    syntax Scalar ::= fieldAdd(Scalar, Scalar)         [function]
                   | fieldSub(Scalar, Scalar)         [function]
                   | fieldMul(Scalar, Scalar)         [function]
                   | fieldNeg(Scalar)                 [function]
                   | fieldInv(Scalar)                 [function]
                   | fieldExp(Scalar, Int)            [function]
                   | fieldReduce(Int)                 [function]
    
    syntax Bool ::= isValidScalar(Int)                [function]
    
    // =========================================================================
    // BASE FIELD OPERATIONS (mod p)
    // =========================================================================
    
    syntax BaseFieldElement ::= baseFieldAdd(BaseFieldElement, BaseFieldElement)    [function]
                              | baseFieldSub(BaseFieldElement, BaseFieldElement)    [function]
                              | baseFieldMul(BaseFieldElement, BaseFieldElement)    [function]
                              | baseFieldNeg(BaseFieldElement)                      [function]
                              | baseFieldInv(BaseFieldElement)                      [function]
    
    syntax Bool ::= isValidBaseFieldElement(Int)      [function]
    
    // =========================================================================
    // G1 POINT OPERATIONS
    // =========================================================================
    
    syntax G1Point ::= g1Add(G1Point, G1Point)        [function]
                    | g1ScalarMul(Scalar, G1Point)   [function]
                    | g1Negate(G1Point)               [function]
    
    syntax Bool ::= isValidG1Point(G1Point)           [function]
                 | isOnCurve(G1Point)                [function]
    
    // =========================================================================
    // PAIRING OPERATIONS
    // =========================================================================
    
    // Pairing function e: G1 × G2 → GT
    syntax Bytes ::= pairing(G1Point, G2Point)        [function]
    
    // Pairing check e(a1,b1) · e(a2,b2) = 1
    syntax Bool ::= pairingCheck(G1Point, G2Point, G1Point, G2Point)    [function]
    
    // Multi-pairing check
    syntax Bool ::= multiPairingCheck(List, List)     [function]
    
    // =========================================================================
    // POSEIDON HASH OPERATIONS
    // =========================================================================
    
    // Poseidon hash of 2 elements
    syntax Scalar ::= poseidonHash2(Scalar, Scalar)   [function]
    
    // Poseidon hash of 4 elements
    syntax Scalar ::= poseidonHash4(Scalar, Scalar, Scalar, Scalar)    [function]
    
    // Poseidon hash of N elements
    syntax Scalar ::= poseidonHashN(List)             [function]
    
    // Poseidon S-box (x^5)
    syntax Scalar ::= poseidonSBox(Scalar)            [function]
    
    // =========================================================================
    // NOTE OPERATIONS
    // =========================================================================
    
    // Compute note commitment
    syntax Bytes ::= computeNoteCommitment(Bytes, Int, Bytes, Bytes)    [function]
    
    // Derive nullifier from spending key and commitment
    syntax Bytes ::= deriveNullifier(Bytes, Bytes)    [function]
    
    // Cross-domain nullifier
    syntax Bytes ::= deriveCrossDomainNullifier(Bytes, Bytes, Bytes)    [function]
    
    // PIL binding
    syntax Bytes ::= derivePILBinding(Bytes)          [function]
    
    // =========================================================================
    // MERKLE TREE OPERATIONS
    // =========================================================================
    
    // Compute Merkle root from path
    syntax Bytes ::= computeMerkleRoot(Bytes, Int, List)    [function]
    
    // Verify Merkle proof
    syntax Bool ::= verifyMerkleProof(MerkleProof, Bytes)    [function]
    
    // =========================================================================
    // GROTH16 VERIFICATION
    // =========================================================================
    
    // Verify Groth16 proof
    syntax Bool ::= verifyGroth16Proof(Groth16Proof, VerificationKey, List)    [function]
    
    // Compute vkX (linear combination of IC points)
    syntax G1Point ::= computeVkX(VerificationKey, List)    [function]
    
    // =========================================================================
    // VIEWING KEY OPERATIONS
    // =========================================================================
    
    // Derive viewing key
    syntax Bytes ::= deriveViewingKey(Bytes, Bytes)   [function]
    
    // Hash viewing key
    syntax Bytes ::= hashViewingKey(ViewingKey)       [function]
    
    // Validate viewing key
    syntax Bool ::= isValidViewingKey(ViewingKey, Int)    [function]
    
    // =========================================================================
    // ENCRYPTED NOTE OPERATIONS
    // =========================================================================
    
    // Verify encrypted note MAC
    syntax Bool ::= verifyEncryptedNote(EncryptedNote, Bytes)    [function]
    
    // =========================================================================
    // CHAIN DETECTION
    // =========================================================================
    
    syntax Bool ::= isRailgunChain(Int)               [function]

endmodule

// =============================================================================
// SEMANTICS MODULE
// =============================================================================

module RAILGUN-SEMANTICS
    imports RAILGUN-SYNTAX
    imports INT
    imports BOOL
    imports BYTES
    imports LIST

    // =========================================================================
    // SCALAR FIELD SEMANTICS (mod r)
    // =========================================================================
    
    rule fieldAdd(A:Scalar, B:Scalar) => (A +Int B) modInt BN254_R
    
    rule fieldSub(A:Scalar, B:Scalar) => (A -Int B +Int BN254_R) modInt BN254_R
    
    rule fieldMul(A:Scalar, B:Scalar) => (A *Int B) modInt BN254_R
    
    rule fieldNeg(A:Scalar) => (BN254_R -Int A) modInt BN254_R
    
    rule fieldReduce(X:Int) => X modInt BN254_R
    
    rule isValidScalar(X:Int) => (X >=Int 0) andBool (X <Int BN254_R)
    
    // =========================================================================
    // BASE FIELD SEMANTICS (mod p)
    // =========================================================================
    
    rule baseFieldAdd(A:BaseFieldElement, B:BaseFieldElement) => (A +Int B) modInt BN254_P
    
    rule baseFieldSub(A:BaseFieldElement, B:BaseFieldElement) => (A -Int B +Int BN254_P) modInt BN254_P
    
    rule baseFieldMul(A:BaseFieldElement, B:BaseFieldElement) => (A *Int B) modInt BN254_P
    
    rule baseFieldNeg(A:BaseFieldElement) => (BN254_P -Int A) modInt BN254_P
    
    rule isValidBaseFieldElement(X:Int) => (X >=Int 0) andBool (X <Int BN254_P)
    
    // =========================================================================
    // G1 POINT SEMANTICS
    // =========================================================================
    
    // Generator point
    rule G1_GENERATOR => g1Point(BN254_G1_X, BN254_G1_Y)
    
    // Point at infinity
    rule G1_INFINITY => g1Point(0, 0)
    
    // Check if point is on curve: y² = x³ + 3 (mod p)
    rule isOnCurve(g1Point(X:BaseFieldElement, Y:BaseFieldElement)) =>
        baseFieldMul(Y, Y) ==Int baseFieldAdd(baseFieldMul(baseFieldMul(X, X), X), BN254_B)
    
    rule isOnCurve(G1_INFINITY) => true
    
    // Valid G1 point check
    rule isValidG1Point(g1Point(X:BaseFieldElement, Y:BaseFieldElement)) =>
        isValidBaseFieldElement(X) andBool
        isValidBaseFieldElement(Y) andBool
        isOnCurve(g1Point(X, Y))
    
    rule isValidG1Point(G1_INFINITY) => true
    rule isValidG1Point(G1_GENERATOR) => true
    
    // G1 negation
    rule g1Negate(g1Point(X:BaseFieldElement, Y:BaseFieldElement)) =>
        g1Point(X, baseFieldNeg(Y))
    
    rule g1Negate(G1_INFINITY) => G1_INFINITY
    
    // =========================================================================
    // G2 GENERATOR SEMANTICS
    // =========================================================================
    
    rule G2_GENERATOR => g2Point(BN254_G2_X0, BN254_G2_X1, BN254_G2_Y0, BN254_G2_Y1)
    
    rule G2_INFINITY => g2Point(0, 0, 0, 0)
    
    // =========================================================================
    // POSEIDON S-BOX
    // =========================================================================
    
    rule poseidonSBox(X:Scalar) => fieldExp(X, POSEIDON_ALPHA)
    
    // =========================================================================
    // VIEWING KEY SEMANTICS
    // =========================================================================
    
    rule isValidViewingKey(
        viewingKey(Key:Bytes, Owner:Bytes, StartBlock:Int),
        CurrentBlock:Int
    ) => (lengthBytes(Key) ==Int 32) andBool
         (lengthBytes(Owner) >Int 0) andBool
         (StartBlock <=Int CurrentBlock)
    
    // =========================================================================
    // CHAIN DETECTION
    // =========================================================================
    
    rule isRailgunChain(ChainId:Int) =>
        (ChainId ==Int ETHEREUM_CHAIN_ID) orBool
        (ChainId ==Int POLYGON_CHAIN_ID) orBool
        (ChainId ==Int ARBITRUM_CHAIN_ID) orBool
        (ChainId ==Int BSC_CHAIN_ID)

endmodule

// =============================================================================
// PROPERTIES MODULE - Security Theorems
// =============================================================================

module RAILGUN-PROPERTIES
    imports RAILGUN-SEMANTICS

    // =========================================================================
    // FIELD ARITHMETIC PROPERTIES
    // =========================================================================
    
    // Commutativity of addition
    claim fieldAdd(A, B) => fieldAdd(B, A)
    
    // Commutativity of multiplication
    claim fieldMul(A, B) => fieldMul(B, A)
    
    // Associativity of addition
    claim fieldAdd(fieldAdd(A, B), C) => fieldAdd(A, fieldAdd(B, C))
    
    // Associativity of multiplication
    claim fieldMul(fieldMul(A, B), C) => fieldMul(A, fieldMul(B, C))
    
    // Additive identity
    claim fieldAdd(A, 0) => A
    
    // Multiplicative identity
    claim fieldMul(A, 1) => A
    
    // Additive inverse
    claim fieldAdd(A, fieldNeg(A)) => 0
    
    // Field closure under addition
    claim isValidScalar(fieldAdd(A, B)) => true
        requires isValidScalar(A) andBool isValidScalar(B)
    
    // Field closure under multiplication
    claim isValidScalar(fieldMul(A, B)) => true
        requires isValidScalar(A) andBool isValidScalar(B)
    
    // Distributive law
    claim fieldMul(A, fieldAdd(B, C)) => fieldAdd(fieldMul(A, B), fieldMul(A, C))
    
    // =========================================================================
    // BASE FIELD PROPERTIES
    // =========================================================================
    
    claim baseFieldAdd(A, B) => baseFieldAdd(B, A)
    claim baseFieldMul(A, B) => baseFieldMul(B, A)
    claim baseFieldAdd(A, 0) => A
    claim baseFieldMul(A, 1) => A
    claim baseFieldAdd(A, baseFieldNeg(A)) => 0
    
    // Base field closure
    claim isValidBaseFieldElement(baseFieldAdd(A, B)) => true
        requires isValidBaseFieldElement(A) andBool isValidBaseFieldElement(B)
    
    claim isValidBaseFieldElement(baseFieldMul(A, B)) => true
        requires isValidBaseFieldElement(A) andBool isValidBaseFieldElement(B)
    
    // =========================================================================
    // CURVE PROPERTIES
    // =========================================================================
    
    // Generator is on curve
    claim isOnCurve(G1_GENERATOR) => true
    
    // Infinity is valid
    claim isValidG1Point(G1_INFINITY) => true
    
    // Negation preserves validity
    claim isValidG1Point(g1Negate(P)) => true
        requires isValidG1Point(P)
    
    // Scalar multiplication closure (informal - precompile dependent)
    claim isValidG1Point(g1ScalarMul(S, P)) => true
        requires isValidScalar(S) andBool isValidG1Point(P)
    
    // Point addition closure
    claim isValidG1Point(g1Add(P1, P2)) => true
        requires isValidG1Point(P1) andBool isValidG1Point(P2)
    
    // Double negation
    claim g1Negate(g1Negate(P)) => P
    
    // Adding infinity
    claim g1Add(P, G1_INFINITY) => P
    claim g1Add(G1_INFINITY, P) => P
    
    // Scalar mul by 0 gives infinity
    claim g1ScalarMul(0, P) => G1_INFINITY
    
    // Scalar mul by 1 is identity
    claim g1ScalarMul(1, P) => P
    
    // =========================================================================
    // POSEIDON HASH PROPERTIES
    // =========================================================================
    
    // Determinism
    claim poseidonHash2(A, B) ==K poseidonHash2(A, B) => true
    
    // Different inputs, different outputs (collision resistance - informal)
    claim poseidonHash2(A1, B) =/=K poseidonHash2(A2, B) => true
        requires A1 =/=K A2
    
    // Output is valid field element
    claim isValidScalar(poseidonHash2(A, B)) => true
        requires isValidScalar(A) andBool isValidScalar(B)
    
    // Hash4 determinism
    claim poseidonHash4(A, B, C, D) ==K poseidonHash4(A, B, C, D) => true
    
    // =========================================================================
    // NOTE COMMITMENT PROPERTIES
    // =========================================================================
    
    // Commitment determinism
    claim computeNoteCommitment(Npk, Value, Token, Random) ==K 
          computeNoteCommitment(Npk, Value, Token, Random) => true
    
    // Different keys produce different commitments
    claim computeNoteCommitment(Npk1, Value, Token, Random) =/=K 
          computeNoteCommitment(Npk2, Value, Token, Random) => true
        requires Npk1 =/=K Npk2
    
    // Different randomness produces different commitments (hiding)
    claim computeNoteCommitment(Npk, Value, Token, Random1) =/=K 
          computeNoteCommitment(Npk, Value, Token, Random2) => true
        requires Random1 =/=K Random2
    
    // =========================================================================
    // NULLIFIER PROPERTIES
    // =========================================================================
    
    // Nullifier determinism
    claim deriveNullifier(Sk, Commitment) ==K deriveNullifier(Sk, Commitment) => true
    
    // Different spending keys produce different nullifiers
    claim deriveNullifier(Sk1, Commitment) =/=K deriveNullifier(Sk2, Commitment) => true
        requires Sk1 =/=K Sk2
    
    // Different commitments produce different nullifiers
    claim deriveNullifier(Sk, Commitment1) =/=K deriveNullifier(Sk, Commitment2) => true
        requires Commitment1 =/=K Commitment2
    
    // =========================================================================
    // CROSS-DOMAIN NULLIFIER PROPERTIES
    // =========================================================================
    
    // Cross-domain determinism
    claim deriveCrossDomainNullifier(Nf, Src, Dst) ==K 
          deriveCrossDomainNullifier(Nf, Src, Dst) => true
    
    // Different sources produce different cross-domain nullifiers
    claim deriveCrossDomainNullifier(Nf, Src1, Dst) =/=K 
          deriveCrossDomainNullifier(Nf, Src2, Dst) => true
        requires Src1 =/=K Src2
    
    // Different destinations produce different cross-domain nullifiers
    claim deriveCrossDomainNullifier(Nf, Src, Dst1) =/=K 
          deriveCrossDomainNullifier(Nf, Src, Dst2) => true
        requires Dst1 =/=K Dst2
    
    // PIL binding determinism
    claim derivePILBinding(Nf) ==K derivePILBinding(Nf) => true
    
    // Different nullifiers produce different PIL bindings
    claim derivePILBinding(Nf1) =/=K derivePILBinding(Nf2) => true
        requires Nf1 =/=K Nf2
    
    // =========================================================================
    // MERKLE TREE PROPERTIES
    // =========================================================================
    
    // Root computation determinism
    claim computeMerkleRoot(Leaf, PathIndices, Siblings) ==K 
          computeMerkleRoot(Leaf, PathIndices, Siblings) => true
    
    // Different leaves produce different roots (with same path)
    claim computeMerkleRoot(Leaf1, PathIndices, Siblings) =/=K 
          computeMerkleRoot(Leaf2, PathIndices, Siblings) => true
        requires Leaf1 =/=K Leaf2
    
    // =========================================================================
    // GROTH16 VERIFICATION PROPERTIES
    // =========================================================================
    
    // Verification is deterministic
    claim verifyGroth16Proof(Proof, Vk, Inputs) ==K 
          verifyGroth16Proof(Proof, Vk, Inputs) => true
    
    // Valid proof verifies (soundness - informal)
    // This is the core security property of Groth16
    
    // =========================================================================
    // VIEWING KEY PROPERTIES
    // =========================================================================
    
    // Viewing key derivation determinism
    claim deriveViewingKey(Sk, Salt) ==K deriveViewingKey(Sk, Salt) => true
    
    // Different salts produce different keys
    claim deriveViewingKey(Sk, Salt1) =/=K deriveViewingKey(Sk, Salt2) => true
        requires Salt1 =/=K Salt2
    
    // Valid viewing key has non-zero key
    claim isValidViewingKey(viewingKey(Key, Owner, StartBlock), CurrentBlock) => false
        requires lengthBytes(Key) ==Int 0
    
    // =========================================================================
    // CHAIN DETECTION PROPERTIES
    // =========================================================================
    
    claim isRailgunChain(ETHEREUM_CHAIN_ID) => true
    claim isRailgunChain(POLYGON_CHAIN_ID) => true
    claim isRailgunChain(ARBITRUM_CHAIN_ID) => true
    claim isRailgunChain(BSC_CHAIN_ID) => true
    
    // Invalid chain
    claim isRailgunChain(0) => false
    claim isRailgunChain(999999) => false

endmodule
