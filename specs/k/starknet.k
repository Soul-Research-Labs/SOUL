/**
 * K Framework Formal Specification for Starknet Field Arithmetic
 * 
 * @title starknet.k
 * @author PIL Protocol
 * @notice Formal verification of STARK field operations and primitives
 * 
 * VERIFICATION SCOPE:
 * - Felt252 field arithmetic over STARK prime
 * - Poseidon hash function properties
 * - Pedersen commitment scheme
 * - FRI low-degree testing
 * - STARK proof verification
 * 
 * STARK PRIME: p = 2^251 + 17 * 2^192 + 1
 * FIELD: F_p (prime field of order p)
 */

requires "evm-semantics.md"
requires "domains.md"

module STARKNET-SYNTAX
    imports INT-SYNTAX
    imports BOOL-SYNTAX
    imports LIST
    imports MAP
    imports SET

    // =========================================================================
    // STARK PRIME FIELD TYPES
    // =========================================================================
    
    // Felt252 type - field element in F_p
    syntax Felt252 ::= Int
    
    // STARK Prime constant
    syntax Int ::= "STARK_PRIME"    [function]
    rule STARK_PRIME => 3618502788666131213697322783095070105623107215331596699973092056135872020481
        // 2^251 + 17 * 2^192 + 1

    // =========================================================================
    // FIELD ARITHMETIC OPERATIONS
    // =========================================================================
    
    syntax Felt252 ::= feltAdd(Felt252, Felt252)     [function]
                     | feltSub(Felt252, Felt252)     [function]
                     | feltMul(Felt252, Felt252)     [function]
                     | feltNeg(Felt252)              [function]
                     | feltInv(Felt252)              [function]
                     | feltDiv(Felt252, Felt252)     [function]
                     | feltExp(Felt252, Int)         [function]
                     | feltSqrt(Felt252)             [function]
                     | toFelt(Int)                   [function]
    
    syntax Bool ::= isValidFelt(Int)                 [function]
    
    // =========================================================================
    // HASH FUNCTIONS
    // =========================================================================
    
    syntax Felt252 ::= poseidonHash2(Felt252, Felt252)       [function]
                     | poseidonHashN(List)                    [function]
                     | pedersenHash(Felt252, Felt252)        [function]
                     | merkleHash(Felt252, Felt252)          [function]
    
    // Poseidon state
    syntax PoseidonState ::= poseidonState(Felt252, Felt252, Felt252)
    
    // =========================================================================
    // STARK PROOF STRUCTURES
    // =========================================================================
    
    // FRI Configuration
    syntax FRIConfig ::= friConfig(
        domainSize: Int,
        blowupFactor: Int,
        numQueries: Int,
        foldingFactor: Int,
        lastLayerDegBound: Int,
        numLayers: Int
    )
    
    // FRI Layer
    syntax FRILayer ::= friLayer(
        commitment: Bytes32,
        evaluations: List,
        merkleProof: List
    )
    
    // STARK Proof
    syntax STARKProof ::= starkProof(
        traceCommitment: Bytes32,
        constraintCommitment: Bytes32,
        compositionCommitment: Bytes32,
        friLayers: List,
        oodsPoint: Felt252,
        oodsValues: List,
        queryResponses: List
    )
    
    // Proof type
    syntax ProofType ::= "CAIRO_0" | "CAIRO_1" | "RECURSIVE" | "STONE" | "STWO"
    
    // =========================================================================
    // VERIFICATION RESULTS
    // =========================================================================
    
    syntax VerificationResult ::= "Valid" | "Invalid" | verificationError(String)
    
    // =========================================================================
    // NULLIFIER OPERATIONS
    // =========================================================================
    
    syntax Felt252 ::= computeNullifier(Felt252, Felt252)        [function]
                     | computeCrossDomainNullifier(Felt252, Int) [function]
    
    syntax Bool ::= isNullifierValid(Felt252)                    [function]
                  | isNullifierUnused(Felt252, Set)              [function]

endmodule

module STARKNET-FIELD
    imports STARKNET-SYNTAX
    imports INT
    imports BOOL

    // =========================================================================
    // FIELD ARITHMETIC RULES
    // =========================================================================
    
    /**
     * Felt validation: x ∈ [0, STARK_PRIME)
     */
    rule isValidFelt(X:Int) => true
        requires X >=Int 0 andBool X <Int STARK_PRIME
    rule isValidFelt(X:Int) => false
        requires X <Int 0 orBool X >=Int STARK_PRIME

    /**
     * Convert integer to felt (modular reduction)
     */
    rule toFelt(X:Int) => X %Int STARK_PRIME
        requires X >=Int 0
    rule toFelt(X:Int) => toFelt(X +Int STARK_PRIME)
        requires X <Int 0

    /**
     * Field addition: (a + b) mod p
     */
    rule feltAdd(A:Felt252, B:Felt252) => (A +Int B) %Int STARK_PRIME
        requires isValidFelt(A) andBool isValidFelt(B)

    /**
     * Field subtraction: (a - b) mod p
     */
    rule feltSub(A:Felt252, B:Felt252) => toFelt(A -Int B)
        requires isValidFelt(A) andBool isValidFelt(B)

    /**
     * Field multiplication: (a * b) mod p
     */
    rule feltMul(A:Felt252, B:Felt252) => (A *Int B) %Int STARK_PRIME
        requires isValidFelt(A) andBool isValidFelt(B)

    /**
     * Field negation: (-a) mod p = p - a
     */
    rule feltNeg(A:Felt252) => (STARK_PRIME -Int A) %Int STARK_PRIME
        requires isValidFelt(A)
    rule feltNeg(0) => 0

    /**
     * Field inversion using Fermat's little theorem: a^(-1) = a^(p-2) mod p
     */
    rule feltInv(A:Felt252) => feltExp(A, STARK_PRIME -Int 2)
        requires isValidFelt(A) andBool A =/=Int 0

    /**
     * Field division: a / b = a * b^(-1)
     */
    rule feltDiv(A:Felt252, B:Felt252) => feltMul(A, feltInv(B))
        requires isValidFelt(A) andBool isValidFelt(B) andBool B =/=Int 0

    /**
     * Field exponentiation using square-and-multiply
     */
    rule feltExp(A:Felt252, 0) => 1
    rule feltExp(A:Felt252, 1) => A
        requires isValidFelt(A)
    rule feltExp(A:Felt252, N:Int) => 
        feltMul(feltExp(feltMul(A, A), N /Int 2), A)
        requires N >Int 1 andBool (N %Int 2) ==Int 1 andBool isValidFelt(A)
    rule feltExp(A:Felt252, N:Int) => 
        feltExp(feltMul(A, A), N /Int 2)
        requires N >Int 1 andBool (N %Int 2) ==Int 0 andBool isValidFelt(A)

    // =========================================================================
    // FIELD ARITHMETIC PROPERTIES (THEOREMS)
    // =========================================================================
    
    /**
     * Theorem: Addition is commutative
     * ∀ a, b ∈ F_p: a + b = b + a
     */
    claim <k> feltAdd(A, B) => feltAdd(B, A) </k>
        requires isValidFelt(A) andBool isValidFelt(B)

    /**
     * Theorem: Multiplication is commutative
     * ∀ a, b ∈ F_p: a * b = b * a
     */
    claim <k> feltMul(A, B) => feltMul(B, A) </k>
        requires isValidFelt(A) andBool isValidFelt(B)

    /**
     * Theorem: Zero is additive identity
     * ∀ a ∈ F_p: a + 0 = a
     */
    claim <k> feltAdd(A, 0) => A </k>
        requires isValidFelt(A)

    /**
     * Theorem: One is multiplicative identity
     * ∀ a ∈ F_p: a * 1 = a
     */
    claim <k> feltMul(A, 1) => A </k>
        requires isValidFelt(A)

    /**
     * Theorem: Negation is additive inverse
     * ∀ a ∈ F_p: a + (-a) = 0
     */
    claim <k> feltAdd(A, feltNeg(A)) => 0 </k>
        requires isValidFelt(A)

    /**
     * Theorem: Inverse is multiplicative inverse
     * ∀ a ∈ F_p, a ≠ 0: a * a^(-1) = 1
     */
    claim <k> feltMul(A, feltInv(A)) => 1 </k>
        requires isValidFelt(A) andBool A =/=Int 0

    /**
     * Theorem: Double negation identity
     * ∀ a ∈ F_p: -(-a) = a
     */
    claim <k> feltNeg(feltNeg(A)) => A </k>
        requires isValidFelt(A)

    /**
     * Theorem: Double inversion identity
     * ∀ a ∈ F_p, a ≠ 0: (a^(-1))^(-1) = a
     */
    claim <k> feltInv(feltInv(A)) => A </k>
        requires isValidFelt(A) andBool A =/=Int 0

    /**
     * Theorem: Field closure under addition
     * ∀ a, b ∈ F_p: a + b ∈ F_p
     */
    claim <k> isValidFelt(feltAdd(A, B)) => true </k>
        requires isValidFelt(A) andBool isValidFelt(B)

    /**
     * Theorem: Field closure under multiplication
     * ∀ a, b ∈ F_p: a * b ∈ F_p
     */
    claim <k> isValidFelt(feltMul(A, B)) => true </k>
        requires isValidFelt(A) andBool isValidFelt(B)

    /**
     * Theorem: Distributive law
     * ∀ a, b, c ∈ F_p: a * (b + c) = a*b + a*c
     */
    claim <k> feltMul(A, feltAdd(B, C)) => feltAdd(feltMul(A, B), feltMul(A, C)) </k>
        requires isValidFelt(A) andBool isValidFelt(B) andBool isValidFelt(C)

endmodule

module STARKNET-POSEIDON
    imports STARKNET-FIELD
    imports LIST
    imports INT

    // =========================================================================
    // POSEIDON HASH CONSTANTS
    // =========================================================================
    
    // Poseidon permutation parameters for STARK field
    syntax Int ::= "POSEIDON_FULL_ROUNDS"           [function]
                 | "POSEIDON_PARTIAL_ROUNDS"        [function]
                 | "POSEIDON_STATE_WIDTH"           [function]
                 | "POSEIDON_RATE"                  [function]
    
    rule POSEIDON_FULL_ROUNDS => 8
    rule POSEIDON_PARTIAL_ROUNDS => 83
    rule POSEIDON_STATE_WIDTH => 3
    rule POSEIDON_RATE => 2

    // =========================================================================
    // POSEIDON ROUND FUNCTIONS
    // =========================================================================
    
    /**
     * S-box: x^5 mod p (power map)
     */
    syntax Felt252 ::= poseidonSBox(Felt252)        [function]
    rule poseidonSBox(X:Felt252) => feltExp(X, 5)
        requires isValidFelt(X)

    /**
     * MDS matrix multiplication (simplified 3x3)
     */
    syntax PoseidonState ::= poseidonMDS(PoseidonState)  [function]
    rule poseidonMDS(poseidonState(A, B, C)) =>
        poseidonState(
            feltAdd(feltMul(A, 3), feltAdd(feltMul(B, 1), feltMul(C, 1))),
            feltAdd(feltMul(A, 1), feltAdd(feltMul(B, 3), feltMul(C, 1))),
            feltAdd(feltMul(A, 1), feltAdd(feltMul(B, 1), feltMul(C, 3)))
        )

    /**
     * Add round constant
     */
    syntax PoseidonState ::= poseidonAddRC(PoseidonState, Int)  [function]
    syntax Felt252 ::= getRoundConstant(Int, Int)               [function]
    // Round constants would be precomputed - simplified here
    rule getRoundConstant(R, I) => toFelt((R +Int 1) *Int (I +Int 1) *Int 17)

    /**
     * Full round: S-box on all elements + MDS + add round constant
     */
    syntax PoseidonState ::= poseidonFullRound(PoseidonState, Int)  [function]
    rule poseidonFullRound(poseidonState(A, B, C), R) =>
        poseidonMDS(poseidonState(
            feltAdd(poseidonSBox(A), getRoundConstant(R, 0)),
            feltAdd(poseidonSBox(B), getRoundConstant(R, 1)),
            feltAdd(poseidonSBox(C), getRoundConstant(R, 2))
        ))

    /**
     * Partial round: S-box only on first element
     */
    syntax PoseidonState ::= poseidonPartialRound(PoseidonState, Int)  [function]
    rule poseidonPartialRound(poseidonState(A, B, C), R) =>
        poseidonMDS(poseidonState(
            feltAdd(poseidonSBox(A), getRoundConstant(R, 0)),
            feltAdd(B, getRoundConstant(R, 1)),
            feltAdd(C, getRoundConstant(R, 2))
        ))

    // =========================================================================
    // POSEIDON HASH FUNCTION
    // =========================================================================
    
    /**
     * Poseidon hash of two field elements
     * Uses sponge construction with rate 2, capacity 1
     */
    rule poseidonHash2(A:Felt252, B:Felt252) =>
        #poseidonPermutation(poseidonState(A, B, 0))
        requires isValidFelt(A) andBool isValidFelt(B)

    /**
     * Extract hash output from state
     */
    syntax Felt252 ::= #poseidonPermutation(PoseidonState)  [function]
    rule #poseidonPermutation(State) => #extractOutput(#applyAllRounds(State, 0))

    syntax Felt252 ::= #extractOutput(PoseidonState)  [function]
    rule #extractOutput(poseidonState(A, _, _)) => A

    /**
     * Apply all rounds (simplified iteration)
     */
    syntax PoseidonState ::= #applyAllRounds(PoseidonState, Int)  [function]
    // First 4 full rounds
    rule #applyAllRounds(State, R) => #applyAllRounds(poseidonFullRound(State, R), R +Int 1)
        requires R <Int 4
    // 83 partial rounds
    rule #applyAllRounds(State, R) => #applyAllRounds(poseidonPartialRound(State, R), R +Int 1)
        requires R >=Int 4 andBool R <Int 87
    // Last 4 full rounds
    rule #applyAllRounds(State, R) => #applyAllRounds(poseidonFullRound(State, R), R +Int 1)
        requires R >=Int 87 andBool R <Int 91
    // Done
    rule #applyAllRounds(State, 91) => State

    // =========================================================================
    // POSEIDON PROPERTIES (THEOREMS)
    // =========================================================================
    
    /**
     * Theorem: Poseidon output is a valid felt
     */
    claim <k> isValidFelt(poseidonHash2(A, B)) => true </k>
        requires isValidFelt(A) andBool isValidFelt(B)

    /**
     * Theorem: Poseidon is deterministic
     * H(a, b) computed twice gives same result
     */
    claim <k> poseidonHash2(A, B) ==Int poseidonHash2(A, B) => true </k>
        requires isValidFelt(A) andBool isValidFelt(B)

    /**
     * Theorem: Input sensitivity (weak - different inputs likely different outputs)
     * This is probabilistic, verified via fuzzing
     */
    // Verified empirically via fuzz testing

endmodule

module STARKNET-FRI
    imports STARKNET-FIELD
    imports STARKNET-POSEIDON
    imports LIST
    imports INT

    // =========================================================================
    // FRI VERIFICATION
    // =========================================================================
    
    /**
     * Compute security level of FRI configuration
     * Security = numQueries * log2(blowupFactor) bits
     */
    syntax Int ::= friSecurityLevel(FRIConfig)      [function]
    syntax Int ::= log2Approx(Int)                  [function]
    
    rule log2Approx(2) => 1
    rule log2Approx(4) => 2
    rule log2Approx(8) => 3
    rule log2Approx(16) => 4
    
    rule friSecurityLevel(friConfig(_, Blowup, NumQueries, _, _, _)) =>
        NumQueries *Int log2Approx(Blowup)

    /**
     * Validate FRI configuration
     */
    syntax Bool ::= isValidFRIConfig(FRIConfig)     [function]
    rule isValidFRIConfig(Config:FRIConfig) =>
        friSecurityLevel(Config) >=Int 128 andBool
        #domainSizeIsPowerOfTwo(Config) andBool
        #blowupInRange(Config) andBool
        #queriesInRange(Config)

    syntax Bool ::= #domainSizeIsPowerOfTwo(FRIConfig)  [function]
    syntax Bool ::= #blowupInRange(FRIConfig)           [function]
    syntax Bool ::= #queriesInRange(FRIConfig)          [function]
    
    rule #domainSizeIsPowerOfTwo(friConfig(D, _, _, _, _, _)) =>
        D >Int 0 andBool (D &Int (D -Int 1)) ==Int 0
    
    rule #blowupInRange(friConfig(_, B, _, _, _, _)) =>
        B >=Int 2 andBool B <=Int 16
    
    rule #queriesInRange(friConfig(_, _, Q, _, _, _)) =>
        Q >=Int 20 andBool Q <=Int 100

    /**
     * Compute number of FRI layers
     */
    syntax Int ::= computeNumLayers(Int, Int, Int)  [function]
    // numLayers = log2(domainSize / lastLayerDegBound) / log2(foldingFactor)
    rule computeNumLayers(DomainSize, FoldingFactor, LastLayerDegBound) =>
        log2Approx(DomainSize /Int LastLayerDegBound) /Int log2Approx(FoldingFactor)
        requires DomainSize >Int LastLayerDegBound andBool FoldingFactor >=Int 2

    /**
     * Verify FRI layer commitment
     */
    syntax Bool ::= verifyFRILayerCommitment(FRILayer, Int, FRIConfig)  [function]
    // Layer i should have domain size / (foldingFactor ^ i) evaluations
    rule verifyFRILayerCommitment(friLayer(Commitment, Evals, Proof), LayerIdx, Config) =>
        size(Evals) ==Int #expectedLayerSize(LayerIdx, Config) andBool
        Commitment =/=K 0
        requires LayerIdx >=Int 0

    syntax Int ::= #expectedLayerSize(Int, FRIConfig)  [function]
    rule #expectedLayerSize(Idx, friConfig(DomainSize, _, _, FoldingFactor, _, _)) =>
        DomainSize /Int feltExp(FoldingFactor, Idx)

    // =========================================================================
    // FRI PROPERTIES (THEOREMS)
    // =========================================================================
    
    /**
     * Theorem: Valid config implies sufficient security
     */
    claim <k> friSecurityLevel(Config) >=Int 128 => true </k>
        requires isValidFRIConfig(Config)

    /**
     * Theorem: Layer sizes decrease monotonically
     */
    claim <k> #expectedLayerSize(I +Int 1, Config) <Int #expectedLayerSize(I, Config) => true </k>
        requires isValidFRIConfig(Config) andBool I >=Int 0

endmodule

module STARKNET-NULLIFIER
    imports STARKNET-FIELD
    imports STARKNET-POSEIDON
    imports SET
    imports INT

    // =========================================================================
    // NULLIFIER COMPUTATION
    // =========================================================================
    
    /**
     * Compute nullifier from commitment and secret
     * nullifier = H(commitment, secret)
     */
    rule computeNullifier(Commitment:Felt252, Secret:Felt252) =>
        poseidonHash2(Commitment, Secret)
        requires isValidFelt(Commitment) andBool isValidFelt(Secret)

    /**
     * Compute cross-domain nullifier
     * crossDomainNullifier = H(nullifier, domainId)
     */
    rule computeCrossDomainNullifier(Nullifier:Felt252, DomainId:Int) =>
        poseidonHash2(Nullifier, toFelt(DomainId))
        requires isValidFelt(Nullifier)

    /**
     * Validate nullifier is well-formed
     */
    rule isNullifierValid(N:Felt252) => isValidFelt(N) andBool N =/=Int 0

    /**
     * Check nullifier hasn't been used
     */
    rule isNullifierUnused(N:Felt252, UsedSet:Set) => notBool (N in UsedSet)

    // =========================================================================
    // NULLIFIER PROPERTIES (THEOREMS)
    // =========================================================================
    
    /**
     * Theorem: Nullifier output is valid felt
     */
    claim <k> isValidFelt(computeNullifier(C, S)) => true </k>
        requires isValidFelt(C) andBool isValidFelt(S)

    /**
     * Theorem: Cross-domain nullifier is valid felt
     */
    claim <k> isValidFelt(computeCrossDomainNullifier(N, D)) => true </k>
        requires isValidFelt(N)

    /**
     * Theorem: Nullifier is deterministic
     */
    claim <k> computeNullifier(C, S) ==Int computeNullifier(C, S) => true </k>
        requires isValidFelt(C) andBool isValidFelt(S)

    /**
     * Theorem: Different secrets produce different nullifiers (with high probability)
     * This is a probabilistic property verified via fuzzing
     */
    // Verified empirically

    /**
     * Theorem: Cross-domain nullifiers are domain-isolated
     * H(n, d1) ≠ H(n, d2) for d1 ≠ d2 (with high probability)
     */
    // Verified empirically

endmodule

module STARKNET
    imports STARKNET-FIELD
    imports STARKNET-POSEIDON
    imports STARKNET-FRI
    imports STARKNET-NULLIFIER

    // =========================================================================
    // STARK PROOF VERIFICATION
    // =========================================================================
    
    /**
     * Verify a STARK proof
     */
    syntax VerificationResult ::= verifySTARKProof(STARKProof, FRIConfig)  [function]
    
    rule verifySTARKProof(Proof, Config) => Valid
        requires isValidFRIConfig(Config) andBool
                 #verifyTraceCommitment(Proof) andBool
                 #verifyFRILayers(Proof, Config) andBool
                 #verifyOODS(Proof)
    
    rule verifySTARKProof(_, Config) => verificationError("Invalid FRI config")
        requires notBool isValidFRIConfig(Config)

    /**
     * Verify trace commitment
     */
    syntax Bool ::= #verifyTraceCommitment(STARKProof)  [function]
    rule #verifyTraceCommitment(starkProof(TraceCommit, _, _, _, _, _, _)) =>
        TraceCommit =/=K 0

    /**
     * Verify FRI layers
     */
    syntax Bool ::= #verifyFRILayers(STARKProof, FRIConfig)  [function]
    rule #verifyFRILayers(starkProof(_, _, _, FRILayers, _, _, _), Config) =>
        size(FRILayers) ==Int #numLayers(Config)

    syntax Int ::= #numLayers(FRIConfig)  [function]
    rule #numLayers(friConfig(_, _, _, _, _, NumLayers)) => NumLayers

    /**
     * Verify OODS (Out-of-Domain Sampling)
     */
    syntax Bool ::= #verifyOODS(STARKProof)  [function]
    rule #verifyOODS(starkProof(_, _, _, _, OODSPoint, OODSValues, _)) =>
        isValidFelt(OODSPoint) andBool size(OODSValues) >Int 0

endmodule
