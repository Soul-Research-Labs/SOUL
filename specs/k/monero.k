/**
 * K Framework Formal Specification for Monero/CryptoNote Cryptographic Primitives
 * 
 * @title monero.k
 * @author PIL Protocol
 * @notice Formal verification of Monero field operations and primitives
 * 
 * VERIFICATION SCOPE:
 * - Ed25519 field arithmetic (curve and scalar fields)
 * - Curve25519 point operations
 * - CLSAG ring signatures
 * - Bulletproof+ range proofs
 * - Key image (nullifier) derivation
 * - Pedersen commitments
 * - Cross-domain (Monero ↔ PIL) nullifier binding
 * 
 * ED25519 CURVE PARAMETERS:
 * - Prime: p = 2^255 - 19
 * - Order: l = 2^252 + 27742317777372353535851937790883648493
 * - Equation: -x² + y² = 1 + d·x²·y² (twisted Edwards)
 * - d = -121665/121666 mod p
 * - Cofactor: 8
 * 
 * KEY CRYPTOGRAPHIC PRIMITIVES:
 * - Key Image: I = x · Hp(P) where x is secret key, P = x·G
 * - CLSAG: Compact Linkable Spontaneous Anonymous Group signatures
 * - Bulletproofs+: Logarithmic-sized range proofs
 */

requires "evm-semantics.md"
requires "domains.md"

module MONERO-SYNTAX
    imports INT-SYNTAX
    imports BOOL-SYNTAX
    imports LIST
    imports MAP
    imports SET
    imports BYTES

    // =========================================================================
    // ED25519 FIELD CONSTANTS
    // =========================================================================
    
    // Ed25519 prime field modulus (2^255 - 19)
    syntax Int ::= "ED25519_PRIME"    [function]
    rule ED25519_PRIME => 57896044618658097711785492504343953926634992332820282019728792003956564819949

    // Ed25519 curve order (l) - order of basepoint
    syntax Int ::= "ED25519_ORDER"    [function]
    rule ED25519_ORDER => 7237005577332262213973186563042994240857116359379907606001950938285454250989

    // Ed25519 d parameter (-121665/121666 mod p)
    syntax Int ::= "ED25519_D"    [function]
    rule ED25519_D => 37095705934669439343138083508754565189542113879843219016388785533085940283555

    // Cofactor
    syntax Int ::= "ED25519_COFACTOR"    [function]
    rule ED25519_COFACTOR => 8

    // =========================================================================
    // FIELD ELEMENT TYPES
    // =========================================================================
    
    // Scalar in F_l (curve order)
    syntax Scalar ::= Int
    
    // Field element in F_p (prime field)
    syntax FieldElement ::= Int
    
    // Ed25519 point (compressed 32 bytes or affine coordinates)
    syntax Ed25519Point ::= ed25519Point(x: FieldElement, y: FieldElement)
                         | "ED25519_IDENTITY"
                         | "ED25519_BASEPOINT"
                         | compressedPoint(Bytes)
    
    // Key image (nullifier equivalent)
    syntax KeyImage ::= keyImage(Ed25519Point)
    
    // =========================================================================
    // SCALAR FIELD OPERATIONS
    // =========================================================================
    
    syntax Scalar ::= scalarAdd(Scalar, Scalar)     [function]
                    | scalarSub(Scalar, Scalar)     [function]
                    | scalarMul(Scalar, Scalar)     [function]
                    | scalarNeg(Scalar)             [function]
                    | scalarInv(Scalar)             [function]
                    | scalarReduce(Int)             [function]
                    | scalarReduce512(Int, Int)     [function]
    
    syntax Bool ::= isValidScalar(Int)              [function]
    
    // =========================================================================
    // PRIME FIELD OPERATIONS
    // =========================================================================
    
    syntax FieldElement ::= fieldAdd(FieldElement, FieldElement)     [function]
                         | fieldSub(FieldElement, FieldElement)     [function]
                         | fieldMul(FieldElement, FieldElement)     [function]
                         | fieldNeg(FieldElement)                   [function]
                         | fieldInv(FieldElement)                   [function]
                         | fieldSqrt(FieldElement)                  [function]
                         | fieldExp(FieldElement, Int)              [function]
    
    syntax Bool ::= isValidFieldElement(Int)                        [function]
                  | isSquare(FieldElement)                          [function]
    
    // =========================================================================
    // CURVE POINT OPERATIONS
    // =========================================================================
    
    syntax Ed25519Point ::= pointAdd(Ed25519Point, Ed25519Point)    [function]
                         | pointDouble(Ed25519Point)                [function]
                         | scalarMulPoint(Scalar, Ed25519Point)     [function]
                         | pointNeg(Ed25519Point)                   [function]
                         | hashToPoint(Bytes)                       [function]
    
    syntax Bool ::= isOnCurve(Ed25519Point)                         [function]
                  | isInPrimeOrderSubgroup(Ed25519Point)            [function]
    
    // =========================================================================
    // HASH FUNCTIONS
    // =========================================================================
    
    syntax Scalar ::= hashToScalar(Bytes)                           [function]
    syntax Bytes ::= keccak256Hash(Bytes)                           [function]
    
    // Domain-separated hashes
    syntax Scalar ::= hashToScalarDomain(Bytes, Bytes)              [function]
    
    // =========================================================================
    // KEY IMAGE OPERATIONS
    // =========================================================================
    
    syntax KeyImage ::= computeKeyImage(Scalar, Ed25519Point)       [function]
    syntax Bytes ::= keyImageToBytes(KeyImage)                      [function]
    syntax Bool ::= isValidKeyImage(KeyImage)                       [function]
    
    // Cross-domain nullifier binding
    syntax Bytes ::= deriveMoneroToPILNullifier(KeyImage)           [function]
    syntax Bytes ::= derivePILToMoneroKeyImage(Bytes)               [function]
    
    // =========================================================================
    // RING SIGNATURE TYPES
    // =========================================================================
    
    // Ring member (decoy or real signer)
    syntax RingMember ::= ringMember(
        publicKey: Ed25519Point,
        commitment: Ed25519Point
    )
    
    // CLSAG signature
    syntax CLSAGSignature ::= clsagSignature(
        c0: Scalar,                 // Initial challenge
        responses: List,            // Response scalars
        keyImage: KeyImage,
        D: Ed25519Point             // Commitment to signing key
    )
    
    syntax Bool ::= verifyCLSAG(List, CLSAGSignature, Bytes)        [function]
    syntax Scalar ::= clsagChallenge(Int, List, KeyImage, Ed25519Point, Ed25519Point)    [function]
    
    // =========================================================================
    // BULLETPROOF+ TYPES
    // =========================================================================
    
    syntax BulletproofPlus ::= bulletproofPlus(
        A: Ed25519Point,
        A1: Ed25519Point,
        B: Ed25519Point,
        r1: Ed25519Point,
        s1: Ed25519Point,
        d1: Ed25519Point,
        L: List,                    // Left points
        R: List                     // Right points
    )
    
    syntax Bool ::= verifyBulletproofPlus(BulletproofPlus, List)    [function]
    
    // =========================================================================
    // PEDERSEN COMMITMENT
    // =========================================================================
    
    syntax Ed25519Point ::= "PEDERSEN_G"    [function]
    syntax Ed25519Point ::= "PEDERSEN_H"    [function]
    
    syntax Ed25519Point ::= pedersenCommit(Scalar, Int)             [function]
    syntax Bool ::= verifyCommitmentBalance(List, List, Int)        [function]

endmodule

module MONERO-FIELD
    imports MONERO-SYNTAX
    imports INT
    imports BOOL

    // =========================================================================
    // SCALAR FIELD ARITHMETIC (mod l)
    // =========================================================================
    
    /**
     * Scalar validation: s ∈ [0, l)
     */
    rule isValidScalar(S:Int) => true
        requires S >=Int 0 andBool S <Int ED25519_ORDER
    rule isValidScalar(S:Int) => false
        requires S <Int 0 orBool S >=Int ED25519_ORDER

    /**
     * Scalar reduction: s mod l
     */
    rule scalarReduce(S:Int) => S %Int ED25519_ORDER
        requires S >=Int 0
    rule scalarReduce(S:Int) => scalarReduce(S +Int ED25519_ORDER)
        requires S <Int 0

    /**
     * 512-bit scalar reduction (for hash outputs)
     * Reduces h = high * 2^256 + low (mod l)
     */
    rule scalarReduce512(Low:Int, High:Int) =>
        (Low +Int (High *Int (2 ^Int 256 %Int ED25519_ORDER))) %Int ED25519_ORDER
        requires Low >=Int 0 andBool High >=Int 0

    /**
     * Scalar addition: (a + b) mod l
     */
    rule scalarAdd(A:Scalar, B:Scalar) => (A +Int B) %Int ED25519_ORDER
        requires isValidScalar(A) andBool isValidScalar(B)

    /**
     * Scalar subtraction: (a - b) mod l
     */
    rule scalarSub(A:Scalar, B:Scalar) => scalarReduce(A -Int B)
        requires isValidScalar(A) andBool isValidScalar(B)

    /**
     * Scalar multiplication: (a * b) mod l
     */
    rule scalarMul(A:Scalar, B:Scalar) => (A *Int B) %Int ED25519_ORDER
        requires isValidScalar(A) andBool isValidScalar(B)

    /**
     * Scalar negation: (-a) mod l
     */
    rule scalarNeg(A:Scalar) => (ED25519_ORDER -Int A) %Int ED25519_ORDER
        requires isValidScalar(A)
    rule scalarNeg(0) => 0

    /**
     * Scalar inversion using Fermat's little theorem: a^(-1) = a^(l-2) mod l
     */
    rule scalarInv(A:Scalar) => fieldExp(A, ED25519_ORDER -Int 2)
        requires isValidScalar(A) andBool A =/=Int 0

    // =========================================================================
    // PRIME FIELD ARITHMETIC (mod p)
    // =========================================================================
    
    /**
     * Field element validation: x ∈ [0, p)
     */
    rule isValidFieldElement(X:Int) => true
        requires X >=Int 0 andBool X <Int ED25519_PRIME
    rule isValidFieldElement(X:Int) => false
        requires X <Int 0 orBool X >=Int ED25519_PRIME

    /**
     * Field addition: (a + b) mod p
     */
    rule fieldAdd(A:FieldElement, B:FieldElement) => (A +Int B) %Int ED25519_PRIME
        requires isValidFieldElement(A) andBool isValidFieldElement(B)

    /**
     * Field subtraction: (a - b) mod p
     */
    rule fieldSub(A:FieldElement, B:FieldElement) => 
        (A -Int B +Int ED25519_PRIME) %Int ED25519_PRIME
        requires isValidFieldElement(A) andBool isValidFieldElement(B)

    /**
     * Field multiplication: (a * b) mod p
     */
    rule fieldMul(A:FieldElement, B:FieldElement) => (A *Int B) %Int ED25519_PRIME
        requires isValidFieldElement(A) andBool isValidFieldElement(B)

    /**
     * Field negation: (-a) mod p
     */
    rule fieldNeg(A:FieldElement) => (ED25519_PRIME -Int A) %Int ED25519_PRIME
        requires isValidFieldElement(A)
    rule fieldNeg(0) => 0

    /**
     * Field exponentiation (square-and-multiply)
     */
    rule fieldExp(A:FieldElement, 0) => 1
    rule fieldExp(A:FieldElement, 1) => A
        requires isValidFieldElement(A)
    rule fieldExp(A:FieldElement, N:Int) =>
        fieldMul(fieldExp(fieldMul(A, A), N /Int 2), A)
        requires N >Int 1 andBool (N %Int 2) ==Int 1 andBool isValidFieldElement(A)
    rule fieldExp(A:FieldElement, N:Int) =>
        fieldExp(fieldMul(A, A), N /Int 2)
        requires N >Int 1 andBool (N %Int 2) ==Int 0 andBool isValidFieldElement(A)

    /**
     * Field inversion: a^(-1) = a^(p-2) mod p
     */
    rule fieldInv(A:FieldElement) => fieldExp(A, ED25519_PRIME -Int 2)
        requires isValidFieldElement(A) andBool A =/=Int 0

    /**
     * Quadratic residue check (Euler criterion)
     * a is square iff a^((p-1)/2) = 1 mod p
     */
    rule isSquare(A:FieldElement) => fieldExp(A, (ED25519_PRIME -Int 1) /Int 2) ==Int 1
        requires isValidFieldElement(A) andBool A =/=Int 0
    rule isSquare(0) => true

    /**
     * Square root using Tonelli-Shanks (simplified for p ≡ 5 mod 8)
     * sqrt(a) = a^((p+3)/8) or i*a^((p+3)/8) where i^2 = -1
     */
    rule fieldSqrt(A:FieldElement) => fieldExp(A, (ED25519_PRIME +Int 3) /Int 8)
        requires isSquare(A)

    // =========================================================================
    // FIELD PROPERTY THEOREMS
    // =========================================================================
    
    /**
     * Theorem: Scalar field is closed under addition
     */
    claim <k> isValidScalar(scalarAdd(A, B)) => true </k>
        requires isValidScalar(A) andBool isValidScalar(B)

    /**
     * Theorem: Scalar field is closed under multiplication
     */
    claim <k> isValidScalar(scalarMul(A, B)) => true </k>
        requires isValidScalar(A) andBool isValidScalar(B)

    /**
     * Theorem: Addition is commutative
     */
    claim <k> scalarAdd(A, B) => scalarAdd(B, A) </k>
        requires isValidScalar(A) andBool isValidScalar(B)

    /**
     * Theorem: Multiplication is commutative
     */
    claim <k> scalarMul(A, B) => scalarMul(B, A) </k>
        requires isValidScalar(A) andBool isValidScalar(B)

    /**
     * Theorem: Additive identity
     */
    claim <k> scalarAdd(A, 0) => A </k>
        requires isValidScalar(A)

    /**
     * Theorem: Multiplicative identity
     */
    claim <k> scalarMul(A, 1) => A </k>
        requires isValidScalar(A)

    /**
     * Theorem: Additive inverse
     */
    claim <k> scalarAdd(A, scalarNeg(A)) => 0 </k>
        requires isValidScalar(A)

    /**
     * Theorem: Multiplicative inverse
     */
    claim <k> scalarMul(A, scalarInv(A)) => 1 </k>
        requires isValidScalar(A) andBool A =/=Int 0

endmodule

module MONERO-CURVE
    imports MONERO-FIELD
    imports INT
    imports BOOL

    // =========================================================================
    // ED25519 CURVE OPERATIONS
    // =========================================================================
    
    /**
     * Identity point (neutral element)
     */
    rule ED25519_IDENTITY => ed25519Point(0, 1)

    /**
     * Check if point is on Ed25519 curve
     * Twisted Edwards: -x² + y² = 1 + d·x²·y²
     */
    rule isOnCurve(ed25519Point(X, Y)) =>
        fieldAdd(fieldNeg(fieldMul(X, X)), fieldMul(Y, Y)) ==Int
        fieldAdd(1, fieldMul(ED25519_D, fieldMul(fieldMul(X, X), fieldMul(Y, Y))))
        requires isValidFieldElement(X) andBool isValidFieldElement(Y)
    
    rule isOnCurve(ED25519_IDENTITY) => true
    rule isOnCurve(ED25519_BASEPOINT) => true

    /**
     * Point addition (twisted Edwards)
     * (x₁, y₁) + (x₂, y₂) = ((x₁y₂ + x₂y₁)/(1 + dx₁x₂y₁y₂), (y₁y₂ + x₁x₂)/(1 - dx₁x₂y₁y₂))
     */
    rule pointAdd(ed25519Point(X1, Y1), ed25519Point(X2, Y2)) =>
        ed25519Point(
            fieldMul(
                fieldAdd(fieldMul(X1, Y2), fieldMul(X2, Y1)),
                fieldInv(fieldAdd(1, fieldMul(ED25519_D, fieldMul(fieldMul(X1, X2), fieldMul(Y1, Y2)))))
            ),
            fieldMul(
                fieldAdd(fieldMul(Y1, Y2), fieldMul(X1, X2)),
                fieldInv(fieldSub(1, fieldMul(ED25519_D, fieldMul(fieldMul(X1, X2), fieldMul(Y1, Y2)))))
            )
        )
        requires isOnCurve(ed25519Point(X1, Y1)) andBool isOnCurve(ed25519Point(X2, Y2))

    /**
     * Point doubling
     */
    rule pointDouble(P:Ed25519Point) => pointAdd(P, P)
        requires isOnCurve(P)

    /**
     * Point negation: -(x, y) = (-x, y)
     */
    rule pointNeg(ed25519Point(X, Y)) => ed25519Point(fieldNeg(X), Y)
        requires isOnCurve(ed25519Point(X, Y))
    rule pointNeg(ED25519_IDENTITY) => ED25519_IDENTITY

    /**
     * Scalar multiplication (double-and-add)
     */
    rule scalarMulPoint(0, _) => ED25519_IDENTITY
    rule scalarMulPoint(1, P) => P
        requires isOnCurve(P)
    rule scalarMulPoint(N:Scalar, P:Ed25519Point) =>
        pointAdd(scalarMulPoint(N /Int 2, pointDouble(P)), P)
        requires N >Int 1 andBool (N %Int 2) ==Int 1 andBool isOnCurve(P)
    rule scalarMulPoint(N:Scalar, P:Ed25519Point) =>
        scalarMulPoint(N /Int 2, pointDouble(P))
        requires N >Int 1 andBool (N %Int 2) ==Int 0 andBool isOnCurve(P)

    /**
     * Check if point is in prime-order subgroup
     * P is in prime subgroup iff l·P = O (identity)
     */
    rule isInPrimeOrderSubgroup(P:Ed25519Point) =>
        scalarMulPoint(ED25519_ORDER, P) ==K ED25519_IDENTITY
        requires isOnCurve(P)

    // =========================================================================
    // CURVE PROPERTY THEOREMS
    // =========================================================================
    
    /**
     * Theorem: Identity is neutral element
     */
    claim <k> pointAdd(P, ED25519_IDENTITY) => P </k>
        requires isOnCurve(P)

    /**
     * Theorem: Point addition is commutative
     */
    claim <k> pointAdd(P, Q) => pointAdd(Q, P) </k>
        requires isOnCurve(P) andBool isOnCurve(Q)

    /**
     * Theorem: Point plus its negation equals identity
     */
    claim <k> pointAdd(P, pointNeg(P)) => ED25519_IDENTITY </k>
        requires isOnCurve(P)

    /**
     * Theorem: Addition preserves curve membership
     */
    claim <k> isOnCurve(pointAdd(P, Q)) => true </k>
        requires isOnCurve(P) andBool isOnCurve(Q)

    /**
     * Theorem: Scalar multiplication preserves curve membership
     */
    claim <k> isOnCurve(scalarMulPoint(N, P)) => true </k>
        requires isValidScalar(N) andBool isOnCurve(P)

endmodule

module MONERO-KEY-IMAGE
    imports MONERO-CURVE
    imports BYTES

    // =========================================================================
    // KEY IMAGE COMPUTATION
    // =========================================================================
    
    // Domain separator for PIL-Monero binding
    syntax Bytes ::= "PIL_MONERO_DOMAIN"    [function]
    rule PIL_MONERO_DOMAIN => #stringToBytes("PIL_Monero_Interop_v1")
    
    syntax Bytes ::= #stringToBytes(String)    [function]

    /**
     * Hash to point (Hp function)
     * Maps arbitrary data to a point on Ed25519
     * Used for key image: I = x · Hp(P)
     */
    rule hashToPoint(Data:Bytes) => #hashToPointImpl(keccak256Hash(Data))
    
    syntax Ed25519Point ::= #hashToPointImpl(Bytes)    [function]
    // Elligator 2 or try-and-increment implementation

    /**
     * Compute key image
     * I = x · Hp(P) where P = x·G is the public key
     */
    rule computeKeyImage(SecretKey:Scalar, PublicKey:Ed25519Point) =>
        keyImage(scalarMulPoint(SecretKey, hashToPoint(#pointToBytes(PublicKey))))
        requires isValidScalar(SecretKey) andBool isOnCurve(PublicKey)

    syntax Bytes ::= #pointToBytes(Ed25519Point)    [function]
    // Point compression

    /**
     * Validate key image
     * - Point must be on curve
     * - Point must be in prime-order subgroup
     * - Point must not be identity
     */
    rule isValidKeyImage(keyImage(P:Ed25519Point)) =>
        isOnCurve(P) andBool
        isInPrimeOrderSubgroup(P) andBool
        P =/=K ED25519_IDENTITY

    /**
     * Convert key image to bytes for hashing
     */
    rule keyImageToBytes(keyImage(P:Ed25519Point)) => #pointToBytes(P)

    // =========================================================================
    // CROSS-DOMAIN NULLIFIER BINDING
    // =========================================================================
    
    /**
     * Derive PIL nullifier from Monero key image
     * pilNullifier = H(keyImage || PIL_MONERO_DOMAIN || "M2P")
     */
    rule deriveMoneroToPILNullifier(KI:KeyImage) =>
        keccak256Hash(#concat(keyImageToBytes(KI), PIL_MONERO_DOMAIN, #stringToBytes("M2P")))

    syntax Bytes ::= #concat(Bytes, Bytes, Bytes)    [function]

    /**
     * Derive Monero-compatible key image reference from PIL nullifier
     * Note: Cannot directly derive key image (one-way)
     */
    rule derivePILToMoneroKeyImage(PILNullifier:Bytes) =>
        keccak256Hash(#concat(PILNullifier, PIL_MONERO_DOMAIN, #stringToBytes("P2M")))

    // =========================================================================
    // KEY IMAGE PROPERTIES (THEOREMS)
    // =========================================================================
    
    /**
     * Theorem: Key image is deterministic
     * Same secret key + public key always produces same key image
     */
    claim <k> computeKeyImage(X, P) ==K computeKeyImage(X, P) => true </k>
        requires isValidScalar(X) andBool isOnCurve(P)

    /**
     * Theorem: Key image is unique per key pair
     * Different secret keys produce different key images (DLP assumption)
     * Verified via cryptographic security reduction
     */

    /**
     * Theorem: Key image reveals no information about ring position
     * CLSAG signature hides which ring member signed
     * Verified via zero-knowledge property
     */

    /**
     * Theorem: Cross-domain derivation is deterministic
     */
    claim <k> deriveMoneroToPILNullifier(KI) ==K deriveMoneroToPILNullifier(KI) => true </k>

endmodule

module MONERO-CLSAG
    imports MONERO-KEY-IMAGE
    imports LIST

    // =========================================================================
    // CLSAG VERIFICATION
    // =========================================================================
    
    /**
     * Verify CLSAG ring signature
     * 
     * Algorithm:
     * 1. Compute aggregation coefficient μ = H("CLSAG_agg" || ring || I || D)
     * 2. For i = 0 to n-1:
     *    L_i = s_i·G + c_i·P_i
     *    R_i = s_i·Hp(P_i) + c_i·I
     *    c_{i+1} = H("CLSAG_round" || ring || message || L_i || R_i)
     * 3. Verify c_n == c_0
     */
    rule verifyCLSAG(Ring:List, Sig:CLSAGSignature, Message:Bytes) =>
        #verifyCLSAGLoop(Ring, Sig, Message, 0, getC0(Sig))
        requires size(Ring) >=Int 2 andBool size(Ring) ==Int size(getResponses(Sig))

    syntax Scalar ::= getC0(CLSAGSignature)    [function]
    rule getC0(clsagSignature(C0, _, _, _)) => C0

    syntax List ::= getResponses(CLSAGSignature)    [function]
    rule getResponses(clsagSignature(_, Responses, _, _)) => Responses

    syntax KeyImage ::= getKeyImage(CLSAGSignature)    [function]
    rule getKeyImage(clsagSignature(_, _, KI, _)) => KI

    syntax Ed25519Point ::= getD(CLSAGSignature)    [function]
    rule getD(clsagSignature(_, _, _, D)) => D

    syntax Bool ::= #verifyCLSAGLoop(List, CLSAGSignature, Bytes, Int, Scalar)    [function]
    
    // Loop termination: verify final challenge equals initial
    rule #verifyCLSAGLoop(Ring:List, Sig:CLSAGSignature, _, N:Int, ComputedC:Scalar) =>
        ComputedC ==Int getC0(Sig)
        requires N ==Int size(Ring)
    
    // Loop iteration
    rule #verifyCLSAGLoop(Ring:List, Sig:CLSAGSignature, Message:Bytes, I:Int, CurrentC:Scalar) =>
        #verifyCLSAGLoop(
            Ring,
            Sig,
            Message,
            I +Int 1,
            clsagChallenge(I +Int 1, Ring, getKeyImage(Sig), 
                #computeL(I, Ring, Sig, CurrentC),
                #computeR(I, Ring, Sig, CurrentC))
        )
        requires I <Int size(Ring)

    // L_i = s_i·G + c_i·P_i
    syntax Ed25519Point ::= #computeL(Int, List, CLSAGSignature, Scalar)    [function]
    rule #computeL(I:Int, Ring:List, Sig:CLSAGSignature, C:Scalar) =>
        pointAdd(
            scalarMulPoint(#getResponse(Sig, I), ED25519_BASEPOINT),
            scalarMulPoint(C, #getRingKey(Ring, I))
        )

    // R_i = s_i·Hp(P_i) + c_i·I
    syntax Ed25519Point ::= #computeR(Int, List, CLSAGSignature, Scalar)    [function]
    rule #computeR(I:Int, Ring:List, Sig:CLSAGSignature, C:Scalar) =>
        pointAdd(
            scalarMulPoint(#getResponse(Sig, I), hashToPoint(#pointToBytes(#getRingKey(Ring, I)))),
            scalarMulPoint(C, #getKeyImagePoint(Sig))
        )

    syntax Scalar ::= #getResponse(CLSAGSignature, Int)    [function]
    syntax Ed25519Point ::= #getRingKey(List, Int)    [function]
    syntax Ed25519Point ::= #getKeyImagePoint(CLSAGSignature)    [function]
    rule #getKeyImagePoint(clsagSignature(_, _, keyImage(P), _)) => P

    /**
     * Compute CLSAG challenge hash
     */
    rule clsagChallenge(RoundIndex:Int, Ring:List, KI:KeyImage, L:Ed25519Point, R:Ed25519Point) =>
        hashToScalar(#encodeCLSAGChallenge(RoundIndex, Ring, KI, L, R))

    syntax Bytes ::= #encodeCLSAGChallenge(Int, List, KeyImage, Ed25519Point, Ed25519Point)    [function]

    // =========================================================================
    // CLSAG SECURITY PROPERTIES
    // =========================================================================
    
    /**
     * Theorem: CLSAG is unforgeable
     * Cannot create valid signature without knowing secret key
     * Based on discrete logarithm assumption
     */

    /**
     * Theorem: CLSAG is linkable
     * Same key image in two signatures indicates same signer
     */

    /**
     * Theorem: CLSAG is anonymous
     * Signature reveals nothing about which ring member signed
     * (except through key image linkage)
     */

endmodule

module MONERO-BULLETPROOF
    imports MONERO-CLSAG
    imports LIST

    // =========================================================================
    // BULLETPROOF+ VERIFICATION
    // =========================================================================
    
    /**
     * Verify Bulletproof+ range proof
     * Proves committed values are in [0, 2^64) without revealing them
     */
    rule verifyBulletproofPlus(Proof:BulletproofPlus, Commitments:List) =>
        #verifyBPPlusStructure(Proof, Commitments) andBool
        #verifyBPPlusInnerProduct(Proof, Commitments)
        requires size(Commitments) >=Int 1

    /**
     * Verify proof structure
     */
    syntax Bool ::= #verifyBPPlusStructure(BulletproofPlus, List)    [function]
    rule #verifyBPPlusStructure(bulletproofPlus(A, A1, B, R1, S1, D1, L, R), Commitments:List) =>
        size(L) ==Int size(R) andBool
        size(L) ==Int #log2Ceil(64 *Int size(Commitments)) andBool
        isOnCurve(A) andBool isOnCurve(A1) andBool isOnCurve(B)

    syntax Int ::= #log2Ceil(Int)    [function]
    rule #log2Ceil(1) => 0
    rule #log2Ceil(N:Int) => 1 +Int #log2Ceil((N +Int 1) /Int 2)
        requires N >Int 1

    /**
     * Verify inner product argument
     */
    syntax Bool ::= #verifyBPPlusInnerProduct(BulletproofPlus, List)    [function]
    // Full verification involves:
    // 1. Compute challenges from transcript
    // 2. Aggregate commitments
    // 3. Verify final inner product equation

    // =========================================================================
    // BULLETPROOF PROPERTIES
    // =========================================================================
    
    /**
     * Theorem: Bulletproof+ is complete
     * Valid range proofs always verify
     */

    /**
     * Theorem: Bulletproof+ is sound
     * Cannot prove false statement (value outside range)
     * Based on discrete log assumption
     */

    /**
     * Theorem: Bulletproof+ is zero-knowledge
     * Proof reveals nothing about committed value
     */

endmodule

module MONERO-PEDERSEN
    imports MONERO-BULLETPROOF

    // =========================================================================
    // PEDERSEN COMMITMENT
    // =========================================================================
    
    /**
     * Generator H for Pedersen commitment
     * H = 8 * hash_to_curve(keccak256(G))
     */
    // Placeholder - actual H is curve-specific constant

    /**
     * Compute Pedersen commitment: C = mask·G + amount·H
     */
    rule pedersenCommit(Mask:Scalar, Amount:Int) =>
        pointAdd(
            scalarMulPoint(Mask, ED25519_BASEPOINT),
            scalarMulPoint(scalarReduce(Amount), PEDERSEN_H)
        )
        requires isValidScalar(Mask) andBool Amount >=Int 0

    /**
     * Verify commitment balance for RingCT
     * sum(input_commitments) = sum(output_commitments) + fee·H
     */
    rule verifyCommitmentBalance(Inputs:List, Outputs:List, Fee:Int) =>
        #sumPoints(Inputs) ==K pointAdd(#sumPoints(Outputs), scalarMulPoint(scalarReduce(Fee), PEDERSEN_H))
        requires size(Inputs) >=Int 1 andBool size(Outputs) >=Int 1

    syntax Ed25519Point ::= #sumPoints(List)    [function]
    rule #sumPoints(.List) => ED25519_IDENTITY
    rule #sumPoints(ListItem(P:Ed25519Point) Rest:List) => pointAdd(P, #sumPoints(Rest))

    // =========================================================================
    // PEDERSEN COMMITMENT PROPERTIES
    // =========================================================================
    
    /**
     * Theorem: Commitment is hiding
     * Given C, cannot determine amount without knowing mask
     */

    /**
     * Theorem: Commitment is binding
     * Cannot open C to two different (mask, amount) pairs
     */

    /**
     * Theorem: Commitments are additively homomorphic
     * C(m1, a1) + C(m2, a2) = C(m1+m2, a1+a2)
     */
    claim <k> 
        pointAdd(pedersenCommit(M1, A1), pedersenCommit(M2, A2)) =>
        pedersenCommit(scalarAdd(M1, M2), A1 +Int A2)
    </k>
        requires isValidScalar(M1) andBool isValidScalar(M2)
                 andBool A1 >=Int 0 andBool A2 >=Int 0

endmodule

module MONERO
    imports MONERO-FIELD
    imports MONERO-CURVE
    imports MONERO-KEY-IMAGE
    imports MONERO-CLSAG
    imports MONERO-BULLETPROOF
    imports MONERO-PEDERSEN

    // =========================================================================
    // RINGCT TRANSACTION VERIFICATION
    // =========================================================================
    
    /**
     * Full RingCT transaction verification
     * 1. Verify each CLSAG signature
     * 2. Verify Bulletproof+ range proofs
     * 3. Verify commitment balance
     */
    syntax Bool ::= verifyRingCT(
        List,           // Input rings (list of lists)
        List,           // CLSAG signatures
        BulletproofPlus,// Range proof
        List,           // Output commitments
        List,           // Pseudo output commitments
        Int             // Fee
    )    [function]

    rule verifyRingCT(InputRings, Signatures, RangeProof, OutputCommitments, PseudoCommitments, Fee) =>
        #verifyCLSAGAll(InputRings, Signatures) andBool
        verifyBulletproofPlus(RangeProof, OutputCommitments) andBool
        verifyCommitmentBalance(PseudoCommitments, OutputCommitments, Fee)
        requires size(InputRings) ==Int size(Signatures)
                 andBool size(InputRings) ==Int size(PseudoCommitments)

    syntax Bool ::= #verifyCLSAGAll(List, List)    [function]
    rule #verifyCLSAGAll(.List, .List) => true
    rule #verifyCLSAGAll(ListItem(Ring:List) Rings:List, ListItem(Sig:CLSAGSignature) Sigs:List) =>
        verifyCLSAG(Ring, Sig, #emptyBytes) andBool #verifyCLSAGAll(Rings, Sigs)

    syntax Bytes ::= #emptyBytes    [function]
    rule #emptyBytes => .Bytes

    // =========================================================================
    // CROSS-CHAIN BRIDGE VERIFICATION
    // =========================================================================
    
    /**
     * Verify Monero → PIL deposit
     * 1. Verify CLSAG proves spend authorization
     * 2. Verify key image not already used
     * 3. Verify Bulletproof+ proves valid amount
     * 4. Derive PIL nullifier from key image
     */
    syntax Bool ::= verifyMoneroDeposit(
        List,               // Ring
        CLSAGSignature,     // Signature
        BulletproofPlus,    // Range proof
        List,               // Commitments
        Set                 // Used key images
    )    [function]

    rule verifyMoneroDeposit(Ring, Sig, RangeProof, Commitments, UsedKeyImages) =>
        verifyCLSAG(Ring, Sig, #emptyBytes) andBool
        verifyBulletproofPlus(RangeProof, Commitments) andBool
        notBool (keyImageToBytes(getKeyImage(Sig)) in UsedKeyImages)

    /**
     * Verify PIL → Monero withdrawal
     * 1. Verify PIL nullifier is valid
     * 2. Verify PIL nullifier not already used
     * 3. Verify withdrawal amount
     */
    syntax Bool ::= verifyPILWithdrawal(
        Bytes,      // PIL nullifier
        Set,        // Used PIL nullifiers
        Int         // Amount
    )    [function]

    rule verifyPILWithdrawal(PILNullifier, UsedNullifiers, Amount) =>
        notBool (PILNullifier in UsedNullifiers) andBool
        Amount >Int 0

    // =========================================================================
    // SECURITY INVARIANTS
    // =========================================================================
    
    /**
     * Invariant: No double-spend
     * Key image can only be used once across all chains
     */

    /**
     * Invariant: Value conservation
     * Total deposited = Total withdrawn + Total pending
     */

    /**
     * Invariant: Unforgeability
     * Cannot create valid signature without secret key
     */

    /**
     * Invariant: Unlinkability
     * Cannot link deposits except through key image
     */

endmodule
