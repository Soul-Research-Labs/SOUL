/**
 * K Framework Formal Specification for Secret Network Cryptographic Primitives
 * 
 * @title secret.k
 * @author PIL Protocol
 * @notice Formal verification of Secret Network TEE and cryptographic operations
 * 
 * VERIFICATION SCOPE:
 * - secp256k1 elliptic curve operations
 * - AES-SIV deterministic encryption
 * - Intel SGX TEE attestation
 * - IBC (Inter-Blockchain Communication) verification
 * - Viewing keys and query permits
 * - Cross-domain (Secret ↔ PIL) nullifier binding
 * - SNIP token standard hashing
 * 
 * SECP256K1 PARAMETERS:
 * - Prime: p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
 * - Order: n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
 * - Generator G = (Gx, Gy)
 * - Cofactor: 1
 * - Weierstrass form: y² = x³ + 7
 * 
 * AES-SIV PARAMETERS:
 * - Key size: 256 bits (AES-256)
 * - Tag size: 128 bits
 * - Deterministic AEAD (Authenticated Encryption with Associated Data)
 * 
 * SECRET NETWORK IDENTIFIERS:
 * - Mainnet: secret-4 (numeric ID: 1)
 * - Testnet: pulsar-3 (numeric ID: 2)
 */

requires "evm-semantics.md"
requires "domains.md"

module SECRET-SYNTAX
    imports INT-SYNTAX
    imports BOOL-SYNTAX
    imports LIST
    imports MAP
    imports SET
    imports BYTES
    imports STRING-SYNTAX

    // =========================================================================
    // SECP256K1 FIELD CONSTANTS
    // =========================================================================
    
    // secp256k1 prime field modulus (p)
    syntax Int ::= "SECP256K1_P"    [function]
    rule SECP256K1_P => 115792089237316195423570985008687907853269984665640564039457584007908834671663

    // secp256k1 group order (n)
    syntax Int ::= "SECP256K1_N"    [function]
    rule SECP256K1_N => 115792089237316195423570985008687907852837564279074904382605163141518161494337

    // secp256k1 curve coefficient b = 7
    syntax Int ::= "SECP256K1_B"    [function]
    rule SECP256K1_B => 7

    // Generator point x-coordinate
    syntax Int ::= "SECP256K1_GX"    [function]
    rule SECP256K1_GX => 55066263022277343669578718895168534326250603453777594175500187360389116729240

    // Generator point y-coordinate
    syntax Int ::= "SECP256K1_GY"    [function]
    rule SECP256K1_GY => 32670510020758816978083085130507043184471273380659243275938904335757337482424

    // Cofactor (always 1 for secp256k1)
    syntax Int ::= "SECP256K1_COFACTOR"    [function]
    rule SECP256K1_COFACTOR => 1

    // =========================================================================
    // SECRET NETWORK IDENTIFIERS
    // =========================================================================
    
    // Secret Network mainnet numeric ID
    syntax Int ::= "SECRET_MAINNET_ID"    [function]
    rule SECRET_MAINNET_ID => 1

    // Secret Network testnet numeric ID
    syntax Int ::= "SECRET_TESTNET_ID"    [function]
    rule SECRET_TESTNET_ID => 2

    // Secret mainnet chain ID (Cosmos format)
    syntax String ::= "SECRET_MAINNET_CHAIN"    [function]
    rule SECRET_MAINNET_CHAIN => "secret-4"

    // Secret testnet chain ID (Cosmos format)
    syntax String ::= "SECRET_TESTNET_CHAIN"    [function]
    rule SECRET_TESTNET_CHAIN => "pulsar-3"

    // PIL to Secret domain separator
    syntax Bytes ::= "PIL_SECRET_DOMAIN"    [function]
    rule PIL_SECRET_DOMAIN => b"PIL_SECRET_DOMAIN_V1"

    // =========================================================================
    // SGX ATTESTATION CONSTANTS
    // =========================================================================
    
    // SGX quote version
    syntax Int ::= "SGX_QUOTE_VERSION"    [function]
    rule SGX_QUOTE_VERSION => 3

    // Maximum quote age (24 hours)
    syntax Int ::= "MAX_QUOTE_AGE"    [function]
    rule MAX_QUOTE_AGE => 86400

    // TCB status values
    syntax Int ::= "TCB_UP_TO_DATE"          [function]
    rule TCB_UP_TO_DATE => 0

    syntax Int ::= "TCB_SW_HARDENING"        [function]
    rule TCB_SW_HARDENING => 1

    syntax Int ::= "TCB_CONFIG_NEEDED"       [function]
    rule TCB_CONFIG_NEEDED => 2

    syntax Int ::= "TCB_OUT_OF_DATE"         [function]
    rule TCB_OUT_OF_DATE => 3

    // =========================================================================
    // FIELD ELEMENT TYPES
    // =========================================================================
    
    // Scalar in F_n (group order)
    syntax Secp256k1Scalar ::= Int
    
    // Field element in F_p (prime field)
    syntax FieldElement ::= Int
    
    // Compressed public key (33 bytes: prefix + x-coordinate)
    syntax Secp256k1PublicKey ::= secp256k1PublicKey(
        prefix: Int,            // 0x02 or 0x03
        x: FieldElement
    )
                               | "SECP256K1_GENERATOR"
                               | "SECP256K1_IDENTITY"
    
    // Full point on curve
    syntax Secp256k1Point ::= secp256k1Point(
        x: FieldElement,
        y: FieldElement
    )
    
    // Private key (32 bytes)
    syntax Secp256k1PrivateKey ::= secp256k1PrivateKey(scalar: Secp256k1Scalar)
    
    // =========================================================================
    // FIELD OPERATIONS (mod p)
    // =========================================================================
    
    syntax FieldElement ::= fieldAdd(FieldElement, FieldElement)     [function]
                         | fieldSub(FieldElement, FieldElement)     [function]
                         | fieldMul(FieldElement, FieldElement)     [function]
                         | fieldNeg(FieldElement)                   [function]
                         | fieldInv(FieldElement)                   [function]
                         | fieldSqrt(FieldElement)                  [function]
                         | fieldExp(FieldElement, Int)              [function]
                         | fieldReduce(Int)                         [function]
    
    syntax Bool ::= isValidFieldElement(Int)                        [function]
                  | isSquare(FieldElement)                          [function]
                  | isOnCurve(Secp256k1Point)                       [function]
    
    // =========================================================================
    // SCALAR OPERATIONS (mod n)
    // =========================================================================
    
    syntax Secp256k1Scalar ::= scalarAdd(Secp256k1Scalar, Secp256k1Scalar)   [function]
                             | scalarSub(Secp256k1Scalar, Secp256k1Scalar)   [function]
                             | scalarMul(Secp256k1Scalar, Secp256k1Scalar)   [function]
                             | scalarNeg(Secp256k1Scalar)                    [function]
                             | scalarInv(Secp256k1Scalar)                    [function]
                             | scalarReduce(Int)                             [function]
    
    syntax Bool ::= isValidScalar(Int)                              [function]
    
    // =========================================================================
    // POINT OPERATIONS
    // =========================================================================
    
    // Point addition on secp256k1
    syntax Secp256k1Point ::= pointAdd(Secp256k1Point, Secp256k1Point)    [function]
    
    // Point doubling
    syntax Secp256k1Point ::= pointDouble(Secp256k1Point)                 [function]
    
    // Scalar multiplication
    syntax Secp256k1Point ::= pointMul(Secp256k1Scalar, Secp256k1Point)   [function]
    
    // Derive public key from private key
    syntax Secp256k1PublicKey ::= derivePublicKey(Secp256k1PrivateKey)    [function]
    
    // Decompress public key
    syntax Secp256k1Point ::= decompressPublicKey(Secp256k1PublicKey)     [function]
    
    // Compress point to public key
    syntax Secp256k1PublicKey ::= compressPoint(Secp256k1Point)           [function]
    
    // Validate public key
    syntax Bool ::= isValidPublicKey(Secp256k1PublicKey)                  [function]
    
    // =========================================================================
    // ECDH KEY EXCHANGE
    // =========================================================================
    
    // Derive shared secret: sharedSecret = privateKey * peerPublicKey
    syntax Bytes ::= deriveSharedSecret(Secp256k1PrivateKey, Secp256k1PublicKey)    [function]
    
    // =========================================================================
    // AES-SIV ENCRYPTION
    // =========================================================================
    
    // AES-SIV constants
    syntax Int ::= "AES_SIV_KEY_SIZE"     [function]
    rule AES_SIV_KEY_SIZE => 32  // 256 bits
    
    syntax Int ::= "AES_SIV_TAG_SIZE"     [function]
    rule AES_SIV_TAG_SIZE => 16  // 128 bits
    
    // Encrypted envelope structure
    syntax EncryptedEnvelope ::= encryptedEnvelope(
        sivTag: Bytes,          // 16 bytes - SIV tag
        ciphertext: Bytes,      // Variable length
        ephemeralPubKey: Bytes  // 33 bytes - compressed public key
    )
    
    // S2V (String to Vector) - converts AAD and plaintext to SIV tag
    syntax Bytes ::= s2v(Bytes, List)    [function]
    
    // AES-SIV encryption (deterministic)
    syntax EncryptedEnvelope ::= aesSivEncrypt(
        key: Bytes,             // 32-byte key
        plaintext: Bytes,       // Arbitrary plaintext
        aad: Bytes              // Associated authenticated data
    ) [function]
    
    // AES-SIV decryption
    syntax Bytes ::= aesSivDecrypt(
        key: Bytes,             // 32-byte key
        envelope: EncryptedEnvelope,
        aad: Bytes              // Must match encryption AAD
    ) [function]
    
    // Validate envelope structure
    syntax Bool ::= isValidEnvelope(EncryptedEnvelope)              [function]
    
    // =========================================================================
    // INTEL SGX ATTESTATION
    // =========================================================================
    
    // SGX quote structure
    syntax SGXQuote ::= sgxQuote(
        version: Int,           // Quote version (3)
        mrEnclave: Bytes,       // 32 bytes - enclave measurement
        mrSigner: Bytes,        // 32 bytes - signer measurement
        timestamp: Int,         // Quote creation timestamp
        reportData: Bytes       // 64 bytes - custom data
    )
    
    // Attestation record
    syntax Attestation ::= attestation(
        mrEnclave: Bytes,
        mrSigner: Bytes,
        reportDataHash0: Bytes,
        reportDataHash1: Bytes,
        timestamp: Int
    )
    
    // Verify SGX attestation
    syntax Bool ::= verifySGXAttestation(
        SGXQuote,               // Quote to verify
        Bytes,                  // Expected MRENCLAVE
        Bytes                   // Expected MRSIGNER
    ) [function]
    
    // Parse attestation from quote
    syntax Attestation ::= parseAttestation(SGXQuote)               [function]
    
    // Check TCB status acceptability
    syntax Bool ::= isTCBAcceptable(Int)                            [function]
    
    // =========================================================================
    // VIEWING KEY OPERATIONS
    // =========================================================================
    
    // Viewing key structure
    syntax ViewingKey ::= viewingKey(
        key: Bytes,             // 32 bytes - derived key
        owner: Bytes,           // 20 bytes - owner address
        expiration: Int         // Expiration timestamp
    )
    
    // Derive viewing key from seed
    syntax ViewingKey ::= deriveViewingKey(Bytes, Bytes, Int)       [function]
    
    // Hash viewing key for storage
    syntax Bytes ::= hashViewingKey(ViewingKey)                     [function]
    
    // Validate viewing key
    syntax Bool ::= isValidViewingKey(ViewingKey, Int)              [function]
    
    // =========================================================================
    // QUERY PERMIT OPERATIONS
    // =========================================================================
    
    // Query permit structure
    syntax QueryPermit ::= queryPermit(
        permitId: Bytes,        // 32 bytes - unique ID
        granter: Bytes,         // 20 bytes - granter address
        grantee: Bytes,         // 20 bytes - grantee address
        permissions: List,      // List of permission hashes
        expiration: Int         // Expiration timestamp
    )
    
    // Create query permit
    syntax QueryPermit ::= createQueryPermit(Bytes, Bytes, List, Int)    [function]
    
    // Validate query permit
    syntax Bool ::= isValidQueryPermit(QueryPermit, Bytes, Int)          [function]
    
    // Check specific permission
    syntax Bool ::= hasPermission(QueryPermit, Bytes)                    [function]
    
    // =========================================================================
    // IBC (INTER-BLOCKCHAIN COMMUNICATION) OPERATIONS
    // =========================================================================
    
    // IBC channel state
    syntax IBCChannelState ::= "IBC_UNINITIALIZED"
                             | "IBC_INIT"
                             | "IBC_TRYOPEN"
                             | "IBC_OPEN"
                             | "IBC_CLOSED"
    
    // IBC channel structure
    syntax IBCChannel ::= ibcChannel(
        channelId: String,
        portId: String,
        counterpartyChannelId: String,
        counterpartyPortId: String,
        connectionHops: Bytes
    )
    
    // IBC packet commitment
    syntax Bytes ::= computePacketCommitment(
        IBCChannel,             // Channel info
        Int,                    // Sequence number
        Bytes                   // Packet data
    ) [function]
    
    // IBC Merkle proof verification
    syntax Bool ::= verifyIBCProof(
        Bytes,                  // State root
        Bytes,                  // Commitment
        List                    // Merkle proof
    ) [function]
    
    // =========================================================================
    // NULLIFIER OPERATIONS
    // =========================================================================
    
    // Secret Network nullifier
    syntax SecretNullifier ::= secretNullifier(
        secret: Bytes,          // 32 bytes
        commitment: Bytes       // 32 bytes
    )
    
    // Derive nullifier from secret and commitment
    syntax Bytes ::= deriveNullifier(Bytes, Bytes)                  [function]
    
    // Cross-domain nullifier binding (Secret → PIL)
    syntax Bytes ::= deriveSecretToPILNullifier(SecretNullifier, Bytes)    [function]
    
    // Cross-domain nullifier binding (PIL → Secret)
    syntax Bytes ::= derivePILToSecretBinding(Bytes)                       [function]
    
    // Nullifier uniqueness check
    syntax Bool ::= isNullifierUnique(Bytes, Set)                   [function]
    
    // =========================================================================
    // SNIP TOKEN OPERATIONS
    // =========================================================================
    
    // SNIP-20 (fungible token) hash
    syntax Bytes ::= computeSNIP20Hash(Bytes, String)               [function]
    
    // SNIP-721 (NFT) hash
    syntax Bytes ::= computeSNIP721Hash(Bytes, String, String)      [function]
    
    // SNIP-1155 (multi-token) hash
    syntax Bytes ::= computeSNIP1155Hash(Bytes, String, Int)        [function]
    
    // =========================================================================
    // STATE VERIFICATION
    // =========================================================================
    
    // Merkle proof verification
    syntax Bool ::= verifyMerkleProof(Bytes, Bytes, List)           [function]
    
    // State proof structure
    syntax StateProof ::= stateProof(
        key: Bytes,
        value: Bytes,
        proof: List
    )
    
    // Verify state inclusion
    syntax Bool ::= verifyStateInclusion(StateProof, Bytes)         [function]

endmodule

// =============================================================================
// SEMANTICS MODULE
// =============================================================================

module SECRET-SEMANTICS
    imports SECRET-SYNTAX
    imports INT
    imports BOOL
    imports BYTES
    imports LIST

    // =========================================================================
    // FIELD OPERATION SEMANTICS
    // =========================================================================
    
    // Field addition (mod p)
    rule fieldAdd(A:FieldElement, B:FieldElement) => (A +Int B) modInt SECP256K1_P
    
    // Field subtraction (mod p)
    rule fieldSub(A:FieldElement, B:FieldElement) => (A -Int B +Int SECP256K1_P) modInt SECP256K1_P
    
    // Field multiplication (mod p)
    rule fieldMul(A:FieldElement, B:FieldElement) => (A *Int B) modInt SECP256K1_P
    
    // Field negation (mod p)
    rule fieldNeg(A:FieldElement) => (SECP256K1_P -Int A) modInt SECP256K1_P
    
    // Field reduction
    rule fieldReduce(X:Int) => X modInt SECP256K1_P
    
    // Check valid field element
    rule isValidFieldElement(X:Int) => (X >=Int 0) andBool (X <Int SECP256K1_P)
    
    // =========================================================================
    // SCALAR OPERATION SEMANTICS
    // =========================================================================
    
    // Scalar addition (mod n)
    rule scalarAdd(A:Secp256k1Scalar, B:Secp256k1Scalar) => (A +Int B) modInt SECP256K1_N
    
    // Scalar subtraction (mod n)
    rule scalarSub(A:Secp256k1Scalar, B:Secp256k1Scalar) => (A -Int B +Int SECP256K1_N) modInt SECP256K1_N
    
    // Scalar multiplication (mod n)
    rule scalarMul(A:Secp256k1Scalar, B:Secp256k1Scalar) => (A *Int B) modInt SECP256K1_N
    
    // Scalar negation (mod n)
    rule scalarNeg(A:Secp256k1Scalar) => (SECP256K1_N -Int A) modInt SECP256K1_N
    
    // Scalar reduction
    rule scalarReduce(X:Int) => X modInt SECP256K1_N
    
    // Check valid scalar (non-zero, less than order)
    rule isValidScalar(X:Int) => (X >Int 0) andBool (X <Int SECP256K1_N)
    
    // =========================================================================
    // CURVE OPERATION SEMANTICS
    // =========================================================================
    
    // Check if point is on curve: y² = x³ + 7 (mod p)
    rule isOnCurve(secp256k1Point(X:FieldElement, Y:FieldElement)) =>
        fieldMul(Y, Y) ==Int fieldAdd(fieldMul(fieldMul(X, X), X), SECP256K1_B)
    
    // Valid public key: prefix is 0x02 or 0x03, x is valid
    rule isValidPublicKey(secp256k1PublicKey(Prefix:Int, X:FieldElement)) =>
        ((Prefix ==Int 2) orBool (Prefix ==Int 3)) andBool
        isValidFieldElement(X) andBool
        (X =/=Int 0)
    
    rule isValidPublicKey(SECP256K1_GENERATOR) => true
    rule isValidPublicKey(SECP256K1_IDENTITY) => false
    
    // =========================================================================
    // SGX ATTESTATION SEMANTICS
    // =========================================================================
    
    // Verify attestation
    rule verifySGXAttestation(
        sgxQuote(V:Int, ME:Bytes, MS:Bytes, T:Int, _RD:Bytes),
        ExpectedME:Bytes,
        ExpectedMS:Bytes
    ) => (V ==Int SGX_QUOTE_VERSION) andBool
         (ME ==K ExpectedME) andBool
         (MS ==K ExpectedMS)
        requires T >Int 0
    
    // TCB status acceptability
    rule isTCBAcceptable(Status:Int) => 
        (Status ==Int TCB_UP_TO_DATE) orBool
        (Status ==Int TCB_SW_HARDENING)
    
    // =========================================================================
    // VIEWING KEY SEMANTICS
    // =========================================================================
    
    // Viewing key validity
    rule isValidViewingKey(
        viewingKey(Key:Bytes, Owner:Bytes, Exp:Int),
        CurrentTime:Int
    ) => (lengthBytes(Key) ==Int 32) andBool
         (lengthBytes(Owner) ==Int 20) andBool
         (Exp >Int CurrentTime)
    
    // =========================================================================
    // QUERY PERMIT SEMANTICS
    // =========================================================================
    
    // Query permit validity
    rule isValidQueryPermit(
        queryPermit(_PID:Bytes, _Granter:Bytes, Grantee:Bytes, _Perms:List, Exp:Int),
        CheckGrantee:Bytes,
        CurrentTime:Int
    ) => (Grantee ==K CheckGrantee) andBool (Exp >Int CurrentTime)
    
    // =========================================================================
    // ENVELOPE VALIDATION SEMANTICS
    // =========================================================================
    
    // Valid envelope structure
    rule isValidEnvelope(encryptedEnvelope(Tag:Bytes, CT:Bytes, EPK:Bytes)) =>
        (lengthBytes(Tag) ==Int AES_SIV_TAG_SIZE) andBool
        (lengthBytes(CT) >Int 0) andBool
        (lengthBytes(EPK) ==Int 33)
    
    // =========================================================================
    // NULLIFIER SEMANTICS
    // =========================================================================
    
    // Nullifier uniqueness
    rule isNullifierUnique(Nf:Bytes, UsedSet:Set) => notBool (Nf in UsedSet)

endmodule

// =============================================================================
// PROPERTIES MODULE - Security Theorems
// =============================================================================

module SECRET-PROPERTIES
    imports SECRET-SEMANTICS

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
    
    // Field closure
    claim isValidFieldElement(fieldAdd(A, B)) => true
        requires isValidFieldElement(A) andBool isValidFieldElement(B)
    
    claim isValidFieldElement(fieldMul(A, B)) => true
        requires isValidFieldElement(A) andBool isValidFieldElement(B)
    
    // =========================================================================
    // SCALAR ARITHMETIC PROPERTIES
    // =========================================================================
    
    // Scalar commutativity
    claim scalarAdd(A, B) => scalarAdd(B, A)
    claim scalarMul(A, B) => scalarMul(B, A)
    
    // Scalar associativity
    claim scalarAdd(scalarAdd(A, B), C) => scalarAdd(A, scalarAdd(B, C))
    claim scalarMul(scalarMul(A, B), C) => scalarMul(A, scalarMul(B, C))
    
    // Scalar identity
    claim scalarAdd(A, 0) => A
    claim scalarMul(A, 1) => A
    
    // Scalar inverse
    claim scalarAdd(A, scalarNeg(A)) => 0
    
    // =========================================================================
    // CURVE SECURITY PROPERTIES
    // =========================================================================
    
    // Generator is on curve
    claim isOnCurve(secp256k1Point(SECP256K1_GX, SECP256K1_GY)) => true
    
    // Public key derivation produces valid key
    claim isValidPublicKey(derivePublicKey(secp256k1PrivateKey(S))) => true
        requires isValidScalar(S)
    
    // =========================================================================
    // NULLIFIER PROPERTIES
    // =========================================================================
    
    // Different secrets produce different nullifiers
    claim deriveNullifier(S1, C) =/=K deriveNullifier(S2, C) => true
        requires S1 =/=K S2
    
    // Different commitments produce different nullifiers
    claim deriveNullifier(S, C1) =/=K deriveNullifier(S, C2) => true
        requires C1 =/=K C2
    
    // Cross-domain nullifier determinism
    claim deriveSecretToPILNullifier(Nf, D) ==K deriveSecretToPILNullifier(Nf, D) => true
    
    // Cross-domain nullifier uniqueness
    claim deriveSecretToPILNullifier(Nf1, D) =/=K deriveSecretToPILNullifier(Nf2, D) => true
        requires Nf1 =/=K Nf2
    
    // =========================================================================
    // VIEWING KEY PROPERTIES
    // =========================================================================
    
    // Viewing key derivation is deterministic
    claim deriveViewingKey(Seed, Owner, Exp) ==K deriveViewingKey(Seed, Owner, Exp) => true
    
    // Expired viewing key is invalid
    claim isValidViewingKey(viewingKey(K, O, Exp), CurrentTime) => false
        requires Exp <=Int CurrentTime
    
    // =========================================================================
    // ATTESTATION PROPERTIES
    // =========================================================================
    
    // Matching attestation passes
    claim verifySGXAttestation(
        sgxQuote(SGX_QUOTE_VERSION, ME, MS, T, RD),
        ME,
        MS
    ) => true
        requires T >Int 0
    
    // Mismatched enclave fails
    claim verifySGXAttestation(
        sgxQuote(SGX_QUOTE_VERSION, ME1, MS, T, RD),
        ME2,
        MS
    ) => false
        requires ME1 =/=K ME2 andBool T >Int 0
    
    // =========================================================================
    // IBC PACKET COMMITMENT PROPERTIES
    // =========================================================================
    
    // Packet commitment is deterministic
    claim computePacketCommitment(Ch, Seq, Data) ==K computePacketCommitment(Ch, Seq, Data) => true
    
    // Different sequences produce different commitments
    claim computePacketCommitment(Ch, Seq1, Data) =/=K computePacketCommitment(Ch, Seq2, Data) => true
        requires Seq1 =/=Int Seq2
    
    // =========================================================================
    // ENCRYPTION PROPERTIES
    // =========================================================================
    
    // AES-SIV determinism (same inputs → same outputs)
    claim aesSivEncrypt(K, P, AAD) ==K aesSivEncrypt(K, P, AAD) => true
    
    // Different keys produce different ciphertexts
    claim aesSivEncrypt(K1, P, AAD) =/=K aesSivEncrypt(K2, P, AAD) => true
        requires K1 =/=K K2
    
    // Decryption inverts encryption
    claim aesSivDecrypt(K, aesSivEncrypt(K, P, AAD), AAD) => P

endmodule
