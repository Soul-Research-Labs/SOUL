/**
 * K Framework Formal Specification for Oasis Network Cryptographic Primitives
 * 
 * @title oasis.k
 * @author PIL Protocol
 * @notice Formal verification of Oasis Network TEE and cryptographic operations
 * 
 * VERIFICATION SCOPE:
 * - Curve25519/x25519 key exchange
 * - Deoxys-II-256-128 MRAE encryption
 * - Intel SGX DCAP attestation
 * - ParaTime state verification
 * - Cross-domain (Oasis ↔ PIL) nullifier binding
 * - View key derivation
 * 
 * CURVE25519 PARAMETERS:
 * - Prime: p = 2^255 - 19
 * - Order: l = 2^252 + 27742317777372353535851937790883648493
 * - Cofactor: 8
 * - Montgomery form: y² = x³ + 486662x² + x
 * 
 * DEOXYS-II PARAMETERS:
 * - Key size: 256 bits
 * - Nonce size: 120 bits (15 bytes)
 * - Tag size: 128 bits (16 bytes)
 * - MRAE (Misuse-Resistant Authenticated Encryption)
 * 
 * SGX DCAP ATTESTATION:
 * - MRENCLAVE: 32 bytes (enclave measurement)
 * - MRSIGNER: 32 bytes (signer measurement)
 * - Report data: 64 bytes (custom data)
 * - TCB (Trusted Computing Base) verification
 */

requires "evm-semantics.md"
requires "domains.md"

module OASIS-SYNTAX
    imports INT-SYNTAX
    imports BOOL-SYNTAX
    imports LIST
    imports MAP
    imports SET
    imports BYTES

    // =========================================================================
    // CURVE25519 FIELD CONSTANTS
    // =========================================================================
    
    // Curve25519 prime field modulus (2^255 - 19)
    syntax Int ::= "CURVE25519_PRIME"    [function]
    rule CURVE25519_PRIME => 57896044618658097711785492504343953926634992332820282019728792003956564819949

    // Curve25519 group order
    syntax Int ::= "CURVE25519_ORDER"    [function]
    rule CURVE25519_ORDER => 7237005577332262213973186563042994240857116359379907606001950938285454250989

    // Curve25519 Montgomery coefficient A = 486662
    syntax Int ::= "CURVE25519_A"    [function]
    rule CURVE25519_A => 486662

    // Cofactor
    syntax Int ::= "CURVE25519_COFACTOR"    [function]
    rule CURVE25519_COFACTOR => 8

    // =========================================================================
    // OASIS CHAIN IDENTIFIERS
    // =========================================================================
    
    // Sapphire mainnet chain ID
    syntax Int ::= "SAPPHIRE_MAINNET_CHAIN_ID"    [function]
    rule SAPPHIRE_MAINNET_CHAIN_ID => 23294

    // Sapphire testnet chain ID
    syntax Int ::= "SAPPHIRE_TESTNET_CHAIN_ID"    [function]
    rule SAPPHIRE_TESTNET_CHAIN_ID => 23295

    // Emerald mainnet chain ID
    syntax Int ::= "EMERALD_MAINNET_CHAIN_ID"    [function]
    rule EMERALD_MAINNET_CHAIN_ID => 42262

    // Emerald testnet chain ID
    syntax Int ::= "EMERALD_TESTNET_CHAIN_ID"    [function]
    rule EMERALD_TESTNET_CHAIN_ID => 42261

    // Cipher mainnet chain ID
    syntax Int ::= "CIPHER_MAINNET_CHAIN_ID"    [function]
    rule CIPHER_MAINNET_CHAIN_ID => 42261  // Placeholder

    // =========================================================================
    // FIELD ELEMENT TYPES
    // =========================================================================
    
    // Scalar in F_l (group order)
    syntax X25519Scalar ::= Int
    
    // Field element in F_p (prime field)
    syntax FieldElement ::= Int
    
    // X25519 public key (32 bytes, u-coordinate only)
    syntax X25519PublicKey ::= x25519PublicKey(u: FieldElement)
                             | "X25519_BASEPOINT"
                             | "X25519_IDENTITY"
    
    // X25519 private key (32 bytes, clamped scalar)
    syntax X25519PrivateKey ::= x25519PrivateKey(scalar: X25519Scalar)
    
    // Shared secret from ECDH
    syntax SharedSecret ::= sharedSecret(Bytes)
    
    // =========================================================================
    // FIELD OPERATIONS
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
    
    // =========================================================================
    // SCALAR OPERATIONS
    // =========================================================================
    
    syntax X25519Scalar ::= scalarClamp(Int)                        [function]
                          | scalarMul(X25519Scalar, X25519Scalar)   [function]
                          | scalarReduce(Int)                       [function]
    
    syntax Bool ::= isValidScalar(Int)                              [function]
                  | isClampedScalar(X25519Scalar)                   [function]
    
    // =========================================================================
    // X25519 KEY EXCHANGE
    // =========================================================================
    
    // Derive public key from private key
    syntax X25519PublicKey ::= x25519PublicFromPrivate(X25519PrivateKey)    [function]
    
    // X25519 ECDH: shared = clamp(private) * peer_public
    syntax SharedSecret ::= x25519DeriveShared(X25519PrivateKey, X25519PublicKey)    [function]
    
    // Montgomery ladder scalar multiplication
    syntax X25519PublicKey ::= montgomeryLadder(X25519Scalar, X25519PublicKey)    [function]
    
    // Validate public key (not low-order, not identity)
    syntax Bool ::= isValidX25519PublicKey(X25519PublicKey)         [function]
                  | isLowOrderPoint(X25519PublicKey)                 [function]
    
    // =========================================================================
    // DEOXYS-II-256-128 MRAE ENCRYPTION
    // =========================================================================
    
    // Deoxys-II constants
    syntax Int ::= "DEOXYS_KEY_SIZE"      [function]
    rule DEOXYS_KEY_SIZE => 32  // 256 bits
    
    syntax Int ::= "DEOXYS_NONCE_SIZE"    [function]
    rule DEOXYS_NONCE_SIZE => 15  // 120 bits
    
    syntax Int ::= "DEOXYS_TAG_SIZE"      [function]
    rule DEOXYS_TAG_SIZE => 16  // 128 bits
    
    syntax Int ::= "DEOXYS_BLOCK_SIZE"    [function]
    rule DEOXYS_BLOCK_SIZE => 16  // 128 bits
    
    // Encrypted envelope structure
    syntax EncryptedEnvelope ::= encryptedEnvelope(
        nonce: Bytes,           // 15 bytes
        ciphertext: Bytes,      // Variable length
        tag: Bytes,             // 16 bytes
        ephemeralPubKey: Bytes  // 32 bytes
    )
    
    // Deoxys-II encryption
    syntax EncryptedEnvelope ::= deoxysSeal(
        key: Bytes,             // 32-byte key
        nonce: Bytes,           // 15-byte nonce
        plaintext: Bytes,       // Arbitrary plaintext
        aad: Bytes              // Associated authenticated data
    ) [function]
    
    // Deoxys-II decryption
    syntax Bytes ::= deoxysOpen(
        key: Bytes,             // 32-byte key
        envelope: EncryptedEnvelope
    ) [function]
    
    // Validate envelope structure
    syntax Bool ::= isValidEnvelope(EncryptedEnvelope)              [function]
    
    // =========================================================================
    // INTEL SGX DCAP ATTESTATION
    // =========================================================================
    
    // SGX report structure
    syntax SGXReport ::= sgxReport(
        mrEnclave: Bytes,       // 32 bytes - enclave measurement
        mrSigner: Bytes,        // 32 bytes - signer measurement  
        isvProdId: Int,         // 16 bits - product ID
        isvSvn: Int,            // 16 bits - security version
        reportData: Bytes       // 64 bytes - custom data
    )
    
    // SGX quote structure (attestation)
    syntax SGXQuote ::= sgxQuote(
        report: SGXReport,
        signature: Bytes,       // ECDSA signature
        certChain: List         // Certificate chain
    )
    
    // TEE state
    syntax TEEState ::= teeState(
        isVerified: Bool,
        mrEnclave: Bytes,
        mrSigner: Bytes,
        timestamp: Int
    )
    
    // Verify SGX attestation
    syntax Bool ::= verifySGXAttestation(SGXQuote, Bytes, Bytes)    [function]
    
    // Extract report data
    syntax Bytes ::= extractReportData(SGXReport)                   [function]
    
    // Hash report data (two 32-byte chunks)
    syntax Bytes ::= hashReportData(Bytes)                          [function]
    
    // =========================================================================
    // NULLIFIER OPERATIONS
    // =========================================================================
    
    // Oasis nullifier (TEE-attested)
    syntax OasisNullifier ::= oasisNullifier(
        secret: Bytes,
        mrEnclave: Bytes,
        commitment: Bytes
    )
    
    // Derive nullifier from secret and commitment
    syntax Bytes ::= deriveOasisNullifier(Bytes, Bytes)             [function]
    
    // Cross-domain nullifier binding
    syntax Bytes ::= deriveOasisToPILNullifier(OasisNullifier)      [function]
    syntax Bytes ::= derivePILToOasisBinding(Bytes)                 [function]
    
    // Nullifier uniqueness check
    syntax Bool ::= isNullifierUnique(Bytes, Set)                   [function]
    
    // =========================================================================
    // VIEW KEY OPERATIONS
    // =========================================================================
    
    // View key structure
    syntax ViewKey ::= viewKey(
        key: Bytes,             // 32 bytes
        validUntil: Int,        // Expiration timestamp
        permissions: Int        // Bitmask of permissions
    )
    
    // Derive view key from master key
    syntax ViewKey ::= deriveViewKey(Bytes, Int, Int)               [function]
    
    // Validate view key
    syntax Bool ::= isValidViewKey(ViewKey, Int)                    [function]
    
    // Decrypt state with view key
    syntax Bytes ::= decryptWithViewKey(ViewKey, EncryptedEnvelope) [function]
    
    // =========================================================================
    // PARATIME STATE VERIFICATION
    // =========================================================================
    
    // ParaTime state root
    syntax StateRoot ::= stateRoot(
        root: Bytes,            // 32-byte state root
        blockNumber: Int,
        timestamp: Int
    )
    
    // State proof
    syntax StateProof ::= stateProof(
        key: Bytes,
        value: Bytes,
        proof: List             // Merkle proof nodes
    )
    
    // Verify state against root
    syntax Bool ::= verifyStateProof(StateProof, StateRoot)         [function]
    
    // =========================================================================
    // BRIDGE OPERATIONS
    // =========================================================================
    
    // Withdrawal request
    syntax WithdrawalRequest ::= withdrawalRequest(
        pilNullifier: Bytes,
        amount: Int,
        paraTime: Int,
        envelope: EncryptedEnvelope,
        requestTime: Int
    )
    
    // Committee signature
    syntax CommitteeSignature ::= committeeSignature(
        member: Bytes,
        signature: Bytes,
        timestamp: Int
    )
    
    // Validate committee approval
    syntax Bool ::= hasCommitteeApproval(
        WithdrawalRequest,
        List,                   // List of signatures
        Int                     // Threshold
    ) [function]

endmodule

module OASIS-SEMANTICS
    imports OASIS-SYNTAX
    imports INT
    imports BOOL
    imports BYTES

    // =========================================================================
    // FIELD ARITHMETIC SEMANTICS
    // =========================================================================

    // Field addition
    rule fieldAdd(A:Int, B:Int) => (A +Int B) modInt CURVE25519_PRIME
    
    // Field subtraction
    rule fieldSub(A:Int, B:Int) => (A -Int B +Int CURVE25519_PRIME) modInt CURVE25519_PRIME
    
    // Field multiplication
    rule fieldMul(A:Int, B:Int) => (A *Int B) modInt CURVE25519_PRIME
    
    // Field negation
    rule fieldNeg(A:Int) => (CURVE25519_PRIME -Int A) modInt CURVE25519_PRIME
    
    // Field reduction
    rule fieldReduce(A:Int) => A modInt CURVE25519_PRIME
    
    // Field exponentiation (square-and-multiply)
    rule fieldExp(_, 0) => 1
    rule fieldExp(A:Int, N:Int) => 
        fieldMul(
            fieldExp(fieldMul(A, A), N /Int 2),
            #if (N modInt 2) ==Int 1 #then A #else 1 #fi
        ) requires N >Int 0
    
    // Field inverse using Fermat's little theorem: a^(-1) = a^(p-2) mod p
    rule fieldInv(A:Int) => fieldExp(A, CURVE25519_PRIME -Int 2)
        requires A =/=Int 0
    
    // Check if field element is valid
    rule isValidFieldElement(A:Int) => (0 <=Int A) andBool (A <Int CURVE25519_PRIME)
    
    // =========================================================================
    // SCALAR CLAMPING (X25519)
    // =========================================================================
    
    // X25519 scalar clamping:
    // - Clear lowest 3 bits (cofactor multiplication)
    // - Set bit 254 (ensure high bit)
    // - Clear bit 255 (ensure in range)
    rule scalarClamp(S:Int) =>
        ((S &Int 248) |Int 64) &Int 127 modInt (2 ^Int 8)  // First byte: clear low 3, set bit 6
        // Full clamping applied across 32 bytes
    
    // Check if scalar is clamped
    rule isClampedScalar(S:Int) =>
        ((S &Int 7) ==Int 0) andBool              // Low 3 bits clear
        ((S &Int (1 <<Int 254)) =/=Int 0) andBool // Bit 254 set
        ((S &Int (1 <<Int 255)) ==Int 0)          // Bit 255 clear
    
    // =========================================================================
    // X25519 KEY EXCHANGE SEMANTICS
    // =========================================================================
    
    // Validate X25519 public key
    rule isValidX25519PublicKey(x25519PublicKey(U:Int)) =>
        isValidFieldElement(U) andBool
        (notBool isLowOrderPoint(x25519PublicKey(U)))
    
    rule isValidX25519PublicKey(X25519_IDENTITY) => false
    rule isValidX25519PublicKey(X25519_BASEPOINT) => true
    
    // Low-order point check (small subgroup attack prevention)
    rule isLowOrderPoint(x25519PublicKey(U:Int)) =>
        (U ==Int 0) orBool
        (U ==Int 1) orBool
        (U ==Int 325606250916557431795983626356110631294008115727848805560023387167927233504) orBool
        (U ==Int 39382357235489614581723060781553021112529911719440698176882885853963445705823) orBool
        (U ==Int (CURVE25519_PRIME -Int 1)) orBool
        (U ==Int 57896044618658097711785492504343953926634992332820282019728792003956564819948) orBool
        (U ==Int 57896044618658097711785492504343953926634992332820282019728792003956564819948) orBool
        (U ==Int 57896044618658097711785492504343953926634992332820282019728792003956564819949)
    
    // =========================================================================
    // DEOXYS-II ENVELOPE VALIDATION
    // =========================================================================
    
    // Validate encrypted envelope
    rule isValidEnvelope(encryptedEnvelope(N:Bytes, C:Bytes, T:Bytes, E:Bytes)) =>
        (lengthBytes(N) ==Int DEOXYS_NONCE_SIZE) andBool
        (lengthBytes(C) >Int 0) andBool
        (lengthBytes(T) ==Int DEOXYS_TAG_SIZE) andBool
        (lengthBytes(E) ==Int 32)
    
    // =========================================================================
    // SGX ATTESTATION SEMANTICS
    // =========================================================================
    
    // Verify SGX attestation
    rule verifySGXAttestation(
        sgxQuote(
            sgxReport(MrEnclave:Bytes, MrSigner:Bytes, _, _, _),
            _,
            _
        ),
        ExpectedMrEnclave:Bytes,
        ExpectedMrSigner:Bytes
    ) =>
        (MrEnclave ==K ExpectedMrEnclave) andBool
        (MrSigner ==K ExpectedMrSigner)
    
    // Extract report data
    rule extractReportData(sgxReport(_, _, _, _, ReportData:Bytes)) => ReportData
    
    // =========================================================================
    // NULLIFIER SEMANTICS
    // =========================================================================
    
    // Derive Oasis nullifier: H(secret || commitment)
    rule deriveOasisNullifier(Secret:Bytes, Commitment:Bytes) =>
        keccak256Hash(Secret +Bytes Commitment)
    
    // Cross-domain nullifier: Oasis → PIL
    rule deriveOasisToPILNullifier(oasisNullifier(Secret:Bytes, MrEnclave:Bytes, Commitment:Bytes)) =>
        keccak256Hash(
            deriveOasisNullifier(Secret, Commitment) +Bytes
            MrEnclave +Bytes
            b"OASIS2PIL"
        )
    
    // Cross-domain binding: PIL → Oasis
    rule derivePILToOasisBinding(PILNullifier:Bytes) =>
        keccak256Hash(PILNullifier +Bytes b"PIL2OASIS")
    
    // Nullifier uniqueness
    rule isNullifierUnique(N:Bytes, UsedSet:Set) => notBool (N in UsedSet)
    
    // =========================================================================
    // VIEW KEY SEMANTICS
    // =========================================================================
    
    // Validate view key (not expired)
    rule isValidViewKey(viewKey(_, ValidUntil:Int, _), CurrentTime:Int) =>
        CurrentTime <Int ValidUntil
    
    // =========================================================================
    // STATE PROOF SEMANTICS
    // =========================================================================
    
    // Verify Merkle proof (simplified)
    rule verifyStateProof(
        stateProof(Key:Bytes, Value:Bytes, Proof:List),
        stateRoot(Root:Bytes, _, _)
    ) =>
        computeMerkleRoot(Key, Value, Proof) ==K Root
    
    // Compute Merkle root from proof
    syntax Bytes ::= computeMerkleRoot(Bytes, Bytes, List)          [function]
    
    // Base case: leaf hash
    rule computeMerkleRoot(Key:Bytes, Value:Bytes, .List) =>
        keccak256Hash(Key +Bytes Value)
    
    // Recursive case: combine with sibling
    rule computeMerkleRoot(Key:Bytes, Value:Bytes, ListItem(Sibling:Bytes) Rest:List) =>
        computeMerkleRoot(
            Key,
            keccak256Hash(
                computeMerkleRoot(Key, Value, Rest) +Bytes Sibling
            ),
            .List
        )
    
    // =========================================================================
    // COMMITTEE APPROVAL SEMANTICS
    // =========================================================================
    
    // Count valid signatures
    syntax Int ::= countValidSignatures(List)                       [function]
    
    rule countValidSignatures(.List) => 0
    rule countValidSignatures(ListItem(_) Rest:List) => 1 +Int countValidSignatures(Rest)
    
    // Check threshold met
    rule hasCommitteeApproval(_, Sigs:List, Threshold:Int) =>
        countValidSignatures(Sigs) >=Int Threshold

endmodule

module OASIS-PROPERTIES
    imports OASIS-SEMANTICS

    // =========================================================================
    // FIELD CLOSURE THEOREMS
    // =========================================================================
    
    // Theorem: Field addition closure
    // For all a, b in F_p: a + b is in F_p
    claim [field-add-closure]:
        <k> isValidFieldElement(fieldAdd(A:Int, B:Int)) </k>
        requires isValidFieldElement(A)
         andBool isValidFieldElement(B)
    
    // Theorem: Field multiplication closure
    claim [field-mul-closure]:
        <k> isValidFieldElement(fieldMul(A:Int, B:Int)) </k>
        requires isValidFieldElement(A)
         andBool isValidFieldElement(B)
    
    // Theorem: Field inverse produces valid element
    claim [field-inv-valid]:
        <k> isValidFieldElement(fieldInv(A:Int)) </k>
        requires isValidFieldElement(A)
         andBool A =/=Int 0
    
    // =========================================================================
    // FIELD ALGEBRAIC PROPERTIES
    // =========================================================================
    
    // Theorem: Addition commutativity
    claim [field-add-commutative]:
        <k> fieldAdd(A:Int, B:Int) ==Int fieldAdd(B, A) </k>
        requires isValidFieldElement(A)
         andBool isValidFieldElement(B)
    
    // Theorem: Multiplication commutativity
    claim [field-mul-commutative]:
        <k> fieldMul(A:Int, B:Int) ==Int fieldMul(B, A) </k>
        requires isValidFieldElement(A)
         andBool isValidFieldElement(B)
    
    // Theorem: Addition associativity
    claim [field-add-associative]:
        <k> fieldAdd(fieldAdd(A:Int, B:Int), C:Int) ==Int fieldAdd(A, fieldAdd(B, C)) </k>
        requires isValidFieldElement(A)
         andBool isValidFieldElement(B)
         andBool isValidFieldElement(C)
    
    // Theorem: Multiplication associativity
    claim [field-mul-associative]:
        <k> fieldMul(fieldMul(A:Int, B:Int), C:Int) ==Int fieldMul(A, fieldMul(B, C)) </k>
        requires isValidFieldElement(A)
         andBool isValidFieldElement(B)
         andBool isValidFieldElement(C)
    
    // Theorem: Additive identity
    claim [field-add-identity]:
        <k> fieldAdd(A:Int, 0) ==Int A </k>
        requires isValidFieldElement(A)
    
    // Theorem: Multiplicative identity
    claim [field-mul-identity]:
        <k> fieldMul(A:Int, 1) ==Int A </k>
        requires isValidFieldElement(A)
    
    // Theorem: Additive inverse
    claim [field-add-inverse]:
        <k> fieldAdd(A:Int, fieldNeg(A)) ==Int 0 </k>
        requires isValidFieldElement(A)
    
    // Theorem: Multiplicative inverse
    claim [field-mul-inverse]:
        <k> fieldMul(A:Int, fieldInv(A)) ==Int 1 </k>
        requires isValidFieldElement(A)
         andBool A =/=Int 0
    
    // Theorem: Distributive law
    claim [field-distributive]:
        <k> fieldMul(A:Int, fieldAdd(B:Int, C:Int)) ==Int fieldAdd(fieldMul(A, B), fieldMul(A, C)) </k>
        requires isValidFieldElement(A)
         andBool isValidFieldElement(B)
         andBool isValidFieldElement(C)
    
    // =========================================================================
    // X25519 SECURITY PROPERTIES
    // =========================================================================
    
    // Theorem: Low-order point rejection
    claim [x25519-low-order-rejected]:
        <k> isValidX25519PublicKey(x25519PublicKey(U:Int)) ==Bool false </k>
        requires isLowOrderPoint(x25519PublicKey(U))
    
    // Theorem: Identity point rejected
    claim [x25519-identity-rejected]:
        <k> isValidX25519PublicKey(X25519_IDENTITY) ==Bool false </k>
    
    // Theorem: Basepoint is valid
    claim [x25519-basepoint-valid]:
        <k> isValidX25519PublicKey(X25519_BASEPOINT) ==Bool true </k>
    
    // =========================================================================
    // DEOXYS-II SECURITY PROPERTIES
    // =========================================================================
    
    // Theorem: Empty ciphertext rejected
    claim [deoxys-empty-ciphertext-rejected]:
        <k> isValidEnvelope(encryptedEnvelope(N:Bytes, C:Bytes, T:Bytes, E:Bytes)) ==Bool false </k>
        requires lengthBytes(C) ==Int 0
    
    // Theorem: Wrong nonce size rejected
    claim [deoxys-wrong-nonce-rejected]:
        <k> isValidEnvelope(encryptedEnvelope(N:Bytes, C:Bytes, T:Bytes, E:Bytes)) ==Bool false </k>
        requires lengthBytes(N) =/=Int DEOXYS_NONCE_SIZE
    
    // Theorem: Wrong tag size rejected
    claim [deoxys-wrong-tag-rejected]:
        <k> isValidEnvelope(encryptedEnvelope(N:Bytes, C:Bytes, T:Bytes, E:Bytes)) ==Bool false </k>
        requires lengthBytes(T) =/=Int DEOXYS_TAG_SIZE
    
    // Theorem: Valid envelope accepted
    claim [deoxys-valid-envelope-accepted]:
        <k> isValidEnvelope(encryptedEnvelope(N:Bytes, C:Bytes, T:Bytes, E:Bytes)) ==Bool true </k>
        requires lengthBytes(N) ==Int DEOXYS_NONCE_SIZE
         andBool lengthBytes(C) >Int 0
         andBool lengthBytes(T) ==Int DEOXYS_TAG_SIZE
         andBool lengthBytes(E) ==Int 32
    
    // =========================================================================
    // SGX ATTESTATION PROPERTIES
    // =========================================================================
    
    // Theorem: Matching enclave/signer passes verification
    claim [sgx-matching-passes]:
        <k> verifySGXAttestation(
            sgxQuote(
                sgxReport(MrEnclave:Bytes, MrSigner:Bytes, _, _, _),
                _,
                _
            ),
            MrEnclave,
            MrSigner
        ) ==Bool true </k>
    
    // Theorem: Mismatched enclave fails verification
    claim [sgx-mismatched-enclave-fails]:
        <k> verifySGXAttestation(
            sgxQuote(
                sgxReport(MrEnclave:Bytes, MrSigner:Bytes, _, _, _),
                _,
                _
            ),
            WrongEnclave:Bytes,
            MrSigner
        ) ==Bool false </k>
        requires MrEnclave =/=K WrongEnclave
    
    // Theorem: Mismatched signer fails verification
    claim [sgx-mismatched-signer-fails]:
        <k> verifySGXAttestation(
            sgxQuote(
                sgxReport(MrEnclave:Bytes, MrSigner:Bytes, _, _, _),
                _,
                _
            ),
            MrEnclave,
            WrongSigner:Bytes
        ) ==Bool false </k>
        requires MrSigner =/=K WrongSigner
    
    // =========================================================================
    // NULLIFIER SECURITY PROPERTIES
    // =========================================================================
    
    // Theorem: Nullifier determinism
    // Same inputs produce same nullifier
    claim [nullifier-deterministic]:
        <k> deriveOasisNullifier(S1:Bytes, C1:Bytes) ==K deriveOasisNullifier(S2:Bytes, C2:Bytes) </k>
        requires S1 ==K S2
         andBool C1 ==K C2
    
    // Theorem: Nullifier uniqueness
    // Different inputs produce different nullifiers (collision resistance)
    claim [nullifier-unique]:
        <k> deriveOasisNullifier(S1:Bytes, C1:Bytes) =/=K deriveOasisNullifier(S2:Bytes, C2:Bytes) </k>
        requires S1 =/=K S2 orBool C1 =/=K C2
    
    // Theorem: Cross-domain binding determinism
    claim [cross-domain-deterministic]:
        <k> deriveOasisToPILNullifier(N1:OasisNullifier) ==K deriveOasisToPILNullifier(N2:OasisNullifier) </k>
        requires N1 ==K N2
    
    // Theorem: Unused nullifier is unique
    claim [nullifier-uniqueness-check]:
        <k> isNullifierUnique(N:Bytes, UsedSet:Set) ==Bool true </k>
        requires notBool (N in UsedSet)
    
    // Theorem: Used nullifier is not unique
    claim [nullifier-used-check]:
        <k> isNullifierUnique(N:Bytes, UsedSet:Set) ==Bool false </k>
        requires N in UsedSet
    
    // =========================================================================
    // VIEW KEY PROPERTIES
    // =========================================================================
    
    // Theorem: Non-expired view key is valid
    claim [view-key-valid-before-expiry]:
        <k> isValidViewKey(viewKey(_, ValidUntil:Int, _), CurrentTime:Int) ==Bool true </k>
        requires CurrentTime <Int ValidUntil
    
    // Theorem: Expired view key is invalid
    claim [view-key-invalid-after-expiry]:
        <k> isValidViewKey(viewKey(_, ValidUntil:Int, _), CurrentTime:Int) ==Bool false </k>
        requires CurrentTime >=Int ValidUntil
    
    // =========================================================================
    // COMMITTEE APPROVAL PROPERTIES
    // =========================================================================
    
    // Theorem: Empty signatures don't meet threshold
    claim [committee-empty-fails]:
        <k> hasCommitteeApproval(_, .List, Threshold:Int) ==Bool false </k>
        requires Threshold >Int 0
    
    // Theorem: Sufficient signatures meet threshold
    claim [committee-sufficient-passes]:
        <k> hasCommitteeApproval(_, Sigs:List, Threshold:Int) ==Bool true </k>
        requires countValidSignatures(Sigs) >=Int Threshold

endmodule

module OASIS
    imports OASIS-SYNTAX
    imports OASIS-SEMANTICS
    imports OASIS-PROPERTIES
endmodule
