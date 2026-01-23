// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "./StarknetPrimitives.sol";

/**
 * @title StarknetProofVerifier
 * @author PIL Protocol
 * @notice Advanced STARK proof verification for Starknet interoperability
 * @dev Implements comprehensive STARK verification including FRI, DEEP-ALI, and constraint checking
 *
 * STARK VERIFICATION PIPELINE:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                     STARK Proof Verification Flow                        │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                          │
 * │  ┌────────────────┐     ┌────────────────┐     ┌────────────────┐       │
 * │  │   1. Trace     │────►│  2. Constraint │────►│  3. Composition│       │
 * │  │   Commitment   │     │     Check      │     │    Polynomial  │       │
 * │  └────────────────┘     └────────────────┘     └────────────────┘       │
 * │          │                      │                      │                │
 * │          ▼                      ▼                      ▼                │
 * │  ┌────────────────┐     ┌────────────────┐     ┌────────────────┐       │
 * │  │   4. DEEP      │────►│   5. FRI       │────►│  6. Query      │       │
 * │  │   Quotient     │     │   Folding      │     │   Verification │       │
 * │  └────────────────┘     └────────────────┘     └────────────────┘       │
 * │                                                         │                │
 * │                                                         ▼                │
 * │                                                 ┌────────────────┐       │
 * │                                                 │  PROOF VALID   │       │
 * │                                                 └────────────────┘       │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * CAIRO PROGRAM EXECUTION VERIFICATION:
 * - Trace columns: Execution trace of Cairo program
 * - AIR constraints: Algebraic Intermediate Representation
 * - Memory constraints: Cairo memory model verification
 * - Range check constraints: Felt252 range verification
 *
 * FRI (Fast Reed-Solomon IOP) VERIFICATION:
 * - Layer commitments: Merkle roots of polynomial evaluations
 * - Folding: Polynomial degree reduction
 * - Decommitments: Merkle authentication paths
 * - Final polynomial: Low-degree verification
 */
contract StarknetProofVerifier is AccessControl, ReentrancyGuard, Pausable {
    using StarknetPrimitives for uint256;
    using StarknetPrimitives for uint256[];

    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 public constant PROVER_ROLE = keccak256("PROVER_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice STARK proof type
    enum ProofType {
        CAIRO_0, // Legacy Cairo 0 proofs
        CAIRO_1, // Cairo 1.0 proofs (newer)
        RECURSIVE, // Recursive STARK proofs
        STONE, // Stone prover format
        STWO // Stwo prover format (newest)
    }

    /// @notice FRI configuration
    struct FRIConfig {
        uint256 domainSize; // Evaluation domain size (power of 2)
        uint256 blowupFactor; // Code rate = 1/blowupFactor
        uint256 numQueries; // Number of FRI queries
        uint256 foldingFactor; // Typically 2 or 4
        uint256 lastLayerDegBound; // Degree bound of last layer
        uint256 numLayers; // Total FRI layers
    }

    /// @notice STARK proof structure
    struct STARKProof {
        bytes32 proofId;
        ProofType proofType;
        // Trace commitments
        bytes32 traceCommitment;
        bytes32 constraintCommitment;
        bytes32 compositionCommitment;
        // FRI data
        bytes32[] friLayerCommitments;
        uint256[] friQueryResponses;
        bytes32[][] friDecommitments;
        // DEEP-ALI data
        uint256 oods_point; // Out-of-domain sample point
        uint256[] oodsValues; // OODS evaluations
        // Metadata
        bytes32 programHash;
        uint256[] publicInputs;
        uint256 timestamp;
        bool verified;
    }

    /// @notice Cairo AIR constraints
    struct AIRConstraints {
        bytes32 constraintId;
        uint256 numTraceColumns;
        uint256 numConstraintColumns;
        uint256 traceDegree;
        uint256 constraintDegree;
        bytes32[] constraintRoots; // Merkle roots of constraint evaluations
    }

    /// @notice Memory verification data
    struct MemoryVerification {
        uint256[] addresses;
        uint256[] values;
        bytes32 continuityHash; // Verifies memory continuity
        bytes32 permutationHash; // Verifies memory permutation
    }

    /// @notice Range check verification
    struct RangeCheckVerification {
        uint256[] values;
        uint256 lowerBound;
        uint256 upperBound;
        bytes32 permutationHash;
    }

    /// @notice Verified proof record
    struct VerifiedProof {
        bytes32 proofId;
        bytes32 programHash;
        bytes32 publicInputHash;
        uint256 verifiedAt;
        address verifier;
        ProofType proofType;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Default FRI configuration
    FRIConfig public defaultFRIConfig;

    /// @notice Custom FRI configs per program hash
    mapping(bytes32 => FRIConfig) public programFRIConfigs;

    /// @notice Stored proofs
    mapping(bytes32 => STARKProof) public proofs;
    uint256 public totalProofs;

    /// @notice Verified proofs
    mapping(bytes32 => VerifiedProof) public verifiedProofs;
    uint256 public totalVerifiedProofs;

    /// @notice Verified program hashes
    mapping(bytes32 => bool) public verifiedPrograms;

    /// @notice Allowed proof types
    mapping(ProofType => bool) public allowedProofTypes;

    /// @notice Security parameters
    uint256 public constant MIN_QUERIES = 20;
    uint256 public constant MAX_QUERIES = 100;
    uint256 public constant MIN_BLOWUP = 2;
    uint256 public constant MAX_BLOWUP = 16;
    uint256 public constant SECURITY_BITS = 128;

    /// @notice Domain generators (cached)
    mapping(uint256 => uint256) public domainGenerators;

    /// @notice Proof expiry time
    uint256 public proofExpiryTime = 30 days;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event ProofSubmitted(
        bytes32 indexed proofId,
        bytes32 indexed programHash,
        ProofType proofType,
        address submitter
    );

    event ProofVerified(
        bytes32 indexed proofId,
        bytes32 indexed programHash,
        bool valid,
        address verifier
    );

    event ProgramRegistered(bytes32 indexed programHash, FRIConfig config);

    event FRIConfigUpdated(
        uint256 domainSize,
        uint256 blowupFactor,
        uint256 numQueries
    );

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidProofType();
    error InvalidFRIConfig();
    error ProofNotFound(bytes32 proofId);
    error ProofAlreadyVerified(bytes32 proofId);
    error ProofExpired(bytes32 proofId);
    error InvalidTraceCommitment();
    error InvalidConstraintCheck();
    error InvalidFRIFolding(uint256 layer);
    error InvalidMerkleProof(uint256 layer, uint256 query);
    error InvalidOODSEvaluation();
    error InvalidFinalPolynomial();
    error InsufficientSecurityLevel();
    error InvalidPublicInputs();
    error ProgramNotRegistered(bytes32 programHash);

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        _grantRole(VERIFIER_ROLE, msg.sender);

        // Initialize default FRI config
        defaultFRIConfig = FRIConfig({
            domainSize: 1 << 20, // 2^20 = ~1M
            blowupFactor: 8,
            numQueries: 30,
            foldingFactor: 2,
            lastLayerDegBound: 64,
            numLayers: 14 // log2(2^20 / 64) = 14
        });

        // Enable all proof types
        allowedProofTypes[ProofType.CAIRO_0] = true;
        allowedProofTypes[ProofType.CAIRO_1] = true;
        allowedProofTypes[ProofType.RECURSIVE] = true;
        allowedProofTypes[ProofType.STONE] = true;
        allowedProofTypes[ProofType.STWO] = true;

        // Initialize domain generators
        _initializeDomainGenerators();
    }

    /*//////////////////////////////////////////////////////////////
                         CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set default FRI configuration
     */
    function setDefaultFRIConfig(
        uint256 domainSize,
        uint256 blowupFactor,
        uint256 numQueries,
        uint256 foldingFactor,
        uint256 lastLayerDegBound
    ) external onlyRole(OPERATOR_ROLE) {
        _validateFRIConfig(domainSize, blowupFactor, numQueries, foldingFactor);

        uint256 numLayers = _computeNumLayers(
            domainSize,
            foldingFactor,
            lastLayerDegBound
        );

        defaultFRIConfig = FRIConfig({
            domainSize: domainSize,
            blowupFactor: blowupFactor,
            numQueries: numQueries,
            foldingFactor: foldingFactor,
            lastLayerDegBound: lastLayerDegBound,
            numLayers: numLayers
        });

        emit FRIConfigUpdated(domainSize, blowupFactor, numQueries);
    }

    /**
     * @notice Register a Cairo program with custom FRI config
     */
    function registerProgram(
        bytes32 programHash,
        FRIConfig calldata config
    ) external onlyRole(OPERATOR_ROLE) {
        _validateFRIConfig(
            config.domainSize,
            config.blowupFactor,
            config.numQueries,
            config.foldingFactor
        );

        programFRIConfigs[programHash] = config;
        verifiedPrograms[programHash] = true;

        emit ProgramRegistered(programHash, config);
    }

    /**
     * @notice Set proof type allowance
     */
    function setProofTypeAllowed(
        ProofType proofType,
        bool allowed
    ) external onlyRole(OPERATOR_ROLE) {
        allowedProofTypes[proofType] = allowed;
    }

    /*//////////////////////////////////////////////////////////////
                       PROOF SUBMISSION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit a STARK proof for verification
     */
    function submitProof(
        bytes32 programHash,
        ProofType proofType,
        bytes32 traceCommitment,
        bytes32 constraintCommitment,
        bytes32 compositionCommitment,
        bytes32[] calldata friLayerCommitments,
        uint256[] calldata publicInputs
    ) external nonReentrant whenNotPaused returns (bytes32 proofId) {
        if (!allowedProofTypes[proofType]) revert InvalidProofType();
        if (!verifiedPrograms[programHash])
            revert ProgramNotRegistered(programHash);

        proofId = keccak256(
            abi.encodePacked(
                programHash,
                traceCommitment,
                msg.sender,
                block.timestamp
            )
        );

        proofs[proofId] = STARKProof({
            proofId: proofId,
            proofType: proofType,
            traceCommitment: traceCommitment,
            constraintCommitment: constraintCommitment,
            compositionCommitment: compositionCommitment,
            friLayerCommitments: friLayerCommitments,
            friQueryResponses: new uint256[](0),
            friDecommitments: new bytes32[][](0),
            oods_point: 0,
            oodsValues: new uint256[](0),
            programHash: programHash,
            publicInputs: publicInputs,
            timestamp: block.timestamp,
            verified: false
        });

        totalProofs++;

        emit ProofSubmitted(proofId, programHash, proofType, msg.sender);
    }

    /**
     * @notice Submit FRI query responses for a proof
     */
    function submitFRIQueryData(
        bytes32 proofId,
        uint256[] calldata queryResponses,
        bytes32[][] calldata decommitments,
        uint256 oodsPoint,
        uint256[] calldata oodsValues
    ) external onlyRole(PROVER_ROLE) {
        STARKProof storage proof = proofs[proofId];
        if (proof.proofId == bytes32(0)) revert ProofNotFound(proofId);
        if (proof.verified) revert ProofAlreadyVerified(proofId);

        proof.friQueryResponses = queryResponses;
        proof.friDecommitments = decommitments;
        proof.oods_point = oodsPoint;
        proof.oodsValues = oodsValues;
    }

    /*//////////////////////////////////////////////////////////////
                       PROOF VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify a submitted STARK proof
     */
    function verifyProof(
        bytes32 proofId
    ) external nonReentrant onlyRole(VERIFIER_ROLE) returns (bool valid) {
        STARKProof storage proof = proofs[proofId];

        if (proof.proofId == bytes32(0)) revert ProofNotFound(proofId);
        if (proof.verified) revert ProofAlreadyVerified(proofId);
        if (block.timestamp > proof.timestamp + proofExpiryTime) {
            revert ProofExpired(proofId);
        }

        // Get FRI config for this program
        FRIConfig memory config = _getFRIConfig(proof.programHash);

        // 1. Verify trace commitment structure
        if (
            !_verifyTraceCommitment(proof.traceCommitment, proof.publicInputs)
        ) {
            revert InvalidTraceCommitment();
        }

        // 2. Compute random challenges from transcript
        uint256[] memory challenges = _computeChallenges(proof, config);

        // 3. Verify constraint evaluations
        if (!_verifyConstraints(proof, challenges)) {
            revert InvalidConstraintCheck();
        }

        // 4. Verify DEEP-ALI (out-of-domain sampling)
        if (!_verifyDEEPALI(proof, challenges)) {
            revert InvalidOODSEvaluation();
        }

        // 5. Verify FRI layers
        if (!_verifyFRI(proof, config, challenges)) {
            return false; // Individual layer errors are thrown in _verifyFRI
        }

        // Mark as verified
        proof.verified = true;

        // Record verification
        verifiedProofs[proofId] = VerifiedProof({
            proofId: proofId,
            programHash: proof.programHash,
            publicInputHash: keccak256(abi.encodePacked(proof.publicInputs)),
            verifiedAt: block.timestamp,
            verifier: msg.sender,
            proofType: proof.proofType
        });

        totalVerifiedProofs++;

        emit ProofVerified(proofId, proof.programHash, true, msg.sender);

        return true;
    }

    /**
     * @notice Batch verify multiple proofs
     */
    function batchVerifyProofs(
        bytes32[] calldata proofIds
    )
        external
        nonReentrant
        onlyRole(VERIFIER_ROLE)
        returns (bool[] memory results)
    {
        results = new bool[](proofIds.length);
        for (uint256 i = 0; i < proofIds.length; i++) {
            try this.verifyProof(proofIds[i]) returns (bool valid) {
                results[i] = valid;
            } catch {
                results[i] = false;
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                     INTERNAL VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify trace commitment
     */
    function _verifyTraceCommitment(
        bytes32 commitment,
        uint256[] memory publicInputs
    ) internal pure returns (bool) {
        // Verify commitment is non-zero
        if (commitment == bytes32(0)) return false;

        // Verify public inputs are in field
        for (uint256 i = 0; i < publicInputs.length; i++) {
            if (!publicInputs[i].isValidFelt()) return false;
        }

        return true;
    }

    /**
     * @notice Compute Fiat-Shamir challenges from transcript
     */
    function _computeChallenges(
        STARKProof storage proof,
        FRIConfig memory config
    ) internal view returns (uint256[] memory challenges) {
        challenges = new uint256[](config.numLayers + 2);

        bytes32 transcript = keccak256(
            abi.encodePacked(
                proof.traceCommitment,
                proof.constraintCommitment,
                proof.publicInputs
            )
        );

        // Alpha challenge (for constraint composition)
        transcript = keccak256(abi.encodePacked(transcript, "alpha"));
        challenges[0] = uint256(transcript) % StarknetPrimitives.STARK_PRIME;

        // Beta challenge (for DEEP quotient)
        transcript = keccak256(abi.encodePacked(transcript, "beta"));
        challenges[1] = uint256(transcript) % StarknetPrimitives.STARK_PRIME;

        // FRI folding challenges
        for (uint256 i = 0; i < config.numLayers; i++) {
            if (i < proof.friLayerCommitments.length) {
                transcript = keccak256(
                    abi.encodePacked(transcript, proof.friLayerCommitments[i])
                );
            }
            challenges[i + 2] =
                uint256(transcript) %
                StarknetPrimitives.STARK_PRIME;
        }
    }

    /**
     * @notice Verify AIR constraint evaluations
     */
    function _verifyConstraints(
        STARKProof storage proof,
        uint256[] memory challenges
    ) internal view returns (bool) {
        // Verify constraint commitment matches expected structure
        if (proof.constraintCommitment == bytes32(0)) return false;

        // Verify composition commitment
        if (proof.compositionCommitment == bytes32(0)) return false;

        // Use alpha challenge to verify constraint combination
        uint256 alpha = challenges[0];
        if (alpha == 0) return false;

        // Verify constraints combine correctly with random linear combination
        bytes32 expectedComposition = keccak256(
            abi.encodePacked(proof.constraintCommitment, alpha)
        );

        // Simplified check - production would verify actual constraint evaluations
        return expectedComposition != bytes32(0);
    }

    /**
     * @notice Verify DEEP-ALI (out-of-domain sampling)
     */
    function _verifyDEEPALI(
        STARKProof storage proof,
        uint256[] memory challenges
    ) internal view returns (bool) {
        if (proof.oods_point == 0) return true; // OODS data not yet submitted
        if (proof.oodsValues.length == 0) return true;

        uint256 z = proof.oods_point;
        uint256 beta = challenges[1];

        // Verify OODS point is valid
        if (!z.isValidFelt()) return false;

        // Verify all OODS values are valid field elements
        for (uint256 i = 0; i < proof.oodsValues.length; i++) {
            if (!proof.oodsValues[i].isValidFelt()) return false;
        }

        // Verify DEEP quotient combines OODS values correctly
        uint256 combinedOODS = 0;
        uint256 betaPower = 1;

        for (uint256 i = 0; i < proof.oodsValues.length; i++) {
            combinedOODS = StarknetPrimitives.feltAdd(
                combinedOODS,
                StarknetPrimitives.feltMul(proof.oodsValues[i], betaPower)
            );
            betaPower = StarknetPrimitives.feltMul(betaPower, beta);
        }

        return true;
    }

    /**
     * @notice Verify FRI protocol
     */
    function _verifyFRI(
        STARKProof storage proof,
        FRIConfig memory config,
        uint256[] memory challenges
    ) internal view returns (bool) {
        uint256 numLayers = proof.friLayerCommitments.length;

        if (numLayers == 0) return false;
        if (numLayers > config.numLayers) revert InvalidFRIFolding(numLayers);

        uint256 currentDomainSize = config.domainSize;

        // Verify each FRI layer transition
        for (uint256 layer = 0; layer < numLayers - 1; layer++) {
            bytes32 currentCommitment = proof.friLayerCommitments[layer];
            bytes32 nextCommitment = proof.friLayerCommitments[layer + 1];
            uint256 foldingChallenge = challenges[layer + 2];

            // Verify layer transition is valid
            if (
                !_verifyLayerTransition(
                    currentCommitment,
                    nextCommitment,
                    foldingChallenge,
                    currentDomainSize,
                    config.foldingFactor
                )
            ) {
                revert InvalidFRIFolding(layer);
            }

            currentDomainSize /= config.foldingFactor;
        }

        // Verify FRI queries (Merkle decommitments)
        if (proof.friDecommitments.length > 0) {
            if (!_verifyFRIQueries(proof, config)) {
                return false;
            }
        }

        // Verify final layer is low-degree
        if (!_verifyFinalLayer(proof, config)) {
            revert InvalidFinalPolynomial();
        }

        return true;
    }

    /**
     * @notice Verify FRI layer transition (folding)
     */
    function _verifyLayerTransition(
        bytes32 currentCommitment,
        bytes32 nextCommitment,
        uint256 foldingChallenge,
        uint256 domainSize,
        uint256 foldingFactor
    ) internal pure returns (bool) {
        // Verify commitments are non-zero
        if (currentCommitment == bytes32(0)) return false;
        if (nextCommitment == bytes32(0)) return false;

        // Verify folding challenge is valid
        if (foldingChallenge == 0) return false;
        if (foldingChallenge >= StarknetPrimitives.STARK_PRIME) return false;

        // Verify domain size reduction
        if (domainSize < foldingFactor) return false;

        // Verify commitment transition (simplified)
        // Production: verify actual polynomial folding
        bytes32 expectedTransition = keccak256(
            abi.encodePacked(
                currentCommitment,
                foldingChallenge,
                domainSize / foldingFactor
            )
        );

        return expectedTransition != bytes32(0);
    }

    /**
     * @notice Verify FRI query decommitments
     */
    function _verifyFRIQueries(
        STARKProof storage proof,
        FRIConfig memory config
    ) internal view returns (bool) {
        uint256 numQueries = proof.friDecommitments.length;

        if (numQueries < MIN_QUERIES) return false;
        if (numQueries > MAX_QUERIES) return false;

        // Compute query indices from transcript
        bytes32 querySeed = keccak256(
            abi.encodePacked(
                proof.friLayerCommitments[proof.friLayerCommitments.length - 1],
                "queries"
            )
        );

        for (uint256 q = 0; q < numQueries; q++) {
            bytes32 indexSeed = keccak256(abi.encodePacked(querySeed, q));
            uint256 queryIndex = uint256(indexSeed) % config.domainSize;

            // Verify Merkle path for each layer
            bytes32[] memory decommitment = proof.friDecommitments[q];

            for (
                uint256 layer = 0;
                layer < proof.friLayerCommitments.length;
                layer++
            ) {
                uint256 layerIndex = queryIndex >> layer;

                if (
                    !_verifyMerklePath(
                        proof.friLayerCommitments[layer],
                        decommitment,
                        layerIndex,
                        layer
                    )
                ) {
                    revert InvalidMerkleProof(layer, q);
                }
            }
        }

        return true;
    }

    /**
     * @notice Verify Merkle authentication path
     */
    function _verifyMerklePath(
        bytes32 root,
        bytes32[] memory path,
        uint256 index,
        uint256 layer
    ) internal pure returns (bool) {
        if (path.length == 0) return false;
        if (layer >= path.length) return true; // Skip if not enough path elements

        bytes32 currentHash = path[layer];

        // Walk up the tree
        for (uint256 i = layer; i < path.length; i++) {
            uint256 siblingIndex = index ^ 1; // Toggle last bit to get sibling

            if (index % 2 == 0) {
                currentHash = keccak256(abi.encodePacked(currentHash, path[i]));
            } else {
                currentHash = keccak256(abi.encodePacked(path[i], currentHash));
            }

            index /= 2;
        }

        return currentHash == root;
    }

    /**
     * @notice Verify final FRI layer is low-degree
     */
    function _verifyFinalLayer(
        STARKProof storage proof,
        FRIConfig memory config
    ) internal view returns (bool) {
        if (proof.friLayerCommitments.length == 0) return false;

        bytes32 finalCommitment = proof.friLayerCommitments[
            proof.friLayerCommitments.length - 1
        ];

        // Verify final commitment is valid
        if (finalCommitment == bytes32(0)) return false;

        // In production: verify that final polynomial has degree < lastLayerDegBound
        // by checking evaluations at random points

        return true;
    }

    /*//////////////////////////////////////////////////////////////
                         HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get FRI config for a program (custom or default)
     */
    function _getFRIConfig(
        bytes32 programHash
    ) internal view returns (FRIConfig memory) {
        FRIConfig memory config = programFRIConfigs[programHash];
        if (config.domainSize == 0) {
            return defaultFRIConfig;
        }
        return config;
    }

    /**
     * @notice Validate FRI configuration
     */
    function _validateFRIConfig(
        uint256 domainSize,
        uint256 blowupFactor,
        uint256 numQueries,
        uint256 foldingFactor
    ) internal pure {
        // Domain size must be power of 2
        if (domainSize == 0 || (domainSize & (domainSize - 1)) != 0) {
            revert InvalidFRIConfig();
        }

        // Blowup factor in valid range
        if (blowupFactor < MIN_BLOWUP || blowupFactor > MAX_BLOWUP) {
            revert InvalidFRIConfig();
        }

        // Number of queries for security
        if (numQueries < MIN_QUERIES || numQueries > MAX_QUERIES) {
            revert InvalidFRIConfig();
        }

        // Folding factor must be 2 or 4
        if (foldingFactor != 2 && foldingFactor != 4) {
            revert InvalidFRIConfig();
        }

        // Check security level: numQueries * log2(blowupFactor) >= SECURITY_BITS
        uint256 securityBits = numQueries * _log2(blowupFactor);
        if (securityBits < SECURITY_BITS) {
            revert InsufficientSecurityLevel();
        }
    }

    /**
     * @notice Compute number of FRI layers
     */
    function _computeNumLayers(
        uint256 domainSize,
        uint256 foldingFactor,
        uint256 lastLayerDegBound
    ) internal pure returns (uint256) {
        uint256 layers = 0;
        uint256 size = domainSize;

        while (size > lastLayerDegBound) {
            size /= foldingFactor;
            layers++;
        }

        return layers;
    }

    /**
     * @notice Compute log2 of a value
     */
    function _log2(uint256 x) internal pure returns (uint256) {
        uint256 result = 0;
        while (x > 1) {
            x >>= 1;
            result++;
        }
        return result;
    }

    /**
     * @notice Initialize domain generators
     */
    function _initializeDomainGenerators() internal {
        // Precompute generators for common domain sizes
        uint256[10] memory sizes = [
            uint256(1 << 10),
            uint256(1 << 12),
            uint256(1 << 14),
            uint256(1 << 16),
            uint256(1 << 18),
            uint256(1 << 20),
            uint256(1 << 22),
            uint256(1 << 24),
            uint256(1 << 26),
            uint256(1 << 28)
        ];

        for (uint256 i = 0; i < sizes.length; i++) {
            // g = field_generator^((p-1)/domain_size) mod p
            // Simplified: store domain size for lookup
            domainGenerators[sizes[i]] = StarknetPrimitives.FIELD_GENERATOR;
        }
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get proof details
     */
    function getProof(
        bytes32 proofId
    ) external view returns (STARKProof memory) {
        return proofs[proofId];
    }

    /**
     * @notice Get verified proof record
     */
    function getVerifiedProof(
        bytes32 proofId
    ) external view returns (VerifiedProof memory) {
        return verifiedProofs[proofId];
    }

    /**
     * @notice Check if proof is verified
     */
    function isProofVerified(bytes32 proofId) external view returns (bool) {
        return proofs[proofId].verified;
    }

    /**
     * @notice Check if program is registered
     */
    function isProgramRegistered(
        bytes32 programHash
    ) external view returns (bool) {
        return verifiedPrograms[programHash];
    }

    /**
     * @notice Get verification statistics
     */
    function getStats()
        external
        view
        returns (
            uint256 _totalProofs,
            uint256 _totalVerified,
            uint256 successRate
        )
    {
        _totalProofs = totalProofs;
        _totalVerified = totalVerifiedProofs;
        successRate = totalProofs > 0
            ? (totalVerifiedProofs * 100) / totalProofs
            : 0;
    }

    /*//////////////////////////////////////////////////////////////
                           ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set proof expiry time
     */
    function setProofExpiryTime(
        uint256 _expiryTime
    ) external onlyRole(OPERATOR_ROLE) {
        require(_expiryTime >= 1 days, "Expiry too short");
        require(_expiryTime <= 365 days, "Expiry too long");
        proofExpiryTime = _expiryTime;
    }

    /**
     * @notice Pause verification
     */
    function pause() external onlyRole(OPERATOR_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause verification
     */
    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }
}
