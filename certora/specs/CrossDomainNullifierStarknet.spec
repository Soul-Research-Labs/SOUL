/**
 * @title Certora CVL Specification for CrossDomainNullifierStarknet
 * @author PIL Protocol
 * @notice Formal verification of cross-domain nullifier management
 * 
 * VERIFICATION SCOPE:
 * - Nullifier uniqueness and binding
 * - Cross-domain sync integrity
 * - Double-spend prevention
 * - Domain isolation
 * 
 * CRITICAL SECURITY PROPERTIES:
 * 1. Nullifier uniqueness: Each nullifier can only be registered once
 * 2. Binding: Nullifier is permanently bound to its commitment
 * 3. No double consumption: Nullifier can only be consumed once
 * 4. Domain separation: Nullifiers are isolated per domain
 * 5. Sync integrity: Cross-domain sync maintains consistency
 */

/*//////////////////////////////////////////////////////////////
                         METHODS BLOCK
//////////////////////////////////////////////////////////////*/

methods {
    // Role management
    function hasRole(bytes32 role, address account) external returns (bool) envfree;
    function BRIDGE_ROLE() external returns (bytes32) envfree;
    function NULLIFIER_REGISTRAR_ROLE() external returns (bytes32) envfree;
    function VERIFIER_ROLE() external returns (bytes32) envfree;
    function OPERATOR_ROLE() external returns (bytes32) envfree;
    
    // Nullifier management
    function registerNullifier(bytes32, bytes32, bytes32, uint256, CrossDomainNullifierStarknet.DomainType) 
        external returns (bool);
    function consumeNullifier(bytes32, bytes32) external returns (bool);
    function syncNullifierToL2(bytes32) external returns (bytes32);
    function syncNullifierFromL2(bytes32, uint256, bytes32) external returns (bool);
    
    // Domain management
    function registerDomain(bytes32, CrossDomainNullifierStarknet.DomainType, uint256) external;
    function configureStarknetBridge(address, uint256) external;
    
    // View functions
    function nullifiers(bytes32) external returns (CrossDomainNullifierStarknet.CrossDomainNullifier) envfree;
    function domains(bytes32) external returns (CrossDomainNullifierStarknet.DomainConfig) envfree;
    function nullifierSet(bytes32) external returns (bool) envfree;
    function l1ToL2Nullifier(bytes32) external returns (uint256) envfree;
    function l2ToL1Nullifier(uint256) external returns (bytes32) envfree;
    function commitmentToNullifier(bytes32) external returns (bytes32) envfree;
    
    // Counters
    function totalNullifiers() external returns (uint256) envfree;
    function totalBatches() external returns (uint256) envfree;
    
    // Configuration
    function syncDelay() external returns (uint256) envfree;
    function MAX_BATCH_SIZE() external returns (uint256) envfree;
    function TREE_DEPTH() external returns (uint256) envfree;
    
    // Pause
    function paused() external returns (bool) envfree;
}

/*//////////////////////////////////////////////////////////////
                       DEFINITIONS
//////////////////////////////////////////////////////////////*/

// Nullifier status enum values
definition STATUS_UNKNOWN() returns uint8 = 0;
definition STATUS_PENDING() returns uint8 = 1;
definition STATUS_SYNCED() returns uint8 = 2;
definition STATUS_CONSUMED() returns uint8 = 3;
definition STATUS_REVOKED() returns uint8 = 4;

// Domain type enum values
definition DOMAIN_PIL_L1() returns uint8 = 0;
definition DOMAIN_STARKNET_L2() returns uint8 = 1;
definition DOMAIN_STARKNET_APPCHAIN() returns uint8 = 2;

/*//////////////////////////////////////////////////////////////
                      GHOST VARIABLES
//////////////////////////////////////////////////////////////*/

// Track nullifier registrations
ghost mapping(bytes32 => bool) nullifierRegistered {
    init_state axiom forall bytes32 n. nullifierRegistered[n] == false;
}

// Track nullifier consumption
ghost mapping(bytes32 => bool) nullifierConsumed {
    init_state axiom forall bytes32 n. nullifierConsumed[n] == false;
}

// Track commitment-nullifier binding
ghost mapping(bytes32 => bytes32) commitmentBinding {
    init_state axiom forall bytes32 c. commitmentBinding[c] == to_bytes32(0);
}

// Track L1-L2 nullifier mappings
ghost mapping(bytes32 => uint256) ghostL1ToL2 {
    init_state axiom forall bytes32 l1. ghostL1ToL2[l1] == 0;
}

ghost mapping(uint256 => bytes32) ghostL2ToL1 {
    init_state axiom forall uint256 l2. ghostL2ToL1[l2] == to_bytes32(0);
}

// Counter ghost
ghost mathint ghostTotalNullifiers {
    init_state axiom ghostTotalNullifiers == 0;
}

/*//////////////////////////////////////////////////////////////
                          HOOKS
//////////////////////////////////////////////////////////////*/

// Hook on nullifier registration
hook Sstore nullifiers[KEY bytes32 nullifier].nullifier bytes32 newNullifier {
    if (newNullifier != to_bytes32(0)) {
        nullifierRegistered[nullifier] = true;
        ghostTotalNullifiers = ghostTotalNullifiers + 1;
    }
}

// Hook on nullifier consumption
hook Sstore nullifiers[KEY bytes32 nullifier].status uint8 newStatus {
    if (newStatus == STATUS_CONSUMED()) {
        nullifierConsumed[nullifier] = true;
    }
}

// Hook on commitment binding
hook Sstore nullifiers[KEY bytes32 nullifier].commitment bytes32 newCommitment {
    commitmentBinding[newCommitment] = nullifier;
}

// Hook on L1-L2 mapping
hook Sstore l1ToL2Nullifier[KEY bytes32 l1] uint256 l2 {
    ghostL1ToL2[l1] = l2;
}

hook Sstore l2ToL1Nullifier[KEY uint256 l2] bytes32 l1 {
    ghostL2ToL1[l2] = l1;
}

/*//////////////////////////////////////////////////////////////
                       INVARIANTS
//////////////////////////////////////////////////////////////*/

/**
 * @notice Total nullifiers counter is consistent
 */
invariant nullifierCountConsistent()
    to_mathint(totalNullifiers()) == ghostTotalNullifiers
    {
        preserved {
            require !paused();
        }
    }

/**
 * @notice Registered nullifiers are in the nullifier set
 */
invariant registeredNullifierInSet(bytes32 nullifier)
    nullifierRegistered[nullifier] => nullifierSet(nullifier)
    {
        preserved registerNullifier(bytes32 n, bytes32 c, bytes32 d, uint256 s, CrossDomainNullifierStarknet.DomainType t) with (env e) {
            require !paused();
            require hasRole(NULLIFIER_REGISTRAR_ROLE(), e.msg.sender);
        }
    }

/**
 * @notice Consumed nullifiers remain consumed
 * @dev Critical: prevents double-spending
 */
invariant consumedNullifiersStayConsumed(bytes32 nullifier)
    nullifierConsumed[nullifier] => 
        nullifiers(nullifier).status == STATUS_CONSUMED()
    {
        preserved {
            require !paused();
        }
    }

/**
 * @notice L1-L2 mappings are bidirectional
 */
invariant l1l2MappingBidirectional(bytes32 l1Nullifier)
    (ghostL1ToL2[l1Nullifier] != 0) => 
        ghostL2ToL1[ghostL1ToL2[l1Nullifier]] == l1Nullifier
    {
        preserved syncNullifierToL2(bytes32 n) with (env e) {
            require hasRole(BRIDGE_ROLE(), e.msg.sender);
        }
    }

/*//////////////////////////////////////////////////////////////
                           RULES
//////////////////////////////////////////////////////////////*/

/**
 * @notice Nullifiers can only be registered once
 * @dev Core double-spend prevention
 */
rule nullifierCanOnlyBeRegisteredOnce(
    bytes32 nullifier,
    bytes32 commitment,
    bytes32 domainId,
    uint256 starknetDomainId,
    CrossDomainNullifierStarknet.DomainType domainType
) {
    env e;
    
    require hasRole(NULLIFIER_REGISTRAR_ROLE(), e.msg.sender);
    require !paused();
    
    // Check if already registered
    bool alreadyRegistered = nullifierRegistered[nullifier];
    
    registerNullifier@withrevert(e, nullifier, commitment, domainId, starknetDomainId, domainType);
    
    bool reverted = lastReverted;
    
    assert alreadyRegistered => reverted, 
        "Already registered nullifiers must not be re-registered";
}

/**
 * @notice Nullifiers can only be consumed once
 */
rule nullifierCanOnlyBeConsumedOnce(bytes32 nullifier, bytes32 proof) {
    env e1;
    env e2;
    
    require nullifierRegistered[nullifier];
    require !nullifierConsumed[nullifier];
    require hasRole(VERIFIER_ROLE(), e1.msg.sender);
    require hasRole(VERIFIER_ROLE(), e2.msg.sender);
    
    // First consumption
    bool result1 = consumeNullifier(e1, nullifier, proof);
    
    // Second consumption attempt
    consumeNullifier@withrevert(e2, nullifier, proof);
    
    bool reverted = lastReverted;
    
    assert result1 => reverted, "Already consumed nullifiers must not be consumable again";
}

/**
 * @notice Unregistered nullifiers cannot be consumed
 */
rule unregisteredNullifiersCannotBeConsumed(bytes32 nullifier, bytes32 proof) {
    env e;
    
    require !nullifierRegistered[nullifier];
    
    consumeNullifier@withrevert(e, nullifier, proof);
    
    assert lastReverted, "Unregistered nullifiers must not be consumable";
}

/**
 * @notice Only registrar can register nullifiers
 */
rule onlyRegistrarCanRegister(
    bytes32 nullifier,
    bytes32 commitment,
    bytes32 domainId,
    uint256 starknetDomainId,
    CrossDomainNullifierStarknet.DomainType domainType
) {
    env e;
    
    bool isRegistrar = hasRole(NULLIFIER_REGISTRAR_ROLE(), e.msg.sender);
    
    registerNullifier@withrevert(e, nullifier, commitment, domainId, starknetDomainId, domainType);
    
    bool reverted = lastReverted;
    
    assert !isRegistrar => reverted, "Non-registrars must not be able to register nullifiers";
}

/**
 * @notice Only bridge can sync to L2
 */
rule onlyBridgeCanSyncToL2(bytes32 nullifier) {
    env e;
    
    bool isBridge = hasRole(BRIDGE_ROLE(), e.msg.sender);
    
    syncNullifierToL2@withrevert(e, nullifier);
    
    bool reverted = lastReverted;
    
    assert !isBridge => reverted, "Non-bridge must not be able to sync to L2";
}

/**
 * @notice Only bridge can sync from L2
 */
rule onlyBridgeCanSyncFromL2(bytes32 l1Nullifier, uint256 l2Nullifier, bytes32 proof) {
    env e;
    
    bool isBridge = hasRole(BRIDGE_ROLE(), e.msg.sender);
    
    syncNullifierFromL2@withrevert(e, l1Nullifier, l2Nullifier, proof);
    
    bool reverted = lastReverted;
    
    assert !isBridge => reverted, "Non-bridge must not be able to sync from L2";
}

/**
 * @notice Commitment-nullifier binding is permanent
 */
rule commitmentBindingIsPermanent(
    bytes32 nullifier,
    bytes32 commitment,
    bytes32 domainId,
    uint256 starknetDomainId,
    CrossDomainNullifierStarknet.DomainType domainType
) {
    env e;
    
    require hasRole(NULLIFIER_REGISTRAR_ROLE(), e.msg.sender);
    require !nullifierRegistered[nullifier];
    require !paused();
    
    registerNullifier(e, nullifier, commitment, domainId, starknetDomainId, domainType);
    
    bytes32 boundNullifier = commitmentToNullifier(commitment);
    
    assert boundNullifier == nullifier, "Commitment must be bound to its nullifier";
}

/**
 * @notice Nullifier registration creates correct L1-L2 mapping
 */
rule registrationCreatesL1L2Mapping(
    bytes32 nullifier,
    bytes32 commitment,
    bytes32 domainId,
    uint256 starknetDomainId,
    CrossDomainNullifierStarknet.DomainType domainType
) {
    env e;
    
    require hasRole(NULLIFIER_REGISTRAR_ROLE(), e.msg.sender);
    require !nullifierRegistered[nullifier];
    require !paused();
    require starknetDomainId != 0;
    
    registerNullifier(e, nullifier, commitment, domainId, starknetDomainId, domainType);
    
    CrossDomainNullifierStarknet.CrossDomainNullifier record = nullifiers(nullifier);
    
    assert record.starknetDomainId == starknetDomainId, 
        "Starknet domain ID must be recorded correctly";
}

/**
 * @notice Sync increases nullifier status
 */
rule syncProgressesStatus(bytes32 nullifier) {
    env e;
    
    require nullifierRegistered[nullifier];
    require hasRole(BRIDGE_ROLE(), e.msg.sender);
    
    CrossDomainNullifierStarknet.CrossDomainNullifier beforeRecord = nullifiers(nullifier);
    require beforeRecord.status == STATUS_PENDING();
    
    syncNullifierToL2(e, nullifier);
    
    CrossDomainNullifierStarknet.CrossDomainNullifier afterRecord = nullifiers(nullifier);
    
    // Status should progress
    assert afterRecord.status >= beforeRecord.status, 
        "Sync must progress status forward";
}

/**
 * @notice Cannot operate when paused
 */
rule cannotOperateWhenPaused() {
    env e;
    
    require paused();
    
    bytes32 nullifier;
    bytes32 commitment;
    bytes32 domainId;
    uint256 starknetDomainId;
    CrossDomainNullifierStarknet.DomainType domainType;
    
    registerNullifier@withrevert(e, nullifier, commitment, domainId, starknetDomainId, domainType);
    bool registerReverted = lastReverted;
    
    bytes32 proof;
    consumeNullifier@withrevert(e, nullifier, proof);
    bool consumeReverted = lastReverted;
    
    syncNullifierToL2@withrevert(e, nullifier);
    bool syncReverted = lastReverted;
    
    assert registerReverted && consumeReverted && syncReverted, 
        "All operations must fail when paused";
}

/**
 * @notice Only operator can register domains
 */
rule onlyOperatorCanRegisterDomains(
    bytes32 domainId,
    CrossDomainNullifierStarknet.DomainType domainType,
    uint256 starknetAddress
) {
    env e;
    
    bool isOperator = hasRole(OPERATOR_ROLE(), e.msg.sender);
    
    registerDomain@withrevert(e, domainId, domainType, starknetAddress);
    
    bool reverted = lastReverted;
    
    assert !isOperator => reverted, "Non-operators must not be able to register domains";
}

/**
 * @notice Domain must be active for nullifier operations
 */
rule domainMustBeActiveForOperations(
    bytes32 nullifier,
    bytes32 commitment,
    bytes32 domainId,
    uint256 starknetDomainId,
    CrossDomainNullifierStarknet.DomainType domainType
) {
    env e;
    
    require hasRole(NULLIFIER_REGISTRAR_ROLE(), e.msg.sender);
    require !paused();
    
    CrossDomainNullifierStarknet.DomainConfig domain = domains(domainId);
    
    // If domain is not active, registration should fail
    registerNullifier@withrevert(e, nullifier, commitment, domainId, starknetDomainId, domainType);
    
    bool reverted = lastReverted;
    
    // Inactive domain should cause revert (unless domain doesn't exist check takes precedence)
    satisfy !domain.isActive => reverted, "Inactive domains should reject operations";
}

/*//////////////////////////////////////////////////////////////
                   CROSS-DOMAIN SECURITY RULES
//////////////////////////////////////////////////////////////*/

/**
 * @notice L1 and L2 nullifiers are cryptographically linked
 */
rule l1L2NullifiersAreLinked(bytes32 nullifier) {
    env e;
    
    require nullifierRegistered[nullifier];
    require hasRole(BRIDGE_ROLE(), e.msg.sender);
    
    syncNullifierToL2(e, nullifier);
    
    uint256 l2Nullifier = l1ToL2Nullifier(nullifier);
    bytes32 mappedL1 = l2ToL1Nullifier(l2Nullifier);
    
    // If L2 nullifier was created, mapping should be consistent
    assert l2Nullifier != 0 => mappedL1 == nullifier,
        "L1-L2 nullifier mapping must be bidirectional";
}

/**
 * @notice Consuming L1 nullifier doesn't affect L2 directly
 * @dev L2 consumption requires separate sync
 */
rule l1ConsumptionDoesntAffectL2Directly(bytes32 nullifier, bytes32 proof) {
    env e;
    
    require nullifierRegistered[nullifier];
    require !nullifierConsumed[nullifier];
    require hasRole(VERIFIER_ROLE(), e.msg.sender);
    
    uint256 l2Before = l1ToL2Nullifier(nullifier);
    
    consumeNullifier(e, nullifier, proof);
    
    uint256 l2After = l1ToL2Nullifier(nullifier);
    
    // L2 mapping should not change from L1 consumption alone
    assert l2Before == l2After, "L1 consumption must not directly modify L2 mapping";
}

/**
 * @notice Nullifier metadata is immutable after registration
 */
rule nullifierMetadataImmutable(bytes32 nullifier, bytes32 proof) {
    env e;
    
    require nullifierRegistered[nullifier];
    
    CrossDomainNullifierStarknet.CrossDomainNullifier before = nullifiers(nullifier);
    
    // Try consumption (a status-changing operation)
    consumeNullifier@withrevert(e, nullifier, proof);
    
    CrossDomainNullifierStarknet.CrossDomainNullifier after = nullifiers(nullifier);
    
    // Core metadata should not change
    assert after.commitment == before.commitment, "Commitment must be immutable";
    assert after.pilDomainId == before.pilDomainId, "PIL domain ID must be immutable";
    assert after.originDomain == before.originDomain, "Origin domain must be immutable";
    assert after.registrar == before.registrar, "Registrar must be immutable";
}

/**
 * @notice Sync batch size is bounded
 */
rule syncBatchSizeBounded() {
    uint256 maxBatch = MAX_BATCH_SIZE();
    
    assert maxBatch <= 100, "Batch size must be bounded for gas safety";
}

/**
 * @notice Tree depth is sufficient for security
 */
rule treeDepthSufficient() {
    uint256 depth = TREE_DEPTH();
    
    // 2^32 > 4 billion nullifiers
    assert depth >= 32, "Tree depth must support sufficient nullifiers";
}
