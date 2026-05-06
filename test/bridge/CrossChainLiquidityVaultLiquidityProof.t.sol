// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {CrossChainLiquidityVault} from "../../contracts/bridge/CrossChainLiquidityVault.sol";
import {ILiquidityProofVerifier} from "../../contracts/interfaces/ILiquidityProofVerifier.sol";
import {BN254ScalarField} from "../../contracts/libraries/BN254ScalarField.sol";

contract MockLiquidityProofVerifier is ILiquidityProofVerifier {
    bool public result = true;
    uint256 public calls;

    function setResult(bool value) external {
        result = value;
    }

    function verify(
        bytes calldata,
        bytes32[] calldata
    ) external override returns (bool ok) {
        ++calls;
        return result;
    }
}

contract CrossChainLiquidityVaultLiquidityProofTest is Test {
    uint256 internal constant BN254_R =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    CrossChainLiquidityVault internal vault;
    MockLiquidityProofVerifier internal verifier;

    address internal admin = address(this);
    address internal operator = makeAddr("operator");
    address internal guardian = makeAddr("guardian");
    address internal privacyHub = makeAddr("privacyHub");
    address internal lp = makeAddr("lp");
    address internal recipient = makeAddr("recipient");

    function setUp() public {
        vm.warp(1_000_000);
        vault = new CrossChainLiquidityVault(
            admin,
            operator,
            guardian,
            privacyHub,
            5000
        );
        verifier = new MockLiquidityProofVerifier();
        vault.setLiquidityProofVerifier(address(verifier));

        vm.deal(lp, 10 ether);
        vm.prank(lp);
        vault.depositETH{value: 10 ether}();
    }

    function _inputs() internal view returns (bytes32[] memory inputs) {
        inputs = new bytes32[](5);
        inputs[0] = bytes32(uint256(1));
        inputs[1] = bytes32(uint256(2));
        inputs[2] = bytes32(uint256(3));
        inputs[3] = bytes32(uint256(4));
        inputs[4] = bytes32(uint256(block.timestamp));
    }

    function test_AttestLiquidityProof_RecordsRequestBoundAttestation() public {
        bytes32 requestId = keccak256("request");
        bytes memory proof = hex"deadbeef";
        bytes32[] memory inputs = _inputs();

        vm.prank(privacyHub);
        vault.attestLiquidityProof(requestId, proof, inputs);

        assertTrue(vault.liquidityProofNullifiers(inputs[2]));
        (
            bytes32 nullifier,
            bytes32 proofHash,
            bytes32 publicInputsHash,
            uint64 attestedAt,
            bool released
        ) = vault.liquidityProofAttestations(requestId);
        assertEq(nullifier, inputs[2]);
        assertEq(proofHash, keccak256(proof));
        assertEq(publicInputsHash, keccak256(abi.encode(inputs)));
        assertEq(attestedAt, uint64(block.timestamp));
        assertFalse(released);
        assertEq(verifier.calls(), 1);
    }

    function test_AttestLiquidityProof_RevertsOnWrongInputLength() public {
        bytes32[] memory tooLong = new bytes32[](6);
        tooLong[4] = bytes32(uint256(block.timestamp));

        vm.prank(privacyHub);
        vm.expectRevert(
            abi.encodeWithSelector(
                CrossChainLiquidityVault
                    .LiquidityProofInvalidPublicInputCount
                    .selector,
                uint256(5),
                uint256(6)
            )
        );
        vault.attestLiquidityProof(
            keccak256("request"),
            hex"deadbeef",
            tooLong
        );
    }

    function test_AttestLiquidityProof_RevertsOnOutOfFieldInput() public {
        bytes32[] memory inputs = _inputs();
        inputs[1] = bytes32(uint256(BN254_R));

        vm.prank(privacyHub);
        vm.expectRevert(
            abi.encodeWithSelector(
                BN254ScalarField.FieldElementOutOfRange.selector,
                uint256(1),
                bytes32(uint256(BN254_R))
            )
        );
        vault.attestLiquidityProof(keccak256("request"), hex"deadbeef", inputs);
    }

    function test_AttestLiquidityProof_RevertsOnStaleTimestamp() public {
        bytes32[] memory inputs = _inputs();
        inputs[4] = bytes32(
            uint256(block.timestamp - vault.MAX_LIQUIDITY_PROOF_AGE() - 1)
        );

        vm.prank(privacyHub);
        vm.expectRevert(
            abi.encodeWithSelector(
                CrossChainLiquidityVault
                    .LiquidityProofTimestampOutOfRange
                    .selector,
                uint256(inputs[4]),
                block.timestamp
            )
        );
        vault.attestLiquidityProof(keccak256("request"), hex"deadbeef", inputs);
    }

    function test_ReleaseLiquidity_RevertsWhenProofRequiredButMissing() public {
        vault.setLiquidityProofRequiredForRelease(true);

        vm.prank(privacyHub);
        vm.expectRevert(
            abi.encodeWithSelector(
                CrossChainLiquidityVault
                    .LiquidityProofAttestationMissing
                    .selector,
                bytes32("missing")
            )
        );
        vault.releaseLiquidity(
            bytes32("missing"),
            address(0),
            recipient,
            1 ether,
            1
        );
    }

    function test_ReleaseLiquidity_ConsumesRequiredAttestation() public {
        bytes32 requestId = keccak256("request");
        bytes32[] memory inputs = _inputs();

        vm.prank(privacyHub);
        vault.attestLiquidityProof(requestId, hex"deadbeef", inputs);

        vault.setLiquidityProofRequiredForRelease(true);

        vm.prank(privacyHub);
        vault.releaseLiquidity(requestId, address(0), recipient, 1 ether, 1);

        (, , , , bool released) = vault.liquidityProofAttestations(requestId);
        assertTrue(released);
        assertEq(vault.pendingReleaseCount(), 1);

        vm.prank(privacyHub);
        vm.expectRevert(
            abi.encodeWithSelector(
                CrossChainLiquidityVault
                    .LiquidityProofAttestationAlreadyReleased
                    .selector,
                requestId
            )
        );
        vault.releaseLiquidity(requestId, address(0), recipient, 1 ether, 1);
    }
}
