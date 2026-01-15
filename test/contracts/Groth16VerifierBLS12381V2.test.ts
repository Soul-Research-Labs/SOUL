import { expect } from "chai";
import { ethers } from "hardhat";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("Groth16VerifierBLS12381V2", function () {
  let verifier: any;
  let owner: SignerWithAddress;
  let user1: SignerWithAddress;

  beforeEach(async function () {
    [owner, user1] = await ethers.getSigners();

    const Verifier = await ethers.getContractFactory("Groth16VerifierBLS12381V2");
    verifier = await Verifier.deploy();
    await verifier.waitForDeployment();
  });

  describe("Deployment", function () {
    it("Should set the correct owner", async function () {
      expect(await verifier.owner()).to.equal(owner.address);
    });

    it("Should start unpaused", async function () {
      expect(await verifier.paused()).to.be.false;
    });
  });

  describe("Verification Key Management", function () {
    // Sample verification key (placeholder values)
    const sampleVK = {
      alpha: {
        x: ethers.getBigInt("1"),
        y: ethers.getBigInt("2"),
      },
      beta: {
        x: [ethers.getBigInt("3"), ethers.getBigInt("4")],
        y: [ethers.getBigInt("5"), ethers.getBigInt("6")],
      },
      gamma: {
        x: [ethers.getBigInt("7"), ethers.getBigInt("8")],
        y: [ethers.getBigInt("9"), ethers.getBigInt("10")],
      },
      delta: {
        x: [ethers.getBigInt("11"), ethers.getBigInt("12")],
        y: [ethers.getBigInt("13"), ethers.getBigInt("14")],
      },
      ic: [
        { x: ethers.getBigInt("15"), y: ethers.getBigInt("16") },
        { x: ethers.getBigInt("17"), y: ethers.getBigInt("18") },
      ],
    };

    it("Should set verification key", async function () {
      const circuitId = ethers.keccak256(ethers.toUtf8Bytes("test_circuit"));
      
      await expect(verifier.setVerificationKey(circuitId, sampleVK))
        .to.emit(verifier, "VerificationKeySet")
        .withArgs(circuitId);

      const storedVK = await verifier.getVerificationKey(circuitId);
      expect(storedVK.alpha.x).to.equal(sampleVK.alpha.x);
    });

    it("Should only allow owner to set verification key", async function () {
      const circuitId = ethers.keccak256(ethers.toUtf8Bytes("test_circuit"));
      
      await expect(
        verifier.connect(user1).setVerificationKey(circuitId, sampleVK)
      ).to.be.revertedWithCustomError(verifier, "OwnableUnauthorizedAccount");
    });

    it("Should remove verification key", async function () {
      const circuitId = ethers.keccak256(ethers.toUtf8Bytes("test_circuit"));
      await verifier.setVerificationKey(circuitId, sampleVK);

      await expect(verifier.removeVerificationKey(circuitId))
        .to.emit(verifier, "VerificationKeyRemoved")
        .withArgs(circuitId);
    });
  });

  describe("Proof Verification", function () {
    const circuitId = ethers.keccak256(ethers.toUtf8Bytes("test_circuit"));

    // Sample proof (placeholder values)
    const sampleProof = {
      a: { x: ethers.getBigInt("1"), y: ethers.getBigInt("2") },
      b: {
        x: [ethers.getBigInt("3"), ethers.getBigInt("4")],
        y: [ethers.getBigInt("5"), ethers.getBigInt("6")],
      },
      c: { x: ethers.getBigInt("7"), y: ethers.getBigInt("8") },
    };

    const publicInputs = [ethers.getBigInt("100")];

    beforeEach(async function () {
      const sampleVK = {
        alpha: { x: ethers.getBigInt("1"), y: ethers.getBigInt("2") },
        beta: {
          x: [ethers.getBigInt("3"), ethers.getBigInt("4")],
          y: [ethers.getBigInt("5"), ethers.getBigInt("6")],
        },
        gamma: {
          x: [ethers.getBigInt("7"), ethers.getBigInt("8")],
          y: [ethers.getBigInt("9"), ethers.getBigInt("10")],
        },
        delta: {
          x: [ethers.getBigInt("11"), ethers.getBigInt("12")],
          y: [ethers.getBigInt("13"), ethers.getBigInt("14")],
        },
        ic: [
          { x: ethers.getBigInt("15"), y: ethers.getBigInt("16") },
          { x: ethers.getBigInt("17"), y: ethers.getBigInt("18") },
        ],
      };
      await verifier.setVerificationKey(circuitId, sampleVK);
    });

    it("Should verify proof (stub returns true)", async function () {
      // Note: The actual verifier is a stub that returns true
      const result = await verifier.verifyProof(circuitId, sampleProof, publicInputs);
      expect(result).to.be.true;
    });

    it("Should emit ProofVerified event", async function () {
      await expect(verifier.verifyProof(circuitId, sampleProof, publicInputs))
        .to.emit(verifier, "ProofVerified")
        .withArgs(circuitId, true);
    });

    it("Should revert when paused", async function () {
      await verifier.pause();
      await expect(
        verifier.verifyProof(circuitId, sampleProof, publicInputs)
      ).to.be.revertedWithCustomError(verifier, "EnforcedPause");
    });

    it("Should track verification count", async function () {
      await verifier.verifyProof(circuitId, sampleProof, publicInputs);
      expect(await verifier.getVerificationCount(circuitId)).to.equal(1);

      await verifier.verifyProof(circuitId, sampleProof, publicInputs);
      expect(await verifier.getVerificationCount(circuitId)).to.equal(2);
    });
  });

  describe("Batch Verification", function () {
    const circuitId = ethers.keccak256(ethers.toUtf8Bytes("test_circuit"));

    const sampleProof = {
      a: { x: ethers.getBigInt("1"), y: ethers.getBigInt("2") },
      b: {
        x: [ethers.getBigInt("3"), ethers.getBigInt("4")],
        y: [ethers.getBigInt("5"), ethers.getBigInt("6")],
      },
      c: { x: ethers.getBigInt("7"), y: ethers.getBigInt("8") },
    };

    beforeEach(async function () {
      const sampleVK = {
        alpha: { x: ethers.getBigInt("1"), y: ethers.getBigInt("2") },
        beta: {
          x: [ethers.getBigInt("3"), ethers.getBigInt("4")],
          y: [ethers.getBigInt("5"), ethers.getBigInt("6")],
        },
        gamma: {
          x: [ethers.getBigInt("7"), ethers.getBigInt("8")],
          y: [ethers.getBigInt("9"), ethers.getBigInt("10")],
        },
        delta: {
          x: [ethers.getBigInt("11"), ethers.getBigInt("12")],
          y: [ethers.getBigInt("13"), ethers.getBigInt("14")],
        },
        ic: [
          { x: ethers.getBigInt("15"), y: ethers.getBigInt("16") },
          { x: ethers.getBigInt("17"), y: ethers.getBigInt("18") },
        ],
      };
      await verifier.setVerificationKey(circuitId, sampleVK);
    });

    it("Should verify batch of proofs", async function () {
      const proofs = [sampleProof, sampleProof, sampleProof];
      const publicInputsArray = [
        [ethers.getBigInt("100")],
        [ethers.getBigInt("200")],
        [ethers.getBigInt("300")],
      ];

      const result = await verifier.batchVerifyProofs(circuitId, proofs, publicInputsArray);
      expect(result).to.be.true;
    });

    it("Should revert on mismatched array lengths", async function () {
      const proofs = [sampleProof, sampleProof];
      const publicInputsArray = [
        [ethers.getBigInt("100")],
      ];

      await expect(
        verifier.batchVerifyProofs(circuitId, proofs, publicInputsArray)
      ).to.be.revertedWithCustomError(verifier, "ArrayLengthMismatch");
    });

    it("Should revert on empty batch", async function () {
      await expect(
        verifier.batchVerifyProofs(circuitId, [], [])
      ).to.be.revertedWithCustomError(verifier, "EmptyBatch");
    });
  });

  describe("Pause Functionality", function () {
    it("Should allow owner to pause", async function () {
      await verifier.pause();
      expect(await verifier.paused()).to.be.true;
    });

    it("Should allow owner to unpause", async function () {
      await verifier.pause();
      await verifier.unpause();
      expect(await verifier.paused()).to.be.false;
    });

    it("Should not allow non-owner to pause", async function () {
      await expect(verifier.connect(user1).pause()).to.be.revertedWithCustomError(
        verifier,
        "OwnableUnauthorizedAccount"
      );
    });
  });
});
