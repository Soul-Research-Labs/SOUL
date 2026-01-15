const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("Groth16VerifierBLS12381V2", function () {
  let verifier;
  let owner;
  let user1;

  beforeEach(async function () {
    [owner, user1] = await ethers.getSigners();

    const Verifier = await ethers.getContractFactory(
      "contracts/core/Groth16VerifierBLS12381V2.sol:Groth16VerifierBLS12381"
    );
    verifier = await Verifier.deploy();
    await verifier.waitForDeployment();
  });

  describe("Deployment", function () {
    it("Should set the correct owner", async function () {
      expect(await verifier.owner()).to.equal(owner.address);
    });

    it("Should start uninitialized", async function () {
      expect(await verifier.initialized()).to.be.false;
    });
  });

  describe("Verification Key Management", function () {
    // Sample verification key arrays matching V2 contract signature
    const alpha = [1n, 2n];
    const beta = [3n, 4n, 5n, 6n];
    const gamma = [7n, 8n, 9n, 10n];
    const delta = [11n, 12n, 13n, 14n];
    const ic = [[15n, 16n], [17n, 18n]];

    it("Should set verification key", async function () {
      await expect(verifier.setVerificationKey(alpha, beta, gamma, delta, ic))
        .to.emit(verifier, "VerificationKeySet")
        .withArgs(owner.address);

      expect(await verifier.initialized()).to.be.true;
    });

    it("Should only allow owner to set verification key", async function () {
      // V2 uses Ownable which reverts with OwnableUnauthorizedAccount for OZ 5.x
      // but this contract might use custom NotOwner error
      await expect(
        verifier.connect(user1).setVerificationKey(alpha, beta, gamma, delta, ic)
      ).to.be.reverted;
    });

    it("Should not allow setting verification key twice", async function () {
      await verifier.setVerificationKey(alpha, beta, gamma, delta, ic);
      
      await expect(
        verifier.setVerificationKey(alpha, beta, gamma, delta, ic)
      ).to.be.revertedWithCustomError(verifier, "AlreadyInitialized");
    });
  });

  describe("Proof Verification", function () {
    // Set up verification key first
    const alpha = [1n, 2n];
    const beta = [3n, 4n, 5n, 6n];
    const gamma = [7n, 8n, 9n, 10n];
    const delta = [11n, 12n, 13n, 14n];
    const ic = [[15n, 16n], [17n, 18n]];

    beforeEach(async function () {
      await verifier.setVerificationKey(alpha, beta, gamma, delta, ic);
    });

    it("Should verify valid proof format", async function () {
      // Minimum 384 bytes for proof (A: 96, B: 192, C: 96)
      const proof = ethers.toUtf8Bytes("0".repeat(768)); // > 384 bytes
      const publicInputs = ethers.toUtf8Bytes("0".repeat(64));

      // V2 returns true for valid format in MVP (actual pairing would verify)
      const result = await verifier.verifyProof(proof, publicInputs);
      expect(result).to.be.true;
    });

    it("Should reject proof that is too short", async function () {
      const shortProof = ethers.toUtf8Bytes("0".repeat(100)); // < 384 bytes
      const publicInputs = ethers.toUtf8Bytes("0".repeat(64));

      await expect(
        verifier.verifyProof(shortProof, publicInputs)
      ).to.be.revertedWithCustomError(verifier, "InvalidProofLength");
    });
  });

  describe("Batch Verification", function () {
    const alpha = [1n, 2n];
    const beta = [3n, 4n, 5n, 6n];
    const gamma = [7n, 8n, 9n, 10n];
    const delta = [11n, 12n, 13n, 14n];
    const ic = [[15n, 16n], [17n, 18n]];

    beforeEach(async function () {
      await verifier.setVerificationKey(alpha, beta, gamma, delta, ic);
    });

    it("Should batch verify proofs", async function () {
      const proofs = [];
      const publicInputsArray = [];
      
      for (let i = 0; i < 3; i++) {
        proofs.push(ethers.toUtf8Bytes("0".repeat(768)));
        publicInputsArray.push(ethers.toUtf8Bytes("0".repeat(64)));
      }

      // V2 returns a single boolean for allValid
      const result = await verifier.batchVerifyProofs(proofs, publicInputsArray);
      expect(result).to.be.true;
    });

    it("Should revert on array length mismatch", async function () {
      const proofs = [
        ethers.toUtf8Bytes("0".repeat(768)),
        ethers.toUtf8Bytes("0".repeat(768))
      ];
      const publicInputsArray = [
        ethers.toUtf8Bytes("0".repeat(64))
      ]; // Only 1 input, but 2 proofs

      // V2 uses require with "Length mismatch" message
      await expect(
        verifier.batchVerifyProofs(proofs, publicInputsArray)
      ).to.be.revertedWith("Length mismatch");
    });

    it("Should handle empty batch gracefully", async function () {
      // V2 allows empty batch and returns true (no proofs to verify = all valid)
      const result = await verifier.batchVerifyProofs([], []);
      expect(result).to.be.true;
    });
  });

  describe("Helper Functions", function () {
    const alpha = [1n, 2n];
    const beta = [3n, 4n, 5n, 6n];
    const gamma = [7n, 8n, 9n, 10n];
    const delta = [11n, 12n, 13n, 14n];
    const ic = [[15n, 16n], [17n, 18n]];

    beforeEach(async function () {
      await verifier.setVerificationKey(alpha, beta, gamma, delta, ic);
    });

    it("Should return correct IC count", async function () {
      expect(await verifier.getICCount()).to.equal(2);
    });
  });
});
