import { expect } from "chai";
import { ethers } from "hardhat";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("ConfidentialStateContainerV2", function () {
  let container: any;
  let verifier: any;
  let owner: SignerWithAddress;
  let user1: SignerWithAddress;
  let user2: SignerWithAddress;

  beforeEach(async function () {
    [owner, user1, user2] = await ethers.getSigners();

    // Deploy verifier
    const Verifier = await ethers.getContractFactory("Groth16VerifierBLS12381");
    verifier = await Verifier.deploy();
    await verifier.waitForDeployment();

    // Deploy container
    const Container = await ethers.getContractFactory("ConfidentialStateContainerV2");
    container = await Container.deploy(await verifier.getAddress());
    await container.waitForDeployment();
  });

  describe("Deployment", function () {
    it("Should set the correct verifier address", async function () {
      expect(await container.verifier()).to.equal(await verifier.getAddress());
    });

    it("Should set the correct owner", async function () {
      expect(await container.owner()).to.equal(owner.address);
    });

    it("Should revert on zero verifier address", async function () {
      const Container = await ethers.getContractFactory("ConfidentialStateContainerV2");
      await expect(Container.deploy(ethers.ZeroAddress)).to.be.revertedWithCustomError(
        Container,
        "ZeroAddress"
      );
    });
  });

  describe("State Registration", function () {
    const encryptedState = ethers.toUtf8Bytes("encrypted_data");
    const commitment = ethers.keccak256(ethers.toUtf8Bytes("commitment1"));
    const nullifier = ethers.keccak256(ethers.toUtf8Bytes("nullifier1"));
    const proof = ethers.toUtf8Bytes("0".repeat(768)); // 384 bytes min
    const publicInputs = ethers.toUtf8Bytes("0".repeat(64));

    it("Should register state successfully", async function () {
      await expect(
        container.connect(user1).registerState(encryptedState, commitment, nullifier, proof, publicInputs)
      )
        .to.emit(container, "StateRegistered")
        .withArgs(commitment, user1.address);

      expect(await container.stateExists(commitment)).to.be.true;
      expect(await container.getStateOwner(commitment)).to.equal(user1.address);
    });

    it("Should revert on duplicate nullifier", async function () {
      await container.connect(user1).registerState(encryptedState, commitment, nullifier, proof, publicInputs);

      const newCommitment = ethers.keccak256(ethers.toUtf8Bytes("commitment2"));
      await expect(
        container.connect(user1).registerState(encryptedState, newCommitment, nullifier, proof, publicInputs)
      ).to.be.revertedWithCustomError(container, "NullifierAlreadyUsed");
    });

    it("Should revert on empty encrypted state", async function () {
      await expect(
        container.connect(user1).registerState([], commitment, nullifier, proof, publicInputs)
      ).to.be.revertedWithCustomError(container, "EmptyEncryptedState");
    });

    it("Should revert when paused", async function () {
      await container.pause();
      await expect(
        container.connect(user1).registerState(encryptedState, commitment, nullifier, proof, publicInputs)
      ).to.be.revertedWithCustomError(container, "EnforcedPause");
    });
  });

  describe("State Transfer", function () {
    const encryptedState = ethers.toUtf8Bytes("encrypted_data");
    const commitment = ethers.keccak256(ethers.toUtf8Bytes("commitment1"));
    const nullifier = ethers.keccak256(ethers.toUtf8Bytes("nullifier1"));
    const proof = ethers.toUtf8Bytes("0".repeat(768));
    const publicInputs = ethers.toUtf8Bytes("0".repeat(64));

    beforeEach(async function () {
      await container.connect(user1).registerState(encryptedState, commitment, nullifier, proof, publicInputs);
    });

    it("Should transfer state successfully", async function () {
      const newEncryptedState = ethers.toUtf8Bytes("new_encrypted_data");
      const newCommitment = ethers.keccak256(ethers.toUtf8Bytes("commitment2"));
      const newNullifier = ethers.keccak256(ethers.toUtf8Bytes("nullifier2"));

      await expect(
        container
          .connect(user1)
          .transferState(commitment, newEncryptedState, newCommitment, newNullifier, proof, publicInputs, user2.address)
      )
        .to.emit(container, "StateTransferred")
        .withArgs(commitment, newCommitment, user2.address);

      expect(await container.getStateOwner(newCommitment)).to.equal(user2.address);
    });

    it("Should revert if not owner", async function () {
      const newEncryptedState = ethers.toUtf8Bytes("new_encrypted_data");
      const newCommitment = ethers.keccak256(ethers.toUtf8Bytes("commitment2"));
      const newNullifier = ethers.keccak256(ethers.toUtf8Bytes("nullifier2"));

      await expect(
        container
          .connect(user2)
          .transferState(commitment, newEncryptedState, newCommitment, newNullifier, proof, publicInputs, user2.address)
      ).to.be.revertedWithCustomError(container, "NotStateOwner");
    });
  });

  describe("Admin Functions", function () {
    it("Should update verifier", async function () {
      const NewVerifier = await ethers.getContractFactory("Groth16VerifierBLS12381");
      const newVerifier = await NewVerifier.deploy();
      await newVerifier.waitForDeployment();

      await expect(container.setVerifier(await newVerifier.getAddress()))
        .to.emit(container, "VerifierUpdated");
    });

    it("Should pause and unpause", async function () {
      await container.pause();
      expect(await container.paused()).to.be.true;

      await container.unpause();
      expect(await container.paused()).to.be.false;
    });

    it("Should only allow owner to pause", async function () {
      await expect(container.connect(user1).pause()).to.be.revertedWithCustomError(
        container,
        "OwnableUnauthorizedAccount"
      );
    });
  });
});
