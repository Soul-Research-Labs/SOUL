import { expect } from "chai";
import { ethers } from "hardhat";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("NullifierRegistryV2", function () {
  let registry: any;
  let owner: SignerWithAddress;
  let registrar: SignerWithAddress;
  let user1: SignerWithAddress;

  beforeEach(async function () {
    [owner, registrar, user1] = await ethers.getSigners();

    const Registry = await ethers.getContractFactory("NullifierRegistryV2");
    registry = await Registry.deploy();
    await registry.waitForDeployment();

    // Add registrar
    await registry.addAuthorizedRegistrar(registrar.address);
  });

  describe("Deployment", function () {
    it("Should set the correct owner", async function () {
      expect(await registry.owner()).to.equal(owner.address);
    });

    it("Should start unpaused", async function () {
      expect(await registry.paused()).to.be.false;
    });
  });

  describe("Authorized Registrars", function () {
    it("Should add authorized registrar", async function () {
      const newRegistrar = user1.address;
      await expect(registry.addAuthorizedRegistrar(newRegistrar))
        .to.emit(registry, "RegistrarAdded")
        .withArgs(newRegistrar);

      expect(await registry.isAuthorizedRegistrar(newRegistrar)).to.be.true;
    });

    it("Should remove authorized registrar", async function () {
      await expect(registry.removeAuthorizedRegistrar(registrar.address))
        .to.emit(registry, "RegistrarRemoved")
        .withArgs(registrar.address);

      expect(await registry.isAuthorizedRegistrar(registrar.address)).to.be.false;
    });

    it("Should revert on zero address", async function () {
      await expect(
        registry.addAuthorizedRegistrar(ethers.ZeroAddress)
      ).to.be.revertedWithCustomError(registry, "ZeroAddress");
    });

    it("Should revert if already authorized", async function () {
      await expect(
        registry.addAuthorizedRegistrar(registrar.address)
      ).to.be.revertedWithCustomError(registry, "AlreadyAuthorized");
    });
  });

  describe("Nullifier Registration", function () {
    const nullifier = ethers.keccak256(ethers.toUtf8Bytes("nullifier1"));
    const sourceChain = 1;

    it("Should register nullifier", async function () {
      await expect(registry.connect(registrar).registerNullifier(nullifier, sourceChain))
        .to.emit(registry, "NullifierRegistered")
        .withArgs(nullifier, sourceChain, registrar.address);

      expect(await registry.isNullifierUsed(nullifier)).to.be.true;
    });

    it("Should revert on duplicate nullifier", async function () {
      await registry.connect(registrar).registerNullifier(nullifier, sourceChain);

      await expect(
        registry.connect(registrar).registerNullifier(nullifier, sourceChain)
      ).to.be.revertedWithCustomError(registry, "NullifierAlreadyExists");
    });

    it("Should revert for unauthorized registrar", async function () {
      await expect(
        registry.connect(user1).registerNullifier(nullifier, sourceChain)
      ).to.be.revertedWithCustomError(registry, "NotAuthorizedRegistrar");
    });

    it("Should revert when paused", async function () {
      await registry.pause();
      await expect(
        registry.connect(registrar).registerNullifier(nullifier, sourceChain)
      ).to.be.revertedWithCustomError(registry, "EnforcedPause");
    });
  });

  describe("Batch Registration", function () {
    it("Should register batch of nullifiers", async function () {
      const nullifiers = [
        ethers.keccak256(ethers.toUtf8Bytes("nullifier1")),
        ethers.keccak256(ethers.toUtf8Bytes("nullifier2")),
        ethers.keccak256(ethers.toUtf8Bytes("nullifier3")),
      ];
      const sourceChains = [1, 2, 1];

      await registry.connect(registrar).registerNullifierBatch(nullifiers, sourceChains);

      for (const nullifier of nullifiers) {
        expect(await registry.isNullifierUsed(nullifier)).to.be.true;
      }
    });

    it("Should revert on mismatched array lengths", async function () {
      const nullifiers = [
        ethers.keccak256(ethers.toUtf8Bytes("nullifier1")),
        ethers.keccak256(ethers.toUtf8Bytes("nullifier2")),
      ];
      const sourceChains = [1];

      await expect(
        registry.connect(registrar).registerNullifierBatch(nullifiers, sourceChains)
      ).to.be.revertedWithCustomError(registry, "ArrayLengthMismatch");
    });

    it("Should revert on empty batch", async function () {
      await expect(
        registry.connect(registrar).registerNullifierBatch([], [])
      ).to.be.revertedWithCustomError(registry, "EmptyBatch");
    });
  });

  describe("Nullifier Info", function () {
    const nullifier = ethers.keccak256(ethers.toUtf8Bytes("nullifier1"));
    const sourceChain = 137; // Polygon

    beforeEach(async function () {
      await registry.connect(registrar).registerNullifier(nullifier, sourceChain);
    });

    it("Should return correct nullifier info", async function () {
      const info = await registry.getNullifierInfo(nullifier);
      expect(info.sourceChain).to.equal(sourceChain);
      expect(info.registrar).to.equal(registrar.address);
      expect(info.timestamp).to.be.gt(0);
    });

    it("Should revert for non-existent nullifier", async function () {
      const unknownNullifier = ethers.keccak256(ethers.toUtf8Bytes("unknown"));
      await expect(
        registry.getNullifierInfo(unknownNullifier)
      ).to.be.revertedWithCustomError(registry, "NullifierNotFound");
    });
  });

  describe("Cross-Chain Verification", function () {
    const nullifier = ethers.keccak256(ethers.toUtf8Bytes("nullifier1"));

    it("Should verify nullifier across chains", async function () {
      await registry.connect(registrar).registerNullifier(nullifier, 1);

      // Query from chain perspective
      expect(await registry.isNullifierUsedOnChain(nullifier, 1)).to.be.true;
      expect(await registry.isNullifierUsedOnChain(nullifier, 2)).to.be.false;
    });

    it("Should check global nullifier usage", async function () {
      await registry.connect(registrar).registerNullifier(nullifier, 1);
      
      expect(await registry.isNullifierUsed(nullifier)).to.be.true;
    });
  });

  describe("Statistics", function () {
    it("Should track total nullifiers", async function () {
      expect(await registry.getTotalNullifiers()).to.equal(0);

      await registry.connect(registrar).registerNullifier(
        ethers.keccak256(ethers.toUtf8Bytes("n1")),
        1
      );
      expect(await registry.getTotalNullifiers()).to.equal(1);

      await registry.connect(registrar).registerNullifier(
        ethers.keccak256(ethers.toUtf8Bytes("n2")),
        1
      );
      expect(await registry.getTotalNullifiers()).to.equal(2);
    });
  });

  describe("Pause Functionality", function () {
    it("Should pause and unpause", async function () {
      await registry.pause();
      expect(await registry.paused()).to.be.true;

      await registry.unpause();
      expect(await registry.paused()).to.be.false;
    });

    it("Should only allow owner to pause", async function () {
      await expect(registry.connect(user1).pause()).to.be.revertedWithCustomError(
        registry,
        "OwnableUnauthorizedAccount"
      );
    });
  });
});
