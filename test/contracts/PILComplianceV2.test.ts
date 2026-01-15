import { expect } from "chai";
import { ethers } from "hardhat";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { time } from "@nomicfoundation/hardhat-network-helpers";

describe("PILComplianceV2", function () {
  let compliance: any;
  let owner: SignerWithAddress;
  let provider: SignerWithAddress;
  let user1: SignerWithAddress;
  let user2: SignerWithAddress;

  beforeEach(async function () {
    [owner, provider, user1, user2] = await ethers.getSigners();

    const Compliance = await ethers.getContractFactory("PILComplianceV2");
    compliance = await Compliance.deploy();
    await compliance.waitForDeployment();

    // Add provider
    await compliance.addProvider(provider.address, "TestProvider");
  });

  describe("Deployment", function () {
    it("Should set correct owner", async function () {
      expect(await compliance.owner()).to.equal(owner.address);
    });

    it("Should start unpaused", async function () {
      expect(await compliance.paused()).to.be.false;
    });
  });

  describe("Provider Management", function () {
    it("Should add provider", async function () {
      await expect(compliance.addProvider(user1.address, "NewProvider"))
        .to.emit(compliance, "ProviderAdded")
        .withArgs(user1.address, "NewProvider");

      expect(await compliance.isProvider(user1.address)).to.be.true;
    });

    it("Should remove provider", async function () {
      await expect(compliance.removeProvider(provider.address))
        .to.emit(compliance, "ProviderRemoved")
        .withArgs(provider.address);

      expect(await compliance.isProvider(provider.address)).to.be.false;
    });

    it("Should revert on zero address", async function () {
      await expect(
        compliance.addProvider(ethers.ZeroAddress, "Invalid")
      ).to.be.revertedWithCustomError(compliance, "ZeroAddress");
    });

    it("Should revert if already provider", async function () {
      await expect(
        compliance.addProvider(provider.address, "Duplicate")
      ).to.be.revertedWithCustomError(compliance, "AlreadyProvider");
    });

    it("Should only allow owner to manage providers", async function () {
      await expect(
        compliance.connect(user1).addProvider(user2.address, "Unauthorized")
      ).to.be.revertedWithCustomError(compliance, "OwnableUnauthorizedAccount");
    });
  });

  describe("KYC Registration", function () {
    const ONE_YEAR = 365 * 24 * 60 * 60;

    describe("Tier 1 KYC", function () {
      it("Should register tier 1 KYC", async function () {
        const expiry = (await time.latest()) + ONE_YEAR;
        const commitment = ethers.keccak256(ethers.toUtf8Bytes("kyc_commitment"));

        await expect(
          compliance.connect(provider).registerKYC(user1.address, 1, expiry, commitment, "US")
        )
          .to.emit(compliance, "KYCRegistered")
          .withArgs(user1.address, 1, expiry, provider.address);

        expect(await compliance.isKYCValid(user1.address)).to.be.true;
      });

      it("Should check KYC tier", async function () {
        const expiry = (await time.latest()) + ONE_YEAR;
        const commitment = ethers.keccak256(ethers.toUtf8Bytes("kyc_commitment"));

        await compliance.connect(provider).registerKYC(user1.address, 1, expiry, commitment, "US");

        expect(await compliance.getKYCTier(user1.address)).to.equal(1);
      });
    });

    describe("Tier 2 KYC", function () {
      it("Should register tier 2 KYC", async function () {
        const expiry = (await time.latest()) + ONE_YEAR;
        const commitment = ethers.keccak256(ethers.toUtf8Bytes("kyc_commitment_t2"));

        await compliance.connect(provider).registerKYC(user1.address, 2, expiry, commitment, "GB");

        expect(await compliance.getKYCTier(user1.address)).to.equal(2);
      });

      it("Should allow higher tier operations", async function () {
        const expiry = (await time.latest()) + ONE_YEAR;
        const commitment = ethers.keccak256(ethers.toUtf8Bytes("kyc_commitment"));

        await compliance.connect(provider).registerKYC(user1.address, 2, expiry, commitment, "DE");

        expect(await compliance.meetsKYCRequirement(user1.address, 1)).to.be.true;
        expect(await compliance.meetsKYCRequirement(user1.address, 2)).to.be.true;
        expect(await compliance.meetsKYCRequirement(user1.address, 3)).to.be.false;
      });
    });

    describe("Tier 3 KYC (Institutional)", function () {
      it("Should register tier 3 KYC", async function () {
        const expiry = (await time.latest()) + ONE_YEAR;
        const commitment = ethers.keccak256(ethers.toUtf8Bytes("institutional_commitment"));

        await compliance.connect(provider).registerKYC(user1.address, 3, expiry, commitment, "CH");

        expect(await compliance.getKYCTier(user1.address)).to.equal(3);
      });
    });

    it("Should revert for unauthorized provider", async function () {
      const expiry = (await time.latest()) + ONE_YEAR;
      const commitment = ethers.keccak256(ethers.toUtf8Bytes("commitment"));

      await expect(
        compliance.connect(user1).registerKYC(user2.address, 1, expiry, commitment, "US")
      ).to.be.revertedWithCustomError(compliance, "NotAuthorizedProvider");
    });

    it("Should revert for invalid tier", async function () {
      const expiry = (await time.latest()) + ONE_YEAR;
      const commitment = ethers.keccak256(ethers.toUtf8Bytes("commitment"));

      await expect(
        compliance.connect(provider).registerKYC(user1.address, 0, expiry, commitment, "US")
      ).to.be.revertedWithCustomError(compliance, "InvalidKYCTier");

      await expect(
        compliance.connect(provider).registerKYC(user1.address, 4, expiry, commitment, "US")
      ).to.be.revertedWithCustomError(compliance, "InvalidKYCTier");
    });

    it("Should revert for past expiry", async function () {
      const pastExpiry = (await time.latest()) - ONE_YEAR;
      const commitment = ethers.keccak256(ethers.toUtf8Bytes("commitment"));

      await expect(
        compliance.connect(provider).registerKYC(user1.address, 1, pastExpiry, commitment, "US")
      ).to.be.revertedWithCustomError(compliance, "InvalidExpiry");
    });
  });

  describe("KYC Expiration", function () {
    const ONE_YEAR = 365 * 24 * 60 * 60;

    it("Should detect expired KYC", async function () {
      const shortExpiry = (await time.latest()) + 100; // 100 seconds
      const commitment = ethers.keccak256(ethers.toUtf8Bytes("commitment"));

      await compliance.connect(provider).registerKYC(user1.address, 1, shortExpiry, commitment, "US");

      expect(await compliance.isKYCValid(user1.address)).to.be.true;

      // Fast forward
      await time.increase(101);

      expect(await compliance.isKYCValid(user1.address)).to.be.false;
    });

    it("Should allow KYC renewal", async function () {
      const shortExpiry = (await time.latest()) + 100;
      const commitment1 = ethers.keccak256(ethers.toUtf8Bytes("commitment1"));

      await compliance.connect(provider).registerKYC(user1.address, 1, shortExpiry, commitment1, "US");

      // Renew before expiry
      const newExpiry = (await time.latest()) + ONE_YEAR;
      const commitment2 = ethers.keccak256(ethers.toUtf8Bytes("commitment2"));

      await compliance.connect(provider).registerKYC(user1.address, 1, newExpiry, commitment2, "US");

      // Fast forward past original expiry
      await time.increase(200);

      expect(await compliance.isKYCValid(user1.address)).to.be.true;
    });
  });

  describe("KYC Revocation", function () {
    const ONE_YEAR = 365 * 24 * 60 * 60;

    beforeEach(async function () {
      const expiry = (await time.latest()) + ONE_YEAR;
      const commitment = ethers.keccak256(ethers.toUtf8Bytes("commitment"));
      await compliance.connect(provider).registerKYC(user1.address, 1, expiry, commitment, "US");
    });

    it("Should revoke KYC by provider", async function () {
      await expect(compliance.connect(provider).revokeKYC(user1.address, "Fraudulent activity"))
        .to.emit(compliance, "KYCRevoked")
        .withArgs(user1.address, provider.address, "Fraudulent activity");

      expect(await compliance.isKYCValid(user1.address)).to.be.false;
    });

    it("Should revoke KYC by owner", async function () {
      await compliance.revokeKYC(user1.address, "Admin decision");

      expect(await compliance.isKYCValid(user1.address)).to.be.false;
    });

    it("Should track revocation reason", async function () {
      await compliance.connect(provider).revokeKYC(user1.address, "Test reason");

      const kycInfo = await compliance.getKYCInfo(user1.address);
      expect(kycInfo.revoked).to.be.true;
      expect(kycInfo.revocationReason).to.equal("Test reason");
    });
  });

  describe("Sanctions Management", function () {
    it("Should add sanctioned address", async function () {
      await expect(compliance.addSanctionedAddress(user1.address, "OFAC"))
        .to.emit(compliance, "AddressSanctioned")
        .withArgs(user1.address, "OFAC");

      expect(await compliance.isSanctioned(user1.address)).to.be.true;
    });

    it("Should remove sanctioned address", async function () {
      await compliance.addSanctionedAddress(user1.address, "OFAC");

      await expect(compliance.removeSanctionedAddress(user1.address))
        .to.emit(compliance, "SanctionRemoved")
        .withArgs(user1.address);

      expect(await compliance.isSanctioned(user1.address)).to.be.false;
    });

    it("Should block KYC validity for sanctioned addresses", async function () {
      const expiry = (await time.latest()) + 365 * 24 * 60 * 60;
      const commitment = ethers.keccak256(ethers.toUtf8Bytes("commitment"));
      await compliance.connect(provider).registerKYC(user1.address, 1, expiry, commitment, "US");

      expect(await compliance.isKYCValid(user1.address)).to.be.true;

      await compliance.addSanctionedAddress(user1.address, "OFAC");

      expect(await compliance.isKYCValid(user1.address)).to.be.false;
    });

    it("Should only allow owner to manage sanctions", async function () {
      await expect(
        compliance.connect(user1).addSanctionedAddress(user2.address, "Test")
      ).to.be.revertedWithCustomError(compliance, "OwnableUnauthorizedAccount");
    });
  });

  describe("Jurisdiction Management", function () {
    it("Should add restricted jurisdiction", async function () {
      await expect(compliance.addRestrictedJurisdiction("KP"))
        .to.emit(compliance, "JurisdictionRestricted")
        .withArgs("KP");

      expect(await compliance.isJurisdictionRestricted("KP")).to.be.true;
    });

    it("Should remove restricted jurisdiction", async function () {
      await compliance.addRestrictedJurisdiction("IR");
      
      await expect(compliance.removeRestrictedJurisdiction("IR"))
        .to.emit(compliance, "JurisdictionUnrestricted")
        .withArgs("IR");

      expect(await compliance.isJurisdictionRestricted("IR")).to.be.false;
    });

    it("Should block KYC for restricted jurisdictions", async function () {
      await compliance.addRestrictedJurisdiction("RU");

      const expiry = (await time.latest()) + 365 * 24 * 60 * 60;
      const commitment = ethers.keccak256(ethers.toUtf8Bytes("commitment"));

      await expect(
        compliance.connect(provider).registerKYC(user1.address, 1, expiry, commitment, "RU")
      ).to.be.revertedWithCustomError(compliance, "JurisdictionRestricted");
    });
  });

  describe("Audit Logs", function () {
    it("Should create audit log entry", async function () {
      const eventType = ethers.keccak256(ethers.toUtf8Bytes("TRANSFER"));
      const data = ethers.toUtf8Bytes("transfer_details");

      await expect(compliance.connect(provider).logAuditEvent(user1.address, eventType, data))
        .to.emit(compliance, "AuditLogCreated");
    });

    it("Should retrieve audit log count", async function () {
      const eventType = ethers.keccak256(ethers.toUtf8Bytes("TRANSFER"));
      const data = ethers.toUtf8Bytes("details");

      await compliance.connect(provider).logAuditEvent(user1.address, eventType, data);
      await compliance.connect(provider).logAuditEvent(user1.address, eventType, data);
      await compliance.connect(provider).logAuditEvent(user1.address, eventType, data);

      expect(await compliance.getAuditLogCount(user1.address)).to.equal(3);
    });

    it("Should only allow providers to log", async function () {
      const eventType = ethers.keccak256(ethers.toUtf8Bytes("TRANSFER"));
      const data = ethers.toUtf8Bytes("details");

      await expect(
        compliance.connect(user1).logAuditEvent(user2.address, eventType, data)
      ).to.be.revertedWithCustomError(compliance, "NotAuthorizedProvider");
    });
  });

  describe("Batch Operations", function () {
    it("Should batch check KYC", async function () {
      const expiry = (await time.latest()) + 365 * 24 * 60 * 60;
      
      await compliance.connect(provider).registerKYC(
        user1.address, 1, expiry,
        ethers.keccak256(ethers.toUtf8Bytes("c1")), "US"
      );
      await compliance.connect(provider).registerKYC(
        user2.address, 2, expiry,
        ethers.keccak256(ethers.toUtf8Bytes("c2")), "GB"
      );

      const results = await compliance.batchCheckKYC([user1.address, user2.address, owner.address]);
      expect(results[0]).to.be.true;
      expect(results[1]).to.be.true;
      expect(results[2]).to.be.false; // Owner has no KYC
    });
  });

  describe("Pause Functionality", function () {
    it("Should prevent KYC registration when paused", async function () {
      await compliance.pause();

      const expiry = (await time.latest()) + 365 * 24 * 60 * 60;
      const commitment = ethers.keccak256(ethers.toUtf8Bytes("commitment"));

      await expect(
        compliance.connect(provider).registerKYC(user1.address, 1, expiry, commitment, "US")
      ).to.be.revertedWithCustomError(compliance, "EnforcedPause");
    });
  });
});
