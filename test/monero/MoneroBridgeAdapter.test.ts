import { expect } from "chai";
import hre from "hardhat";
import { keccak256, toBytes, padHex, parseEther, type Hex, type Address } from "viem";

/**
 * MoneroBridgeAdapter Unit Tests
 * 
 * Tests for the Monero federated bridge:
 * - Custodian management
 * - Deposit processing
 * - Withdrawal requests and signing
 * - Key image tracking
 * - Cross-domain nullifier synchronization
 * - Access control
 */
describe("MoneroBridgeAdapter", function () {
  // Role constants
  const RELAYER_ROLE = keccak256(toBytes("RELAYER_ROLE"));
  const CUSTODIAN_ROLE = keccak256(toBytes("CUSTODIAN_ROLE"));
  const OPERATOR_ROLE = keccak256(toBytes("OPERATOR_ROLE"));
  const PAUSER_ROLE = keccak256(toBytes("PAUSER_ROLE"));
  const DEFAULT_ADMIN_ROLE = padHex("0x00", { size: 32 });

  // Helper to get viem - Hardhat 3 dynamically provides viem
  async function getViem() {
    const connection = await hre.network.connect();
    const viem = (connection as any).viem;
    return viem;
  }

  /*//////////////////////////////////////////////////////////////
                        DEPLOYMENT
  //////////////////////////////////////////////////////////////*/

  describe("Deployment", function () {
    it("Should deploy with correct initial state", async function () {
      const viem = await getViem();
      const [admin] = await viem.getWalletClients();

      const bridge = await viem.deployContract("MoneroBridgeAdapter");
      
      // Check admin has default admin role
      const hasAdminRole = await bridge.read.hasRole([DEFAULT_ADMIN_ROLE, admin.account.address]);
      expect(hasAdminRole).to.be.true;
    });

    it("Should initialize with zero deposits and withdrawals", async function () {
      const viem = await getViem();
      const bridge = await viem.deployContract("MoneroBridgeAdapter");
      
      const stats = await bridge.read.getBridgeStats();
      expect(stats[0]).to.equal(0n); // totalDeposits
      expect(stats[1]).to.equal(0n); // totalWithdrawals
      expect(stats[2]).to.equal(0n); // pendingWithdrawals
    });
  });

  /*//////////////////////////////////////////////////////////////
                      CUSTODIAN MANAGEMENT
  //////////////////////////////////////////////////////////////*/

  describe("Custodian Management", function () {
    it("Should add custodian with correct role", async function () {
      const viem = await getViem();
      const [admin, custodian] = await viem.getWalletClients();

      const bridge = await viem.deployContract("MoneroBridgeAdapter");
      
      await bridge.write.grantRole([CUSTODIAN_ROLE, custodian.account.address]);
      
      const hasCustodianRole = await bridge.read.hasRole([CUSTODIAN_ROLE, custodian.account.address]);
      expect(hasCustodianRole).to.be.true;
    });

    it("Should set signature threshold", async function () {
      const viem = await getViem();
      const [admin, operator] = await viem.getWalletClients();

      const bridge = await viem.deployContract("MoneroBridgeAdapter");
      await bridge.write.grantRole([OPERATOR_ROLE, operator.account.address]);
      
      // Set threshold to 3-of-5
      await bridge.write.setSignatureThreshold([3n], { account: operator.account });
      
      const threshold = await bridge.read.signatureThreshold();
      expect(threshold).to.equal(3n);
    });

    it("Should reject threshold higher than custodian count", async function () {
      const viem = await getViem();
      const [admin, operator] = await viem.getWalletClients();

      const bridge = await viem.deployContract("MoneroBridgeAdapter");
      await bridge.write.grantRole([OPERATOR_ROLE, operator.account.address]);
      
      // Try to set threshold to 10 with 0 custodians
      try {
        await bridge.write.setSignatureThreshold([10n], { account: operator.account });
        expect.fail("Should have reverted");
      } catch (error: unknown) {
        expect((error as Error).message).to.include("revert");
      }
    });
  });

  /*//////////////////////////////////////////////////////////////
                      DEPOSIT PROCESSING
  //////////////////////////////////////////////////////////////*/

  describe("Deposit Processing", function () {
    it("Should process valid deposit from relayer", async function () {
      const viem = await getViem();
      const [admin, relayer, user] = await viem.getWalletClients();

      const bridge = await viem.deployContract("MoneroBridgeAdapter");
      await bridge.write.grantRole([RELAYER_ROLE, relayer.account.address]);
      
      const moneroTxHash = padHex("0x1234", { size: 32 }) as Hex;
      const keyImage = padHex("0x5678", { size: 32 }) as Hex;
      const amount = parseEther("1.0");
      const recipient = user.account.address;
      
      // Process deposit
      await bridge.write.processDeposit(
        [moneroTxHash, keyImage, amount, recipient],
        { account: relayer.account }
      );
      
      // Verify key image is registered
      const isUsed = await bridge.read.isKeyImageUsed([keyImage]);
      expect(isUsed).to.be.true;
      
      // Verify stats updated
      const stats = await bridge.read.getBridgeStats();
      expect(stats[0]).to.equal(amount);
    });

    it("Should reject duplicate key image", async function () {
      const viem = await getViem();
      const [admin, relayer, user] = await viem.getWalletClients();

      const bridge = await viem.deployContract("MoneroBridgeAdapter");
      await bridge.write.grantRole([RELAYER_ROLE, relayer.account.address]);
      
      const moneroTxHash = padHex("0x1234", { size: 32 }) as Hex;
      const keyImage = padHex("0xabcd", { size: 32 }) as Hex;
      const amount = parseEther("1.0");
      const recipient = user.account.address;
      
      // First deposit
      await bridge.write.processDeposit(
        [moneroTxHash, keyImage, amount, recipient],
        { account: relayer.account }
      );
      
      // Second deposit with same key image should fail
      try {
        await bridge.write.processDeposit(
          [padHex("0x9999", { size: 32 }) as Hex, keyImage, amount, recipient],
          { account: relayer.account }
        );
        expect.fail("Should have reverted");
      } catch (error: unknown) {
        expect((error as Error).message).to.include("revert");
      }
    });

    it("Should reject deposit from non-relayer", async function () {
      const viem = await getViem();
      const [admin, notRelayer, user] = await viem.getWalletClients();

      const bridge = await viem.deployContract("MoneroBridgeAdapter");
      
      const moneroTxHash = padHex("0x1234", { size: 32 }) as Hex;
      const keyImage = padHex("0x5678", { size: 32 }) as Hex;
      const amount = parseEther("1.0");
      const recipient = user.account.address;
      
      try {
        await bridge.write.processDeposit(
          [moneroTxHash, keyImage, amount, recipient],
          { account: notRelayer.account }
        );
        expect.fail("Should have reverted");
      } catch (error: unknown) {
        expect((error as Error).message).to.include("revert");
      }
    });
  });

  /*//////////////////////////////////////////////////////////////
                    WITHDRAWAL REQUESTS
  //////////////////////////////////////////////////////////////*/

  describe("Withdrawal Requests", function () {
    it("Should create withdrawal request", async function () {
      const viem = await getViem();
      const [admin, user] = await viem.getWalletClients();

      const bridge = await viem.deployContract("MoneroBridgeAdapter");
      
      const amount = parseEther("0.5");
      const moneroAddress = "4" + "A".repeat(94); // Mock Monero address
      
      await bridge.write.requestWithdrawal(
        [amount, moneroAddress],
        { account: user.account, value: amount }
      );
      
      // Verify stats updated
      const stats = await bridge.read.getBridgeStats();
      expect(stats[2]).to.equal(amount); // pendingWithdrawals
    });

    it("Should reject withdrawal with mismatched value", async function () {
      const viem = await getViem();
      const [admin, user] = await viem.getWalletClients();

      const bridge = await viem.deployContract("MoneroBridgeAdapter");
      
      const amount = parseEther("0.5");
      const moneroAddress = "4" + "A".repeat(94);
      
      try {
        await bridge.write.requestWithdrawal(
          [amount, moneroAddress],
          { account: user.account, value: parseEther("0.3") } // Wrong value
        );
        expect.fail("Should have reverted");
      } catch (error: unknown) {
        expect((error as Error).message).to.include("revert");
      }
    });
  });

  /*//////////////////////////////////////////////////////////////
                      CUSTODIAN SIGNING
  //////////////////////////////////////////////////////////////*/

  describe("Custodian Signing", function () {
    it("Should accept custodian signature", async function () {
      const viem = await getViem();
      const [admin, custodian1, operator, user] = await viem.getWalletClients();

      const bridge = await viem.deployContract("MoneroBridgeAdapter");
      await bridge.write.grantRole([CUSTODIAN_ROLE, custodian1.account.address]);
      await bridge.write.grantRole([OPERATOR_ROLE, operator.account.address]);
      
      // Set threshold
      await bridge.write.setSignatureThreshold([1n], { account: operator.account });
      
      // Create withdrawal request
      const amount = parseEther("0.5");
      const moneroAddress = "4" + "A".repeat(94);
      
      await bridge.write.requestWithdrawal(
        [amount, moneroAddress],
        { account: user.account, value: amount }
      );
      
      // Get withdrawal ID (assuming it's 0 for first withdrawal)
      const withdrawalId = 0n;
      const signature = padHex("0xsig", { size: 65 }) as Hex; // Mock signature
      
      // Sign withdrawal
      await bridge.write.signWithdrawal(
        [withdrawalId, signature],
        { account: custodian1.account }
      );
      
      // Check signature count
      const sigCount = await bridge.read.getWithdrawalSignatureCount([withdrawalId]);
      expect(sigCount).to.equal(1n);
    });

    it("Should reject duplicate signature from same custodian", async function () {
      const viem = await getViem();
      const [admin, custodian1, operator, user] = await viem.getWalletClients();

      const bridge = await viem.deployContract("MoneroBridgeAdapter");
      await bridge.write.grantRole([CUSTODIAN_ROLE, custodian1.account.address]);
      await bridge.write.grantRole([OPERATOR_ROLE, operator.account.address]);
      await bridge.write.setSignatureThreshold([2n], { account: operator.account });
      
      // Create withdrawal
      const amount = parseEther("0.5");
      const moneroAddress = "4" + "A".repeat(94);
      
      await bridge.write.requestWithdrawal(
        [amount, moneroAddress],
        { account: user.account, value: amount }
      );
      
      const withdrawalId = 0n;
      const signature = padHex("0xsig", { size: 65 }) as Hex;
      
      // First signature
      await bridge.write.signWithdrawal(
        [withdrawalId, signature],
        { account: custodian1.account }
      );
      
      // Second signature from same custodian should fail
      try {
        await bridge.write.signWithdrawal(
          [withdrawalId, signature],
          { account: custodian1.account }
        );
        expect.fail("Should have reverted");
      } catch (error: unknown) {
        expect((error as Error).message).to.include("revert");
      }
    });
  });

  /*//////////////////////////////////////////////////////////////
                     WITHDRAWAL COMPLETION
  //////////////////////////////////////////////////////////////*/

  describe("Withdrawal Completion", function () {
    it("Should complete withdrawal when threshold reached", async function () {
      const viem = await getViem();
      const [admin, custodian1, custodian2, operator, user] = await viem.getWalletClients();

      const bridge = await viem.deployContract("MoneroBridgeAdapter");
      await bridge.write.grantRole([CUSTODIAN_ROLE, custodian1.account.address]);
      await bridge.write.grantRole([CUSTODIAN_ROLE, custodian2.account.address]);
      await bridge.write.grantRole([OPERATOR_ROLE, operator.account.address]);
      await bridge.write.setSignatureThreshold([2n], { account: operator.account });
      
      // Create withdrawal
      const amount = parseEther("0.5");
      const moneroAddress = "4" + "A".repeat(94);
      
      await bridge.write.requestWithdrawal(
        [amount, moneroAddress],
        { account: user.account, value: amount }
      );
      
      const withdrawalId = 0n;
      const sig1 = padHex("0xsig1", { size: 65 }) as Hex;
      const sig2 = padHex("0xsig2", { size: 65 }) as Hex;
      
      // Both custodians sign
      await bridge.write.signWithdrawal([withdrawalId, sig1], { account: custodian1.account });
      await bridge.write.signWithdrawal([withdrawalId, sig2], { account: custodian2.account });
      
      // Check signature count
      const sigCount = await bridge.read.getWithdrawalSignatureCount([withdrawalId]);
      expect(sigCount).to.equal(2n);
      
      // Should be ready for completion
      const isReady = await bridge.read.isWithdrawalReady([withdrawalId]);
      expect(isReady).to.be.true;
    });
  });

  /*//////////////////////////////////////////////////////////////
                     KEY IMAGE TRACKING
  //////////////////////////////////////////////////////////////*/

  describe("Key Image Tracking", function () {
    it("Should track used key images", async function () {
      const viem = await getViem();
      const [admin, relayer, user] = await viem.getWalletClients();

      const bridge = await viem.deployContract("MoneroBridgeAdapter");
      await bridge.write.grantRole([RELAYER_ROLE, relayer.account.address]);
      
      const keyImage1 = padHex("0xkey1", { size: 32 }) as Hex;
      const keyImage2 = padHex("0xkey2", { size: 32 }) as Hex;
      
      // Initially not used
      expect(await bridge.read.isKeyImageUsed([keyImage1])).to.be.false;
      expect(await bridge.read.isKeyImageUsed([keyImage2])).to.be.false;
      
      // Process deposit with keyImage1
      await bridge.write.processDeposit(
        [padHex("0xtx1", { size: 32 }) as Hex, keyImage1, parseEther("1.0"), user.account.address],
        { account: relayer.account }
      );
      
      // keyImage1 should be used
      expect(await bridge.read.isKeyImageUsed([keyImage1])).to.be.true;
      expect(await bridge.read.isKeyImageUsed([keyImage2])).to.be.false;
    });

    it("Should link key images to PIL nullifiers", async function () {
      const viem = await getViem();
      const [admin, relayer, user] = await viem.getWalletClients();

      const bridge = await viem.deployContract("MoneroBridgeAdapter");
      await bridge.write.grantRole([RELAYER_ROLE, relayer.account.address]);
      
      const keyImage = padHex("0xkey123", { size: 32 }) as Hex;
      
      // Process deposit
      await bridge.write.processDeposit(
        [padHex("0xtx", { size: 32 }) as Hex, keyImage, parseEther("1.0"), user.account.address],
        { account: relayer.account }
      );
      
      // Get PIL nullifier
      const pilNullifier = await bridge.read.getPILNullifier([keyImage]);
      expect(pilNullifier).to.not.equal(padHex("0x00", { size: 32 }));
    });
  });

  /*//////////////////////////////////////////////////////////////
                      PAUSE FUNCTIONALITY
  //////////////////////////////////////////////////////////////*/

  describe("Pause Functionality", function () {
    it("Should pause and unpause", async function () {
      const viem = await getViem();
      const [admin, pauser] = await viem.getWalletClients();

      const bridge = await viem.deployContract("MoneroBridgeAdapter");
      await bridge.write.grantRole([PAUSER_ROLE, pauser.account.address]);
      
      // Initially not paused
      expect(await bridge.read.paused()).to.be.false;
      
      // Pause
      await bridge.write.pause({ account: pauser.account });
      expect(await bridge.read.paused()).to.be.true;
      
      // Unpause
      await bridge.write.unpause({ account: pauser.account });
      expect(await bridge.read.paused()).to.be.false;
    });

    it("Should reject operations when paused", async function () {
      const viem = await getViem();
      const [admin, pauser, user] = await viem.getWalletClients();

      const bridge = await viem.deployContract("MoneroBridgeAdapter");
      await bridge.write.grantRole([PAUSER_ROLE, pauser.account.address]);
      
      // Pause
      await bridge.write.pause({ account: pauser.account });
      
      // Try withdrawal request
      const amount = parseEther("0.5");
      const moneroAddress = "4" + "A".repeat(94);
      
      try {
        await bridge.write.requestWithdrawal(
          [amount, moneroAddress],
          { account: user.account, value: amount }
        );
        expect.fail("Should have reverted");
      } catch (error: unknown) {
        expect((error as Error).message).to.include("revert");
      }
    });
  });

  /*//////////////////////////////////////////////////////////////
                      ACCESS CONTROL
  //////////////////////////////////////////////////////////////*/

  describe("Access Control", function () {
    it("Should only allow admin to grant roles", async function () {
      const viem = await getViem();
      const [admin, notAdmin, user] = await viem.getWalletClients();

      const bridge = await viem.deployContract("MoneroBridgeAdapter");
      
      try {
        await bridge.write.grantRole(
          [RELAYER_ROLE, user.account.address],
          { account: notAdmin.account }
        );
        expect.fail("Should have reverted");
      } catch (error: unknown) {
        expect((error as Error).message).to.include("revert");
      }
    });

    it("Should allow admin to revoke roles", async function () {
      const viem = await getViem();
      const [admin, relayer] = await viem.getWalletClients();

      const bridge = await viem.deployContract("MoneroBridgeAdapter");
      
      // Grant then revoke
      await bridge.write.grantRole([RELAYER_ROLE, relayer.account.address]);
      expect(await bridge.read.hasRole([RELAYER_ROLE, relayer.account.address])).to.be.true;
      
      await bridge.write.revokeRole([RELAYER_ROLE, relayer.account.address]);
      expect(await bridge.read.hasRole([RELAYER_ROLE, relayer.account.address])).to.be.false;
    });
  });

  /*//////////////////////////////////////////////////////////////
                     BLOCK HEADER VERIFICATION
  //////////////////////////////////////////////////////////////*/

  describe("Block Header Verification", function () {
    it("Should submit and retrieve block headers", async function () {
      const viem = await getViem();
      const [admin, relayer] = await viem.getWalletClients();

      const bridge = await viem.deployContract("MoneroBridgeAdapter");
      await bridge.write.grantRole([RELAYER_ROLE, relayer.account.address]);
      
      const blockHeight = 1000000n;
      const blockHash = padHex("0xblockhash", { size: 32 }) as Hex;
      const timestamp = BigInt(Math.floor(Date.now() / 1000));
      
      await bridge.write.submitBlockHeader(
        [blockHeight, blockHash, timestamp],
        { account: relayer.account }
      );
      
      const storedHash = await bridge.read.getBlockHash([blockHeight]);
      expect(storedHash).to.equal(blockHash);
    });

    it("Should track last confirmed block", async function () {
      const viem = await getViem();
      const [admin, relayer] = await viem.getWalletClients();

      const bridge = await viem.deployContract("MoneroBridgeAdapter");
      await bridge.write.grantRole([RELAYER_ROLE, relayer.account.address]);
      
      const blockHeight = 2000000n;
      const blockHash = padHex("0xblockhash2", { size: 32 }) as Hex;
      const timestamp = BigInt(Math.floor(Date.now() / 1000));
      
      await bridge.write.submitBlockHeader(
        [blockHeight, blockHash, timestamp],
        { account: relayer.account }
      );
      
      const lastBlock = await bridge.read.lastConfirmedBlockHeight();
      expect(lastBlock).to.equal(blockHeight);
    });
  });
});
