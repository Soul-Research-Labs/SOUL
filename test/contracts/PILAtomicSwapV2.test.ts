import { expect } from "chai";
import { ethers } from "hardhat";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { time } from "@nomicfoundation/hardhat-network-helpers";

describe("PILAtomicSwapV2", function () {
  let swap: any;
  let token: any;
  let owner: SignerWithAddress;
  let alice: SignerWithAddress;
  let bob: SignerWithAddress;
  let feeCollector: SignerWithAddress;

  const ONE_HOUR = 3600;
  const ONE_ETH = ethers.parseEther("1");

  beforeEach(async function () {
    [owner, alice, bob, feeCollector] = await ethers.getSigners();

    // Deploy mock ERC20
    const Token = await ethers.getContractFactory("MockERC20");
    token = await Token.deploy("Test Token", "TEST", ethers.parseEther("10000"));
    await token.waitForDeployment();

    // Transfer tokens to alice
    await token.transfer(alice.address, ethers.parseEther("1000"));

    // Deploy swap contract
    const Swap = await ethers.getContractFactory("PILAtomicSwapV2");
    swap = await Swap.deploy(feeCollector.address);
    await swap.waitForDeployment();
  });

  describe("Deployment", function () {
    it("Should set correct fee collector", async function () {
      expect(await swap.feeCollector()).to.equal(feeCollector.address);
    });

    it("Should set correct owner", async function () {
      expect(await swap.owner()).to.equal(owner.address);
    });

    it("Should revert on zero fee collector", async function () {
      const Swap = await ethers.getContractFactory("PILAtomicSwapV2");
      await expect(Swap.deploy(ethers.ZeroAddress)).to.be.revertedWithCustomError(
        Swap,
        "ZeroAddress"
      );
    });
  });

  describe("ETH Swaps", function () {
    const hashlock = ethers.keccak256(ethers.toUtf8Bytes("secret123"));
    const secret = ethers.toUtf8Bytes("secret123");
    const stealthCommitment = ethers.keccak256(ethers.toUtf8Bytes("stealth"));

    describe("Initiation", function () {
      it("Should initiate ETH swap", async function () {
        const timelock = (await time.latest()) + ONE_HOUR;

        const tx = await swap
          .connect(alice)
          .initiateEthSwap(bob.address, hashlock, timelock, stealthCommitment, { value: ONE_ETH });

        const receipt = await tx.wait();
        const event = receipt.logs.find((log: any) => log.fragment?.name === "SwapInitiated");
        expect(event).to.not.be.undefined;
      });

      it("Should revert with zero value", async function () {
        const timelock = (await time.latest()) + ONE_HOUR;

        await expect(
          swap.connect(alice).initiateEthSwap(bob.address, hashlock, timelock, stealthCommitment, { value: 0 })
        ).to.be.revertedWithCustomError(swap, "ZeroAmount");
      });

      it("Should revert with past timelock", async function () {
        const pastTime = (await time.latest()) - ONE_HOUR;

        await expect(
          swap.connect(alice).initiateEthSwap(bob.address, hashlock, pastTime, stealthCommitment, { value: ONE_ETH })
        ).to.be.revertedWithCustomError(swap, "InvalidTimelock");
      });

      it("Should revert with zero recipient", async function () {
        const timelock = (await time.latest()) + ONE_HOUR;

        await expect(
          swap.connect(alice).initiateEthSwap(ethers.ZeroAddress, hashlock, timelock, stealthCommitment, { value: ONE_ETH })
        ).to.be.revertedWithCustomError(swap, "ZeroAddress");
      });
    });

    describe("Redemption", function () {
      let swapId: string;

      beforeEach(async function () {
        const timelock = (await time.latest()) + ONE_HOUR;
        const tx = await swap
          .connect(alice)
          .initiateEthSwap(bob.address, hashlock, timelock, stealthCommitment, { value: ONE_ETH });
        const receipt = await tx.wait();
        const event = receipt.logs.find((log: any) => log.fragment?.name === "SwapInitiated");
        swapId = event.args[0];
      });

      it("Should redeem with correct secret", async function () {
        const bobBalanceBefore = await ethers.provider.getBalance(bob.address);

        await expect(swap.connect(bob).redeem(swapId, secret))
          .to.emit(swap, "SwapRedeemed")
          .withArgs(swapId, bob.address);

        const bobBalanceAfter = await ethers.provider.getBalance(bob.address);
        expect(bobBalanceAfter).to.be.gt(bobBalanceBefore);
      });

      it("Should revert with wrong secret", async function () {
        const wrongSecret = ethers.toUtf8Bytes("wrongsecret");

        await expect(swap.connect(bob).redeem(swapId, wrongSecret)).to.be.revertedWithCustomError(
          swap,
          "InvalidSecret"
        );
      });

      it("Should revert if already redeemed", async function () {
        await swap.connect(bob).redeem(swapId, secret);

        await expect(swap.connect(bob).redeem(swapId, secret)).to.be.revertedWithCustomError(
          swap,
          "SwapNotActive"
        );
      });
    });

    describe("Refund", function () {
      let swapId: string;

      beforeEach(async function () {
        const timelock = (await time.latest()) + ONE_HOUR;
        const tx = await swap
          .connect(alice)
          .initiateEthSwap(bob.address, hashlock, timelock, stealthCommitment, { value: ONE_ETH });
        const receipt = await tx.wait();
        const event = receipt.logs.find((log: any) => log.fragment?.name === "SwapInitiated");
        swapId = event.args[0];
      });

      it("Should refund after timelock", async function () {
        // Fast forward past timelock
        await time.increase(ONE_HOUR + 1);

        const aliceBalanceBefore = await ethers.provider.getBalance(alice.address);

        await expect(swap.connect(alice).refund(swapId))
          .to.emit(swap, "SwapRefunded")
          .withArgs(swapId, alice.address);

        const aliceBalanceAfter = await ethers.provider.getBalance(alice.address);
        expect(aliceBalanceAfter).to.be.gt(aliceBalanceBefore);
      });

      it("Should revert before timelock", async function () {
        await expect(swap.connect(alice).refund(swapId)).to.be.revertedWithCustomError(
          swap,
          "TimelockNotExpired"
        );
      });

      it("Should only allow initiator to refund", async function () {
        await time.increase(ONE_HOUR + 1);

        await expect(swap.connect(bob).refund(swapId)).to.be.revertedWithCustomError(
          swap,
          "NotInitiator"
        );
      });
    });
  });

  describe("Token Swaps", function () {
    const hashlock = ethers.keccak256(ethers.toUtf8Bytes("secret456"));
    const secret = ethers.toUtf8Bytes("secret456");
    const stealthCommitment = ethers.keccak256(ethers.toUtf8Bytes("stealth2"));
    const amount = ethers.parseEther("100");

    describe("Initiation", function () {
      beforeEach(async function () {
        await token.connect(alice).approve(await swap.getAddress(), amount);
      });

      it("Should initiate token swap", async function () {
        const timelock = (await time.latest()) + ONE_HOUR;

        await expect(
          swap.connect(alice).initiateTokenSwap(
            await token.getAddress(),
            amount,
            bob.address,
            hashlock,
            timelock,
            stealthCommitment
          )
        ).to.emit(swap, "SwapInitiated");
      });

      it("Should transfer tokens to contract", async function () {
        const timelock = (await time.latest()) + ONE_HOUR;
        const swapAddress = await swap.getAddress();

        await swap.connect(alice).initiateTokenSwap(
          await token.getAddress(),
          amount,
          bob.address,
          hashlock,
          timelock,
          stealthCommitment
        );

        expect(await token.balanceOf(swapAddress)).to.equal(amount);
      });
    });

    describe("Redemption", function () {
      let swapId: string;

      beforeEach(async function () {
        await token.connect(alice).approve(await swap.getAddress(), amount);
        const timelock = (await time.latest()) + ONE_HOUR;

        const tx = await swap.connect(alice).initiateTokenSwap(
          await token.getAddress(),
          amount,
          bob.address,
          hashlock,
          timelock,
          stealthCommitment
        );
        const receipt = await tx.wait();
        const event = receipt.logs.find((log: any) => log.fragment?.name === "SwapInitiated");
        swapId = event.args[0];
      });

      it("Should transfer tokens to recipient", async function () {
        const bobBalanceBefore = await token.balanceOf(bob.address);

        await swap.connect(bob).redeem(swapId, secret);

        const bobBalanceAfter = await token.balanceOf(bob.address);
        // Account for fee
        expect(bobBalanceAfter).to.be.gt(bobBalanceBefore);
      });
    });
  });

  describe("Fee Management", function () {
    it("Should update fee rate", async function () {
      const newFee = 50; // 0.5%

      await expect(swap.setFeeRate(newFee))
        .to.emit(swap, "FeeRateUpdated")
        .withArgs(newFee);

      expect(await swap.feeRate()).to.equal(newFee);
    });

    it("Should revert on excessive fee", async function () {
      const excessiveFee = 1001; // > 10%

      await expect(swap.setFeeRate(excessiveFee)).to.be.revertedWithCustomError(
        swap,
        "FeeTooHigh"
      );
    });

    it("Should update fee collector", async function () {
      await expect(swap.setFeeCollector(bob.address))
        .to.emit(swap, "FeeCollectorUpdated")
        .withArgs(bob.address);
    });

    it("Should only allow owner to update fees", async function () {
      await expect(swap.connect(alice).setFeeRate(50)).to.be.revertedWithCustomError(
        swap,
        "OwnableUnauthorizedAccount"
      );
    });
  });

  describe("Pause Functionality", function () {
    it("Should prevent swaps when paused", async function () {
      await swap.pause();

      const hashlock = ethers.keccak256(ethers.toUtf8Bytes("secret"));
      const timelock = (await time.latest()) + ONE_HOUR;
      const stealthCommitment = ethers.keccak256(ethers.toUtf8Bytes("stealth"));

      await expect(
        swap.connect(alice).initiateEthSwap(bob.address, hashlock, timelock, stealthCommitment, { value: ONE_ETH })
      ).to.be.revertedWithCustomError(swap, "EnforcedPause");
    });
  });

  describe("Swap Queries", function () {
    it("Should return swap details", async function () {
      const hashlock = ethers.keccak256(ethers.toUtf8Bytes("secret789"));
      const timelock = (await time.latest()) + ONE_HOUR;
      const stealthCommitment = ethers.keccak256(ethers.toUtf8Bytes("stealth3"));

      const tx = await swap
        .connect(alice)
        .initiateEthSwap(bob.address, hashlock, timelock, stealthCommitment, { value: ONE_ETH });
      const receipt = await tx.wait();
      const event = receipt.logs.find((log: any) => log.fragment?.name === "SwapInitiated");
      const swapId = event.args[0];

      const details = await swap.getSwap(swapId);
      expect(details.initiator).to.equal(alice.address);
      expect(details.recipient).to.equal(bob.address);
      expect(details.hashlock).to.equal(hashlock);
    });
  });
});
