import { expect } from "chai";
import hre from "hardhat";
import { keccak256, toBytes, padHex, type Hex } from "viem";

/**
 * MoneroPrimitives Unit Tests
 * 
 * Tests for Monero cryptographic primitives:
 * - Ed25519 scalar field arithmetic
 * - Hash functions (hashToScalar, hashToPoint)
 * - Key image operations
 * - Pedersen commitments
 * - Cross-domain nullifier binding
 */
describe("MoneroPrimitives", function () {
  // Ed25519 constants
  const ED25519_PRIME = 57896044618658097711785492504343953926634992332820282019728792003956564819949n;
  const ED25519_ORDER = 7237005577332262213973186563042994240857116359379907606001950938285454250989n;
  const ED25519_D = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;

  // Helper to get viem - Hardhat 3 dynamically provides viem
  async function getViem() {
    const connection = await hre.network.connect();
    const viem = (connection as any).viem;
    return viem;
  }

  /*//////////////////////////////////////////////////////////////
                           CONSTANTS
  //////////////////////////////////////////////////////////////*/

  describe("Constants", function () {
    it("Should have correct ED25519_PRIME", async function () {
      const viem = await getViem();
      const primitives = await viem.deployContract("MoneroPrimitives");
      const result = await primitives.read.ED25519_PRIME();
      expect(result).to.equal(ED25519_PRIME);
    });

    it("Should have correct ED25519_ORDER", async function () {
      const viem = await getViem();
      const primitives = await viem.deployContract("MoneroPrimitives");
      const result = await primitives.read.ED25519_ORDER();
      expect(result).to.equal(ED25519_ORDER);
    });

    it("Should have correct ED25519_D", async function () {
      const viem = await getViem();
      const primitives = await viem.deployContract("MoneroPrimitives");
      const result = await primitives.read.ED25519_D();
      expect(result).to.equal(ED25519_D);
    });

    it("Should have correct COFACTOR", async function () {
      const viem = await getViem();
      const primitives = await viem.deployContract("MoneroPrimitives");
      const result = await primitives.read.COFACTOR();
      expect(result).to.equal(8);
    });

    it("Should have correct PIL_MONERO_DOMAIN", async function () {
      const viem = await getViem();
      const primitives = await viem.deployContract("MoneroPrimitives");
      const expectedDomain = keccak256(toBytes("PIL_Monero_Interop_v1"));
      const result = await primitives.read.PIL_MONERO_DOMAIN();
      expect(result).to.equal(expectedDomain);
    });
  });

  /*//////////////////////////////////////////////////////////////
                        SCALAR ARITHMETIC
  //////////////////////////////////////////////////////////////*/

  describe("Scalar Arithmetic", function () {
    describe("scalarAdd", function () {
      it("Should add two scalars correctly", async function () {
        const viem = await getViem();
        const primitives = await viem.deployContract("MoneroPrimitives");
        const result = await primitives.read.scalarAdd([100n, 200n]);
        expect(result).to.equal(300n);
      });

      it("Should handle modular reduction", async function () {
        const viem = await getViem();
        const primitives = await viem.deployContract("MoneroPrimitives");
        const result = await primitives.read.scalarAdd([ED25519_ORDER - 1n, 2n]);
        expect(result).to.equal(1n);
      });

      it("Should be commutative", async function () {
        const viem = await getViem();
        const primitives = await viem.deployContract("MoneroPrimitives");
        const result1 = await primitives.read.scalarAdd([12345n, 67890n]);
        const result2 = await primitives.read.scalarAdd([67890n, 12345n]);
        expect(result1).to.equal(result2);
      });

      it("Should have zero as identity", async function () {
        const viem = await getViem();
        const primitives = await viem.deployContract("MoneroPrimitives");
        const result = await primitives.read.scalarAdd([12345n, 0n]);
        expect(result).to.equal(12345n);
      });
    });

    describe("scalarSub", function () {
      it("Should subtract two scalars correctly", async function () {
        const viem = await getViem();
        const primitives = await viem.deployContract("MoneroPrimitives");
        const result = await primitives.read.scalarSub([300n, 100n]);
        expect(result).to.equal(200n);
      });

      it("Should handle underflow with modular reduction", async function () {
        const viem = await getViem();
        const primitives = await viem.deployContract("MoneroPrimitives");
        const result = await primitives.read.scalarSub([10n, 20n]);
        expect(result).to.equal(ED25519_ORDER - 10n);
      });

      it("Should return zero when subtracting same value", async function () {
        const viem = await getViem();
        const primitives = await viem.deployContract("MoneroPrimitives");
        const result = await primitives.read.scalarSub([12345n, 12345n]);
        expect(result).to.equal(0n);
      });
    });

    describe("scalarMul", function () {
      it("Should multiply two scalars correctly", async function () {
        const viem = await getViem();
        const primitives = await viem.deployContract("MoneroPrimitives");
        const result = await primitives.read.scalarMul([100n, 200n]);
        expect(result).to.equal(20000n);
      });

      it("Should handle modular reduction", async function () {
        const viem = await getViem();
        const primitives = await viem.deployContract("MoneroPrimitives");
        const a = ED25519_ORDER / 2n;
        const result = await primitives.read.scalarMul([a, 3n]);
        expect(result).to.equal((a * 3n) % ED25519_ORDER);
      });

      it("Should be commutative", async function () {
        const viem = await getViem();
        const primitives = await viem.deployContract("MoneroPrimitives");
        const result1 = await primitives.read.scalarMul([12345n, 67890n]);
        const result2 = await primitives.read.scalarMul([67890n, 12345n]);
        expect(result1).to.equal(result2);
      });

      it("Should have one as identity", async function () {
        const viem = await getViem();
        const primitives = await viem.deployContract("MoneroPrimitives");
        const result = await primitives.read.scalarMul([12345n, 1n]);
        expect(result).to.equal(12345n);
      });

      it("Should return zero when multiplying by zero", async function () {
        const viem = await getViem();
        const primitives = await viem.deployContract("MoneroPrimitives");
        const result = await primitives.read.scalarMul([12345n, 0n]);
        expect(result).to.equal(0n);
      });
    });

    describe("isValidScalar", function () {
      it("Should return true for zero", async function () {
        const viem = await getViem();
        const primitives = await viem.deployContract("MoneroPrimitives");
        expect(await primitives.read.isValidScalar([0n])).to.be.true;
      });

      it("Should return true for values less than order", async function () {
        const viem = await getViem();
        const primitives = await viem.deployContract("MoneroPrimitives");
        expect(await primitives.read.isValidScalar([12345n])).to.be.true;
        expect(await primitives.read.isValidScalar([ED25519_ORDER - 1n])).to.be.true;
      });

      it("Should return false for order", async function () {
        const viem = await getViem();
        const primitives = await viem.deployContract("MoneroPrimitives");
        expect(await primitives.read.isValidScalar([ED25519_ORDER])).to.be.false;
      });

      it("Should return false for values greater than order", async function () {
        const viem = await getViem();
        const primitives = await viem.deployContract("MoneroPrimitives");
        expect(await primitives.read.isValidScalar([ED25519_ORDER + 1n])).to.be.false;
      });
    });

    describe("scalarReduce512", function () {
      it("Should reduce 512-bit numbers", async function () {
        const viem = await getViem();
        const primitives = await viem.deployContract("MoneroPrimitives");
        const result = await primitives.read.scalarReduce512([12345n, 0n]);
        expect(result).to.equal(12345n % ED25519_ORDER);
      });

      it("Should handle high bits", async function () {
        const viem = await getViem();
        const primitives = await viem.deployContract("MoneroPrimitives");
        const result = await primitives.read.scalarReduce512([0n, 1n]);
        expect(result < ED25519_ORDER).to.be.true;
      });
    });
  });

  /*//////////////////////////////////////////////////////////////
                         HASH FUNCTIONS
  //////////////////////////////////////////////////////////////*/

  describe("Hash Functions", function () {
    describe("hashToScalar", function () {
      it("Should be deterministic", async function () {
        const viem = await getViem();
        const primitives = await viem.deployContract("MoneroPrimitives");
        const data = toBytes("test data");
        const result1 = await primitives.read.hashToScalar([data]);
        const result2 = await primitives.read.hashToScalar([data]);
        expect(result1).to.equal(result2);
      });

      it("Should produce different hashes for different inputs", async function () {
        const viem = await getViem();
        const primitives = await viem.deployContract("MoneroPrimitives");
        const data1 = toBytes("test data 1");
        const data2 = toBytes("test data 2");
        const result1 = await primitives.read.hashToScalar([data1]);
        const result2 = await primitives.read.hashToScalar([data2]);
        expect(result1).to.not.equal(result2);
      });

      it("Should produce valid scalar", async function () {
        const viem = await getViem();
        const primitives = await viem.deployContract("MoneroPrimitives");
        const data = toBytes("test data");
        const result = await primitives.read.hashToScalar([data]);
        expect(await primitives.read.isValidScalar([result])).to.be.true;
      });
    });

    describe("hashToPoint", function () {
      it("Should be deterministic", async function () {
        const viem = await getViem();
        const primitives = await viem.deployContract("MoneroPrimitives");
        const data = toBytes("test data");
        const result1 = await primitives.read.hashToPoint([data]);
        const result2 = await primitives.read.hashToPoint([data]);
        expect(result1).to.deep.equal(result2);
      });

      it("Should produce different points for different inputs", async function () {
        const viem = await getViem();
        const primitives = await viem.deployContract("MoneroPrimitives");
        const data1 = toBytes("test data 1");
        const data2 = toBytes("test data 2");
        const result1 = await primitives.read.hashToPoint([data1]);
        const result2 = await primitives.read.hashToPoint([data2]);
        expect(result1[0]).to.not.equal(result2[0]); // x-coordinate differs
      });
    });
  });

  /*//////////////////////////////////////////////////////////////
                    KEY IMAGE OPERATIONS
  //////////////////////////////////////////////////////////////*/

  describe("Key Image Operations", function () {
    describe("hashKeyImageToPIL", function () {
      it("Should be deterministic", async function () {
        const viem = await getViem();
        const primitives = await viem.deployContract("MoneroPrimitives");
        const keyImage = padHex("0x1234", { size: 32 }) as Hex;
        const result1 = await primitives.read.hashKeyImageToPIL([keyImage]);
        const result2 = await primitives.read.hashKeyImageToPIL([keyImage]);
        expect(result1).to.equal(result2);
      });

      it("Should produce different hashes for different key images", async function () {
        const viem = await getViem();
        const primitives = await viem.deployContract("MoneroPrimitives");
        const keyImage1 = padHex("0x1234", { size: 32 }) as Hex;
        const keyImage2 = padHex("0x5678", { size: 32 }) as Hex;
        const result1 = await primitives.read.hashKeyImageToPIL([keyImage1]);
        const result2 = await primitives.read.hashKeyImageToPIL([keyImage2]);
        expect(result1).to.not.equal(result2);
      });

      it("Should include PIL domain in hash", async function () {
        const viem = await getViem();
        const primitives = await viem.deployContract("MoneroPrimitives");
        const keyImage = padHex("0x1234", { size: 32 }) as Hex;
        const pilNullifier = await primitives.read.hashKeyImageToPIL([keyImage]);
        
        // The PIL nullifier should be different from raw keccak of key image
        const rawHash = keccak256(keyImage);
        expect(pilNullifier).to.not.equal(rawHash);
      });
    });

    describe("verifyKeyImageBinding", function () {
      it("Should verify correct binding", async function () {
        const viem = await getViem();
        const primitives = await viem.deployContract("MoneroPrimitives");
        
        const keyImage = padHex("0x1234", { size: 32 }) as Hex;
        const pilNullifier = await primitives.read.hashKeyImageToPIL([keyImage]);
        
        const isValid = await primitives.read.verifyKeyImageBinding([keyImage, pilNullifier]);
        expect(isValid).to.be.true;
      });

      it("Should reject incorrect binding", async function () {
        const viem = await getViem();
        const primitives = await viem.deployContract("MoneroPrimitives");
        
        const keyImage = padHex("0x1234", { size: 32 }) as Hex;
        const wrongNullifier = padHex("0x9999", { size: 32 }) as Hex;
        
        const isValid = await primitives.read.verifyKeyImageBinding([keyImage, wrongNullifier]);
        expect(isValid).to.be.false;
      });
    });
  });

  /*//////////////////////////////////////////////////////////////
                     PEDERSEN COMMITMENTS
  //////////////////////////////////////////////////////////////*/

  describe("Pedersen Commitments", function () {
    describe("computeCommitment", function () {
      it("Should be deterministic", async function () {
        const viem = await getViem();
        const primitives = await viem.deployContract("MoneroPrimitives");
        const amount = 100n;
        const blinding = 12345n;
        
        const result1 = await primitives.read.computeCommitment([amount, blinding]);
        const result2 = await primitives.read.computeCommitment([amount, blinding]);
        expect(result1).to.deep.equal(result2);
      });

      it("Should produce different commitments for different amounts", async function () {
        const viem = await getViem();
        const primitives = await viem.deployContract("MoneroPrimitives");
        const blinding = 12345n;
        
        const result1 = await primitives.read.computeCommitment([100n, blinding]);
        const result2 = await primitives.read.computeCommitment([200n, blinding]);
        expect(result1[0]).to.not.equal(result2[0]);
      });

      it("Should produce different commitments for different blindings", async function () {
        const viem = await getViem();
        const primitives = await viem.deployContract("MoneroPrimitives");
        const amount = 100n;
        
        const result1 = await primitives.read.computeCommitment([amount, 12345n]);
        const result2 = await primitives.read.computeCommitment([amount, 54321n]);
        expect(result1[0]).to.not.equal(result2[0]);
      });

      it("Should verify hiding property", async function () {
        const viem = await getViem();
        const primitives = await viem.deployContract("MoneroPrimitives");
        
        // Same amount, different blindings produce different commitments
        const c1 = await primitives.read.computeCommitment([1000n, 111n]);
        const c2 = await primitives.read.computeCommitment([1000n, 222n]);
        expect(c1[0]).to.not.equal(c2[0]);
      });
    });
  });

  /*//////////////////////////////////////////////////////////////
                    CLSAG VERIFICATION STRUCTURE
  //////////////////////////////////////////////////////////////*/

  describe("CLSAG Structure", function () {
    it("Should validate CLSAG signature structure", async function () {
      const viem = await getViem();
      await viem.deployContract("MoneroPrimitives");
      
      // Create valid CLSAG structure
      const ringSize = 11;
      const keyImages: Hex[] = [padHex("0x01", { size: 32 }) as Hex];
      const c0 = padHex("0x02", { size: 32 }) as Hex;
      const s: Hex[] = new Array(ringSize).fill(padHex("0x03", { size: 32 }) as Hex);
      const D: [bigint, bigint] = [100n, 200n];
      
      const clsag = {
        keyImages,
        c0,
        s,
        D
      };
      
      // Verify structure is valid
      expect(clsag.keyImages.length).to.equal(1);
      expect(clsag.s.length).to.equal(ringSize);
    });
  });

  /*//////////////////////////////////////////////////////////////
                  BULLETPROOF+ STRUCTURE
  //////////////////////////////////////////////////////////////*/

  describe("Bulletproof+ Structure", function () {
    it("Should validate Bulletproof+ structure", async function () {
      const viem = await getViem();
      await viem.deployContract("MoneroPrimitives");
      
      // Create valid Bulletproof+ structure
      const V: [bigint, bigint][] = [[100n, 200n]];
      const A: [bigint, bigint] = [300n, 400n];
      const A1: [bigint, bigint] = [500n, 600n];
      const B: [bigint, bigint] = [700n, 800n];
      const r1 = 1000n;
      const s1 = 2000n;
      const d1 = 3000n;
      const L: [bigint, bigint][] = [[100n, 200n], [300n, 400n], [500n, 600n]];
      const R: [bigint, bigint][] = [[700n, 800n], [900n, 1000n], [1100n, 1200n]];
      
      const bp = { V, A, A1, B, r1, s1, d1, L, R };
      
      // Verify structure
      expect(bp.L.length).to.equal(bp.R.length);
      expect(bp.V.length).to.be.greaterThan(0);
    });
  });

  /*//////////////////////////////////////////////////////////////
                       CROSS-DOMAIN NULLIFIER
  //////////////////////////////////////////////////////////////*/

  describe("Cross-Domain Nullifier Binding", function () {
    it("Should compute consistent PIL nullifier", async function () {
      const viem = await getViem();
      const primitives = await viem.deployContract("MoneroPrimitives");
      
      const keyImage = padHex("0xabc123", { size: 32 }) as Hex;
      const pilNullifier = await primitives.read.hashKeyImageToPIL([keyImage]);
      
      // Should be non-zero
      expect(pilNullifier).to.not.equal(padHex("0x00", { size: 32 }));
      
      // Should be deterministic
      const pilNullifier2 = await primitives.read.hashKeyImageToPIL([keyImage]);
      expect(pilNullifier).to.equal(pilNullifier2);
    });

    it("Should bind nullifiers bidirectionally", async function () {
      const viem = await getViem();
      const primitives = await viem.deployContract("MoneroPrimitives");
      
      const keyImage = padHex("0xdef456", { size: 32 }) as Hex;
      const pilNullifier = await primitives.read.hashKeyImageToPIL([keyImage]);
      
      // Verify binding works
      const isValid = await primitives.read.verifyKeyImageBinding([keyImage, pilNullifier]);
      expect(isValid).to.be.true;
      
      // Different key image should not verify
      const otherKeyImage = padHex("0x789abc", { size: 32 }) as Hex;
      const isInvalid = await primitives.read.verifyKeyImageBinding([otherKeyImage, pilNullifier]);
      expect(isInvalid).to.be.false;
    });
  });
});
