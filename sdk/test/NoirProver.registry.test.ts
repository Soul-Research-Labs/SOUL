import { expect } from "chai";
import * as fs from "fs/promises";
import * as path from "path";
import {
  Circuit,
  createProver,
  getProver,
  type CircuitArtifact,
} from "../src/zkprover/NoirProver";
import {
  ALL_REGISTERED_CIRCUITS,
  CIRCUIT_REGISTRY,
  validateCircuitArtifact,
} from "../src/zkprover/CircuitRegistry";

describe("NoirProver circuit registry", () => {
  it("keeps the Circuit enum aligned with the registry", () => {
    expect(Object.values(Circuit).sort()).to.deep.equal(
      [...ALL_REGISTERED_CIRCUITS].sort(),
    );
    expect(ALL_REGISTERED_CIRCUITS).to.include("liquidity_proof");
    expect(Object.values(Circuit)).to.include(Circuit.LiquidityProof);
  });

  it("rejects unsupported circuit IDs before generating placeholders", async () => {
    const prover = createProver({ mode: "development" });

    try {
      await prover.generateProof("not_registered" as Circuit, {});
      expect.fail("Expected unsupported circuit to throw");
    } catch (err: any) {
      expect(err.message).to.include("Unsupported Noir circuit");
    }
  });

  it("can require declared public inputs for development proofs", async () => {
    const prover = createProver({
      mode: "development",
      strictPublicInputs: true,
    });

    const result = await prover.generateProof(Circuit.LiquidityProof, {
      lock_commitment: "0x" + "11".repeat(32),
      pool_commitment: "0x" + "22".repeat(32),
      nullifier: "0x" + "33".repeat(32),
      transfer_amount_hash: "0x" + "44".repeat(32),
      timestamp_bound: "123456789",
    });

    expect(result.isPlaceholder).to.equal(true);
    expect(result.publicInputs).to.deep.equal([
      "0x" + "11".repeat(32),
      "0x" + "22".repeat(32),
      "0x" + "33".repeat(32),
      "0x" + "44".repeat(32),
      "123456789",
    ]);
  });

  it("fails strict public-input mode when declared inputs are missing", async () => {
    const prover = createProver({
      mode: "development",
      strictPublicInputs: true,
    });

    try {
      await prover.generateProof(Circuit.StateCommitment, {
        secret: "0x" + "aa".repeat(32),
        nullifier: "0x" + "bb".repeat(32),
      });
      expect.fail("Expected missing public inputs to throw");
    } catch (err: any) {
      expect(err.message).to.include("Missing declared public inputs");
      expect(err.message).to.include("commitment");
      expect(err.message).to.include("owner_pubkey");
    }
  });

  it("does not reuse a development singleton for production mode", async () => {
    const dev = await getProver({ mode: "development" });
    expect(dev.mode).to.equal("development");

    try {
      const prod = await getProver({ mode: "production" });
      expect(prod.mode).to.equal("production");
      expect(prod).to.not.equal(dev);
    } catch (err: any) {
      expect(err.message).to.include("production mode");
    }
  });

  it("validates compiled artifact public inputs against the registry", async () => {
    const projectRoot = path.resolve(__dirname, "..", "..");
    const artifactPath = path.join(
      projectRoot,
      "noir",
      "target",
      `${CIRCUIT_REGISTRY.liquidity_proof.artifact}.json`,
    );
    const artifact = JSON.parse(
      await fs.readFile(artifactPath, "utf-8"),
    ) as CircuitArtifact;

    expect(() =>
      validateCircuitArtifact(Circuit.LiquidityProof, artifact),
    ).not.to.throw();
  });
});
