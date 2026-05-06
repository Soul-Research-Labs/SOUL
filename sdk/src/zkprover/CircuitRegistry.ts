/**
 * ZASEON Noir circuit registry.
 *
 * This file is the SDK-side source of truth for compiled circuit identifiers
 * and their public input ABI. Keep it aligned with the Noir circuit sources
 * and the compiled artifacts under `noir/target/`.
 */

export interface CircuitMetadata {
  /** Circuit identifier used in artifact filenames and SDK APIs. */
  id: string;
  /** Expected artifact basename under `noir/target/`. */
  artifact: string;
  /** Top-level public ABI parameters, in Noir ABI order. */
  publicInputs: readonly string[];
}

interface CircuitArtifactLike {
  bytecode?: unknown;
  abi?: {
    parameters?: Array<{ name?: unknown; visibility?: unknown }>;
  };
}

export const CIRCUIT_REGISTRY = {
  accredited_investor: {
    id: "accredited_investor",
    artifact: "accredited_investor",
    publicInputs: [
      "identity_commitment",
      "qualification_nullifier",
      "issuer_pubkey",
      "qualification_path",
      "current_timestamp",
    ],
  },
  aggregator: {
    id: "aggregator",
    artifact: "aggregator",
    publicInputs: ["batch_size", "batch_id"],
  },
  balance_proof: {
    id: "balance_proof",
    artifact: "balance_proof",
    publicInputs: [
      "old_root",
      "new_root",
      "nullifier_hash",
      "public_amount",
      "token",
      "is_deposit",
    ],
  },
  compliance_proof: {
    id: "compliance_proof",
    artifact: "compliance_proof",
    publicInputs: [
      "credential_commitment",
      "issuer_pubkey",
      "holder_pubkey",
      "current_timestamp",
      "required_jurisdictions",
      "min_credential_type",
      "policy_id",
    ],
  },
  container: {
    id: "container",
    artifact: "container",
    publicInputs: [
      "state_commitment",
      "nullifier_hash",
      "current_timestamp",
      "expiry_timestamp",
    ],
  },
  cross_chain_proof: {
    id: "cross_chain_proof",
    artifact: "cross_chain_proof",
    publicInputs: [
      "dest_chain_id",
      "relayer_pubkey",
      "proof_commitment",
      "timestamp",
      "fee",
    ],
  },
  cross_domain_nullifier: {
    id: "cross_domain_nullifier",
    artifact: "cross_domain_nullifier",
    publicInputs: [
      "source_chain_id",
      "source_app_id",
      "source_epoch_id",
      "source_nullifier",
      "target_chain_id",
      "target_app_id",
      "target_epoch_id",
      "target_nullifier",
      "target_transition_id",
    ],
  },
  encrypted_transfer: {
    id: "encrypted_transfer",
    artifact: "encrypted_transfer",
    publicInputs: [
      "sender_balance_commitment",
      "sender_new_balance_commitment",
      "recipient_balance_commitment",
      "recipient_new_balance_commitment",
      "transfer_amount_commitment",
      "nullifier_value",
      "min_transfer",
      "max_transfer_limit",
    ],
  },
  liquidity_proof: {
    id: "liquidity_proof",
    artifact: "liquidity_proof",
    publicInputs: [
      "lock_commitment",
      "pool_commitment",
      "nullifier",
      "transfer_amount_hash",
      "timestamp_bound",
    ],
  },
  merkle_proof: {
    id: "merkle_proof",
    artifact: "merkle_proof",
    publicInputs: ["leaf", "root"],
  },
  nullifier: {
    id: "nullifier",
    artifact: "nullifier",
    publicInputs: ["nullifier_hash", "domain_id", "commitment_root"],
  },
  pedersen_commitment: {
    id: "pedersen_commitment",
    artifact: "pedersen_commitment",
    publicInputs: ["commitment", "owner_pubkey"],
  },
  policy: {
    id: "policy",
    artifact: "policy",
    publicInputs: ["policy_hash", "user_commitment", "merkle_root"],
  },
  policy_bound_proof: {
    id: "policy_bound_proof",
    artifact: "policy_bound_proof",
    publicInputs: [
      "vk_hash",
      "policy_hash",
      "domain_separator",
      "data_commitment",
    ],
  },
  private_transfer: {
    id: "private_transfer",
    artifact: "private_transfer",
    publicInputs: ["pub_inputs"],
  },
  ring_signature: {
    id: "ring_signature",
    artifact: "ring_signature",
    publicInputs: ["pub_inputs"],
  },
  sanctions_check: {
    id: "sanctions_check",
    artifact: "sanctions_check",
    publicInputs: [
      "sanctions_merkle_root",
      "identity_commitment",
      "compliance_nullifier",
      "credential_issuer_pubkey",
      "current_timestamp",
    ],
  },
  shielded_pool: {
    id: "shielded_pool",
    artifact: "shielded_pool",
    publicInputs: [
      "merkle_root",
      "nullifier",
      "recipient",
      "relayer",
      "fee",
      "amount",
      "asset_id",
    ],
  },
  state_commitment: {
    id: "state_commitment",
    artifact: "state_commitment",
    publicInputs: ["commitment", "owner_pubkey"],
  },
  state_transfer: {
    id: "state_transfer",
    artifact: "state_transfer",
    publicInputs: [
      "old_commitment",
      "new_commitment",
      "old_nullifier",
      "sender_pubkey",
      "recipient_pubkey",
      "transfer_value",
    ],
  },
  swap_proof: {
    id: "swap_proof",
    artifact: "swap_proof",
    publicInputs: [
      "old_balance_root",
      "new_balance_root",
      "pool_id",
      "nullifier_hash",
      "min_amount_out",
      "fee_amount",
      "reserve_in",
      "reserve_out",
      "new_reserve_in",
      "new_reserve_out",
      "pool_fee_rate",
    ],
  },
} as const satisfies Record<string, CircuitMetadata>;

export type RegisteredCircuit = keyof typeof CIRCUIT_REGISTRY;

export const ALL_REGISTERED_CIRCUITS = Object.freeze(
  Object.keys(CIRCUIT_REGISTRY) as RegisteredCircuit[],
);

export function isRegisteredCircuit(
  circuit: string,
): circuit is RegisteredCircuit {
  return Object.prototype.hasOwnProperty.call(CIRCUIT_REGISTRY, circuit);
}

export function assertRegisteredCircuit(circuit: string): RegisteredCircuit {
  if (!isRegisteredCircuit(circuit)) {
    throw new Error(
      `Unsupported Noir circuit: ${circuit}. Registered circuits: ${ALL_REGISTERED_CIRCUITS.join(", ")}`,
    );
  }
  return circuit;
}

export function getCircuitMetadata(circuit: string): CircuitMetadata {
  return CIRCUIT_REGISTRY[assertRegisteredCircuit(circuit)];
}

export function getRegisteredPublicInputs(circuit: string): readonly string[] {
  return getCircuitMetadata(circuit).publicInputs;
}

export function validateCircuitArtifact(
  circuit: string,
  artifact: CircuitArtifactLike,
): void {
  const metadata = getCircuitMetadata(circuit);
  if (!artifact || typeof artifact.bytecode !== "string") {
    throw new Error(`Circuit ${circuit} artifact is missing bytecode`);
  }
  if (artifact.bytecode.length === 0) {
    throw new Error(`Circuit ${circuit} artifact bytecode is empty`);
  }
  if (!Array.isArray(artifact.abi?.parameters)) {
    throw new Error(`Circuit ${circuit} artifact is missing ABI parameters`);
  }

  const actual = artifact.abi.parameters
    .filter((parameter) => parameter.visibility === "public")
    .map((parameter) => String(parameter.name));
  const expected = [...metadata.publicInputs];

  if (actual.join("\u0000") !== expected.join("\u0000")) {
    throw new Error(
      `Circuit ${circuit} public input ABI drift: expected [${expected.join(", ")}], got [${actual.join(", ")}]`,
    );
  }
}

export function flattenPublicInputValue(value: unknown): string[] {
  if (value === undefined || value === null) {
    throw new Error("Missing public input value");
  }
  if (typeof value === "bigint") return [value.toString()];
  if (typeof value === "number" || typeof value === "boolean") {
    return [String(value)];
  }
  if (typeof value === "string") return [value];
  if (value instanceof Uint8Array) {
    return [`0x${Buffer.from(value).toString("hex")}`];
  }
  if (Array.isArray(value)) {
    return value.flatMap((entry) => flattenPublicInputValue(entry));
  }
  if (typeof value === "object") {
    return Object.values(value).flatMap((entry) =>
      flattenPublicInputValue(entry),
    );
  }
  return [String(value)];
}

export function extractRegisteredPublicInputs(
  circuit: string,
  inputs: Record<string, unknown>,
): string[] | null {
  const publicInputs = getRegisteredPublicInputs(circuit);
  if (!publicInputs.every((name) => Object.hasOwn(inputs, name))) {
    return null;
  }
  return publicInputs.flatMap((name) => flattenPublicInputValue(inputs[name]));
}
