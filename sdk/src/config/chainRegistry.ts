/**
 * Chain registry loader.
 *
 * Single source of truth for chain metadata. Integrators add a new L2 by
 * dropping an entry into `chains.json` — no code changes required.
 */
import { keccak256, stringToBytes } from "viem";
import chainsData from "./chains.json";

export type ChainTier = "mainnet" | "testnet" | "staging" | "local";
export type Finality = "instant" | "safe" | "finalized";

export interface ChainEntry {
  chainId: number;
  name: string;
  nativeToken: string;
  rpcUrlEnv: string;
  explorer: string;
  blockTime: number;
  finality: Finality;
  isL2: boolean;
  parentChainId?: number;
  tier: ChainTier;
  bridgeAdapter?: string;
  addresses: Record<string, `0x${string}`>;
}

type Registry = { chains: Record<string, ChainEntry> };

const REGISTRY = chainsData as unknown as Registry;

/** All known chains keyed by slug (`ethereum`, `arbitrum`, ...). */
export function allChains(): Record<string, ChainEntry> {
  return REGISTRY.chains;
}

/** Lookup a chain entry by slug. Throws if unknown. */
export function chainBySlug(slug: string): ChainEntry {
  const c = REGISTRY.chains[slug];
  if (!c) throw new Error(`Unknown chain slug: ${slug}`);
  return c;
}

/** Lookup by numeric chain id. Returns undefined if unknown. */
export function chainById(chainId: number): ChainEntry | undefined {
  for (const c of Object.values(REGISTRY.chains)) {
    if (c.chainId === chainId) return c;
  }
  return undefined;
}

/** All chains of a given tier. */
export function chainsByTier(tier: ChainTier): ChainEntry[] {
  return Object.values(REGISTRY.chains).filter((c) => c.tier === tier);
}

/** Resolve the RPC URL for a chain from its env-var binding. */
export function rpcUrlFor(slug: string): string | undefined {
  const c = chainBySlug(slug);
  if (typeof process === "undefined" || !process.env) return undefined;
  return process.env[c.rpcUrlEnv];
}

/**
 * Validate that an Ethereum address is syntactically correct AND passes
 * EIP-55 mixed-case checksum. Rejects lowercase / uppercase-only addresses
 * that happen to parse as hex — those may have been corrupted by a
 * checksum-losing copy-paste and should never be loaded from a config
 * file used for on-chain routing.
 *
 * Uses viem's audited Keccak implementation for the EIP-55 checksum hash.
 */
export function isChecksumAddress(addr: string): boolean {
  if (!/^0x[0-9a-fA-F]{40}$/.test(addr)) return false;
  // All-lower or all-upper (case-insensitive) are only acceptable if the
  // checksum is *intentionally* waived. For a registry that routes value
  // we require a mixed-case EIP-55 address.
  const lower = addr.toLowerCase();
  const upper = addr.toUpperCase();
  if (addr === lower || addr === upper) return false;
  return eip55Checksum(lower) === addr;
}

/** Deterministic EIP-55 checksum using viem's Keccak implementation. */
function eip55Checksum(lowerAddr: string): string {
  const body = lowerAddr.slice(2);
  const hash = keccak256(stringToBytes(body)).slice(2);
  let out = "0x";
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (c >= "0" && c <= "9") {
      out += c;
    } else {
      // If the i-th nibble of the hash is >= 8, uppercase.
      const nibble = parseInt(hash[i], 16);
      out += nibble >= 8 ? c.toUpperCase() : c;
    }
  }
  return out;
}

/**
 * Validate every address in the registry. Call once at SDK init to
 * surface any hand-edited `chains.json` entry that lost its EIP-55
 * checksum — a common way for typos and redirects to slip in.
 */
export function validateRegistryAddresses(): void {
  for (const [slug, entry] of Object.entries(REGISTRY.chains)) {
    for (const [name, addr] of Object.entries(entry.addresses)) {
      if (!isChecksumAddress(addr as string)) {
        throw new Error(
          `chainRegistry: ${slug}.${name} has invalid EIP-55 checksum: ${addr}`,
        );
      }
    }
  }
}

/**
 * Probe an RPC endpoint and confirm its reported chain id matches
 * the registry entry. Throws on mismatch — callers should treat
 * mismatch as an abort condition, not a warning.
 */
export async function assertRpcChainMatches(
  slug: string,
  fetchFn: typeof fetch = fetch,
): Promise<void> {
  const entry = chainBySlug(slug);
  const url = rpcUrlFor(slug);
  if (!url) throw new Error(`chainRegistry: missing RPC URL for ${slug}`);
  const res = await fetchFn(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "eth_chainId",
      params: [],
    }),
  });
  if (!res.ok) {
    throw new Error(
      `chainRegistry: RPC probe failed (${res.status}) for ${slug}`,
    );
  }
  const body = (await res.json()) as { result?: string };
  if (!body.result) {
    throw new Error(`chainRegistry: RPC probe returned no chainId for ${slug}`);
  }
  const reported = Number.parseInt(body.result, 16);
  if (reported !== entry.chainId) {
    throw new Error(
      `chainRegistry: RPC for ${slug} reports chainId ${reported}, expected ${entry.chainId}`,
    );
  }
}
