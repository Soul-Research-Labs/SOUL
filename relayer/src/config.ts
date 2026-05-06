/**
 * ZASEON Relayer - Configuration
 */

export interface ChainConfig {
  name: string;
  chainId: number;
  rpcUrl: string;
  bridgeAddress?: string;
  proofHubAddress?: string;
  relayContractAddress?: string;
  registryAddress?: string;
  confirmations: number;
}

export interface RelayerConfig {
  chains: ChainConfig[];
  redisUrl: string;
  logLevel: string;
  healthPort: number;
  privateKey?: string;
  maxRetries: number;
  retryDelayMs: number;
  drainTimeoutMs: number;
  deadLetterQueueMaxSize: number;
  circuitBreakerFailureThreshold: number;
  circuitBreakerWindowMs: number;
  circuitBreakerMinSamples: number;
}

const CHAIN_DEFAULTS: Record<string, Omit<ChainConfig, "rpcUrl">> = {
  ethereum: { name: "Ethereum", chainId: 1, confirmations: 12 },
  arbitrum: { name: "Arbitrum", chainId: 42161, confirmations: 1 },
  optimism: { name: "Optimism", chainId: 10, confirmations: 1 },
  base: { name: "Base", chainId: 8453, confirmations: 1 },
  aztec: { name: "Aztec", chainId: 4100, confirmations: 1 },
  "arbitrum-sepolia": {
    name: "Arbitrum Sepolia",
    chainId: 421614,
    confirmations: 1,
  },
  "optimism-sepolia": {
    name: "Optimism Sepolia",
    chainId: 11155420,
    confirmations: 1,
  },
  sepolia: { name: "Sepolia", chainId: 11155111, confirmations: 2 },
};

function isProductionEnv(): boolean {
  return (
    process.env.NODE_ENV === "production" ||
    process.env.RELAYER_ENV === "production"
  );
}

function parseIntegerEnv(
  key: string,
  fallback: number,
  min: number,
  max = Number.MAX_SAFE_INTEGER,
): number {
  const raw = process.env[key];
  if (raw === undefined || raw === "") return fallback;

  const parsed = Number.parseInt(raw, 10);
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
    throw new Error(
      `${key} must be an integer in range [${min}, ${max}], got ${raw}`,
    );
  }
  return parsed;
}

function loadRequiredEnv(
  key: string,
  production: boolean,
  developmentFallback: string,
): string {
  const value = process.env[key];
  if (value && value.trim() !== "") return value;
  if (production) {
    throw new Error(`${key} is required in production relayer mode`);
  }
  return developmentFallback;
}

function loadPrivateKey(production: boolean): string | undefined {
  const key = process.env.RELAYER_PRIVATE_KEY;
  if (!key || key.trim() === "") {
    if (production) {
      throw new Error(
        "RELAYER_PRIVATE_KEY is required in production relayer mode",
      );
    }
    return undefined;
  }

  if (!/^0x[0-9a-fA-F]{64}$/.test(key)) {
    throw new Error(
      "RELAYER_PRIVATE_KEY must be a 32-byte hex string with 0x prefix",
    );
  }
  return key;
}

export function loadConfig(): RelayerConfig {
  const production = isProductionEnv();
  const chainNames = (process.env.CHAINS || "ethereum,arbitrum,optimism,base")
    .split(",")
    .map((name) => name.trim().toLowerCase())
    .filter(Boolean);

  const unknownChains = chainNames.filter((name) => !CHAIN_DEFAULTS[name]);
  if (unknownChains.length > 0) {
    throw new Error(`Unsupported chain(s): ${unknownChains.join(",")}`);
  }

  const chains: ChainConfig[] = chainNames.map((name) => {
    const envKey = name.replace(/-/g, "_").toUpperCase();
    return {
      ...CHAIN_DEFAULTS[name],
      rpcUrl: loadRequiredEnv(
        `${envKey}_RPC_URL`,
        production,
        `http://localhost:8545`,
      ),
      bridgeAddress: process.env[`${envKey}_BRIDGE_ADDRESS`],
      proofHubAddress: process.env[`${envKey}_PROOF_HUB_ADDRESS`],
      relayContractAddress: process.env[`${envKey}_RELAY_CONTRACT_ADDRESS`],
      registryAddress: process.env[`${envKey}_REGISTRY_ADDRESS`],
    };
  });

  if (chains.length === 0) {
    throw new Error("At least one supported chain must be configured");
  }

  return {
    chains,
    redisUrl: loadRequiredEnv(
      "REDIS_URL",
      production,
      "redis://localhost:6379",
    ),
    logLevel: process.env.LOG_LEVEL || "info",
    healthPort: parseIntegerEnv("HEALTH_PORT", 9090, 1, 65535),
    privateKey: loadPrivateKey(production),
    maxRetries: parseIntegerEnv("MAX_RETRIES", 5, 0),
    retryDelayMs: parseIntegerEnv("RETRY_DELAY_MS", 5000, 0),
    drainTimeoutMs: parseIntegerEnv("DRAIN_TIMEOUT_MS", 30000, 1000),
    deadLetterQueueMaxSize: parseIntegerEnv("DLQ_MAX_SIZE", 1000, 1),
    circuitBreakerFailureThreshold: parseIntegerEnv(
      "CIRCUIT_BREAKER_FAILURE_THRESHOLD",
      70,
      1,
      100,
    ),
    circuitBreakerWindowMs: parseIntegerEnv(
      "CIRCUIT_BREAKER_WINDOW_MS",
      300000,
      1000,
    ),
    circuitBreakerMinSamples: parseIntegerEnv(
      "CIRCUIT_BREAKER_MIN_SAMPLES",
      10,
      1,
    ),
  };
}
