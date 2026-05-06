import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { loadConfig } from "../src/config.js";

const ENV_KEYS = [
  "NODE_ENV",
  "RELAYER_ENV",
  "CHAINS",
  "ETHEREUM_RPC_URL",
  "ARBITRUM_RPC_URL",
  "OPTIMISM_RPC_URL",
  "BASE_RPC_URL",
  "REDIS_URL",
  "RELAYER_PRIVATE_KEY",
  "HEALTH_PORT",
  "MAX_RETRIES",
  "RETRY_DELAY_MS",
  "DRAIN_TIMEOUT_MS",
  "DLQ_MAX_SIZE",
  "CIRCUIT_BREAKER_FAILURE_THRESHOLD",
  "CIRCUIT_BREAKER_WINDOW_MS",
  "CIRCUIT_BREAKER_MIN_SAMPLES",
];

const originalEnv = new Map<string, string | undefined>();

function clearRelayerEnv(): void {
  for (const key of ENV_KEYS) {
    delete process.env[key];
  }
}

describe("loadConfig", () => {
  beforeEach(() => {
    originalEnv.clear();
    for (const key of ENV_KEYS) {
      originalEnv.set(key, process.env[key]);
    }
    clearRelayerEnv();
  });

  afterEach(() => {
    clearRelayerEnv();
    for (const [key, value] of originalEnv.entries()) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  });

  it("allows localhost defaults only outside production mode", () => {
    process.env.CHAINS = "ethereum";

    const config = loadConfig();

    expect(config.chains).toHaveLength(1);
    expect(config.chains[0].rpcUrl).toBe("http://localhost:8545");
    expect(config.redisUrl).toBe("redis://localhost:6379");
    expect(config.privateKey).toBeUndefined();
    expect(config.drainTimeoutMs).toBe(30000);
    expect(config.deadLetterQueueMaxSize).toBe(1000);
    expect(config.circuitBreakerFailureThreshold).toBe(70);
    expect(config.circuitBreakerWindowMs).toBe(300000);
    expect(config.circuitBreakerMinSamples).toBe(10);
  });

  it("requires explicit RPC, Redis, and private key in production", () => {
    process.env.NODE_ENV = "production";
    process.env.CHAINS = "ethereum";

    expect(() => loadConfig()).toThrow(/ETHEREUM_RPC_URL is required/);

    process.env.ETHEREUM_RPC_URL = "https://rpc.example";
    expect(() => loadConfig()).toThrow(/REDIS_URL is required/);

    process.env.REDIS_URL = "redis://redis.example:6379";
    expect(() => loadConfig()).toThrow(/RELAYER_PRIVATE_KEY is required/);
  });

  it("rejects malformed private keys", () => {
    process.env.CHAINS = "ethereum";
    process.env.RELAYER_PRIVATE_KEY = "0x1234";

    expect(() => loadConfig()).toThrow(/32-byte hex string/);
  });

  it("rejects unsupported chain names instead of silently dropping them", () => {
    process.env.CHAINS = "ethereum,not-a-chain";

    expect(() => loadConfig()).toThrow(/Unsupported chain\(s\): not-a-chain/);
  });

  it("validates numeric bounds", () => {
    process.env.CHAINS = "ethereum";
    process.env.HEALTH_PORT = "70000";

    expect(() => loadConfig()).toThrow(/HEALTH_PORT must be an integer/);
  });

  it("validates circuit breaker bounds", () => {
    process.env.CHAINS = "ethereum";
    process.env.CIRCUIT_BREAKER_FAILURE_THRESHOLD = "101";

    expect(() => loadConfig()).toThrow(
      /CIRCUIT_BREAKER_FAILURE_THRESHOLD must be an integer/,
    );
  });
});
