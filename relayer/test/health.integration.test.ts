import { get, type Server } from "http";
import { describe, it, expect, afterEach } from "vitest";
import { HealthReporter } from "../src/health.js";
import { ProofQueue, type RelayTask } from "../src/queue.js";
import type { RelayerConfig } from "../src/config.js";

function stubTask(id: string): RelayTask {
  return {
    id,
    sourceChain: "optimism",
    sourceChainId: 10,
    txHash: "0x" + "1".repeat(64),
    blockNumber: 1,
    logIndex: 0,
    timestamp: Date.now(),
    retries: 0,
    destChainId: 10,
  };
}

const cfg = {
  chains: [],
  redisUrl: "redis://localhost:6379",
  logLevel: "silent",
  healthPort: 0,
  maxRetries: 1,
  retryDelayMs: 1,
  drainTimeoutMs: 1000,
  deadLetterQueueMaxSize: 10,
  circuitBreakerFailureThreshold: 50,
  circuitBreakerWindowMs: 60_000,
  circuitBreakerMinSamples: 1,
  privateKey:
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
} satisfies RelayerConfig;

async function httpGet(port: number, path: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const req = get({ hostname: "127.0.0.1", port, path }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => {
        body += chunk;
      });
      res.on("end", () => resolve(body));
    });
    req.on("error", reject);
  });
}

function reporterPort(reporter: HealthReporter): number {
  const server = (reporter as unknown as { server: Server | null }).server;
  const address = server?.address();
  if (!address || typeof address === "string") {
    throw new Error("Health reporter did not bind to a TCP port");
  }
  return address.port;
}

describe("HealthReporter", () => {
  let reporter: HealthReporter | undefined;

  afterEach(async () => {
    await reporter?.stop();
    reporter = undefined;
  });

  it("exposes queue snapshot and memory health data", async () => {
    const queue = new ProofQueue(cfg);
    queue.enqueue(stubTask("queued"));
    reporter = new HealthReporter(cfg, queue);

    await reporter.start();
    const health = JSON.parse(await httpGet(reporterPort(reporter), "/health"));

    expect(health.status).toBe("ok");
    expect(health.queue.queueSize).toBe(1);
    expect(health.queue.inFlight).toBe(0);
    expect(health.memory.heapUsed).toBeTypeOf("number");
  });

  it("exposes DLQ and circuit-breaker metrics", async () => {
    const queue = new ProofQueue(cfg, async () => {
      throw new Error("destination unavailable");
    });
    queue.enqueue(stubTask("dead"));
    await queue.processNext();
    reporter = new HealthReporter(cfg, queue);

    await reporter.start();
    const port = reporterPort(reporter);
    const dlq = JSON.parse(await httpGet(port, "/dlq"));
    const metrics = await httpGet(port, "/metrics");

    expect(dlq.size).toBe(1);
    expect(dlq.tasks[0].id).toBe("dead");
    expect(metrics).toContain("zaseon_relayer_dlq_size 1");
    expect(metrics).toContain(
      'zaseon_relayer_tasks_total{status="dead_lettered"} 1',
    );
    expect(metrics).toContain(
      'zaseon_relayer_circuit_breaker_open{chain="10"} 1',
    );
  });
});
