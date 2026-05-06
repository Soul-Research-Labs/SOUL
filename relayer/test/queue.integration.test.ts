/**
 * Integration test for the proof-queue pipeline.
 *
 * Uses the public `ProofQueue` API surface; no network is mocked out
 * because we exercise the queue bookkeeping only (metrics, retries,
 * failure classification). Broadcast/submit paths are covered separately.
 */
import { describe, it, expect, beforeEach } from "vitest";
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
  maxRetries: 2,
  retryDelayMs: 1,
  drainTimeoutMs: 1000,
  deadLetterQueueMaxSize: 10,
  circuitBreakerFailureThreshold: 50,
  circuitBreakerWindowMs: 60_000,
  circuitBreakerMinSamples: 2,
  privateKey:
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
} satisfies RelayerConfig;

describe("ProofQueue", () => {
  let q: ProofQueue;

  beforeEach(() => {
    q = new ProofQueue(cfg);
  });

  it("enqueues tasks and reports size", () => {
    expect(q.size).toBe(0);
    expect(q.enqueue(stubTask("a"))).toBe(true);
    expect(q.enqueue(stubTask("b"))).toBe(true);
    expect(q.size).toBe(2);
  });

  it("skips duplicate tasks by idempotency key", () => {
    expect(q.enqueue(stubTask("dup"))).toBe(true);
    expect(q.enqueue(stubTask("dup"))).toBe(false);

    expect(q.size).toBe(1);
    expect(q.metrics.duplicateTasksSkipped).toBe(1);
  });

  it("metrics start at zero", () => {
    expect(q.metrics.tasksTotal).toBe(0);
    expect(q.metrics.tasksSucceeded).toBe(0);
    expect(q.metrics.tasksFailed).toBe(0);
  });

  it("tracks per-chain metrics map", () => {
    expect(q.metrics.perChain).toBeInstanceOf(Map);
    expect(q.metrics.perChain.size).toBe(0);
  });

  it("drain flips running flag safely", async () => {
    await q.drain();
    expect(q.size).toBe(0);
  });

  it("processNext records successful tasks", async () => {
    q = new ProofQueue(cfg, async () => undefined);
    q.enqueue(stubTask("ok"));

    await q.processNext();

    expect(q.size).toBe(0);
    expect(q.metrics.tasksSucceeded).toBe(1);
    expect(q.getSnapshot().completedTaskCount).toBe(1);
    expect(q.getSnapshot().lastSuccessAt).toBeTypeOf("number");
  });

  it("retries failures before moving tasks to the DLQ", async () => {
    q = new ProofQueue(cfg, async () => {
      throw new Error("boom");
    });
    q.enqueue(stubTask("fail"));

    await q.processNext();
    expect(q.size).toBe(1);
    expect(q.dlqSize).toBe(0);
    expect(q.metrics.totalRetries).toBe(1);

    await q.processNext();
    expect(q.size).toBe(0);
    expect(q.dlqSize).toBe(1);
    expect(q.metrics.tasksFailed).toBe(1);
    expect(q.metrics.tasksDeadLettered).toBe(1);
    expect(q.getDeadLetterTasks()[0].error).toBe("boom");
  });

  it("can replay dead-lettered tasks", async () => {
    q = new ProofQueue(cfg, async () => {
      throw new Error("permanent");
    });
    q.enqueue(stubTask("replay"));
    await q.processNext();
    await q.processNext();

    expect(q.dlqSize).toBe(1);
    expect(q.replayDeadLetterTask("replay")).toBe(true);
    expect(q.dlqSize).toBe(0);
    expect(q.size).toBe(1);
  });

  it("opens a per-chain circuit breaker and requeues without retrying", async () => {
    const oneRetry = { ...cfg, maxRetries: 1 } satisfies RelayerConfig;
    q = new ProofQueue(oneRetry, async () => {
      throw new Error("chain down");
    });

    q.enqueue(stubTask("fail-1"));
    await q.processNext();
    q.enqueue(stubTask("fail-2"));
    await q.processNext();

    const breaker = q
      .getSnapshot()
      .circuitBreakers.find((state) => state.chain === "10");
    expect(breaker?.open).toBe(true);

    const pausedTask = stubTask("paused");
    q.enqueue(pausedTask);
    await q.processNext();

    expect(q.size).toBe(1);
    expect(pausedTask.retries).toBe(0);
    expect(q.metrics.circuitBreakerPauses).toBe(1);
  });
});
