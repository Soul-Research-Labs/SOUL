/**
 * ZASEON Relayer - Proof Queue
 *
 * Manages the queue of cross-chain proof relay tasks.
 * Uses an in-memory queue with optional Redis backing for persistence.
 */

import {
  createPublicClient,
  createWalletClient,
  http,
  type Hex,
  decodeEventLog,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { type RelayerConfig } from "./config.js";
import { createLogger } from "./logger.js";
import {
  SUBMIT_PROOF_ABI,
  PROOF_DATA_EMITTED_EVENT,
  RELAY_WATCH_ABI,
} from "./abi.js";

const logger = createLogger("queue");

const delay = (ms: number): Promise<void> =>
  new Promise((resolve) => {
    const timers = globalThis as typeof globalThis & {
      setTimeout: (callback: () => void, ms: number) => unknown;
    };
    timers.setTimeout(resolve, ms);
  });

export interface RelayTask {
  id: string;
  sourceChain: string;
  sourceChainId: number;
  txHash: string;
  blockNumber: number;
  logIndex: number;
  timestamp: number;
  retries: number;
  destChainId?: number;
  targetChain?: string;
  proofId?: string;
  commitment?: string;
  proofData?: Uint8Array;
  error?: string;
  failedAt?: number;
}

interface ChainMetric {
  success: number;
  failure: number;
}

interface CircuitBreakerSample {
  timestamp: number;
  success: boolean;
}

export interface CircuitBreakerState {
  chain: string;
  open: boolean;
  sampleCount: number;
  failures: number;
  successes: number;
  failureRate: number;
  threshold: number;
  windowMs: number;
}

export interface QueueSnapshot {
  queueSize: number;
  inFlight: number;
  dlqSize: number;
  running: boolean;
  processing: boolean;
  currentTaskId?: string;
  completedTaskCount: number;
  duplicateTasksSkipped: number;
  lastSuccessAt?: number;
  lastFailureAt?: number;
  circuitBreakers: CircuitBreakerState[];
}

export type RelayTaskProcessor = (task: RelayTask) => Promise<void>;

export class ProofQueue {
  private queue: RelayTask[] = [];
  private deadLetterQueue: RelayTask[] = [];
  private queuedTaskIds = new Set<string>();
  private inFlightTaskIds = new Set<string>();
  private completedTaskIds = new Set<string>();
  private deadLetterTaskIds = new Set<string>();
  private circuitBreakerSamples = new Map<string, CircuitBreakerSample[]>();
  private processing = false;
  private running = false;
  private loopPromise: Promise<void> | null = null;
  private currentTask: RelayTask | null = null;

  /** Prometheus-compatible counters */
  public metrics = {
    tasksTotal: 0,
    tasksSucceeded: 0,
    tasksFailed: 0,
    tasksDeadLettered: 0,
    duplicateTasksSkipped: 0,
    circuitBreakerPauses: 0,
    totalLatencyMs: 0,
    totalRetries: 0,
    totalGasUsed: 0n,
    lastSuccessAt: undefined as number | undefined,
    lastFailureAt: undefined as number | undefined,
    perChain: new Map<string, ChainMetric>(),
  };

  constructor(
    private config: RelayerConfig,
    private taskProcessor?: RelayTaskProcessor,
  ) {}

  async start(): Promise<void> {
    if (this.running) return;

    logger.info("Starting proof queue processor...");
    this.running = true;
    this.loopPromise = this._processLoop();
  }

  async drain(timeoutMs = this.config.drainTimeoutMs): Promise<void> {
    logger.info(
      { pending: this.queue.length, inFlight: this.inFlightTaskIds.size },
      "Draining queue...",
    );
    this.running = false;

    const deadline = Date.now() + timeoutMs;
    while (this.processing && Date.now() < deadline) {
      await delay(25);
    }

    if (this.processing) {
      throw new Error(
        `Timed out draining proof queue after ${timeoutMs}ms with task ${this.currentTask?.id ?? "unknown"}`,
      );
    }

    if (this.loopPromise) {
      await this.loopPromise;
      this.loopPromise = null;
    }
  }

  enqueue(task: RelayTask): boolean {
    if (this.hasSeenTask(task.id)) {
      this.metrics.duplicateTasksSkipped++;
      logger.warn({ taskId: task.id }, "Duplicate relay task skipped");
      return false;
    }

    // Mark the id before mutating queue state so same-tick concurrent callers
    // cannot both observe the id as unseen and enqueue duplicate relays.
    this.queuedTaskIds.add(task.id);
    this.queue.push(task);
    logger.debug(
      { taskId: task.id, queueSize: this.queue.length },
      "Task enqueued",
    );
    return true;
  }

  get size(): number {
    return this.queue.length;
  }

  get inFlight(): number {
    return this.inFlightTaskIds.size;
  }

  get dlqSize(): number {
    return this.deadLetterQueue.length;
  }

  getDeadLetterTasks(limit = 50): RelayTask[] {
    return this.deadLetterQueue.slice(0, limit).map((task) => ({ ...task }));
  }

  replayDeadLetterTask(taskId: string): boolean {
    const index = this.deadLetterQueue.findIndex((task) => task.id === taskId);
    if (index === -1) return false;

    const [task] = this.deadLetterQueue.splice(index, 1);
    this.deadLetterTaskIds.delete(taskId);
    delete task.error;
    delete task.failedAt;
    task.retries = 0;
    return this.enqueue(task);
  }

  getSnapshot(): QueueSnapshot {
    return {
      queueSize: this.queue.length,
      inFlight: this.inFlightTaskIds.size,
      dlqSize: this.deadLetterQueue.length,
      running: this.running,
      processing: this.processing,
      currentTaskId: this.currentTask?.id,
      completedTaskCount: this.completedTaskIds.size,
      duplicateTasksSkipped: this.metrics.duplicateTasksSkipped,
      lastSuccessAt: this.metrics.lastSuccessAt,
      lastFailureAt: this.metrics.lastFailureAt,
      circuitBreakers: this.getCircuitBreakerStates(),
    };
  }

  isCircuitBreakerOpen(chainKey: string): boolean {
    return this.getCircuitBreakerState(chainKey).open;
  }

  async processNext(): Promise<boolean> {
    if (this.processing || this.queue.length === 0) return false;

    const task = this.queue.shift()!;
    this.queuedTaskIds.delete(task.id);

    const chainKey = this.taskChainKey(task);
    if (this.isCircuitBreakerOpen(chainKey)) {
      this.metrics.circuitBreakerPauses++;
      this.requeueTask(task);
      logger.warn(
        { taskId: task.id, chain: chainKey },
        "Circuit breaker open; relay task re-queued without retry increment",
      );
      return false;
    }

    this.processing = true;
    this.currentTask = task;
    this.inFlightTaskIds.add(task.id);

    try {
      const start = Date.now();
      await this.processTask(task);
      const latency = Date.now() - start;
      this.recordSuccess(task, latency);
      logger.info({ taskId: task.id, latencyMs: latency }, "Task completed");
    } catch (err) {
      this.recordFailure(task, err);
    } finally {
      this.inFlightTaskIds.delete(task.id);
      this.currentTask = null;
      this.processing = false;
    }

    return true;
  }

  private async _processLoop(): Promise<void> {
    while (this.running) {
      await this.processNext();
      await delay(1000);
    }
  }

  private hasSeenTask(taskId: string): boolean {
    return (
      this.queuedTaskIds.has(taskId) ||
      this.inFlightTaskIds.has(taskId) ||
      this.completedTaskIds.has(taskId) ||
      this.deadLetterTaskIds.has(taskId)
    );
  }

  private requeueTask(task: RelayTask): void {
    this.queue.push(task);
    this.queuedTaskIds.add(task.id);
  }

  private recordSuccess(task: RelayTask, latency: number): void {
    this.completedTaskIds.add(task.id);
    this.metrics.tasksTotal++;
    this.metrics.tasksSucceeded++;
    this.metrics.totalLatencyMs += latency;
    this.metrics.lastSuccessAt = Date.now();
    this.recordChainResult(task, true);
  }

  private recordFailure(task: RelayTask, err: unknown): void {
    task.retries++;
    task.error = err instanceof Error ? err.message : String(err);
    this.metrics.totalRetries++;
    this.recordChainResult(task, false);

    if (task.retries < this.config.maxRetries) {
      logger.warn(
        { taskId: task.id, retries: task.retries, error: task.error },
        "Task failed, re-queueing",
      );
      this.requeueTask(task);
      return;
    }

    this.moveToDeadLetter(task);
  }

  private moveToDeadLetter(task: RelayTask): void {
    task.failedAt = Date.now();
    this.metrics.tasksTotal++;
    this.metrics.tasksFailed++;
    this.metrics.tasksDeadLettered++;
    this.metrics.lastFailureAt = task.failedAt;
    this.deadLetterQueue.push({ ...task });
    this.deadLetterTaskIds.add(task.id);

    const maxSize = this.config.deadLetterQueueMaxSize;
    while (this.deadLetterQueue.length > maxSize) {
      const evicted = this.deadLetterQueue.shift();
      if (evicted) this.deadLetterTaskIds.delete(evicted.id);
    }

    logger.error(
      { taskId: task.id, retries: task.retries, error: task.error },
      "Task permanently failed and moved to DLQ",
    );
  }

  private recordChainResult(task: RelayTask, success: boolean): void {
    const chainKey = this.taskChainKey(task);
    const chainMetric = this.metrics.perChain.get(chainKey) ?? {
      success: 0,
      failure: 0,
    };
    if (success) {
      chainMetric.success++;
    } else {
      chainMetric.failure++;
    }
    this.metrics.perChain.set(chainKey, chainMetric);

    const samples = this.prunedSamples(chainKey);
    samples.push({ timestamp: Date.now(), success });
    this.circuitBreakerSamples.set(chainKey, samples);
  }

  private getCircuitBreakerStates(): CircuitBreakerState[] {
    const chainKeys = new Set<string>([
      ...Array.from(this.circuitBreakerSamples.keys()),
      ...Array.from(this.metrics.perChain.keys()),
    ]);
    return Array.from(chainKeys, (chainKey) =>
      this.getCircuitBreakerState(chainKey),
    );
  }

  private getCircuitBreakerState(chainKey: string): CircuitBreakerState {
    const samples = this.prunedSamples(chainKey);
    const failures = samples.filter((sample) => !sample.success).length;
    const successes = samples.length - failures;
    const failureRate =
      samples.length === 0 ? 0 : Math.round((failures * 100) / samples.length);
    const open =
      samples.length >= this.config.circuitBreakerMinSamples &&
      failureRate >= this.config.circuitBreakerFailureThreshold;

    return {
      chain: chainKey,
      open,
      sampleCount: samples.length,
      failures,
      successes,
      failureRate,
      threshold: this.config.circuitBreakerFailureThreshold,
      windowMs: this.config.circuitBreakerWindowMs,
    };
  }

  private prunedSamples(chainKey: string): CircuitBreakerSample[] {
    const cutoff = Date.now() - this.config.circuitBreakerWindowMs;
    const samples = (this.circuitBreakerSamples.get(chainKey) ?? []).filter(
      (sample) => sample.timestamp >= cutoff,
    );
    this.circuitBreakerSamples.set(chainKey, samples);
    return samples;
  }

  private taskChainKey(task: RelayTask): string {
    return task.destChainId?.toString() ?? task.targetChain ?? "unknown";
  }

  private async processTask(task: RelayTask): Promise<void> {
    if (this.taskProcessor) {
      await this.taskProcessor(task);
      return;
    }
    await this._processTask(task);
  }

  private async _processTask(task: RelayTask): Promise<void> {
    logger.info(
      {
        taskId: task.id,
        source: task.sourceChain,
        destChainId: task.destChainId,
      },
      "Processing relay task",
    );

    if (!this.config.privateKey) {
      throw new Error("RELAYER_PRIVATE_KEY not configured");
    }

    // 1. Resolve source and destination chain configs
    const sourceChain = this.config.chains.find(
      (c) => c.chainId === task.sourceChainId,
    );
    if (!sourceChain) {
      throw new Error(`Unknown source chain: ${task.sourceChainId}`);
    }

    const destChain = task.destChainId
      ? this.config.chains.find((c) => c.chainId === task.destChainId)
      : undefined;
    if (!destChain) {
      throw new Error(
        `Destination chain ${task.destChainId} not configured or not in task`,
      );
    }
    if (!destChain.proofHubAddress) {
      throw new Error(`No proofHubAddress configured for ${destChain.name}`);
    }

    // 2. Fetch transaction receipt from source chain to extract proof data
    const sourceClient = createPublicClient({
      transport: http(sourceChain.rpcUrl),
    });

    const receipt = await sourceClient.getTransactionReceipt({
      hash: task.txHash as Hex,
    });

    logger.debug(
      { txHash: task.txHash, logCount: receipt.logs.length },
      "Fetched source receipt",
    );

    // 3. Extract proof data from ProofDataEmitted event in the receipt
    let proofBytes: Hex | undefined;
    let publicInputsBytes: Hex | undefined;
    let commitment: Hex | undefined;

    for (const log of receipt.logs) {
      try {
        const decoded = decodeEventLog({
          abi: RELAY_WATCH_ABI,
          data: log.data,
          topics: log.topics,
        });
        if (decoded.eventName === "ProofRelayed") {
          const args = decoded.args as {
            proofId: Hex;
            sourceChainId: bigint;
            destChainId: bigint;
            commitment: Hex;
            messageId: Hex;
          };
          commitment = args.commitment;
        }
      } catch {
        // Not our event — skip
      }

      try {
        const decoded = decodeEventLog({
          abi: [PROOF_DATA_EMITTED_EVENT],
          data: log.data,
          topics: log.topics,
        });
        if (decoded.eventName === "ProofDataEmitted") {
          const args = decoded.args as {
            proofId: Hex;
            proof: Hex;
            publicInputs: Hex;
          };
          proofBytes = args.proof;
          publicInputsBytes = args.publicInputs;
        }
      } catch {
        // Not our event — skip
      }
    }

    if (!proofBytes || !publicInputsBytes) {
      throw new Error(
        `No ProofDataEmitted found in receipt for tx ${task.txHash}`,
      );
    }

    commitment =
      commitment ||
      (task.commitment as Hex) ||
      (("0x" + "00".repeat(32)) as Hex);

    // 4. Submit proof to destination chain's CrossChainProofHubV3
    const account = privateKeyToAccount(this.config.privateKey as Hex);

    const destWalletClient = createWalletClient({
      account,
      transport: http(destChain.rpcUrl),
    });

    const destPublicClient = createPublicClient({
      transport: http(destChain.rpcUrl),
    });

    logger.info(
      {
        taskId: task.id,
        destChain: destChain.name,
        proofHub: destChain.proofHubAddress,
      },
      "Submitting proof to destination",
    );

    const txHash = await destWalletClient.writeContract({
      address: destChain.proofHubAddress as Hex,
      abi: SUBMIT_PROOF_ABI,
      functionName: "submitProof",
      args: [
        proofBytes,
        publicInputsBytes,
        commitment,
        BigInt(task.sourceChainId),
        BigInt(destChain.chainId),
      ],
      chain: null,
    });

    // 5. Wait for confirmation
    const txReceipt = await destPublicClient.waitForTransactionReceipt({
      hash: txHash,
      confirmations: destChain.confirmations,
    });

    logger.info(
      {
        taskId: task.id,
        destTxHash: txHash,
        blockNumber: Number(txReceipt.blockNumber),
        status: txReceipt.status,
      },
      "Proof submitted to destination chain",
    );

    if (txReceipt.status === "reverted") {
      throw new Error(`Destination tx reverted: ${txHash}`);
    }
  }
}
