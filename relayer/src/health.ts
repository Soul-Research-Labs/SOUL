/**
 * ZASEON Relayer - Health Reporter
 *
 * Exposes /health and /metrics endpoints for monitoring.
 * Compatible with Prometheus scraping and standard health checks.
 */

import { createServer, type IncomingMessage, type ServerResponse } from "http";
import { type RelayerConfig } from "./config.js";
import { type ProofQueue } from "./queue.js";
import { createLogger } from "./logger.js";

const logger = createLogger("health");

export class HealthReporter {
  private server: ReturnType<typeof createServer> | null = null;
  private startTime = Date.now();

  constructor(
    private config: RelayerConfig,
    private queue?: ProofQueue,
  ) {}

  async start(): Promise<void> {
    this.server = createServer((req: IncomingMessage, res: ServerResponse) => {
      if (req.url === "/health") {
        const snapshot = this.queue?.getSnapshot();
        const memory = process.memoryUsage();
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            status: "ok",
            uptime: Date.now() - this.startTime,
            chains: this.config.chains.map((c) => c.name),
            queue: snapshot,
            memory: {
              rss: memory.rss,
              heapUsed: memory.heapUsed,
              heapTotal: memory.heapTotal,
              external: memory.external,
            },
            version: "0.1.0",
          }),
        );
      } else if (req.url?.startsWith("/dlq")) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            size: this.queue?.dlqSize ?? 0,
            tasks: this.queue?.getDeadLetterTasks() ?? [],
          }),
        );
      } else if (req.url === "/metrics") {
        const m = this.queue?.metrics;
        const snapshot = this.queue?.getSnapshot();
        const avgLatency =
          m && m.tasksSucceeded > 0
            ? Math.round(m.totalLatencyMs / m.tasksSucceeded)
            : 0;

        const lines: string[] = [
          `# HELP zaseon_relayer_uptime_ms Relayer uptime in milliseconds`,
          `# TYPE zaseon_relayer_uptime_ms gauge`,
          `zaseon_relayer_uptime_ms ${Date.now() - this.startTime}`,
          `# HELP zaseon_relayer_chains_total Number of watched chains`,
          `# TYPE zaseon_relayer_chains_total gauge`,
          `zaseon_relayer_chains_total ${this.config.chains.length}`,
          `# HELP zaseon_relayer_queue_size Current queue depth`,
          `# TYPE zaseon_relayer_queue_size gauge`,
          `zaseon_relayer_queue_size ${this.queue?.size ?? 0}`,
          `# HELP zaseon_relayer_inflight_tasks Current in-flight relay task count`,
          `# TYPE zaseon_relayer_inflight_tasks gauge`,
          `zaseon_relayer_inflight_tasks ${this.queue?.inFlight ?? 0}`,
          `# HELP zaseon_relayer_dlq_size Current dead-letter queue depth`,
          `# TYPE zaseon_relayer_dlq_size gauge`,
          `zaseon_relayer_dlq_size ${this.queue?.dlqSize ?? 0}`,
          `# HELP zaseon_relayer_tasks_total Total relay tasks processed`,
          `# TYPE zaseon_relayer_tasks_total counter`,
          `zaseon_relayer_tasks_total{status="success"} ${m?.tasksSucceeded ?? 0}`,
          `zaseon_relayer_tasks_total{status="failure"} ${m?.tasksFailed ?? 0}`,
          `zaseon_relayer_tasks_total{status="dead_lettered"} ${m?.tasksDeadLettered ?? 0}`,
          `# HELP zaseon_relayer_duplicate_tasks_skipped_total Duplicate relay tasks skipped by idempotency key`,
          `# TYPE zaseon_relayer_duplicate_tasks_skipped_total counter`,
          `zaseon_relayer_duplicate_tasks_skipped_total ${m?.duplicateTasksSkipped ?? 0}`,
          `# HELP zaseon_relayer_circuit_breaker_pauses_total Relay attempts paused by circuit breakers`,
          `# TYPE zaseon_relayer_circuit_breaker_pauses_total counter`,
          `zaseon_relayer_circuit_breaker_pauses_total ${m?.circuitBreakerPauses ?? 0}`,
          `# HELP zaseon_relayer_relay_latency_avg_ms Average relay latency`,
          `# TYPE zaseon_relayer_relay_latency_avg_ms gauge`,
          `zaseon_relayer_relay_latency_avg_ms ${avgLatency}`,
          `# HELP zaseon_relayer_retries_total Total retry attempts`,
          `# TYPE zaseon_relayer_retries_total counter`,
          `zaseon_relayer_retries_total ${m?.totalRetries ?? 0}`,
          `# HELP zaseon_relayer_gas_used_total Total gas used for relays (wei)`,
          `# TYPE zaseon_relayer_gas_used_total counter`,
          `zaseon_relayer_gas_used_total ${m?.totalGasUsed?.toString() ?? "0"}`,
          `# HELP zaseon_relayer_memory_heap_used_bytes Node.js heap used by relayer`,
          `# TYPE zaseon_relayer_memory_heap_used_bytes gauge`,
          `zaseon_relayer_memory_heap_used_bytes ${process.memoryUsage().heapUsed}`,
        ];

        // Per-chain relay metrics
        if (m?.perChain && m.perChain.size > 0) {
          lines.push(
            `# HELP zaseon_relayer_chain_tasks Per-chain relay task counts`,
            `# TYPE zaseon_relayer_chain_tasks counter`,
          );
          for (const [chainId, counts] of m.perChain) {
            lines.push(
              `zaseon_relayer_chain_tasks{chain="${chainId}",status="success"} ${counts.success}`,
              `zaseon_relayer_chain_tasks{chain="${chainId}",status="failure"} ${counts.failure}`,
            );
          }
        }

        if (snapshot?.circuitBreakers.length) {
          lines.push(
            `# HELP zaseon_relayer_circuit_breaker_open Circuit breaker open state by destination chain`,
            `# TYPE zaseon_relayer_circuit_breaker_open gauge`,
            `# HELP zaseon_relayer_circuit_breaker_failure_rate Circuit breaker failure rate percentage by destination chain`,
            `# TYPE zaseon_relayer_circuit_breaker_failure_rate gauge`,
          );
          for (const breaker of snapshot.circuitBreakers) {
            lines.push(
              `zaseon_relayer_circuit_breaker_open{chain="${breaker.chain}"} ${breaker.open ? 1 : 0}`,
              `zaseon_relayer_circuit_breaker_failure_rate{chain="${breaker.chain}"} ${breaker.failureRate}`,
            );
          }
        }

        lines.push("");

        res.writeHead(200, { "Content-Type": "text/plain" });
        res.end(lines.join("\n"));
      } else {
        res.writeHead(404);
        res.end("Not Found");
      }
    });

    return new Promise((resolve) => {
      this.server!.listen(this.config.healthPort, () => {
        logger.info({ port: this.config.healthPort }, "Health server started");
        resolve();
      });
    });
  }

  async stop(): Promise<void> {
    if (this.server) {
      return new Promise((resolve) => {
        this.server!.close(() => {
          logger.info("Health server stopped");
          resolve();
        });
      });
    }
  }
}
