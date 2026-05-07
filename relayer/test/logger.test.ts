import { afterEach, describe, expect, it, vi } from "vitest";
import { createLogger } from "../src/logger.js";

const LONG_HEX = `0x${"ab".repeat(64)}`;

describe("createLogger", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    delete process.env.LOG_LEVEL;
  });

  it("redacts sensitive fields and long hex payloads", () => {
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((line: string) => {
      logs.push(line);
    });

    const logger = createLogger("test");
    logger.info(
      {
        privateKey: LONG_HEX,
        nested: {
          proof: LONG_HEX,
          txHash: LONG_HEX,
        },
        safe: "visible",
      },
      `submitted ${LONG_HEX}`,
    );

    expect(logs).to.have.length(1);
    const entry = JSON.parse(logs[0]);
    expect(entry.privateKey).to.equal("[REDACTED]");
    expect(entry.nested.proof).to.equal("[REDACTED]");
    expect(entry.nested.txHash).to.equal("0x[redacted:64 bytes]");
    expect(entry.msg).to.include("0x[redacted:64 bytes]");
    expect(logs[0]).not.to.include(LONG_HEX);
  });
});
