/**
 * ZASEON Relayer - Logger
 *
 * Structured JSON logging via pino.
 */

export interface Logger {
  info(obj: Record<string, unknown>, msg?: string): void;
  info(msg: string): void;
  warn(obj: Record<string, unknown>, msg?: string): void;
  warn(msg: string): void;
  error(obj: Record<string, unknown>, msg?: string): void;
  error(msg: string): void;
  debug(obj: Record<string, unknown>, msg?: string): void;
  debug(msg: string): void;
  fatal(obj: Record<string, unknown>, msg?: string): void;
  fatal(msg: string): void;
}

const SENSITIVE_KEY =
  /(privateKey|secret|mnemonic|authorization|token|proof|publicInputs|encryptedState|payload|signature|mac)/i;
const LONG_HEX = /0x[0-9a-fA-F]{64,}/g;

function redactString(value: string): string {
  return value.replace(
    LONG_HEX,
    (match) => `0x[redacted:${Math.floor((match.length - 2) / 2)} bytes]`,
  );
}

function redactValue(key: string, value: unknown, depth = 0): unknown {
  if (SENSITIVE_KEY.test(key)) return "[REDACTED]";
  if (typeof value === "string") return redactString(value);
  if (typeof value === "bigint") return value.toString();
  if (value === null || typeof value !== "object") return value;
  if (depth >= 4) return "[REDACTED:depth]";

  if (Array.isArray(value)) {
    return value.map((entry) => redactValue(key, entry, depth + 1));
  }

  const redacted: Record<string, unknown> = {};
  for (const [childKey, childValue] of Object.entries(
    value as Record<string, unknown>,
  )) {
    redacted[childKey] = redactValue(childKey, childValue, depth + 1);
  }
  return redacted;
}

export function createLogger(component: string): Logger {
  const level = process.env.LOG_LEVEL || "info";
  const levels: Record<string, number> = {
    debug: 0,
    info: 1,
    warn: 2,
    error: 3,
    fatal: 4,
  };
  const minLevel = levels[level] ?? 1;

  const log = (lvl: string, args: unknown[]) => {
    if ((levels[lvl] ?? 0) < minLevel) return;

    const entry: Record<string, unknown> = {
      level: lvl,
      component,
      time: new Date().toISOString(),
    };

    if (args.length === 1 && typeof args[0] === "string") {
      entry.msg = redactString(args[0]);
    } else if (
      args.length >= 1 &&
      typeof args[0] === "object" &&
      args[0] !== null
    ) {
      Object.assign(entry, redactValue("", args[0]) as Record<string, unknown>);
      if (args.length > 1) {
        entry.msg =
          typeof args[1] === "string" ? redactString(args[1]) : args[1];
      }
    }

    // eslint-disable-next-line no-console
    console.log(JSON.stringify(entry));
  };

  return {
    info: (...args: unknown[]) => log("info", args),
    warn: (...args: unknown[]) => log("warn", args),
    error: (...args: unknown[]) => log("error", args),
    debug: (...args: unknown[]) => log("debug", args),
    fatal: (...args: unknown[]) => log("fatal", args),
  } as Logger;
}
