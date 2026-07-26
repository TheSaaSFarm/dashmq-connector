import { createHash } from "crypto";
import { Redis, RedisOptions } from "ioredis";

// ---------------------------------------------------------------------------
// Shared ioredis clients
//
// Opening a connection per operation is a connection storm against the
// customer's Redis. Every consumer instead acquires a client keyed by a hash of
// the connection options (plus a namespace, so different queue libraries never
// share a client) and releases it when done. Clients are reference counted so
// two consumers sharing one client cannot close it out from under each other.
// ---------------------------------------------------------------------------

interface SharedClientEntry {
  client: Redis;
  key: string;
  refCount: number;
}

const sharedClients = new Map<string, SharedClientEntry>();
const clientKeys = new WeakMap<Redis, string>();

// Options that identify a distinct Redis endpoint. Everything else (timeouts,
// retry strategies, listeners) does not change *which* server we talk to.
const CONNECTION_KEYS = [
  "host",
  "port",
  "path",
  "db",
  "username",
  "password",
  "family",
  "keyPrefix",
  "name",
  "role",
  "sentinels",
  "sentinelPassword",
  "sentinelUsername",
  "enableTLSForSentinelMode",
  "tls",
  "natMap",
] as const;

const MAX_HASH_DEPTH = 6;

function stableStringify(value: unknown, depth: number = 0): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "function") return "null";
  if (typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (depth >= MAX_HASH_DEPTH) return '"[max-depth]"';

  if (Buffer.isBuffer(value)) {
    return JSON.stringify(value.toString("base64"));
  }

  if (Array.isArray(value)) {
    return `[${value.map((entry) => stableStringify(entry, depth + 1)).join(",")}]`;
  }

  const record = value as Record<string, unknown>;
  const parts: string[] = [];
  for (const key of Object.keys(record).sort()) {
    const entry = record[key];
    if (entry === undefined || typeof entry === "function") continue;
    parts.push(`${JSON.stringify(key)}:${stableStringify(entry, depth + 1)}`);
  }
  return `{${parts.join(",")}}`;
}

/**
 * Stable fingerprint of the connection-identifying subset of `RedisOptions`.
 * Hashing (rather than serialising) keeps credentials out of cache keys and
 * out of anything that might get logged.
 */
export function hashRedisOptions(options: RedisOptions): string {
  const source = options as Record<string, unknown>;
  const normalized: Record<string, unknown> = {};
  for (const key of CONNECTION_KEYS) {
    const value = source[key];
    if (value === undefined || typeof value === "function") continue;
    normalized[key] = value;
  }
  return createHash("sha256").update(stableStringify(normalized)).digest("hex").slice(0, 32);
}

/**
 * Acquire (or create) a shared client for the given options + namespace.
 * Every successful call must be paired with `releaseSharedRedisClient`.
 */
export function acquireSharedRedisClient(
  options: RedisOptions,
  namespace: string = "default"
): Redis {
  const key = `${namespace}|${hashRedisOptions(options)}`;
  const existing = sharedClients.get(key);

  if (existing && existing.client.status !== "end") {
    existing.refCount += 1;
    return existing.client;
  }

  if (existing) {
    // Client died (status "end"); drop it and build a fresh one.
    sharedClients.delete(key);
    clientKeys.delete(existing.client);
  }

  const client = new Redis(options);
  sharedClients.set(key, { client, key, refCount: 1 });
  clientKeys.set(client, key);
  return client;
}

/** Release a previously acquired client; closes it once the last holder lets go. */
export async function releaseSharedRedisClient(client: Redis): Promise<void> {
  const key = clientKeys.get(client);
  if (!key) return;

  const entry = sharedClients.get(key);
  if (!entry || entry.client !== client) {
    clientKeys.delete(client);
    return;
  }

  entry.refCount -= 1;
  if (entry.refCount > 0) return;

  sharedClients.delete(key);
  clientKeys.delete(client);
  await quitQuietly(client);
}

/** Number of live shared clients — used by tests and diagnostics. */
export function sharedRedisClientCount(): number {
  return sharedClients.size;
}

/** Close every shared client regardless of reference count (process shutdown). */
export async function closeAllSharedRedisClients(): Promise<void> {
  const entries = Array.from(sharedClients.values());
  sharedClients.clear();
  for (const entry of entries) {
    clientKeys.delete(entry.client);
    await quitQuietly(entry.client);
  }
}

async function quitQuietly(client: Redis): Promise<void> {
  try {
    if (client.status !== "end") {
      await client.quit();
    }
  } catch {
    try {
      client.disconnect();
    } catch {
      // Nothing left to do — the socket is already gone.
    }
  }
}
