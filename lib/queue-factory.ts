import { Redis, Cluster } from "ioredis";
import { Connection, isRedisInstance, redisOptsFromConnection } from "./connection";

export type QueueType = "bull" | "bullmq" | "bullmq-pro";

export interface QueueTypeInfo {
  type: QueueType;
  majorVersion: number;
  version?: string;
}

export interface FoundQueue {
  prefix: string;
  name: string;
  type: QueueType;
  majorVersion: number;
  version?: string;
}

const queueNameRegExp = new RegExp("(.*):(.*):id");
const maxCount = 150000;
const maxTime = 40000;

export async function getConnectionQueues(
  connection: Connection,
  queueNames?: string[]
): Promise<FoundQueue[]> {
  const redisClient = isRedisInstance(connection)
    ? connection
    : new Redis(redisOptsFromConnection(connection));

  try {
    const keys = await getQueueKeys(redisClient, queueNames);
    const queues: FoundQueue[] = [];

    for (const key of keys) {
      const match = queueNameRegExp.exec(key);
      if (match) {
        const prefix = match[1];
        const name = match[2];
        const queueType = await getQueueType(name, prefix, redisClient);
        queues.push({
          prefix,
          name,
          ...queueType,
        });
      }
    }

    return queues;
  } finally {
    if (!isRedisInstance(connection)) {
      await redisClient.quit();
    }
  }
}

async function getQueueKeys(
  client: Redis | Cluster,
  queueNames?: string[]
): Promise<string[]> {
  const keys: string[] = [];
  const foundQueues = new Set<string>();

  if (queueNames) {
    for (const queueName of queueNames) {
      let [prefix, name] = queueName.split(":");
      if (!name) {
        name = prefix;
        prefix = "bull";
      }
      const key = `${prefix}:${name}:id`;
      const exists = await client.exists(key);
      if (exists) {
        foundQueues.add(key);
        keys.push(key);
      }
    }
  } else {
    // Scan for all queues
    const startTime = Date.now();
    let cursor = "0";
    do {
      const [nextCursor, scannedKeys] = await client.scan(
        cursor,
        "MATCH",
        "*:*:id",
        "COUNT",
        maxCount,
        "TYPE",
        "string"
      );
      cursor = nextCursor;
      keys.push(...scannedKeys);
    } while (Date.now() - startTime < maxTime && cursor !== "0");
  }

  return keys;
}

/** Queues that predate the `<library>:<semver>` meta field, or are plain Bull. */
const BULL_QUEUE_TYPE: QueueTypeInfo = { type: "bull", majorVersion: 0 };

/**
 * Parse the `version` field of a queue's `:meta` hash.
 *
 * BullMQ writes `bullmq:5.34.10`, BullMQ Pro writes `bullmq-pro:7.10.1`.
 * Anything we do not recognise (missing field, missing separator, unknown
 * library, unparseable semver) degrades to plain Bull, which is what a queue
 * without a usable BullMQ meta version actually is.
 *
 * Pure function — no Redis access — so it is directly testable.
 */
export function parseQueueMetaVersion(longVersion: string | null | undefined): QueueTypeInfo {
  if (!longVersion) return { ...BULL_QUEUE_TYPE };

  const separatorIndex = longVersion.indexOf(":");
  if (separatorIndex <= 0) return { ...BULL_QUEUE_TYPE };

  const library = longVersion.slice(0, separatorIndex).trim().toLowerCase();
  const version = longVersion.slice(separatorIndex + 1).trim();
  if (!version) return { ...BULL_QUEUE_TYPE };

  let type: QueueType;
  if (library === "bullmq-pro") {
    type = "bullmq-pro";
  } else if (library === "bullmq") {
    type = "bullmq";
  } else {
    return { ...BULL_QUEUE_TYPE };
  }

  return { type, majorVersion: parseMajorVersion(version), version };
}

/** Leading semver segment as a non-negative integer; 0 when it cannot be read. */
export function parseMajorVersion(version: string | null | undefined): number {
  if (!version) return 0;
  const leading = version.trim().split(".")[0];
  if (!leading) return 0;
  const major = parseInt(leading, 10);
  if (!Number.isFinite(major) || Number.isNaN(major) || major < 0) return 0;
  return major;
}

export async function getQueueType(
  queueName: string,
  prefix: string,
  client: Redis | Cluster
): Promise<QueueTypeInfo> {
  const metaKey = `${prefix}:${queueName}:meta`;
  const hasMeta = await client.exists(metaKey);

  if (!hasMeta) return { ...BULL_QUEUE_TYPE };

  const longVersion = await client.hget(metaKey, "version");
  return parseQueueMetaVersion(longVersion);
}
