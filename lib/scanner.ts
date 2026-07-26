import { Redis, Cluster } from "ioredis";
import { FoundQueue } from "./queue-factory";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface JobData {
  id: string;
  name: string;
  status: string;
  data: any;
  opts: any;
  progress: number;
  timestamp: number;
  processedOn: number | null;
  finishedOn: number | null;
  failedReason: string | null;
  stacktrace: string | null;
  attemptsMade: number;
  /** BullMQ's "ats". Diverges from attemptsMade while an attempt is in flight. */
  attemptsStarted: number;
  /** opts.attempts — the configured maximum, not the count so far. */
  maxAttempts: number;
  /** BullMQ's "pb": the worker that ran this attempt. */
  processedBy: string | null;
}

export interface QueueCounts {
  waiting: number;
  active: number;
  completed: number;
  failed: number;
  delayed: number;
  paused: number;
}

export interface QueuePayload {
  name: string;
  prefix: string;
  type: string;
  version?: string;
  counts: QueueCounts;
  jobs: JobData[];
}

// ---------------------------------------------------------------------------
// Queue counts — uses pipeline for efficiency
// ---------------------------------------------------------------------------

export async function getQueueCounts(
  redis: Redis | Cluster,
  queueName: string,
  prefix: string
): Promise<QueueCounts> {
  // BullMQ uses "wait" instead of "waiting"
  const keysToCheck = [
    { key: `${prefix}:${queueName}:waiting`, type: "llen" as const },
    { key: `${prefix}:${queueName}:wait`, type: "llen" as const },
    { key: `${prefix}:${queueName}:waiting`, type: "zcard" as const },
    { key: `${prefix}:${queueName}:wait`, type: "zcard" as const },
    { key: `${prefix}:${queueName}:active`, type: "llen" as const },
    { key: `${prefix}:${queueName}:active`, type: "zcard" as const },
    { key: `${prefix}:${queueName}:completed`, type: "zcard" as const },
    { key: `${prefix}:${queueName}:failed`, type: "zcard" as const },
    { key: `${prefix}:${queueName}:failed`, type: "llen" as const },
    { key: `${prefix}:${queueName}:delayed`, type: "zcard" as const },
    { key: `${prefix}:${queueName}:paused`, type: "zcard" as const },
    { key: `${prefix}:${queueName}:paused`, type: "llen" as const },
  ];

  const pipeline = redis.pipeline();
  for (const { key, type } of keysToCheck) {
    if (type === "zcard") {
      pipeline.zcard(key);
    } else {
      pipeline.llen(key);
    }
  }
  const results = await pipeline.exec();
  const values = (results || []).map(([err, val]) => {
    if (err) return 0;
    return typeof val === "number" ? val : 0;
  });

  const [
    waitingL, waitL, waitingZ, waitZ,
    activeL, activeZ,
    completed,
    failedZ, failedL,
    delayed,
    pausedZ, pausedL,
  ] = values;

  return {
    waiting: Math.max(waitingL, waitL, waitingZ, waitZ),
    active: Math.max(activeL, activeZ),
    completed,
    failed: Math.max(failedZ, failedL),
    delayed,
    paused: Math.max(pausedZ, pausedL),
  };
}

// ---------------------------------------------------------------------------
// Get job IDs for a specific status
// ---------------------------------------------------------------------------

const STATUS_KEY_MAP: Record<string, string[]> = {
  waiting: ["wait", "waiting"],
  active: ["active"],
  completed: ["completed"],
  failed: ["failed"],
  delayed: ["delayed"],
  paused: ["paused"],
};

// Lists: waiting, active. Sorted sets: completed, failed, delayed, paused.
// But some versions use different types, so we try both.
const LIST_STATUSES = new Set(["waiting", "wait", "active"]);

export async function getJobIds(
  redis: Redis | Cluster,
  queueName: string,
  status: string,
  prefix: string,
  limit: number = 200
): Promise<string[]> {
  const suffixes = STATUS_KEY_MAP[status] || [status];
  const allIds = new Set<string>();

  for (const suffix of suffixes) {
    const key = `${prefix}:${queueName}:${suffix}`;
    const isListStatus = LIST_STATUSES.has(suffix);

    try {
      if (isListStatus) {
        // Try as list first, then sorted set
        const listIds = await redis.lrange(key, 0, limit - 1).catch(() => [] as string[]);
        if (listIds.length > 0) {
          for (const id of listIds) allIds.add(id);
          continue;
        }
        const zsetIds = await redis.zrange(key, 0, limit - 1, "REV").catch(() => [] as string[]);
        for (const id of zsetIds) allIds.add(id);
      } else {
        // Try as sorted set first, then list
        const zsetIds = await redis.zrange(key, 0, limit - 1, "REV").catch(() => [] as string[]);
        if (zsetIds.length > 0) {
          for (const id of zsetIds) allIds.add(id);
          continue;
        }
        const listIds = await redis.lrange(key, 0, limit - 1).catch(() => [] as string[]);
        for (const id of listIds) allIds.add(id);
      }
    } catch {
      // Skip on error
    }
  }

  return Array.from(allIds).slice(0, limit);
}

// ---------------------------------------------------------------------------
// Fetch job data in batches using pipeline HGETALL
// ---------------------------------------------------------------------------

const CHUNK_SIZE = 200;

export async function fetchJobsBatch(
  redis: Redis | Cluster,
  queueName: string,
  status: string,
  jobIds: string[],
  prefix: string
): Promise<JobData[]> {
  if (jobIds.length === 0) return [];

  const jobs: JobData[] = [];

  for (let i = 0; i < jobIds.length; i += CHUNK_SIZE) {
    const chunk = jobIds.slice(i, i + CHUNK_SIZE);
    const pipeline = redis.pipeline();
    for (const id of chunk) {
      pipeline.hgetall(`${prefix}:${queueName}:${id}`);
    }
    const results = await pipeline.exec();
    if (!results) continue;

    for (let j = 0; j < results.length; j++) {
      const [err, data] = results[j];
      if (err || !data || typeof data !== "object" || Object.keys(data as any).length === 0) continue;

      const jobData = data as Record<string, string>;
      const job = parseJobHash(chunk[j], queueName, status, jobData);
      if (job) jobs.push(job);
    }
  }

  return jobs;
}

function parseJobHash(
  jobId: string,
  queueName: string,
  status: string,
  hash: Record<string, string>
): JobData | null {
  let parsedData: any = {};
  let parsedOpts: any = {};

  try {
    if (hash.data) parsedData = JSON.parse(hash.data);
  } catch {
    parsedData = hash.data || {};
  }

  try {
    if (hash.opts) parsedOpts = JSON.parse(hash.opts);
  } catch {
    parsedOpts = hash.opts || {};
  }

  // Determine job name — same priority as cloud's getJobDetails
  let name: string;
  if (hash.name && hash.name.trim() && hash.name !== queueName) {
    name = hash.name;
  } else if (parsedOpts?.name && parsedOpts.name.trim() && parsedOpts.name !== queueName) {
    name = parsedOpts.name;
  } else if (parsedData?.name && typeof parsedData.name === "string" && parsedData.name.trim() && parsedData.name !== queueName) {
    name = parsedData.name;
  } else {
    name = queueName;
  }

  const timestamp = hash.timestamp ? parseInt(hash.timestamp, 10) : Date.now();
  const processedOn = hash.processedOn ? parseInt(hash.processedOn, 10) : null;
  const finishedOn = hash.finishedOn ? parseInt(hash.finishedOn, 10) : null;
  const progress = hash.progress ? parseInt(hash.progress, 10) : 0;

  // attemptsMade — same logic as cloud. "atm" is the BullMQ v5 spelling; without
  // it a v5 job reports 0 forever, and the cloud keys failure history on this
  // number to tell a retry apart from a re-observation of the same failure.
  let attemptsMade = 0;
  const attemptsValue = hash.attemptsMade ?? hash.atm ?? parsedOpts?.attemptsMade ?? hash.attempts ?? null;
  if (attemptsValue !== null && attemptsValue !== undefined) {
    attemptsMade = parseInt(String(attemptsValue), 10) || 0;
  }
  const upperStatus = status.toUpperCase();
  if (attemptsMade === 0) {
    if (upperStatus === "COMPLETED" && finishedOn) attemptsMade = 1;
    else if (upperStatus === "ACTIVE" && processedOn) attemptsMade = 1;
    else if (upperStatus === "FAILED" && processedOn) attemptsMade = 1;
  }

  const attemptsStarted = hash.ats ? parseInt(hash.ats, 10) || attemptsMade : attemptsMade;

  // opts.attempts is the configured MAX attempts, in both Bull and BullMQ.
  const rawMaxAttempts = parsedOpts?.attempts;
  const parsedMaxAttempts =
    rawMaxAttempts === null || rawMaxAttempts === undefined
      ? 0
      : parseInt(String(rawMaxAttempts), 10);
  const maxAttempts =
    Number.isFinite(parsedMaxAttempts) && parsedMaxAttempts > 0 ? parsedMaxAttempts : 0;

  return {
    id: jobId,
    name,
    status: upperStatus,
    data: parsedData,
    opts: parsedOpts,
    progress,
    timestamp,
    processedOn,
    finishedOn,
    failedReason: hash.failedReason || null,
    stacktrace: hash.stacktrace || null,
    attemptsMade,
    attemptsStarted,
    maxAttempts,
    processedBy: hash.pb || null,
  };
}

// ---------------------------------------------------------------------------
// fullScan — scan all queues, return counts + jobs
// ---------------------------------------------------------------------------

const STATUSES = ["waiting", "active", "completed", "failed", "delayed", "paused"] as const;

export async function fullScan(
  redis: Redis | Cluster,
  queues: FoundQueue[],
  jobLimit: number = 50
): Promise<{ queues: QueuePayload[]; totalJobs: number }> {
  const result: QueuePayload[] = [];
  let totalJobs = 0;

  for (const q of queues) {
    const counts = await getQueueCounts(redis, q.name, q.prefix);
    const jobs: JobData[] = [];

    for (const status of STATUSES) {
      const ids = await getJobIds(redis, q.name, status, q.prefix, jobLimit);
      const batch = await fetchJobsBatch(redis, q.name, status, ids, q.prefix);
      jobs.push(...batch);
    }

    totalJobs += jobs.length;
    result.push({
      name: q.name,
      prefix: q.prefix,
      type: q.type,
      version: q.version,
      counts,
      jobs,
    });
  }

  return { queues: result, totalJobs };
}

// ---------------------------------------------------------------------------
// detectChanges — compare current counts to cached, return changed queue names
// ---------------------------------------------------------------------------

export function totalFromCounts(counts: QueueCounts): number {
  return counts.waiting + counts.active + counts.completed + counts.failed + counts.delayed + counts.paused;
}

export async function detectChanges(
  redis: Redis | Cluster,
  queues: FoundQueue[],
  lastKnownCounts: Map<string, QueueCounts>
): Promise<FoundQueue[]> {
  const changed: FoundQueue[] = [];

  for (const q of queues) {
    const current = await getQueueCounts(redis, q.name, q.prefix);
    const last = lastKnownCounts.get(q.name);

    if (
      !last ||
      current.waiting !== last.waiting ||
      current.active !== last.active ||
      current.completed !== last.completed ||
      current.failed !== last.failed ||
      current.delayed !== last.delayed ||
      current.paused !== last.paused
    ) {
      changed.push(q);
    }

    // Always update the cache
    lastKnownCounts.set(q.name, current);
  }

  return changed;
}
