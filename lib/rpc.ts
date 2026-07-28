import fetch from "node-fetch";
import chalk from "chalk";
import { Redis, Cluster } from "ioredis";
import {
  QueueRegistry,
  QueueNotFoundError,
  UnsupportedQueueTypeError,
} from "./queue-registry";
import { FoundQueue } from "./queue-factory";
import {
  JobData,
  QueueCounts,
  fetchJobLogs,
  fetchJobsBatch,
  getJobIds,
  getQueueCounts,
} from "./scanner";
import { RedactedJob, RedactionEngine, RedactionMode } from "./redaction";

/**
 * On-demand RPC transport.
 *
 * The push loop in client.ts uploads the newest ~200 jobs every 5 seconds
 * whether or not anybody is looking. This transport is the other half: the
 * dashboard asks for exactly what the user is viewing, and only then.
 *
 * There is no WebSocket because Scalingo routes external traffic to the `web`
 * process only, so a dedicated socket process could never be dialled from a
 * customer's network. Instead the connector holds a GET open for ~20s (the
 * platform's first-byte window is 30s); the server answers it the moment a
 * dashboard read enqueues work, or 204s on timeout, and the connector
 * immediately re-polls.
 *
 * Both loops run at once. Nothing here replaces or disables the push loop.
 */

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

export interface RpcRequest {
  id: string;
  method: string;
  params: any;
  /** ISO timestamp; past it, nobody is waiting for the answer any more. */
  deadlineAt: string;
}

/**
 * What a list row is allowed to carry.
 *
 * `job.list` answers the same question as the Postgres list endpoints, which
 * were deliberately changed to stop shipping `data` and `opts` (a 100-row page
 * went from 294 kB to 15 kB). An RPC response has no equivalent of Prisma's
 * explicit `select`, so the discipline has to live in a type: this interface is
 * the connector's version of that select list, and `toJobSummary` is the only
 * way a row reaches a list response.
 *
 * Payloads belong to `job.get`, which is what the details drawer calls.
 */
export interface JobSummary {
  id: string;
  name: string;
  status: string;
  progress: number;
  timestamp: number;
  processedOn: number | null;
  finishedOn: number | null;
  failedReason: string | null;
  attemptsMade: number;
}

/**
 * Project a full job down to its list row. Written field by field rather than
 * by deleting keys, so a new field on JobData is invisible to lists until
 * somebody adds it here on purpose.
 */
export function toJobSummary(job: JobData): JobSummary {
  return {
    id: job.id,
    name: job.name,
    status: job.status,
    progress: job.progress,
    timestamp: job.timestamp,
    processedOn: job.processedOn,
    finishedOn: job.finishedOn,
    failedReason: job.failedReason,
    attemptsMade: job.attemptsMade,
  };
}

interface RpcPollResponse {
  requests?: RpcRequest[];
}

/** Methods this connector can answer. Advertised on every poll. */
export const RPC_METHODS = [
  "ping",
  "queue.list",
  "queue.counts",
  "job.list",
  "job.get",
  "redis.info",
] as const;

export type RpcMethod = (typeof RPC_METHODS)[number];

// ---------------------------------------------------------------------------
// Tunables — mirror lib/connector-rpc.ts on the server
// ---------------------------------------------------------------------------

/** How long the server holds the poll before 204ing. */
const POLL_HOLD_MS = 20_000;

/** Socket budget for one poll: the hold, plus room for the round trip. */
const POLL_REQUEST_TIMEOUT_MS = POLL_HOLD_MS + 10_000;

/** Fallback cadence when the server does not send x-dashmq-rpc-poll-after. */
const DEFAULT_IDLE_POLL_MS = 15_000;

/** Backoff after a transport failure. */
const BACKOFF_MIN_MS = 1_000;
const BACKOFF_MAX_MS = 30_000;

/** Backoff after the server rejects our credentials or our connection id. */
const REJECTED_BACKOFF_MS = 60_000;

/** Ceiling on how long one request may take before we answer with an error. */
const HANDLER_TIMEOUT_MS = 10_000;

/**
 * Ceiling on the error message we post back. The backend clamps this too, but
 * clamping here is what keeps a pathological message (a driver error carrying a
 * whole payload, say) from being rejected wholesale as an oversized body — a
 * truncated reason still tells the user what happened; a 413 tells them
 * nothing.
 */
const MAX_ERROR_CHARS = 2_000;

/** Bounds on what a single job.list may ask for. */
const MAX_JOB_WINDOW = 1_000;
const DEFAULT_JOB_LIMIT = 50;

const PROTOCOL_VERSION = 2;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

class RpcMethodError extends Error {
  readonly code: string;

  constructor(message: string, code: string = "RPC_ERROR") {
    super(message);
    this.name = "RpcMethodError";
    this.code = code;
    Object.setPrototypeOf(this, RpcMethodError.prototype);
  }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

interface HandlerContext {
  registry: QueueRegistry;
  redis: Redis | Cluster;
  defaultPrefix: string;
  redaction: RedactionEngine;
}

/** What the dashboard needs to say which policy produced a response. */
interface RedactionStamp {
  policy: string;
  mode: RedactionMode;
}

function stampFor(ctx: HandlerContext, target: FoundQueue): RedactionStamp {
  return {
    policy: ctx.redaction.policyId,
    mode: ctx.redaction.policyFor(target.prefix, target.name).rule.mode,
  };
}

function asObject(params: any): Record<string, any> {
  return params && typeof params === "object" && !Array.isArray(params)
    ? params
    : {};
}

function requireString(params: Record<string, any>, key: string): string {
  const value = params[key];
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new RpcMethodError(`"${key}" is required`, "BAD_PARAMS");
  }
  return value.trim();
}

/**
 * Resolve a queue descriptor from what the dashboard knows.
 *
 * Only queues discovery has actually seen are resolvable: answering for a queue
 * that does not exist in this Redis would be inventing state.
 */
function resolveQueue(
  ctx: HandlerContext,
  name: string,
  prefix?: string | null
): FoundQueue {
  if (prefix) {
    const described = ctx.registry.describe(prefix, name);
    if (!described) throw new QueueNotFoundError(name, prefix);
    return described;
  }

  const known = ctx.registry.known();
  const preferred = known.find(
    (queue) => queue.name === name && queue.prefix === ctx.defaultPrefix
  );
  if (preferred) return preferred;

  const any = known.find((queue) => queue.name === name);
  if (!any) throw new QueueNotFoundError(name);
  return any;
}

/** Every Redis key a job id can live in, in the order a state is reported. */
function stateKeys(prefix: string, queue: string): Array<{ state: string; key: string }> {
  return [
    { state: "active", key: `${prefix}:${queue}:active` },
    { state: "waiting", key: `${prefix}:${queue}:wait` },
    { state: "waiting", key: `${prefix}:${queue}:waiting` },
    { state: "paused", key: `${prefix}:${queue}:paused` },
    { state: "delayed", key: `${prefix}:${queue}:delayed` },
    { state: "completed", key: `${prefix}:${queue}:completed` },
    { state: "failed", key: `${prefix}:${queue}:failed` },
  ];
}

/**
 * Determine which state a job id is actually in by probing the state keys.
 *
 * Returns null when the probe cannot prove membership — an old Redis without
 * LPOS, an id that is in no list, a hash left behind by a removal. Callers
 * surface that as "unknown" rather than guessing: a job page that confidently
 * shows the wrong state is worse than one that admits it does not know.
 */
async function probeJobState(
  redis: Redis | Cluster,
  prefix: string,
  queue: string,
  jobId: string
): Promise<string | null> {
  const candidates = stateKeys(prefix, queue);

  const typePipeline = redis.pipeline();
  for (const candidate of candidates) typePipeline.type(candidate.key);
  const typeResults = (await typePipeline.exec()) || [];

  const probes: Array<{ state: string; kind: "zset" | "list" }> = [];
  const membershipPipeline = redis.pipeline();

  for (let i = 0; i < candidates.length; i++) {
    const [error, keyType] = typeResults[i] || [null, "none"];
    if (error) continue;

    if (keyType === "zset") {
      probes.push({ state: candidates[i].state, kind: "zset" });
      membershipPipeline.zscore(candidates[i].key, jobId);
    } else if (keyType === "list") {
      probes.push({ state: candidates[i].state, kind: "list" });
      membershipPipeline.lpos(candidates[i].key, jobId);
    }
  }

  if (probes.length === 0) return null;

  const membership = (await membershipPipeline.exec()) || [];

  for (let i = 0; i < probes.length; i++) {
    const [error, value] = membership[i] || [null, null];
    // A missing LPOS (Redis < 6.0.6) leaves the state unproven, which is
    // reported as unknown rather than assumed.
    if (error) continue;
    if (value !== null && value !== undefined) return probes[i].state;
  }

  return null;
}

async function handlePing(): Promise<{ pong: true; at: number }> {
  return { pong: true, at: Date.now() };
}

/**
 * The INFO keys `redis.info` may carry, and nothing else.
 *
 * INFO also reports things the dashboard has no business seeing from outside
 * the customer's network — `executable`, `config_file`, `run_id`, replication
 * peers with their IPs. An allowlist means a new Redis version cannot add a
 * leaking key to our responses by existing; someone has to put it here on
 * purpose, the same discipline {@link JobSummary} applies to job fields.
 */
const REDIS_INFO_KEYS = [
  // server
  "redis_version",
  "redis_mode",
  "os",
  "uptime_in_seconds",
  // clients
  "connected_clients",
  "blocked_clients",
  // memory
  "used_memory",
  "used_memory_human",
  "used_memory_peak_human",
  "maxmemory",
  "maxmemory_human",
  "maxmemory_policy",
  "total_system_memory",
  "mem_fragmentation_ratio",
  // stats
  "total_commands_processed",
  "instantaneous_ops_per_sec",
  "keyspace_hits",
  "keyspace_misses",
  "expired_keys",
  "evicted_keys",
] as const;

/**
 * Parse raw INFO output down to the allowlisted keys.
 *
 * Exported for tests: the interesting behavior is the filtering, which must
 * not need a live Redis to prove.
 */
export function parseRedisInfoText(raw: string): Record<string, string> {
  const allowed = new Set<string>(REDIS_INFO_KEYS);
  const info: Record<string, string> = {};

  // INFO uses \r\n, but be liberal: some proxies rewrite line endings.
  for (const line of raw.split(/\r?\n/)) {
    if (!line || line.startsWith("#")) continue;
    const idx = line.indexOf(":");
    if (idx <= 0) continue;
    const key = line.slice(0, idx);
    if (allowed.has(key)) info[key] = line.slice(idx + 1).trim();
  }

  return info;
}

/**
 * Instance facts for the dashboard's Redis card — version, memory, clients.
 *
 * This is the read that cannot work any other way: the dashboard cannot dial
 * this Redis (that is the whole reason a connector is running), so before this
 * method the instance card either showed nothing or, worse, whatever happened
 * to answer on the *dashboard host's* localhost:6379.
 *
 * On a cluster client INFO answers from one node, so the numbers describe that
 * node rather than the fleet — imperfect, but honestly labelled by
 * `redis_mode: cluster` in the response.
 */
async function handleRedisInfo(
  ctx: HandlerContext
): Promise<{ info: Record<string, string> }> {
  const raw = await ctx.redis.info();
  return { info: parseRedisInfoText(String(raw)) };
}

async function handleQueueList(ctx: HandlerContext): Promise<{
  queues: Array<{
    name: string;
    prefix: string;
    type: string;
    version?: string;
  }>;
}> {
  return {
    queues: ctx.registry.known().map((queue) => ({
      name: queue.name,
      prefix: queue.prefix,
      type: queue.type,
      version: queue.version,
    })),
  };
}

async function handleQueueCounts(
  ctx: HandlerContext,
  params: any
): Promise<{
  queues: Array<{ name: string; prefix: string; counts: QueueCounts }>;
}> {
  const parsed = asObject(params);
  const requested: any[] = Array.isArray(parsed.queues) ? parsed.queues : [];

  const targets: FoundQueue[] =
    requested.length > 0
      ? requested.map((entry) =>
          typeof entry === "string"
            ? resolveQueue(ctx, entry)
            : resolveQueue(ctx, requireString(asObject(entry), "name"), asObject(entry).prefix)
        )
      : ctx.registry.known();

  const queues: Array<{ name: string; prefix: string; counts: QueueCounts }> = [];

  for (const target of targets) {
    queues.push({
      name: target.name,
      prefix: target.prefix,
      counts: await getQueueCounts(ctx.redis, target.name, target.prefix),
    });
  }

  return { queues };
}

/**
 * A page of list rows. Summaries only — see {@link JobSummary}. Anything that
 * needs `data` or `opts` asks `job.get` for one job.
 */
async function handleJobList(
  ctx: HandlerContext,
  params: any
): Promise<{
  queue: string;
  prefix: string;
  status: string;
  offset: number;
  limit: number;
  jobs: JobSummary[];
  redaction: RedactionStamp;
}> {
  const parsed = asObject(params);
  const name = requireString(parsed, "queue");
  const status = requireString(parsed, "status").toLowerCase();
  const target = resolveQueue(ctx, name, parsed.prefix);

  const limit = clamp(
    Number.parseInt(String(parsed.limit ?? DEFAULT_JOB_LIMIT), 10),
    1,
    200,
    DEFAULT_JOB_LIMIT
  );
  const offset = clamp(
    Number.parseInt(String(parsed.offset ?? 0), 10),
    0,
    MAX_JOB_WINDOW - 1,
    0
  );

  // getJobIds returns a newest-first window; slicing it is how the connector
  // paginates without a second key layout to maintain.
  const window = Math.min(offset + limit, MAX_JOB_WINDOW);
  const ids = await getJobIds(ctx.redis, target.name, status, target.prefix, window);
  const page = ids.slice(offset, offset + limit);

  const jobs = await fetchJobsBatch(
    ctx.redis,
    target.name,
    status,
    page,
    target.prefix,
    ctx.redaction
  );

  return {
    queue: target.name,
    prefix: target.prefix,
    status,
    offset,
    limit,
    // Summaries carry no payload, so the per-job sidecar would be 100 copies of
    // the same two facts. The stamp is hoisted to the page instead.
    jobs: jobs.map(toJobSummary),
    redaction: stampFor(ctx, target),
  };
}

/** How many log lines one detail read may carry. */
const MAX_JOB_LOG_LINES = 100;

/**
 * The one method that may return a payload, and only ever for a single job.
 *
 * It also returns the job's logs, which are the surface everyone forgets:
 * `console.log(user)` inside a processor leaks at least as much as the payload
 * it was logging. They come back detector-scrubbed like everything else.
 */
async function handleJobGet(
  ctx: HandlerContext,
  params: any
): Promise<{
  job: RedactedJob | null;
  state: string | null;
  logs: string[];
  redaction: RedactionStamp;
}> {
  const parsed = asObject(params);
  const name = requireString(parsed, "queue");
  const jobId = requireString(parsed, "id");
  const target = resolveQueue(ctx, name, parsed.prefix);

  const state = await probeJobState(ctx.redis, target.prefix, target.name, jobId);

  const jobs = await fetchJobsBatch(
    ctx.redis,
    target.name,
    state ?? "unknown",
    [jobId],
    target.prefix,
    ctx.redaction
  );

  const job = jobs[0] ?? null;
  if (job && !state) {
    // The hash is real, its state is not proven. Say so.
    job.status = "UNKNOWN";
  }

  const wantsLogs = parsed.logs !== false;
  const logs =
    job && wantsLogs
      ? await fetchJobLogs(
          ctx.redis,
          target.name,
          jobId,
          target.prefix,
          ctx.redaction,
          clamp(
            Number.parseInt(String(parsed.logLimit ?? MAX_JOB_LOG_LINES), 10),
            1,
            MAX_JOB_LOG_LINES,
            MAX_JOB_LOG_LINES
          )
        )
      : [];

  return { job, state, logs, redaction: stampFor(ctx, target) };
}

function clamp(
  value: number,
  min: number,
  max: number,
  fallback: number
): number {
  if (!Number.isFinite(value)) return fallback;
  return Math.min(Math.max(Math.trunc(value), min), max);
}

async function dispatch(
  ctx: HandlerContext,
  request: RpcRequest
): Promise<unknown> {
  switch (request.method) {
    case "ping":
      return handlePing();
    case "queue.list":
      return handleQueueList(ctx);
    case "queue.counts":
      return handleQueueCounts(ctx, request.params);
    case "job.list":
      return handleJobList(ctx, request.params);
    case "job.get":
      return handleJobGet(ctx, request.params);
    case "redis.info":
      return handleRedisInfo(ctx);
    default:
      throw new RpcMethodError(
        `Unknown RPC method "${request.method}"`,
        "UNKNOWN_METHOD"
      );
  }
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

export interface RpcTransportOptions {
  token: string;
  backend: string;
  /** The dashboard's id for this connection. RPC cannot run without it. */
  connectionId: string;
  registry: QueueRegistry;
  /** Local redaction policy. Nothing reaches a response without it. */
  redaction: RedactionEngine;
  /** Prefix used when the dashboard addresses a queue by bare name. */
  defaultPrefix?: string;
  /** Overridable for tests. */
  holdTimeoutMs?: number;
}

export class RpcTransport {
  private readonly token: string;
  private readonly backend: string;
  private readonly connectionId: string;
  private readonly registry: QueueRegistry;
  private readonly redaction: RedactionEngine;
  private readonly holdTimeoutMs: number;

  private defaultPrefix: string;
  private running = false;
  private loopPromise: Promise<void> | null = null;
  private controller: AbortController | null = null;
  private sleepTimer: NodeJS.Timeout | null = null;
  private wakeSleep: (() => void) | null = null;
  private backoffMs = BACKOFF_MIN_MS;
  private rejectedLogged = false;

  constructor(options: RpcTransportOptions) {
    this.token = options.token;
    this.backend = options.backend;
    this.connectionId = options.connectionId;
    this.registry = options.registry;
    this.redaction = options.redaction;
    this.defaultPrefix = options.defaultPrefix || "bull";
    this.holdTimeoutMs = options.holdTimeoutMs ?? POLL_REQUEST_TIMEOUT_MS;
  }

  /** Keeps the queue prefix in step with what discovery last saw. */
  setDefaultPrefix(prefix: string): void {
    if (prefix) this.defaultPrefix = prefix;
  }

  start(): void {
    if (this.running) return;
    this.running = true;
    this.loopPromise = this.loop();
  }

  async stop(): Promise<void> {
    if (!this.running) return;
    this.running = false;

    this.controller?.abort();
    this.wakeSleep?.();

    try {
      await this.loopPromise;
    } catch {
      // The loop swallows its own errors; this is belt and braces.
    }
    this.loopPromise = null;
  }

  private async loop(): Promise<void> {
    while (this.running) {
      let waitMs = 0;

      try {
        waitMs = await this.pollOnce();
        this.backoffMs = BACKOFF_MIN_MS;
      } catch (error: any) {
        if (!this.running) break;
        waitMs = this.backoffMs;
        this.backoffMs = Math.min(this.backoffMs * 2, BACKOFF_MAX_MS);
        // Transient network failures are the normal case for a long poll on a
        // laptop; only say something once per escalation.
        if (this.backoffMs >= BACKOFF_MAX_MS) {
          console.error(
            chalk.red("[DashMQ] RPC transport unavailable:"),
            error?.message || error
          );
        }
      }

      if (!this.running) break;
      if (waitMs > 0) await this.sleep(waitMs);
    }
  }

  /** One poll cycle. Returns how long to wait before the next one. */
  private async pollOnce(): Promise<number> {
    const controller = new AbortController();
    this.controller = controller;

    let response;
    try {
      response = await fetch(
        `${this.backend}/api/connector/rpc/poll?connectionId=${encodeURIComponent(this.connectionId)}`,
        {
          method: "GET",
          headers: {
            Authorization: `Bearer ${this.token}`,
            "x-dashmq-rpc-protocol": String(PROTOCOL_VERSION),
            "x-dashmq-rpc-capabilities": RPC_METHODS.join(","),
            // The hash only. The policy itself is a local file and is never
            // uploaded, quoted, or asked for.
            "x-dashmq-redaction-policy": this.redaction.policyId,
            "x-dashmq-redaction-mode": this.redaction.defaultMode,
          },
          signal: controller.signal as any,
          timeout: this.holdTimeoutMs,
        } as any
      );
    } finally {
      this.controller = null;
    }

    if (response.status === 204) {
      const after = Number.parseInt(
        response.headers.get("x-dashmq-rpc-poll-after") || "",
        10
      );
      if (Number.isFinite(after) && after >= 0) return after;
      return DEFAULT_IDLE_POLL_MS;
    }

    if (response.status === 401 || response.status === 403 || response.status === 404) {
      if (!this.rejectedLogged) {
        this.rejectedLogged = true;
        console.error(
          chalk.red("[DashMQ] RPC poll rejected:"),
          `${response.status} — on-demand reads are disabled for this connection.`
        );
      }
      return REJECTED_BACKOFF_MS;
    }

    if (response.status === 400) {
      // The server could not tell which connection is asking. Retrying fast
      // would only repeat the mistake.
      if (!this.rejectedLogged) {
        this.rejectedLogged = true;
        console.error(
          chalk.red("[DashMQ] RPC poll rejected:"),
          "the backend requires a connectionId this connector does not have yet."
        );
      }
      return REJECTED_BACKOFF_MS;
    }

    if (!response.ok) {
      throw new Error(`RPC poll failed with status ${response.status}`);
    }

    this.rejectedLogged = false;

    const body = (await response.json()) as RpcPollResponse;
    const requests = Array.isArray(body?.requests) ? body.requests : [];
    if (requests.length === 0) return 0;

    await Promise.all(requests.map((request) => this.handle(request)));

    // Work was waiting: go straight back for more.
    return 0;
  }

  private async handle(request: RpcRequest): Promise<void> {
    // Past its deadline the caller has already fallen back to Postgres. Doing
    // the Redis work anyway would only burn the customer's resources.
    const deadline = Date.parse(request.deadlineAt);
    if (Number.isFinite(deadline) && deadline <= Date.now()) return;

    const ctx: HandlerContext = {
      registry: this.registry,
      redis: this.registry.redis,
      defaultPrefix: this.defaultPrefix,
      redaction: this.redaction,
    };

    const budget = Number.isFinite(deadline)
      ? Math.max(250, Math.min(deadline - Date.now(), HANDLER_TIMEOUT_MS))
      : HANDLER_TIMEOUT_MS;

    try {
      const result = await withTimeout(dispatch(ctx, request), budget);
      await this.reply(request.id, true, result, null);
    } catch (error: any) {
      const message = describeError(error);
      console.error(
        chalk.red(`[DashMQ] RPC ${request.method} failed:`),
        message
      );
      await this.reply(request.id, false, undefined, message);
    }
  }

  private async reply(
    id: string,
    ok: boolean,
    result: unknown,
    error: string | null
  ): Promise<void> {
    try {
      const response = await fetch(`${this.backend}/api/connector/rpc/reply`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.token}`,
        },
        body: JSON.stringify({
          connectionId: this.connectionId,
          id,
          ok,
          ...(ok ? { result: result ?? null } : { error }),
        }),
      });

      // 409 means the caller already gave up, or another instance answered.
      // That is the designed outcome of a late reply, not a failure.
      if (!response.ok && response.status !== 409) {
        console.error(
          chalk.red("[DashMQ] RPC reply rejected:"),
          response.status
        );
      }
    } catch {
      // The request expires server-side; the user has already been shown the
      // Postgres fallback. Nothing useful left to do.
    }
  }

  private sleep(ms: number): Promise<void> {
    return new Promise<void>((resolve) => {
      const finish = () => {
        if (this.sleepTimer) {
          clearTimeout(this.sleepTimer);
          this.sleepTimer = null;
        }
        this.wakeSleep = null;
        resolve();
      };
      this.wakeSleep = finish;
      this.sleepTimer = setTimeout(finish, ms);
      this.sleepTimer.unref?.();
    });
  }
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new RpcMethodError(`Timed out after ${ms}ms`, "TIMEOUT"));
    }, ms);
    timer.unref?.();

    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        clearTimeout(timer);
        reject(error);
      }
    );
  });
}

function describeError(error: any): string {
  const message = (() => {
    if (error instanceof QueueNotFoundError) return error.message;
    if (error instanceof UnsupportedQueueTypeError) return error.message;
    if (error instanceof RpcMethodError) return error.message;
    return error?.message || String(error);
  })();

  return message.length > MAX_ERROR_CHARS
    ? `${message.slice(0, MAX_ERROR_CHARS)}… (truncated)`
    : message;
}
