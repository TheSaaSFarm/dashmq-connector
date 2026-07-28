import fetch from "node-fetch";
import { Connection, ConnectionOptions, isRedisInstance, redisOptsFromConnection } from "./connection";
import { getConnectionQueues, FoundQueue } from "./queue-factory";
import { fullScan, detectChanges, QueueCounts, QueuePayload } from "./scanner";
import { CommandExecutor } from "./commands";
import { QueueRegistry } from "./queue-registry";
import { RpcTransport } from "./rpc";
import { RedactionEngine } from "./redaction";
import Redis from "ioredis";
import chalk from "chalk";

const { version } = require("../package.json");

/** Ceiling on a quoted response body. Enough to identify it, not to drown in it. */
const MAX_BODY_CHARS = 300;

/**
 * A failed sync described in terms of what went wrong, not by reprinting the
 * server's answer.
 *
 * The previous version interpolated the raw body straight into the message.
 * When a misaddressed backend answers with a Next.js 404 page, that is tens of
 * kilobytes of minified RSC payload in the logs, once every five seconds,
 * burying the one fact that matters: nothing is listening at that URL.
 *
 * An HTML body is itself the diagnosis — this endpoint always answers JSON, so
 * markup means the request reached something other than DashMQ's API.
 */
export function describeHttpFailure(status: number, body: string): string {
  const trimmed = body.trim();
  const looksLikeHtml = /^<(?:!doctype|html)/i.test(trimmed);

  if (looksLikeHtml) {
    return (
      `The backend URL did not answer with JSON (HTTP ${status}). ` +
      `Check that it points at your DashMQ instance and includes no trailing path — ` +
      `the connector appends /api/connector/sync itself.`
    );
  }

  const quoted =
    trimmed.length > MAX_BODY_CHARS
      ? `${trimmed.slice(0, MAX_BODY_CHARS)}… (truncated)`
      : trimmed || "(empty response)";

  return `Server error (HTTP ${status}): ${quoted}`;
}

export class DashMQClient {
  private name: string;
  private token: string;
  private connection: Connection;
  private backend: string;
  private opts: { queueNames?: string[]; configPath?: string | null };
  private intervalId?: NodeJS.Timeout;
  private registry: QueueRegistry;
  private redisConfig: ConnectionOptions; // Store Redis config to send to API

  /**
   * Local redaction policy, loaded from disk once at construction.
   *
   * Constructing it can throw (RedactionConfigError) and deliberately is not
   * caught here: a connector that cannot read its policy must not run. The CLI
   * turns that throw into a clear message and a non-zero exit.
   */
  private redaction: RedactionEngine;

  // Job scanning state
  private isFirstSync: boolean = true;
  private lastKnownCounts: Map<string, QueueCounts> = new Map();
  private commandExecutor?: CommandExecutor;

  // On-demand RPC transport. Runs alongside the 5s push loop, never instead of
  // it: the push loop keeps the Postgres cache warm (and is the fallback the
  // dashboard renders whenever RPC is off, slow, or unavailable), while RPC
  // answers what the user is looking at right now.
  private rpcTransport?: RpcTransport;
  private connectionId?: string;

  constructor(
    name: string,
    token: string,
    connection: Connection | ConnectionOptions,
    backend: string,
    opts: { queueNames?: string[]; configPath?: string | null } = {},
  ) {
    this.name = name;
    this.token = token;
    this.backend = backend;
    this.opts = opts;
    this.redaction = new RedactionEngine({ configPath: opts.configPath ?? null });

    if (isRedisInstance(connection)) {
      this.connection = connection;
      // Extract config from Redis instance if possible
      this.redisConfig = {
        host: (connection as any).options?.host || "localhost",
        port: (connection as any).options?.port || 6379,
        password: (connection as any).options?.password,
        db: (connection as any).options?.db || 0,
      };
      // Caller owns this client — the registry borrows it and will not close it.
      this.registry = new QueueRegistry(connection);
    } else {
      const redisOpts = redisOptsFromConnection(connection);
      this.connection = redisOpts;
      // Store the original connection options
      this.redisConfig = connection;
      this.registry = new QueueRegistry(redisOpts);
    }
  }

  /** Shared queue registry — scanning, commands and RPC all go through it. */
  get queues(): QueueRegistry {
    return this.registry;
  }

  /** The live redaction policy. Read-only: nothing can change it at runtime. */
  get redactionPolicy(): RedactionEngine {
    return this.redaction;
  }

  async start() {
    console.log(`${chalk.yellow("DashMQ:")} ${chalk.blueBright("Connecting to")} ${chalk.gray(this.backend)}`);
    console.log(`${chalk.yellow("DashMQ:")} ${chalk.blueBright("Redaction:")} ${chalk.gray(this.redaction.describe())}`);

    // A default that transmits values is not allowed to be quiet about it. This
    // prints on every start, before the first sync, whenever no policy file
    // exists — which is the state of every installation that upgrades into this
    // release without doing anything.
    for (const line of this.redaction.warnings()) {
      console.warn(`${chalk.yellow("DashMQ:")} ${chalk.yellow(line)}`);
    }

    // Initial connection
    await this.sendConnection();

    // Poll every 5 seconds
    this.intervalId = setInterval(() => {
      this.sendConnection().catch((err) => {
        console.error(chalk.red("[DashMQ] Error sending connection:"), err.message);
      });
    }, 5000);

    console.log(chalk.yellow("DashMQ:") + chalk.green(" Connected and syncing queues every 5 seconds"));
  }

  async stop() {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = undefined;
    }
    if (this.rpcTransport) {
      await this.rpcTransport.stop();
      this.rpcTransport = undefined;
    }
    await this.registry.close();
  }

  private async sendConnection() {
    try {
      // The registry owns the shared Redis client used for every raw read.
      const redisConnection = this.registry.redis as Redis;

      // 1. Discover queues (existing)
      const queues = await getConnectionQueues(redisConnection, this.opts.queueNames);

      // 1b. Reconcile the queue registry: new queues become resolvable, queues
      // that disappeared get their clients closed.
      await this.registry.refresh(queues);

      // 1c. Resolve each queue's effective redaction policy once, here, rather
      // than per job read. After this the per-job cost is a single tree walk.
      this.redaction.prime(queues);

      // 2. Scan for job data
      let queuePayloads: QueuePayload[];

      if (this.isFirstSync) {
        // First sync: full scan of all queues + all jobs
        const scanResult = await fullScan(redisConnection, queues, this.redaction);
        queuePayloads = scanResult.queues;
        console.log(`${chalk.yellow("DashMQ:")} ${chalk.green("Full scan:")} ${chalk.blueBright(scanResult.totalJobs)} jobs across ${chalk.blueBright(queues.length)} queues`);
        this.isFirstSync = false;
      } else {
        // Subsequent syncs: only push changed queues
        const changedQueues = await detectChanges(redisConnection, queues, this.lastKnownCounts);

        if (changedQueues.length > 0) {
          const scanResult = await fullScan(redisConnection, changedQueues, this.redaction);
          queuePayloads = scanResult.queues;

          // Include unchanged queues without job data (just metadata)
          const changedNames = new Set(changedQueues.map((q) => q.name));
          for (const q of queues) {
            if (!changedNames.has(q.name)) {
              const counts = this.lastKnownCounts.get(q.name);
              if (counts) {
                queuePayloads.push({
                  name: q.name,
                  prefix: q.prefix,
                  type: q.type,
                  version: q.version,
                  counts,
                  jobs: [], // No job changes
                });
              }
            }
          }
        } else {
          // No changes — still send queue metadata with counts
          queuePayloads = queues.map((q) => ({
            name: q.name,
            prefix: q.prefix,
            type: q.type,
            version: q.version,
            counts: this.lastKnownCounts.get(q.name) || {
              waiting: 0, active: 0, completed: 0, failed: 0, delayed: 0, paused: 0,
            },
            jobs: [],
          }));
        }
      }

      // 3. Extract Redis connection info to send to API
      const redisInfo: any = {
        host: this.redisConfig.host || "localhost",
        port: this.redisConfig.port || 6379,
        database: this.redisConfig.db || 0,
      };

      if (this.redisConfig.password) {
        redisInfo.password = this.redisConfig.password;
      }
      if (this.redisConfig.username) {
        redisInfo.username = this.redisConfig.username;
      }
      if (this.redisConfig.tls) {
        redisInfo.useTLS = true;
      }

      // 4. Push queue data + jobs to /api/connector/sync
      const response = await fetch(`${this.backend}/api/connector/sync`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.token}`,
        },
        body: JSON.stringify({
          connection: this.name,
          redis: redisInfo,
          queues: queuePayloads,
          version,
          // The handshake reports which policy is live — its hash and its
          // default mode, never its contents. The dashboard can display it and
          // cannot influence it.
          redaction: {
            policy: this.redaction.policyId,
            mode: this.redaction.defaultMode,
            configured: this.redaction.configPath !== null,
          },
        }),
      });

      if (!response.ok) {
        if (response.status === 401) {
          throw new Error("Authorization failed. Please check your token.");
        }
        throw new Error(describeHttpFailure(response.status, await response.text()));
      }

      // A 200 is not a promise of JSON. A proxy, a login redirect or an error
      // page can all answer 200 with HTML, and response.json() throws a parse
      // error naming a character offset — which says nothing about the fact
      // that the backend URL is pointing at the wrong server.
      const raw = await response.text();
      let data: any;
      try {
        data = JSON.parse(raw);
      } catch {
        throw new Error(describeHttpFailure(response.status, raw));
      }
      if (data.success) {
        const totalJobs = queuePayloads.reduce((sum, q) => sum + q.jobs.length, 0);
        if (totalJobs > 0) {
          console.log(`${chalk.yellow("DashMQ:")} ${chalk.green("Synced")} ${chalk.blueBright(queues.length)} queues, ${chalk.blueBright(totalJobs)} jobs`);
        } else {
          console.log(`${chalk.yellow("DashMQ:")} ${chalk.green("Synced")} ${chalk.blueBright(queues.length)} queues`);
        }
      }

      const defaultPrefix = queues.length > 0 ? queues[0].prefix : "bull";

      // 5. Poll for commands and execute them
      if (!this.commandExecutor) {
        this.commandExecutor = new CommandExecutor(this.registry, defaultPrefix);
      }
      await this.commandExecutor.pollAndExecute(this.token, this.backend);

      // 6. Start (or keep) the on-demand RPC loop. It needs the dashboard's id
      // for this connection, which only the sync response can tell us: an API
      // token is account-level, so without an explicit connectionId the backend
      // could hand this connector requests addressed at somebody else's Redis.
      if (typeof data?.connectionId === "string" && data.connectionId) {
        this.connectionId = data.connectionId;
      }
      this.ensureRpcTransport(defaultPrefix);
    } catch (error: any) {
      console.error(chalk.red("[DashMQ] Error:"), error.message);
      throw error;
    }
  }

  /**
   * Bring up the on-demand RPC loop once, and keep its default queue prefix in
   * step with discovery afterwards.
   *
   * The loop is safe to run before the feature is switched on server-side: the
   * poll endpoint answers 204 immediately with a short retry hint while
   * on-demand reads are disabled, which also keeps this connection marked as
   * reachable so enabling the flag takes effect without a restart. Set
   * DASHMQ_RPC=0 to opt out entirely.
   */
  private ensureRpcTransport(defaultPrefix: string) {
    if (process.env.DASHMQ_RPC === "0") return;
    if (!this.connectionId) return;

    if (this.rpcTransport) {
      this.rpcTransport.setDefaultPrefix(defaultPrefix);
      return;
    }

    this.rpcTransport = new RpcTransport({
      token: this.token,
      backend: this.backend,
      connectionId: this.connectionId,
      registry: this.registry,
      redaction: this.redaction,
      defaultPrefix,
    });
    this.rpcTransport.start();

    console.log(
      `${chalk.yellow("DashMQ:")} ${chalk.green("On-demand reads ready")} ${chalk.gray(`(connection ${this.connectionId})`)}`,
    );
  }
}
