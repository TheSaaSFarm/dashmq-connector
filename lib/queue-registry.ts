import { Cluster, Redis, RedisOptions } from "ioredis";
import { FoundQueue, QueueType } from "./queue-factory";
import { acquireSharedRedisClient, releaseSharedRedisClient } from "./redis-clients";

// ---------------------------------------------------------------------------
// Multi-version dispatch
//
// Bull v3/v4 and BullMQ v3/v4/v5 do NOT share a key layout or a Lua script set.
// Driving a Bull queue with a BullMQ `Queue` silently does the wrong thing:
// `pause()` writes a BullMQ meta flag instead of renaming the wait list (so
// Bull workers never observe the pause), `retry()` runs the wrong script
// against the wrong keys, and `getJob()` mis-parses the hash.
//
// So each detected {type, majorVersion} is driven by the module that actually
// speaks that protocol. The BullMQ majors are installed side by side under
// npm aliases (see package.json) exactly like taskforce-connector does.
// ---------------------------------------------------------------------------

export type QueueModuleKey = "bull" | "bullmq" | "bullmq-v3" | "bullmq-v4" | "bullmq-v5";

// Loaded lazily: a customer on BullMQ v5 should never pay to require v3 and v4.
const QUEUE_MODULE_LOADERS: Record<QueueModuleKey, () => any> = {
  bull: () => require("bull"),
  bullmq: () => require("bullmq"),
  "bullmq-v3": () => require("bullmq-v3"),
  "bullmq-v4": () => require("bullmq-v4"),
  "bullmq-v5": () => require("bullmq-v5"),
};

const moduleCache = new Map<QueueModuleKey, any>();

function loadQueueModule(moduleKey: QueueModuleKey): any {
  const cached = moduleCache.get(moduleKey);
  if (cached) return cached;
  const loaded = QUEUE_MODULE_LOADERS[moduleKey]();
  moduleCache.set(moduleKey, loaded);
  return loaded;
}

// ---------------------------------------------------------------------------
// Typed errors
// ---------------------------------------------------------------------------

export class UnsupportedQueueTypeError extends Error {
  readonly code = "UNSUPPORTED_QUEUE_TYPE";
  readonly queueType: string;
  readonly majorVersion: number;

  constructor(queueType: string, majorVersion: number, reason: string) {
    super(
      `Unsupported queue type "${queueType}"` +
        (majorVersion > 0 ? ` (major version ${majorVersion})` : "") +
        `: ${reason}`
    );
    this.name = "UnsupportedQueueTypeError";
    this.queueType = queueType;
    this.majorVersion = majorVersion;
    Object.setPrototypeOf(this, UnsupportedQueueTypeError.prototype);
  }
}

export class QueueNotFoundError extends Error {
  readonly code = "QUEUE_NOT_FOUND";
  readonly queueName: string;
  readonly prefix?: string;

  constructor(queueName: string, prefix?: string) {
    super(
      prefix
        ? `Queue "${prefix}:${queueName}" is not registered on this connection`
        : `Queue "${queueName}" is not registered on this connection`
    );
    this.name = "QueueNotFoundError";
    this.queueName = queueName;
    this.prefix = prefix;
    Object.setPrototypeOf(this, QueueNotFoundError.prototype);
  }
}

export class RegistryClosedError extends Error {
  readonly code = "REGISTRY_CLOSED";

  constructor() {
    super("Queue registry has been closed");
    this.name = "RegistryClosedError";
    Object.setPrototypeOf(this, RegistryClosedError.prototype);
  }
}

// ---------------------------------------------------------------------------
// Structural types shared by Bull and every BullMQ major
// ---------------------------------------------------------------------------

export interface ManagedJob {
  readonly id?: string | number | null;
  remove(): Promise<unknown>;
  retry(state?: string): Promise<unknown>;
}

export interface ManagedQueue {
  getJob(jobId: string): Promise<ManagedJob | null | undefined>;
  pause(): Promise<unknown>;
  resume(): Promise<unknown>;
  close(): Promise<unknown>;
}

export interface RegisteredQueue {
  /** `${prefix}:${name}` — the registry cache key. */
  readonly key: string;
  readonly name: string;
  readonly prefix: string;
  readonly type: QueueType;
  readonly majorVersion: number;
  readonly version?: string;
  /** Which npm module actually drives this queue. */
  readonly moduleKey: QueueModuleKey;
  readonly queue: ManagedQueue;
}

export function queueKey(prefix: string, name: string): string {
  return `${prefix}:${name}`;
}

/**
 * Map a detected queue flavour onto the module that speaks its protocol.
 *
 * bull                 -> "bull"
 * bullmq major 3/4/5   -> the matching npm alias
 * bullmq major 0/other -> top-level "bullmq"
 * bullmq-pro           -> unsupported (the Pro package is licensed and is not
 *                         a dependency; driving it with plain BullMQ would
 *                         corrupt group state)
 */
export function selectQueueModule(type: QueueType, majorVersion: number): QueueModuleKey {
  switch (type) {
    case "bull":
      return "bull";
    case "bullmq":
      switch (majorVersion) {
        case 3:
          return "bullmq-v3";
        case 4:
          return "bullmq-v4";
        case 5:
          return "bullmq-v5";
        default:
          // Major 0 (unknown/legacy) and anything newer than what we alias.
          return "bullmq";
      }
    case "bullmq-pro":
      throw new UnsupportedQueueTypeError(
        type,
        majorVersion,
        "BullMQ Pro requires the licensed @taskforcesh/bullmq-pro client, which the connector does not bundle"
      );
    default:
      throw new UnsupportedQueueTypeError(
        String(type),
        majorVersion,
        "no queue client is registered for this queue type"
      );
  }
}

// ---------------------------------------------------------------------------
// QueueRegistry
// ---------------------------------------------------------------------------

export type RegistryConnection = Redis | Cluster | RedisOptions;

function isRedisLike(connection: RegistryConnection): connection is Redis | Cluster {
  return connection instanceof Redis || connection instanceof Cluster;
}

function extractRedisOptions(connection: Redis | Cluster): RedisOptions {
  if (connection instanceof Cluster) {
    const clusterOptions = (connection as unknown as { options?: { redisOptions?: RedisOptions } })
      .options;
    return { ...(clusterOptions?.redisOptions ?? {}) };
  }
  return { ...connection.options };
}

/**
 * Long-lived cache of live queue clients, keyed by `${prefix}:${name}`.
 *
 * Queues are created lazily on first use and then reused for every subsequent
 * operation, so per-page-view RPC traffic costs zero new Redis connections.
 * Redis connections themselves are shared per queue-library flavour: BullMQ
 * namespaces its Lua commands by package version, so v3/v4/v5 can safely share
 * a socket, but Bull and BullMQ get separate ones.
 */
export class QueueRegistry {
  private readonly redisOptions: RedisOptions;
  private readonly sharedInstance?: Redis | Cluster;
  private readonly client: Redis | Cluster;
  private readonly ownsClient: boolean;

  private readonly descriptors = new Map<string, FoundQueue>();
  private readonly queues = new Map<string, RegisteredQueue>();
  private readonly moduleClients = new Map<string, Redis>();
  private readonly auxiliaryClients: Redis[] = [];
  private closed = false;

  constructor(connection: RegistryConnection) {
    if (isRedisLike(connection)) {
      this.sharedInstance = connection;
      this.client = connection;
      this.ownsClient = false;
      this.redisOptions = extractRedisOptions(connection);
    } else {
      this.redisOptions = connection;
      this.client = acquireSharedRedisClient(connection, "registry");
      this.ownsClient = true;
    }
  }

  /** The client used for raw metadata reads (scanning, counts, job hashes). */
  get redis(): Redis | Cluster {
    return this.client;
  }

  get size(): number {
    return this.queues.size;
  }

  /** Every queue the last `refresh()` discovered, whether instantiated or not. */
  known(): FoundQueue[] {
    return Array.from(this.descriptors.values());
  }

  /** Every queue currently holding a live client. */
  list(): RegisteredQueue[] {
    return Array.from(this.queues.values());
  }

  describe(prefix: string, name: string): FoundQueue | undefined {
    return this.descriptors.get(queueKey(prefix, name));
  }

  has(prefix: string, name: string): boolean {
    return this.descriptors.has(queueKey(prefix, name));
  }

  /**
   * Get (creating on demand) the client for a discovered queue.
   * @throws QueueNotFoundError when the queue was never discovered.
   * @throws UnsupportedQueueTypeError when its flavour cannot be driven.
   */
  get(prefix: string, name: string): RegisteredQueue {
    const descriptor = this.descriptors.get(queueKey(prefix, name));
    if (!descriptor) throw new QueueNotFoundError(name, prefix);
    return this.resolve(descriptor);
  }

  /**
   * Look a queue up by bare name, preferring `preferredPrefix` when the same
   * name exists under several prefixes. Commands from the dashboard carry only
   * the queue name, so this is the path they use.
   */
  getByName(name: string, preferredPrefix?: string): RegisteredQueue {
    if (preferredPrefix) {
      const exact = this.descriptors.get(queueKey(preferredPrefix, name));
      if (exact) return this.resolve(exact);
    }

    const matches = Array.from(this.descriptors.values()).filter((q) => q.name === name);
    if (matches.length === 0) throw new QueueNotFoundError(name, preferredPrefix);
    return this.resolve(matches[0]);
  }

  /** Instantiate (or return the cached client for) a specific descriptor. */
  resolve(descriptor: FoundQueue): RegisteredQueue {
    if (this.closed) throw new RegistryClosedError();

    const key = queueKey(descriptor.prefix, descriptor.name);
    const cached = this.queues.get(key);
    if (
      cached &&
      cached.type === descriptor.type &&
      cached.majorVersion === descriptor.majorVersion
    ) {
      return cached;
    }

    const moduleKey = selectQueueModule(descriptor.type, descriptor.majorVersion);
    const queue = this.createQueue(moduleKey, descriptor.name, descriptor.prefix);
    const registered: RegisteredQueue = {
      key,
      name: descriptor.name,
      prefix: descriptor.prefix,
      type: descriptor.type,
      majorVersion: descriptor.majorVersion,
      version: descriptor.version,
      moduleKey,
      queue,
    };

    this.queues.set(key, registered);
    this.descriptors.set(key, descriptor);
    return registered;
  }

  /**
   * Reconcile the registry against a fresh discovery pass: record the new
   * descriptors, drop queues that disappeared, and rebuild any queue whose
   * detected flavour changed (a redeploy can migrate Bull -> BullMQ in place).
   */
  async refresh(discovered: FoundQueue[]): Promise<void> {
    if (this.closed) throw new RegistryClosedError();

    const seen = new Set<string>();
    const stale: RegisteredQueue[] = [];

    for (const descriptor of discovered) {
      const key = queueKey(descriptor.prefix, descriptor.name);
      seen.add(key);
      this.descriptors.set(key, descriptor);

      const registered = this.queues.get(key);
      if (
        registered &&
        (registered.type !== descriptor.type ||
          registered.majorVersion !== descriptor.majorVersion)
      ) {
        this.queues.delete(key);
        stale.push(registered);
      }
    }

    for (const key of Array.from(this.descriptors.keys())) {
      if (seen.has(key)) continue;
      this.descriptors.delete(key);
      const registered = this.queues.get(key);
      if (registered) {
        this.queues.delete(key);
        stale.push(registered);
      }
    }

    for (const registered of stale) {
      await closeQueueQuietly(registered.queue);
    }
  }

  /** Close every queue client and release every connection this registry owns. */
  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;

    const registered = Array.from(this.queues.values());
    this.queues.clear();
    this.descriptors.clear();

    for (const entry of registered) {
      await closeQueueQuietly(entry.queue);
    }

    for (const client of this.moduleClients.values()) {
      await releaseSharedRedisClient(client);
    }
    this.moduleClients.clear();

    for (const client of this.auxiliaryClients.splice(0)) {
      await releaseSharedRedisClient(client);
    }

    if (this.ownsClient) {
      await releaseSharedRedisClient(this.client as Redis);
    }
  }

  // -------------------------------------------------------------------------
  // Internals
  // -------------------------------------------------------------------------

  private createQueue(
    moduleKey: QueueModuleKey,
    name: string,
    prefix: string
  ): ManagedQueue {
    const connection = this.connectionFor(moduleKey);

    if (moduleKey === "bull") {
      const Bull = loadQueueModule(moduleKey);
      const redisOpts = { ...this.redisOptions };
      // Bull derives its key prefix from `redis.keyPrefix` first; we always
      // want the prefix we actually discovered the queue under.
      delete redisOpts.keyPrefix;

      return new Bull(name, {
        prefix,
        redis: redisOpts,
        // Supplying createClient makes Bull treat every connection as
        // externally owned: it never pushes them onto queue.clients and so
        // never disconnects them in close(). We manage their lifetime instead.
        createClient: (type: string) => {
          if (type === "client") return connection;
          return this.auxiliaryClient(type);
        },
      }) as ManagedQueue;
    }

    const { Queue } = loadQueueModule(moduleKey);
    return new Queue(name, { connection, prefix }) as ManagedQueue;
  }

  /**
   * One connection per queue-library flavour. When the caller handed us a live
   * ioredis instance we reuse it for everything — BullMQ namespaces its Lua
   * command names by package version, so multiple majors can share a socket.
   */
  private connectionFor(moduleKey: QueueModuleKey): Redis | Cluster {
    if (this.sharedInstance) return this.sharedInstance;

    const namespace = moduleKey === "bull" ? "bull" : "bullmq";
    const cached = this.moduleClients.get(namespace);
    if (cached) return cached;

    const client = acquireSharedRedisClient(this.redisOptions, namespace);
    this.moduleClients.set(namespace, client);
    return client;
  }

  /**
   * Bull's subscriber/bclient connections must have ready checks and request
   * retries disabled. We never process jobs, so these are only ever created if
   * Bull asks for them; they are still tracked so close() can release them.
   */
  private auxiliaryClient(type: string): Redis {
    const client = acquireSharedRedisClient(
      {
        ...this.redisOptions,
        keyPrefix: undefined,
        enableReadyCheck: false,
        maxRetriesPerRequest: null,
      },
      `bull-${type}`
    );
    this.auxiliaryClients.push(client);
    return client;
  }
}

async function closeQueueQuietly(queue: ManagedQueue): Promise<void> {
  try {
    await queue.close();
  } catch {
    // A queue whose Redis link already dropped cannot be closed cleanly, and
    // there is nothing useful left to do about it.
  }
}
