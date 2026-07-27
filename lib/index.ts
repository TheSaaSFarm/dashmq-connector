import { Connection, ConnectionOptions } from "./connection";
import { DashMQClient } from "./client";

export { Connection, ConnectionOptions } from "./connection";
export {
  FoundQueue,
  QueueType,
  QueueTypeInfo,
  getQueueType,
  parseQueueMetaVersion,
  parseMajorVersion,
} from "./queue-factory";
export { JobData, QueuePayload, QueueCounts } from "./scanner";
export {
  QueueRegistry,
  QueueModuleKey,
  RegistryConnection,
  RegisteredQueue,
  ManagedQueue,
  ManagedJob,
  UnsupportedQueueTypeError,
  QueueNotFoundError,
  RegistryClosedError,
  selectQueueModule,
  queueKey,
} from "./queue-registry";
export {
  acquireSharedRedisClient,
  releaseSharedRedisClient,
  closeAllSharedRedisClients,
  sharedRedisClientCount,
  hashRedisOptions,
} from "./redis-clients";
export {
  RedactionEngine,
  RedactedJob,
  RedactionSidecar,
  CompiledPolicy,
  compilePolicy,
  compilePattern,
  parsePathPattern,
  matchPath,
} from "./redaction";
export {
  RedactionConfigError,
  RedactionMode,
  RedactionStrategy,
  DetectorName,
  NormalizedRule,
  NormalizedRedactionConfig,
  LoadedRedactionConfig,
  loadRedactionConfig,
  normalizeRedactionConfig,
  computePolicyId,
  defaultRule,
  absentConfig,
  readOrCreateLocalSalt,
  defaultSaltPath,
  REDACTION_MODES,
  REDACTION_STRATEGIES,
  DETECTOR_NAMES,
  REDACTION_CONFIG_VERSION,
} from "./redaction-config";

export const Connect = (
  name: string,
  token: string,
  connection: Connection | ConnectionOptions,
  backend: string = process.env.DASHMQ_BACKEND || "http://localhost:3000",
  opts: {
    queueNames?: string[];
    /** Explicit redaction policy path; overrides the resolution order. */
    configPath?: string | null;
  } = {},
) => {
  return new DashMQClient(name, token, connection, backend, opts);
};
