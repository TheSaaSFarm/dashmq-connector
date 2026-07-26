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

export const Connect = (
  name: string,
  token: string,
  connection: Connection | ConnectionOptions,
  backend: string = process.env.DASHMQ_BACKEND || "http://localhost:3000",
  opts: {
    queueNames?: string[];
  } = {},
) => {
  return new DashMQClient(name, token, connection, backend, opts);
};
