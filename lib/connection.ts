import { Redis, Cluster, RedisOptions } from "ioredis";
import * as url from "url";

export type Connection = RedisOptions | Redis | Cluster;

export interface ConnectionOptions {
  port?: number;
  host?: string;
  password?: string;
  username?: string;
  db?: number;
  uri?: string;
  tls?: object;
}

export function isRedisInstance(connection: Connection): connection is Redis | Cluster {
  return connection instanceof Redis || connection instanceof Cluster;
}

export function redisOptsFromUrl(urlString: string): RedisOptions {
  const redisOpts: RedisOptions = {};
  try {
    const redisUrl = url.parse(urlString);
    redisOpts.port = parseInt(redisUrl.port || "6379", 10);
    redisOpts.host = redisUrl.hostname || "localhost";
    redisOpts.db = redisUrl.pathname
      ? parseInt(urlString.split("/")[1] || "0", 10)
      : 0;
    if (redisUrl.auth) {
      const parts = redisUrl.auth.split(":");
      redisOpts.username = parts[0] || undefined;
      redisOpts.password = parts[1] || undefined;
    }
  } catch (e: any) {
    throw new Error(e.message);
  }
  return redisOpts;
}

export function redisOptsFromConnection(connection: ConnectionOptions): RedisOptions {
  let opts: RedisOptions = {
    host: connection.host || "localhost",
    port: connection.port || 6379,
    db: connection.db || 0,
    username: connection.username,
    password: connection.password,
  };

  if (connection.uri) {
    opts = { ...opts, ...redisOptsFromUrl(connection.uri) };
  }

  if (connection.tls) {
    opts.tls = connection.tls as any;
  }

  opts.retryStrategy = function (times: number) {
    const delay = Math.min(times * 50, 2000);
    return delay;
  };

  return opts;
}
