// Tests for the redis.info allowlist.
//
// INFO reports host details the dashboard has no business seeing from outside
// the customer's network — executable paths, config files, replication peers.
// parseRedisInfoText is the gate: only allowlisted keys survive, so a new
// Redis version cannot add a leaking key to our responses by existing.
//
//   npm test        (builds, then runs)
//   node --test tests/

const test = require("node:test");
const assert = require("node:assert/strict");

const { parseRedisInfoText } = require("../dist/rpc");

const SAMPLE_INFO = [
  "# Server",
  "redis_version:7.2.4",
  "redis_mode:standalone",
  "os:Linux 5.15.0-generic x86_64",
  "executable:/usr/local/bin/redis-server",
  "config_file:/etc/redis/redis.conf",
  "run_id:6f8a2c9d1e3b4a5f6c7d8e9f0a1b2c3d4e5f6a7b",
  "uptime_in_seconds:86400",
  "",
  "# Clients",
  "connected_clients:12",
  "blocked_clients:0",
  "",
  "# Memory",
  "used_memory:1048576",
  "used_memory_human:1.00M",
  "maxmemory:0",
  "maxmemory_policy:noeviction",
  "",
  "# Replication",
  "master_host:10.0.0.5",
  "master_port:6379",
  "",
  "# Stats",
  "keyspace_hits:1000",
  "keyspace_misses:50",
].join("\r\n");

test("keeps allowlisted keys with their values", () => {
  const info = parseRedisInfoText(SAMPLE_INFO);

  assert.equal(info.redis_version, "7.2.4");
  assert.equal(info.os, "Linux 5.15.0-generic x86_64");
  assert.equal(info.uptime_in_seconds, "86400");
  assert.equal(info.connected_clients, "12");
  assert.equal(info.used_memory, "1048576");
  assert.equal(info.used_memory_human, "1.00M");
  assert.equal(info.maxmemory, "0");
  assert.equal(info.keyspace_hits, "1000");
});

test("drops host-identifying keys INFO reports", () => {
  const info = parseRedisInfoText(SAMPLE_INFO);

  assert.equal("executable" in info, false);
  assert.equal("config_file" in info, false);
  assert.equal("run_id" in info, false);
  assert.equal("master_host" in info, false);
  assert.equal("master_port" in info, false);
});

test("tolerates plain-\\n line endings from rewriting proxies", () => {
  const info = parseRedisInfoText("redis_version:7.0.0\nused_memory:42\n");

  assert.equal(info.redis_version, "7.0.0");
  assert.equal(info.used_memory, "42");
});

test("ignores comments, blanks, and colonless lines", () => {
  const info = parseRedisInfoText("# Memory\n\nnot-a-pair\n:orphan\n");

  assert.deepEqual(info, {});
});

test("values containing colons survive whole", () => {
  const info = parseRedisInfoText("os:Linux 5.15.0:with:colons");

  assert.equal(info.os, "Linux 5.15.0:with:colons");
});
