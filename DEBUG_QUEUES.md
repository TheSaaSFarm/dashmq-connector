# Debugging: Why 0 Queues Found?

If the connector is syncing but finding 0 queues, here are things to check:

## 1. Check if Redis has any queues

Connect to your Redis instance and check for queue keys:

```bash
# Connect to Redis
redis-cli

# List all keys matching queue pattern
KEYS "*:*:id"

# Or scan for queues (safer for large databases)
SCAN 0 MATCH "*:*:id" COUNT 100
```

## 2. Queue Key Format

The connector looks for keys matching the pattern: `prefix:queueName:id`

Examples:

- `bull:my-queue:id` (Bull v4)
- `bullmq:my-queue:id` (BullMQ v5)
- `my-prefix:my-queue:id` (custom prefix)

## 3. Create Test Queues

If you don't have any queues, create some test queues:

### Using BullMQ:

```javascript
const { Queue } = require("bullmq");
const Redis = require("ioredis");

const redis = new Redis({
  host: "localhost",
  port: 6379,
});

// Create a test queue
const testQueue = new Queue("test-queue", { connection: redis });

// Add a test job
await testQueue.add("test-job", { data: "test" });

console.log("Test queue created!");
```

### Using Bull:

```javascript
const Queue = require("bull");
const redis = require("ioredis");

const testQueue = new Queue("test-queue", {
  redis: {
    host: "localhost",
    port: 6379,
  },
});

// Add a test job
await testQueue.add({ data: "test" });

console.log("Test queue created!");
```

## 4. Check Connector Logs

The connector should show:

- `DashMQ: Synced X queues` where X > 0

If it shows `Synced 0 queues`, Redis either:

- Has no queues
- Queues don't match the expected pattern
- Connector is connecting to wrong Redis instance

## 5. Verify Redis Connection

Make sure the connector is connecting to the correct Redis:

```bash
# Check what Redis the connector is using
# Default: localhost:6379

# If using custom connection:
dashmq -n "Test" -t YOUR_TOKEN -h YOUR_HOST -p YOUR_PORT
```

## 6. Check Database Number

If your queues are in a different Redis database (not 0):

```bash
dashmq -n "Test" -t YOUR_TOKEN -d 1  # Use database 1
```

## 7. Check Queue Prefix

If your queues use a custom prefix (not "bull" or "bullmq"):

```bash
# The connector should auto-detect, but you can verify:
redis-cli KEYS "*:*:id"
```

Look for the pattern and verify the prefix matches what the connector expects.
