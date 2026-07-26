# Testing DashMQ Connector

## Step 1: Generate an API Token

1. Start your DashMQ app: `cd ../dashmq && pnpm dev`
2. Open http://localhost:3000
3. Log in with your account
4. Go to **Account Settings → API Tokens** (or click your avatar → API Tokens)
5. Click **"Create Token"**
6. Enter a name (e.g., "Local Dev Token")
7. **Copy the token immediately** - you won't see it again!

## Step 2: Set Up Test Redis with Queues

**Important:** The connector needs queues in your Redis to sync. If you see "Synced 0 queues", your Redis instance doesn't have any queues yet.

### Option A: Use Existing Redis with Test Queues

If you already have a Redis instance with Bull/BullMQ queues, skip to Step 3.

### Option B: Create Test Queues

Create a simple test script to add some test queues:

```bash
# Create test-queues.js
cat > test-queues.js << 'EOF'
const { Queue } = require('bullmq');
const Redis = require('ioredis');

const redis = new Redis({
  host: 'localhost',
  port: 6379,
  // password: 'your-password', // if needed
});

// Create a test queue
const testQueue = new Queue('test-queue', { connection: redis });

// Add some test jobs
async function addTestJobs() {
  await testQueue.add('job-1', { data: 'test data 1' });
  await testQueue.add('job-2', { data: 'test data 2' });
  await testQueue.add('job-3', { data: 'test data 3' });
  console.log('Added 3 test jobs to test-queue');

  // Create another queue
  const anotherQueue = new Queue('another-queue', { connection: redis });
  await anotherQueue.add('job-a', { data: 'data a' });
  await anotherQueue.add('job-b', { data: 'data b' });
  console.log('Added 2 test jobs to another-queue');

  console.log('\n✅ Test queues created!');
  console.log('Queues: test-queue, another-queue');
  process.exit(0);
}

addTestJobs().catch(console.error);
EOF

# Run it
node test-queues.js
```

## Step 3: Build and Install the Connector

```bash
cd /Users/bouchentoufgary/Documents/thesaasfarm/dashmq-connector

# Install dependencies
npm install

# Build TypeScript
npm run build

# Install globally (optional, for CLI usage)
npm link
# OR just use: node dist/cmd.js directly
```

## Step 4: Run the Connector

### Basic Usage (Local Redis, default port 6379):

```bash
# Using pnpm link (if you ran pnpm link)
dashmq -n "My Local Test" -t dashmq_YOUR_TOKEN_HERE

# OR using node directly
node dist/cmd.js -n "My Local Test" -t dashmq_YOUR_TOKEN_HERE
```

### With Custom Redis Settings:

```bash
node dist/cmd.js \
  -n "My Test Connection" \
  -t dashmq_YOUR_TOKEN_HERE \
  -h localhost \
  -p 6379 \
  -b http://localhost:3000
```

### Using Environment Variables:

```bash
export DASHMQ_TOKEN=dashmq_YOUR_TOKEN_HERE
export REDIS_HOST=localhost
export REDIS_PORT=6379
export DASHMQ_BACKEND=http://localhost:3000

node dist/cmd.js -n "My Connection"
```

## Step 5: Verify It's Working

1. **Check connector output** - You should see:

   ```
   DashMQ: Connected and syncing queues every 5 seconds
   DashMQ: Synced 2 queues
   ```

2. **Check DashMQ Dashboard**:
   - Open http://localhost:3000/dashboard
   - You should see your connection appear
   - The queues should be visible

3. **Check API logs** - In your DashMQ server logs, you should see:
   ```
   [Connector] Sync from My Test Connection: 2 queues (v1.0.0)
   ```

## Troubleshooting

### "Invalid token" error

- Make sure you copied the full token (including `dashmq_` prefix)
- Verify the token in DashMQ dashboard (check if it exists)

### "No active Redis connection found"

- Make sure you have a Redis connection configured in your workspace
- The token's workspace must have an active Redis connection

### "Cannot find queues"

- Make sure Redis is running: `redis-cli ping` (should return PONG)
- Verify queues exist: `redis-cli KEYS "*:*:id"`
- Check if queues use "bull" or "bullmq" prefix

### Connection refused

- Check Redis is running: `redis-cli ping`
- Verify host/port are correct
- Check firewall/network settings

## Testing with Different Queue Types

### BullMQ v5 (default):

```bash
# Queues will be detected automatically
node dist/cmd.js -n "BullMQ Test" -t dashmq_YOUR_TOKEN
```

### Bull (v4):

```bash
# Also detected automatically
node dist/cmd.js -n "Bull Test" -t dashmq_YOUR_TOKEN
```

### Specific Queues Only:

```bash
node dist/cmd.js \
  -n "Specific Queues" \
  -t dashmq_YOUR_TOKEN \
  --queues "queue1,queue2,queue3"
```

## Quick Test Script

Create `test-connector.sh`:

```bash
#!/bin/bash

# Set your token here
TOKEN="dashmq_YOUR_TOKEN_HERE"

echo "🚀 Starting DashMQ Connector..."
echo "Token: ${TOKEN:0:20}..."

cd /Users/bouchentoufgary/Documents/thesaasfarm/dashmq-connector

node dist/cmd.js \
  -n "Local Test $(date +%H:%M:%S)" \
  -t "$TOKEN" \
  -h localhost \
  -p 6379 \
  -b http://localhost:3000
```

Make it executable and run:

```bash
chmod +x test-connector.sh
./test-connector.sh
```
