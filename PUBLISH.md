# Publishing DashMQ Connector

## Option 1: Publish to npm (Recommended for public use)

Once you're ready to publish:

```bash
cd /Users/bouchentoufgary/Documents/thesaasfarm/dashmq-connector

# Build first
npm run build

# Login to npm (if not already)
npm login

# Publish
npm publish
```

After publishing, other projects can install it:

```bash
npm install dashmq-connector
# or
yarn add dashmq-connector
# or
pnpm add dashmq-connector
```

## Option 2: Install from Git (For private repos or before publishing)

If the repo is on GitHub (public or private), other projects can install directly:

```bash
# Public repo
npm install git+https://github.com/yourusername/dashmq-connector.git

# Private repo (requires auth)
npm install git+https://github.com/yourusername/dashmq-connector.git#main
```

Or in `package.json`:

```json
{
  "dependencies": {
    "dashmq-connector": "git+https://github.com/yourusername/dashmq-connector.git"
  }
}
```

## Option 3: Install from Local Path (For development)

For local development in other projects:

```bash
# In your other project
npm install ../dashmq-connector
# or
pnpm add ../dashmq-connector
```

Or in `package.json`:

```json
{
  "dependencies": {
    "dashmq-connector": "file:../dashmq-connector"
  }
}
```

## Usage in Other Projects

After installing, use it in your project:

### As CLI:

```bash
npx dashmq -n "My Connection" -t YOUR_TOKEN
```

### As Library:

```javascript
const { Connect } = require("dashmq-connector");
// or
import { Connect } from "dashmq-connector";

const connection = Connect("My Connection", "your-token", {
  host: "localhost",
  port: 6379,
});

connection.start();
```

## Current Status

- ✅ Package structure is ready
- ✅ CLI command works (`dashmq`)
- ✅ Can be used as library
- ⏳ Not yet published to npm
- ⏳ Repository URL needs to be updated in package.json
