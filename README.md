# kv-auth-synchroniser

**Asymmetric service-to-service authentication for Cloudflare Workers.**

Uses Ed25519 keypairs and a shared KV namespace as the public key registry. No shared secrets, no symmetric keys — each service authenticates independently.

## How it works

```
┌─────────────┐     Sign(method, path, bodyHash, timestamp)     ┌──────────────┐
│  Service A  │ ─────────────────────────────────────────────→ │  Service B   │
│  (caller)   │   X-Toldby-Signature, X-Toldby-Caller,          │  (receiver)  │
│             │   X-Toldby-Timestamp, X-Toldby-Auth             │              │
└─────────────┘                                                 └──────┬───────┘
                                                                       │
                                                                  ┌────▼───────┐
                                                                  │  KV Store  │
                                                                  │  pubkeys/  │
                                                                  │  service-a │←── fetch A's public key
                                                                  └────────────┘
```

1. **Each service** generates an Ed25519 keypair and publishes its public key to a shared KV namespace under `pubkeys/{serviceName}`.
2. **Service A** signs the request (method + path + timestamp + caller + userEmail + SHA-256(body)) with its private key.
3. **Service B** receives the request, extracts the caller identity from `X-Toldby-Caller`, fetches A's public key from KV, and verifies the signature.

> **Note:** The "path" includes the full query string (e.g., `/api/data?debug=true`). Both the caller identity and the optional user email are part of the signed payload to prevent tampering.

## Installation

```bash
npm install kv-auth-synchroniser
```

## Setup

### 1. Generate a keypair for your service

```bash
node -e "
const { generateKeypair } = require('kv-auth-synchroniser');
generateKeypair().then(kp => {
  console.log('Private key (save as SECRET):', kp.privateKey);
  console.log('Public key raw:', kp.publicKey.raw);
  console.log('Public key spki:', kp.publicKey.spki);
});
"
```

Save the private key as a Cloudflare Workers secret:
```bash
npx wrangler secret put SERVICE_PRIVATE_KEY
```

### 2. Configure a shared KV namespace

All services in your trust domain must have a binding to the same KV namespace:

```jsonc
// wrangler.jsonc
{
  "kv_namespaces": [
    {
      "binding": "PUBKEY_REGISTRY",
      "id": "your-kv-namespace-id"
    }
  ]
}
```

### 3. Initialise the auth utility

```typescript
import { KVAuth } from "kv-auth-synchroniser";

const auth = new KVAuth({
  privateKey: env.SERVICE_PRIVATE_KEY,
  serviceName: "my-service",
  kv: env.PUBKEY_REGISTRY,
});

// On startup / deploy
await auth.init();
await auth.publishPublicKey();
```

## Usage

### Signing outgoing requests

```typescript
const headers = await auth.signRequest("POST", "/api/data", {
  body: JSON.stringify({ hello: "world" }),
  userEmail: "admin@example.com", // optional
});

await fetch("https://target-worker/api/data", { method: "POST", headers });
```

### Verifying incoming requests

```typescript
const result = await auth.verifyRequest(request);
if (!result.valid) {
  return new Response("Forbidden", { status: 403 });
}
console.log(`Caller: ${result.caller}, User: ${result.userEmail}`);
```

### Functional API (no class)

```typescript
import {
  generateKeypair,
  signRequest,
  verifyRequest,
  verifyIncomingRequest,
  publishPublicKey,
  fetchPublicKey,
} from "kv-auth-synchroniser";

const kp = await generateKeypair();
const { signature, timestamp } = await signRequest(kp.privateKey, "GET", "/api/test?foo=bar", {
  caller: "my-service"
});

const valid = await verifyRequest(kp.publicKey.spki, "GET", "/api/test?foo=bar", timestamp, signature, {
  caller: "my-service"
});
```

## API

### `KVAuth` class

| Method | Description |
|--------|-------------|
| `init()` | Import the private key and extract the public key |
| `publishPublicKey()` | Store the public key in KV under `pubkeys/{serviceName}` |
| `getPublicKey(serviceName)` | Fetch another service's public key from KV |
| `signRequest(method, path, opts?)` | Sign a request, returns headers |
| `verifyRequest(request)` | Verify an incoming request's signature |

### Functional API

| Function | Description |
|----------|-------------|
| `generateKeypair()` | Generate a new Ed25519 keypair |
| `signRequest(privateKey, method, path, opts?)` | Sign a request payload |
| `verifyRequest(publicKeySpki, method, path, timestamp, signature, opts?)` | Verify a signature |
| `publishPublicKey(kv, serviceName, spki, raw)` | Publish a public key to KV |
| `fetchPublicKey(kv, serviceName)` | Fetch a public key from KV |
| `verifyIncomingRequest(request, kv)` | Verify an incoming request using KV |

### Request headers

| Header | Value | Purpose |
|--------|-------|---------|
| `X-Toldby-Signature` | base64(Ed25519 signature) | Proof of authenticity |
| `X-Toldby-Caller` | `service-a` (service name) | Identity of the caller (signed) |
| `X-Toldby-Timestamp` | Unix ms timestamp | Prevents replay attacks (5 min window) |
| `X-Toldby-Auth` | `admin@example.com` | Authenticated user email (optional, signed) |

## Security

- **No shared secrets**: Each service has its own private key. Compromise of one service does not affect others.
- **Replay protection**: Timestamps are checked against a 5-minute window.
- **Body integrity**: Request body is SHA-256 hashed and included in the signature.
- **Identity protection**: Both the caller service name and the user email are included in the signed payload, preventing header tampering.
- **Query parameter protection**: The full request path, including query strings, is signed.
- **KV as trust anchor**: Only services with write access to the shared KV can publish public keys.

## License

MIT
