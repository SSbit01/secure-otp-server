# Secure OTP Server

![Logo](/logo.png "Secure OTP Server")

A template server for generating, encrypting, and verifying One-Time Passwords (OTP).
Designed for microservices, modern authentication flows, and serverless environments.

> [!CAUTION]
>
> This server implements several security best practices, but it is not a complete security solution on its own.
> Additional measures such as DDoS protection, rate limiting, and request throttling are necessary for a production environment.
> It is recommended to add these externally via a CDN, proxy, or API gateway.
>
> If you discover a vulnerability, please read the [Security Policy](./SECURITY.md).

## Features

### Secure by Design

Generates cryptographically secure OTPs and encrypts session data using envelope encryption with [AES-KW](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/wrapKey#aes-kw) (KEK) and [AES-256-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode) (DEK),
which is extremely fast on modern CPUs because they have dedicated hardware acceleration ([AES-NI](https://en.wikipedia.org/wiki/AES_instruction_set)),
in addition to being quantum-resistant.

### Customizable

Easily adapt logic for OTP generation, credential validation, and OTP delivery (e.g. email, SMS).

### State-Aware

Prevents replay attacks by using single-use verification keys, while remaining lightweight.

### Multi-Credential Sessions

Store several OTP tokens per session, each bound to a different credential.
Users can move between credentials without restarting the flow, and the session-encrypted cookie enforces a strict cap so tokens stay lightweight.

### High Performance

Built with [Hono](https://hono.dev/) for fast and efficient routing.

### Web Standards-Based

Runs on modern JavaScript runtimes ([Deno](https://deno.com/), [Bun](https://bun.com/), [Cloudflare Workers](https://workers.cloudflare.com/)...).

You can run it on [Node.js](https://nodejs.org/) (>=25), though [Deno](https://deno.com/) and especially [Bun](https://bun.com/) are more recommended.
To use [Node.js](https://nodejs.org/), install the [`@hono/node-server`](https://github.com/honojs/node-server?tab=readme-ov-file#usage) adapter and configure it in [`src/index.ts`](/src/index.ts).

For additional deployment targets such as [Fastly Compute](https://www.fastly.com/products/edge-compute) or [AWS Lambda](https://aws.amazon.com/lambda), refer to the [Hono documentation](https://hono.dev/docs/getting-started/basic#next-step).

## Architecture

This server uses a hybrid design to provide stateful security without the overhead of a storage system.

1. When an OTP is created, its metadata (e.g. credential, expiry, attempts) is compressed and appended to an encrypted list of tokens (one entry per credential) using envelope encryption with AES-KW (KEK) and AES-256-GCM (DEK). The list is sent to the client in a secure, `HttpOnly` cookie.
2. A random ID linked to the list is generated and stored on the server.
3. When the client attempts to verify an OTP, it sends back the encrypted list. The server selects the current credential's token, and after each verification attempt updates its ID.
4. The encrypted cookie stores at most `OTP_MAX_CREDENTIALS` entries, so users can switch between multiple credentials without restarting the flow while keeping the session footprint small.

This process ensures that each encrypted token can only be used for verification once, effectively preventing replay attacks.
By default, the KMS stores key encryption keys (KEKs) in memory, but it can be customized in [`src/custom/kms.ts`](/src/custom/kms.ts) to use a persistent store like Redis or KV storage for serverless environments or distributed systems.

## Getting Started

### 1. Installation

Clone the repository and install dependencies using your preferred package manager.

```sh
# Using Bun
bun install

# Using Deno
deno task install
```

### 2. Configuration

Create a `.env` file in the root of the project. For production, set `NODE_ENV` to `"production"` to enable secure cookies and specify your frontend's origin with `CORS_ORIGIN`.

```env
# .env
NODE_ENV="production"
CORS_ORIGIN="https://your-app.com"
```

See [`sample.env`](/sample.env).

### 3. Running the Server

You can run the server in development mode.

```sh
# Using Bun
bun run bun:dev

# Using Deno
deno task deno:dev
```

## API Reference

For a complete specification, see the [`openapi.json`](/openapi.json) file.

### `POST /api/otp/create`

Generates a new OTP, encrypts the session data, and sends it to the user. This endpoint returns two `HttpOnly` cookies that must be included in subsequent requests.

- **Body**: `application/json`. The schema is defined in [`src/custom/credential.ts`](/src/custom/credential.ts).
- **Logic**: The OTP sending logic is defined in [`src/custom/send.ts`](/src/custom/send.ts).
- **Multi-credential flow**: Sending this request again with a different credential adds another OTP token (until `OTP_MAX_CREDENTIALS` is reached).

### `POST /api/otp/resend`

Generates and sends a new OTP for the current token. This endpoint uses the cookies from the `/api/otp/create` request and does not require a request body.

- **Logic**: Resend timing and limits can be configured in [`src/custom/otp.ts`](/src/custom/otp.ts).

### `POST /api/otp/verify`

Verifies an OTP code. Each verification attempt updates the session token.

- **Body**: `application/x-www-form-urlencoded` with an `otp` parameter (e.g. `otp=12345678`).
- **Logic**: After successful verification, a final action is triggered, defined in [`src/custom/final.ts`](/src/custom/final.ts).

## Customization

Key logic is separated into the following modules:

- [`src/custom/otp.ts`](/src/custom/otp.ts): OTP generation logic (length, characters, expiry), resend delays, and the `OTP_MAX_CREDENTIALS` cap that governs multi-credential sessions.
- [`src/custom/credential.ts`](/src/custom/credential.ts): Validation schema for the `/api/otp/create` request body.
- [`src/custom/send.ts`](/src/custom/send.ts): Logic for sending the OTP to the user (e.g. using an email service).
- [`src/custom/id.ts`](/src/custom/id.ts): Storage for OTP token list IDs (defaults to in-memory).
- [`src/custom/kms.ts`](/src/custom/kms.ts): Storage for encryption key encryptions keys (KEKs; defaults to in-memory).
- [`src/custom/final.ts`](/src/custom/final.ts): Action to perform after successful OTP verification.

Each file contains detailed comments explaining how to modify the code.

### Advanced

You can configure the server's middleware and CORS behavior in [`src/setup/index.ts`](/src/setup/index.ts).

Default settings include:

- All other requests return a 404 error with an empty response body.
- Request body size is capped at 100 KiB.

These defaults are fully customizable within the same file.

## Errors

Server error responses follow this structure:

```typescript
{
  error: string;
  message?: string;
}
```

- `error`: A string representing the error code. You can find all error codes in [`src/lib/error/names.js`](/src/lib/error/names.js).
- `message`: A human-readable description of the error. Static error messages can be changed in [`src/lib/error/static.js`](src/lib/error/static.js).

## Testing

The test suite is written with Bun's built-in test runner. Use `bun run bun:test` to run the tests.

---

This project is [MIT licensed](/LICENSE).

Originally created by [SSbit01](https://ssbit01.github.io).