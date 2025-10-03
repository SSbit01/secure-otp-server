![Logo](/logo.png "Secure OTP Server")

# Secure OTP Server

A template server for generating, encrypting, and verifying One-Time Passwords (OTP). Designed for microservices, modern authentication flows, and serverless environments.

> [!CAUTION]
>
> This server implements several security best practices, but it is not a complete security solution on its own. Additional measures such as DDoS protection, rate limiting, and request throttling are necessary for a production environment. It is recommended to add these externally via a CDN, proxy, or API gateway.
>
> If you discover a vulnerability, please report it by email; the address is located in the `"author"` field of [`package.json`](/package.json).

## Features

- **Secure by Design**: Generates cryptographically secure OTPs and encrypts session data using [AES-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode).
- **Customizable**: Easily adapt logic for OTP generation, credential validation, and OTP delivery (e.g. email, SMS).
- **State-Aware**: Prevents replay attacks by using single-use verification keys, while remaining lightweight.
- **Containerized**: Includes a multi-stage [`Dockerfile`](/Dockerfile) for building a minimal, production-ready image with [Bun](https://bun.com/).
- **High Performance**: Built with [Hono](https://hono.dev/) for fast and efficient routing.
- **Web Standards-Based**: Runs on modern JavaScript runtimes ([Deno](https://deno.com/), [Bun](https://bun.com/), [Cloudflare Workers](https://workers.cloudflare.com/)...).
  - You can run it on [Node.js](https://nodejs.org/), though [Deno](https://deno.com/) and especially [Bun](https://bun.com/) are more recommended. To use [Node.js](https://nodejs.org/), install the [`@hono/node-server`](https://github.com/honojs/node-server?tab=readme-ov-file#usage) adapter and configure it in [`src/index.ts`](/src/index.ts).
  - For additional deployment targets such as [Fastly Compute](https://www.fastly.com/products/edge-compute) or [AWS Lambda](https://aws.amazon.com/lambda), refer to the [Hono documentation](https://hono.dev/docs/getting-started/basic#next-step).

## Architecture

This server uses a hybrid design to provide stateful security without the overhead of a traditional database.

1. When an OTP is created, its metadata (e.g. credential, expiry, attempts) is encrypted into a token using AES-GCM. This token is sent to the client in a secure, `HttpOnly` cookie.
2. The encryption key is not stored directly. Instead, a random, single-use ID is generated and stored on the server, pointing to the key.
3. When the client attempts to verify an OTP, it sends back the encrypted token. The server uses the ID to retrieve the correct key. After each verification attempt, the key and its ID are deleted from the server's key management system (KMS).

This process ensures that each encrypted token can only be used for verification once, effectively preventing replay attacks. By default, the KMS stores keys in memory, but it can be customized in [`src/custom/kms.ts`](/src/custom/kms.ts) to use a persistent store like Redis or KV storage for serverless environments or distributed systems.

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

Create a `.env` file in the root of the project. For production, set `NODE_ENV` to `"production"` to enable secure cookies and specify your frontend's `ORIGIN`.

```env
# .env
NODE_ENV="production"
ORIGIN="https://your-app.com"
```

See [`sample.env`](/sample.env) for all available options.

### 3. Running the Server

You can run the server in development mode with hot-reloading.

```sh
# Using Bun
bun run dev

# Using Deno
deno task dev

# Using Wrangler for Cloudflare Workers
bun run cf:dev
```

## API Reference

For a complete specification, see the [`openapi.json`](/openapi.json) file.

### `POST /api/otp/create`

Generates a new OTP, encrypts the session data, and sends it to the user. This endpoint returns two `HttpOnly` cookies that must be included in subsequent requests.

- **Body**: `application/json`. The schema is defined in [`src/custom/credential.ts`](/src/custom/credential.ts).
- **Logic**: The OTP sending logic is defined in [`src/custom/send.ts`](/src/custom/send.ts).

### `POST /api/otp/resend`

Generates and sends a new OTP for the same session. This endpoint uses the cookies from the `/api/otp/create` request and does not require a request body.

- **Logic**: Resend timing and limits can be configured in [`src/custom/otp.ts`](/src/custom/otp.ts).

### `POST /api/otp/verify`

Verifies an OTP code. Each verification attempt updates the session token.

- **Body**: `application/x-www-form-urlencoded` with an `otp` parameter (e.g. `otp=12345678`).
- **Logic**: After successful verification, a final action is triggered, defined in [`src/custom/final.ts`](/src/custom/final.ts).

## Customization

Key logic is separated into the following modules:

-   [`src/custom/otp.ts`](/src/custom/otp.ts): OTP generation logic (length, characters, expiry).
-   [`src/custom/credential.ts`](/src/custom/credential.ts): Validation schema for the `/api/otp/create` request body.
-   [`src/custom/send.ts`](/src/custom/send.ts): Logic for sending the OTP to the user (e.g. using an email service).
-   [`src/custom/kms.ts`](/src/custom/kms.ts): Storage for single-use encryption keys (defaults to in-memory).
-   [`src/custom/final.ts`](/src/custom/final.ts): Action to perform after successful OTP verification.

Each file contains detailed comments explaining how to modify the code.

### Advanced

You can configure the server's middleware behavior in [`src/setup/index.ts`](/src/setup/index.ts).

Default settings include:

- All other requests return a 404 error with an empty response body.
- Request body size is capped at 100 KiB.

These defaults are fully customizable within the same file.

## Errors

Server error responses follow this structure:

```typescript
{
  "error": string;
  "message": string;
}
```

- `error`: A string representing the error code. You can find all error codes in [`src/lib/error/names.js`](/src/lib/error/names.js).
- `message`: A human-readable description of the error. Static error messages can be changed in [`src/lib/error/static.js`](src/lib/error/static.js).

## Testing

The test suite is written with Bun's built-in test runner.

```sh
bun test
```

## License

This project is [MIT licensed](/LICENSE).

Created by [SSbit01](https://ssbit01.github.io).