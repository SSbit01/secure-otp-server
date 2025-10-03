# Secure OTP Server

A template server for generating, encrypting, and verifying One-Time Passwords (OTP). Designed for microservices, modern authentication flows, and serverless environments.

> [!CAUTION]
> This server implements several security best practices, but it is not a complete security solution on its own. Additional measures such as DDoS protection, rate limiting, and request throttling are necessary for a production environment. It is recommended to add these externally via a CDN, proxy, or API gateway.
>
> If you discover a vulnerability, please report it by email; the address is located in the `"author"` field of `package.json`.

## Features

- **Web Standards-Based**: Built on the Fetch API, it runs in any modern JavaScript runtime (Node.js, Deno, Bun) and serverless environments.
- **Secure by Design**: Generates cryptographically secure OTPs and encrypts session data using AES-GCM.
- **Customizable**: Easily adapt logic for OTP generation, credential validation, and OTP delivery (e.g., email, SMS).
- **State-Aware**: Prevents replay attacks by using single-use verification keys, while remaining lightweight.
- **High Performance**: Built with [Hono](https://hono.dev/) for fast and efficient routing.
- **Containerized**: Includes a multi-stage `Dockerfile` for building a minimal, production-ready image with Bun.

## Architecture

This server uses a hybrid design to provide stateful security without the overhead of a traditional database.

1.  When an OTP is created, its metadata (e.g., credential, expiry, attempts) is encrypted into a token using AES-GCM. This token is sent to the client in a secure, `HttpOnly` cookie.
2.  The encryption key is not stored directly. Instead, a random, single-use ID is generated and stored on the server, pointing to the key.
3.  When the client attempts to verify an OTP, it sends back the encrypted token. The server uses the ID to retrieve the correct key. After each verification, the key and its ID are immediately deleted from the server's key management system (KMS).

This process ensures that each encrypted token can only be used for verification once, effectively preventing replay attacks. By default, the KMS stores keys in memory, but it can be customized in `src/custom/kms.ts` to use a persistent store like Redis or KV storage for serverless environments.

## Getting Started

### Prerequisites

- [Bun](https://bun.sh/) or [Deno](https://deno.land/)

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

See `sample.env` for all available options.

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

For a complete specification, see the `openapi.json` file.

### `POST /api/otp/create`

Generates a new OTP, encrypts the session data, and sends it to the user. This endpoint returns two `HttpOnly` cookies (`__Host-otp-token` and `__Host-otp-id`) that must be included in subsequent requests.

-   **Body**: `application/json`. The schema is defined in `src/custom/credential.ts`.
-   **Logic**: The OTP sending logic is defined in `src/custom/send.ts`.

### `POST /api/otp/resend`

Generates and sends a new OTP for the same session. This endpoint uses the cookies from the `/create` request and does not require a request body.

-   **Logic**: Resend timing and limits can be configured in `src/custom/otp.ts`.

### `POST /apiotp/verify`

Verifies an OTP code. Each verification attempt updates the session token.

-   **Body**: `application/x-www-form-urlencoded` with an `otp` parameter (e.g., `otp=123456`).
-   **Logic**: After successful verification, a final action is triggered, defined in `src/custom/final.ts`.

## Customization

This template is designed to be easily extended. Key logic is separated into the following modules:

-   `src/custom/otp.ts`: OTP generation logic (length, characters, expiry).
-   `src/custom/credential.ts`: Validation schema for the `/create` request body.
-   `src/custom/send.ts`: Logic for sending the OTP to the user (e.g., using an email service).
-   `src/custom/kms.ts`: Storage for single-use encryption keys (defaults to in-memory).
-   `src/custom/final.ts`: Action to perform after successful OTP verification.

Each file contains detailed comments explaining the available options and how to modify the code.

## Testing

The test suite is written with Bun's built-in test runner.

```sh
bun test
```

## License

This project is [MIT licensed](LICENSE).

Created by [SSbit01](https://ssbit01.github.io).