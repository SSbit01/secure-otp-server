# Secure OTP Server

A template server for generating, encrypting, and verifying OTP (One-Time Password) codes. Ideal for microservices and authentication flows.

## Features

- Generate secure OTP codes with customizable length and format.
- Encrypt OTP data using AES-GCM and store in cookies.
- Validate OTP codes and handle resend/attempt limits.
- Easily customizable validation and sending logic.
- Built with [Hono](https://hono.dev/) for fast, modern HTTP APIs.
- Built on Web Standards. It works on any JavaScript runtime.
- A Dockerfile configured.

## Getting Started

### Install dependencies

Feel free to use any package manager you prefer.

```sh
bun install
```

### Run the server

```sh
bun run bun:dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

## API Endpoints

- `POST /api/otp/create` – Generate and send a new OTP
- `POST /api/otp/resend` – Resend OTP (with cookie)
- `POST /api/otp/verify` – Verify OTP code

## Configuration

Set your OTP encryption key in `.env`:

```env
OTP_KEY="your-32-byte-high-entropy-key"
```

See [`sample.env`](sample.env) for an example.

Also set `NODE_ENV` to `"production"` when deploying an HTTPS server, to enable secure cookies.

## Customization

- OTP generation logic: [`src/lib/custom/otp.ts`](src/lib/custom/otp.ts)
- OTP sending logic: [`src/lib/custom/send.ts`](src/lib/custom/send.ts)
- Input validation: [`src/lib/custom/input.ts`](src/lib/custom/input.ts)
- Final action after verification: [`src/lib/custom/final.ts`](src/lib/custom/final.ts)

## License

Created by [SSbit01](https://ssbit01.github.io).