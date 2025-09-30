# Secure OTP Server

A template server for generating, encrypting, and verifying OTP (One-Time Password) codes. Ideal for microservices and authentication flows.

> [!WARNING]
> The documentation is not yet finished.
> In the next few days, I will explain in detail how this server works.

> [!CAUTION]
> Although this server takes many security precautions, additional measures such as DDoS protection, rate limiting and throttling are necessary. It is recommended to add them externally (via CDN or proxies).
>
> If you find any vulnerabilities, please feel free to report them. The best way is to email them before publishing, in case derivative works of this template are used in production. You can find my email address in my profile or in the `author` field of the `package.json`.

## Urgent To-Do list

- Add rate limiting using token metadata, as a second line of defense.
  - 400 ms as default between each OTP verification (configurable).

## Features

- Built on Web Standards. It works on any JavaScript runtime.
- Generate secure OTP codes with customizable length and format.
- Encrypt OTP data using AES-GCM and store in cookies.
- Validate OTP codes and handle resend/attempt limits.
- Easily customizable validation and sending logic.
- Built with [Hono](https://hono.dev/) for fast, modern HTTP APIs.
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

Set `ORIGIN` to the URL of your web platform.

Set `NODE_ENV` to `"production"` when deploying an HTTPS server, to enable secure cookies.

```env
NODE_ENV="production"
ORIGIN="https://example.com"
```

See [`sample.env`](sample.env) for an example.

## Customization

- OTP generation logic: [`src/custom/otp.ts`](src/custom/otp.ts)
- Input validation: [`src/custom/input.ts`](src/custom/input.ts)
- OTP sending logic: [`src/custom/send.ts`](src/custom/send.ts)
- KMS storage: [`src/custom/kms.ts`](src/custom/send.ts)
- Final action after verification: [`src/custom/final.ts`](src/custom/final.ts)

## License

This server template is [MIT licensed](./LICENSE).

Created by [SSbit01](https://ssbit01.github.io).