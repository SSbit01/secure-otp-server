import { env } from "hono/adapter";
import {
  OTP_ALLOW_ONLY_ONE_RESENDING,
  OTP_ATTEMPTS_BLOCK,
  OTP_INVALID_BLOCK_SECONDS,
  OTP_LENGTH,
  OTP_MAX_AGE,
  OTP_MAX_ATTEMPTS,
  OTP_MAX_CREDENTIALS,
  OTP_RADIX,
  OTP_RESEND_BLOCK_SECONDS
} from "#src/custom/default";
import type { Context } from "hono";

const PRODUCTION = "production";

let production: boolean;

export function getEnvOtpAllowOnlyOneResending(c: Context): boolean {
  const envValue = env(c).OTP_ALLOW_ONLY_ONE_RESENDING?.toLowerCase();

  if (envValue) {
    switch (envValue) {
      case "1":
      case "true":
        return true;
      case "0":
      case "false":
        return false;
    }
  }

  return OTP_ALLOW_ONLY_ONE_RESENDING;
}

export function getEnvOtpAttemptsBlock(c: Context): number {
  const envValue = env(c).OTP_ATTEMPTS_BLOCK;

  if (envValue) {
    const parsedEnvValue = +envValue;

    if (!Number.isNaN(parsedEnvValue) && parsedEnvValue >= 0) {
      return parsedEnvValue;
    }
  }

  return OTP_ATTEMPTS_BLOCK;
}

export function getEnvOtpCookiePrefix(c: Context): string {
  return env(c).OTP_COOKIE_PREFIX ?? "__Host-Http-";
}

export function getEnvOtpInvalidBlockSeconds(c: Context): number {
  const envValue = env(c).OTP_INVALID_BLOCK_SECONDS;

  if (envValue) {
    const parsedEnvValue = +envValue;

    if (!Number.isNaN(parsedEnvValue) && parsedEnvValue >= 0) {
      return parsedEnvValue;
    }
  }

  return OTP_INVALID_BLOCK_SECONDS;
}

export function getEnvOtpLength(c: Context): number {
  const envValue = env(c).OTP_LENGTH;

  if (envValue) {
    const parsedEnvValue = +envValue;

    if (!Number.isNaN(parsedEnvValue) && parsedEnvValue > 0) {
      return parsedEnvValue;
    }
  }

  return OTP_LENGTH;
}

export function getEnvOtpMaxAge(c: Context): number {
  const envValue = env(c).OTP_MAX_AGE;

  if (envValue) {
    const parsedEnvValue = +envValue;

    if (!Number.isNaN(parsedEnvValue) && parsedEnvValue > 0) {
      return parsedEnvValue;
    }
  }

  return OTP_MAX_AGE;
}

export function getEnvOtpMaxAttempts(c: Context): number {
  const envValue = env(c).OTP_MAX_ATTEMPTS;

  if (envValue) {
    const parsedEnvValue = +envValue;

    if (!Number.isNaN(parsedEnvValue) && parsedEnvValue > 0) {
      return parsedEnvValue;
    }
  }

  return OTP_MAX_ATTEMPTS;
}

export function getEnvOtpMaxCredentials(c: Context): number {
  const envValue = env(c).OTP_MAX_CREDENTIALS;

  if (envValue) {
    const parsedEnvValue = +envValue;

    if (!Number.isNaN(parsedEnvValue) && parsedEnvValue > 0) {
      return parsedEnvValue;
    }
  }

  return OTP_MAX_CREDENTIALS;
}

export function getEnvOtpRadix(c: Context): number {
  const envValue = env(c).OTP_RADIX;

  if (envValue) {
    const parsedEnvValue = +envValue;

    if (!Number.isNaN(parsedEnvValue) && parsedEnvValue >= 2) {
      return parsedEnvValue;
    }
  }

  return OTP_RADIX;
}

export function getEnvOtpResendBlockSeconds(c: Context): number {
  const envValue = env(c).OTP_RESEND_BLOCK_SECONDS;

  if (envValue) {
    const parsedEnvValue = +envValue;

    if (!Number.isNaN(parsedEnvValue) && parsedEnvValue >= 0) {
      return parsedEnvValue;
    }
  }

  return OTP_RESEND_BLOCK_SECONDS;
}

export function isProduction(c: Context): boolean {
  if (production === undefined) {
    const envVariables = env(c);

    production = envVariables.NODE_ENV?.toLowerCase() === PRODUCTION ||
      envVariables.ENVIRONMENT?.toLowerCase() === PRODUCTION ||
      envVariables.DENO_ENV?.toLowerCase() === PRODUCTION ||
      envVariables.VERCEL_ENV?.toLowerCase() === PRODUCTION;
  }

  return production;
}
