import { env } from "hono/adapter";
import type { Context } from "hono";

const PRODUCTION = "production";

let production: boolean;

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
