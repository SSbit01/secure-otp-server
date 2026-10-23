import { env } from "hono/adapter";
import type { Context } from "hono";

const PRODUCTION = "production";

let production: boolean;

export default function isProduction(c: Context): boolean {
  if (production === undefined) {
    const envVars = env(c);

    production = envVars.NODE_ENV?.toLowerCase() === PRODUCTION ||
      envVars.ENVIRONMENT?.toLowerCase() === PRODUCTION ||
      envVars.DENO_ENV?.toLowerCase() === PRODUCTION ||
      envVars.VERCEL_ENV?.toLowerCase() === PRODUCTION;
  }

  return production;
}
