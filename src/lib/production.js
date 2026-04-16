import { env } from "hono/adapter";

/**
 * @import { Context } from "hono"
 */

const PRODUCTION = "production";

/** @type {boolean} */
let production;

/**
 * Returns whether the server is running in a production environment or not.
 *
 * @param {Context} c
 * @returns {boolean}
 */
export default function isProduction( c ) {
  if ( production === undefined ) {
    const envVars = env( c );
    production = envVars.NODE_ENV?.toLowerCase() === PRODUCTION ||
      envVars.ENVIRONMENT?.toLowerCase() === PRODUCTION ||
      envVars.VERCEL_ENV?.toLowerCase() === PRODUCTION;
  }

  return production;
}
