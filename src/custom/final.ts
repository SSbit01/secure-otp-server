import type { Context } from "hono";

/**
 * This function is executed when the OTP and credential (e.g. email, phone number...) have been successfully verified.
 *
 * Customize this function as you like.
 *
 * @async
 * @function
 * @param {Context} c - Hono context.
 * @param {string} credential - Client credential/ID previously passed in `credential.ts`.
 * @returns {Promise<Response>} [Hono Response using the Hono context](https://hono.dev/docs/getting-started/basic#return-json).
 */
export default async function finalAction(c: Context, credential: string) {
  /**
   * For passwordless authentication:
   * You might want to generate a JWT or session cookie here and return it to the client.
   *
   * For credential verification:
   * You might want to mark the credential (e.g. email, phone number...) as "verified" in your database.
   */

  return c.json({
    credential,
    message: "successfully verified"
  });
}
