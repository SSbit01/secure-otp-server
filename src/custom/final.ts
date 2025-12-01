import { Context } from "hono"


/**
 * This function is executed when the OTP and credential/ID have been successfully verified.
 * 
 * Customize this function as you like.
 * 
 * @async
 * @function
 * @param {Context} c - Hono context.
 * @param {string} credential - Client credential/ID directly taken from the token (that's why it can be only a string).
 * @returns {Promise<Response>} [Hono Response using the Hono context](https://hono.dev/docs/getting-started/basic#return-json).
 */
export default async function finalAction(c: Context, credential: string) {

  return c.json({
    credential,
    message: "successfully verified"
  })

}