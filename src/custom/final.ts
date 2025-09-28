import { Context } from "hono"


/**
 * This function runs when the OTP and the credential/ID have been verified.
 * Customize this function as you like.
 * It should accept the Hono context and the user's credential/ID.
 * It should return a Response using the Hono context.
 */
export default async function finalAction(
  c: Context,
  credential: string
) {

  return c.json({
    message: `"${credential}" successfully verified.`
  })

}