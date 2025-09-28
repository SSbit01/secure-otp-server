import { Context } from "hono"
import { HTTPResponseError } from "hono/types"


/**
 * This function runs when an error occurs.
 * Customize this function as you like.
 * It should accept an Error object and the Hono context.
 */
export default async function errorHandler(
  err: Error | HTTPResponseError,
  c: Context
) {
  console.error(err)
}