import { validator } from "hono/validator"

import { ERR_CREDENTIAL_INVALID } from "@/lib/errors.js"


/**
 * Verify the initial credential/ID before generating and sending an OTP.
 * 
 * - The request header should have `"Content-Type": "application/json"`.
 * - Customize this validator as you like.
 * - The validation target must be `json` and return a credential/ID (not shared with the client) of type `string` or `number` to later confirm that the credentials have been verified.
 * - Remember a JSON can be an object/array or a value (string, number, boolean, null).
 * - Read more about [Hono validators](https://hono.dev/docs/guides/validation#validation).
 */
const credentialValidator = validator("json", (body, c) => {

  /**
   * Is the body invalid or empty?
   */
  if (
    !body ||
    body === true ||
    (typeof body !== "number" && (!body?.length || !Object.keys(body).length))
  ) {
    return c.json(ERR_CREDENTIAL_INVALID, 400)
  }

  return JSON.stringify(body)

})


export default credentialValidator