import { validator } from "hono/validator"

import { ERR_ID_INVALID } from "@/lib/errors.js"


/**
 * Verify the initial credential/ID before generating and sending an OTP.
 * The request header should have `"Content-Type": "application/x-www-form-urlencoded"` with a `credential` parameter.
 * Customize this validator as you like.
 * The validation target must be `form` and return a credential/ID (not shared with the client) of type `string` or `number` to later confirm that the credentials have been verified.
 */
const inputValidator = validator("form", ({ credential }, c) => {

  if (Array.isArray(credential)) {
    credential = credential[0]
  }
  
  if (typeof credential !== "string") {
    return c.json(ERR_ID_INVALID, 400)
  }

  return credential

})


export default inputValidator