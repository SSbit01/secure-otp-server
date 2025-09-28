import { validator } from "hono/validator"

import { ERR_ID_INVALID } from "@/lib/errors.js"


/**
 * Verify the initial credential/ID before generating and sending an OTP.
 * The request header should have `"Content-Type": "application/json"`.
 * Customize this validator as you like.
 * The validation target must be `json` and return a credential/ID (not shared with the client) of type `string` or `number` to later confirm that the credentials have been verified.
 */
const inputValidator = validator("json", (body, c) => {

  return JSON.stringify(body)

})


export default inputValidator