import { validator } from "hono/validator";
import { ERR_CREDENTIAL_INVALID } from "@/lib/error/static";

/**
 * Verify the initial credential (e.g. email, phone number...) before generating and sending an OTP.
 *
 * - Customize this validator as you like, but it must be a form validator.
 * - The validation target must return a credential string (it is not shared with the client).
 * - Read more about [Hono validators](https://hono.dev/docs/guides/validation#validation).
 */
const credentialValidator = validator("form", (body, c) => {
  /**
   * Is the body empty?
   */
  if (!Object.keys(body).length) {
    return c.json(ERR_CREDENTIAL_INVALID, 400);
  }

  return JSON.stringify(body);
});

export default credentialValidator;
