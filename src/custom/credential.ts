import { validator } from "hono/validator";
import { ERR_CREDENTIAL_INVALID } from "@/lib/error/static";

/**
 * Verify the initial credential (e.g. email, phone number...) before generating and sending an OTP.
 *
 * - Customize this validator as you like.
 * - The validation target must return a credential string (not shared with the client).
 * - Read more about [Hono validators](https://hono.dev/docs/guides/validation#validation).
 */
const credentialValidator = validator( "json", ( body, c ) => {
  /**
   * Is the body invalid or empty?
   * A JSON can be an object/array or a value (string, number, boolean, null).
   */
  if (
    !body ||
    body === true ||
    ( typeof body !== "number" && !( body?.length || Object.keys( body ).length ) )
  ) {
    return c.json( ERR_CREDENTIAL_INVALID, 400 );
  }

  return JSON.stringify( body );
} );

export default credentialValidator;
