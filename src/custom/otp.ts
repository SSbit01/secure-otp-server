import process from "node:process"

/**
 * Whether the environment is a test environment.
 * 
 * - You can omit using different values for tests, but some tests might not run or fail.
 */
const isTest = process.env.NODE_ENV === "test"


/**
 * By default, only one resending is allowed per session.
 * You can enable unlimited resendings by setting this variable to `false`.
 * 
 * - It is recommended to set it to `true`.
 */
export const OTP_ALLOW_ONLY_ONE_RESENDING: boolean = true


/**
 * When the user enters the code incorrectly many times and reaches this number of attempts,
 * a timeout of seconds defined in `OTP_INVALID_BLOCK_SECONDS` can be set.
 * 
 * - It needs to be lower than `OTP_MAX_ATTEMPTS`.
 * - Disable OTP blocking by setting it to `0`.
 */
export const OTP_ATTEMPTS_BLOCK: number = 1


/**
 * Prefix for the OTP cookies, only applied in production.
 * 
 * @see {@link https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie#cookie_prefixes|MDN}
 */
export const OTP_COOKIE_PREFIX: string = "__Host-Http-"


/**
 * When the user enters the code incorrectly many times and reaches the number of attempts defined in `OTP_ATTEMPTS_BLOCK`,
 * a timeout of a few seconds can be set.
 * 
 * - It is recommended to set it to 20 seconds.
 */
export const OTP_INVALID_BLOCK_SECONDS: number = isTest ? 3 : 20


/**
 * You can customize the length of OTPs.
 * 
 * - It is recommended to set it between 6 and 10.
 * - Increasesing the OTP length improves security (higher [min-entropy](https://en.wikipedia.org/wiki/Min-entropy)).
 */
export const OTP_LENGTH: number = 10


/**
 * The maximum validity period of an OTP token in seconds.
 * 
 * - If it is too low, tests may fail.
 */
export const OTP_MAX_AGE: number = 180  // 3 minutes


/**
 * Limits the number of OTP tokens a user can submit within a single session.
 *
 * For instance, if a user initiates verification for one credential and then another, the system stores both OTP tokens.
 * This allows the user to return to the original credential verification without creating a new token.
 * This variable directly controls the maximum number of such tokens stored per session.
 */
export const OTP_MAX_CREDENTIALS: number = 3


/**
 * The maximum number of attempts a user can verify an OTP.
 */
export const OTP_MAX_ATTEMPTS: number = 3


/**
 * When sending an OTP, you may want to ask users to wait a few seconds until they have the option to resend another OTP.
 * 
 * - It is recommended to set it to 20 seconds.
 */
export const OTP_RESEND_BLOCK_SECONDS: number = isTest ? 3 : 20


/**
 * You can customize the OTP format using regular expressions.
 * 
 * This will be used to verify OTP values; it has no impact on their creation.
 */
export const OTP_REGEX: RegExp = /[a-z0-9]+/


/**
 * This implenetation creates an OTP with lowercase letters and numbers.
 */
export function createOtp() {
  return (
    crypto.getRandomValues(new BigUint64Array(1))[0]
      .toString(36)
      .substring(0, OTP_LENGTH)
      .padStart(OTP_LENGTH, "0")
  )
}