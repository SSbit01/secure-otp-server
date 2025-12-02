import process from "node:process"

const isTest = process.env.NODE_ENV === "test"


/**
 * Delay based rate limiting between OTP requests.
 * 
 * - It is recommended to set it to 200 milliseconds or higher.
 * - Also, you can add external rate limiting using Cloudflare or other services.
 */
export const MINIMUM_DELAY_BETWEEN_REQUESTS_MS: number = 200  // 0.2 seconds


/**
 * By default, only one resending is allowed per session. You can enable unlimited resendings by setting this variable to `false`.
 * 
 * - It is recommended to set it to `true`.
 */
export const OTP_ALLOW_ONLY_ONE_RESENDING: boolean = true


/**
 * When the user enters the code incorrectly many times and reaches this number of attempts, a timeout of seconds defined in `OTP_INVALID_BLOCK_SECONDS` can be set.
 * 
 * - It needs to be lower than `OTP_MAX_ATTEMPTS`.
 * - Disable OTP blocking by setting it to `0`.
 */
export const OTP_ATTEMPTS_BLOCK: number = 1


/**
 * When the user enters the code incorrectly many times and reaches the number of attempts defined in `OTP_ATTEMPTS_BLOCK`, a timeout of a few seconds can be set.
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
export const OTP_LENGTH: number = 8


/**
 * The maximum validity period of an OTP token in seconds.
 * 
 * - If it is too low, tests may fail.
 */
export const OTP_MAX_AGE: number = 300  // 5 minutes


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
 * You can customize the OTP format using regular expressions.
 * 
 * This will be used to verify OTP values; it has no impact on their creation.
 */
export const OTP_REGEX: RegExp = /\w+/


/**
 * When sending an OTP, you may want to ask users to wait a few seconds until they have the option to resend another OTP.
 * 
 * - It is recommended to set it to 20 seconds.
 */
export const OTP_RESEND_BLOCK_SECONDS: number = isTest ? 3 : 20


/**
 * This implenetation creates an OTP with lowercase letters and numbers.
 * 
 * - The OTP length with this implementation can be up to 11 characters.
 */
export function createOtp() {
  return Math.random().toString(36).substring(2, END_COMPUTED)
}
const END_COMPUTED = OTP_LENGTH + 2