/**
 * You can customize the length of OTPs.
 * 
 * - It is recommended to set it between 6 and 10.
 */
export const OTP_LENGTH = 8

/**
 * You can customize the format of OTPs.
 */
export const OTP_REGEX = /\w+/

/**
 * When sending an OTP for the first time, you may want to ask users to wait a few seconds until they have the option to resend another OTP.
 * 
 * - It is recommended to set it to 30 seconds.
 * - When it is `0` or falsy, the resend route is disabled.
 */
export const RESEND_BLOCK_SECONDS = 30

/**
 * By default, only one resending is allowed per session. You can enable unlimited resendings by setting this variable to `false`.
 * 
 * - It is recommended to set it to `true`.
 */
export const ALLOW_ONLY_ONE_RESENDING = true

/**
 * The maximum number of attempts a user can verify an OTP.
 */
export const MAX_ATTEMPTS = 3

/**
 * When the user enters the code incorrectly many times and reaches this number of attempts, a timeout of seconds defined in `INVALID_BLOCK_SECONDS` can be set.
 * 
 * - It needs to be lower than `MAX_ATTEMPTS`.
 * - Disable OTP blocking by setting it to `0`.
 */
export const ATTEMPTS_BLOCK = 1

/**
 * When the user enters the code incorrectly many times and reaches the number of attempts defined in `ATTEMPTS_BLOCK`, a timeout of a few seconds can be set.
 * 
 * - It is recommended to set it to 30 seconds.
 */
export const INVALID_BLOCK_SECONDS = 30


/**
 * The maximum validity period of an OTP token in seconds.
 */
export const MAX_DURATION_SECONDS = 300  // 5 minutes


/**
 * This implenetation creates an OTP with lowercase letters and numbers.
 * 
 * - The OTP length with this implementation can be up to 11 characters.
 */
export function createOtp(end = END_COMPUTED) {
  return Math.random().toString(36).substring(2, end)
}
const END_COMPUTED = OTP_LENGTH + 2