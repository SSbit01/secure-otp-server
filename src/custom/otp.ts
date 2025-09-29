/**
 * You can customize the length of OTPs.
 */
export const otpLength = 6

/**
 * You can customize the format of OTPs.
 */
export const otpRegex = /\w+/

/**
 * When sending an OTP for the first time, you may want to ask users to wait a few seconds until they have the option to resend another OTP.
 * 
 * - It is recommended to set it to 30 seconds.
 */
export const resendBlockSeconds = 30

/**
 * The maximum number of attempts a user can verify an OTP.
 */
export const maxAttempts = 6

/**
 * The maximum number of attempts a user can verify an OTP before being blocked.
 * It needs to be lower than `maxAttempts`.
 */
export const attemptsBlock = 2

/**
 * When the user enters the code incorrectly many times and reaches the number of attempts set in `attemptsBlock`, a timeout of a few seconds can be set to prevent more requests.
 * 
 * - It is recommended to set it to 30 seconds.
 */
export const otpInvalidBlockSeconds = 30


/**
 * The maximum validity period of an OTP token in seconds.
 */
export const otpMaxDurationSeconds = 1800  // 30 minutes


/**
 * This implenetation creates an OTP with lowercase letters and numbers.
 * 
 * - The OTP length with this implementation can be up to 11 characters.
 */
export function createOtp(end = endComputed) {
  return Math.random().toString(36).substring(2, end)
}
const endComputed = otpLength + 2