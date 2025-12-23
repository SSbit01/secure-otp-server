import { compressNumber, decompressNumber } from "@/lib/compression/number"
import { EXPIRES, OTP, ATTEMPTS, RESEND_BLOCK, OTP_BLOCK } from "@/lib/otp/order"


/**
 * @import { OtpToken } from "@/lib/otp/order"
 */


const OTP_SEPARATOR = "|"


/**
 * @function decodeOtpToken
 * @param {string} otpTokenString 
 * @param {number} [dateNow]
 * @returns {(OtpToken|undefined)}
 */
export function decodeOtpToken(otpTokenString, dateNow = Date.now()) {

  /**
   * @type {any[]}
   */
  const otpToken = otpTokenString.split(OTP_SEPARATOR)

  otpToken[EXPIRES] = decompressNumber(otpToken[EXPIRES])

  if (dateNow >= otpToken[EXPIRES]) {
    return
  }

  /**
   * Presence of token[RESEND_BLOCK] indicates that resending is available.
   * That's why it is not removed, unlike [OTP_BLOCK].
   */

  /**
   * TODO: Check if otpToken[ATTEMPTS] corresponds to MAX_ATTEMPTS.
   * If that's not the case, return bad request to the client and rotate KEK.
   */

  if (otpToken[ATTEMPTS]) {
    otpToken[ATTEMPTS] = +otpToken[ATTEMPTS]
    if (otpToken[OTP_BLOCK]) {
      const otpBlock = decompressNumber(otpToken[OTP_BLOCK])
      if (dateNow < otpBlock) {
        otpToken[OTP_BLOCK] = otpBlock
        otpToken[RESEND_BLOCK] &&= decompressNumber(otpToken[RESEND_BLOCK])
      } else if (otpToken[RESEND_BLOCK]) {
        otpToken[RESEND_BLOCK] = decompressNumber(otpToken[RESEND_BLOCK])
        /** Trim the array to save space. */
        otpToken.length = OTP_BLOCK
      } else {
        /** Trim the array to save space. */
        otpToken.length = RESEND_BLOCK
      }
    } else {
      otpToken[RESEND_BLOCK] &&= decompressNumber(otpToken[RESEND_BLOCK])
    }
  }

  // @ts-expect-error: TS doesn't know that this must be a `OtpToken` array.
  return otpToken

}


/**
 * @function encodeOtpToken
 * @param {OtpToken} otpToken
 * @returns {string}
 */
export function encodeOtpToken(otpToken) {

  /**
   * @type {any[]}
   */
  const encodedToken = otpToken.slice()

  encodedToken[EXPIRES] = compressNumber(encodedToken[EXPIRES])

  if (encodedToken[OTP]) {
    encodedToken[RESEND_BLOCK] &&= compressNumber(encodedToken[RESEND_BLOCK])
    encodedToken[OTP_BLOCK] &&= compressNumber(encodedToken[OTP_BLOCK])
  }

  return encodedToken.join(OTP_SEPARATOR)

}