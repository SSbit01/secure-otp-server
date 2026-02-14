import { OTP_ATTEMPTS_BLOCK, OTP_LENGTH, OTP_MAX_ATTEMPTS, OTP_REGEX } from "@/custom/otp"

import { compressNumber, decompressNumber } from "@/lib/compression/number"
import { OTP_INVALID_BLOCK_MS, OTP_MAX_AGE_MS, OTP_RESEND_BLOCK_MS } from "@/lib/computed"
import { decodeCredential, encodeCredential } from "@/lib/otp/encode/credential"


/**
 * @typedef {[
 *  credential: string,
 *  expires: number,
 *  otp?: string,
 *  attempts?: number,
 *  resendBlock?: number,
 *  otpBlock?: number
 * ]} OtpToken
 */


export const CREDENTIAL = 0
export const EXPIRES = 1
export const OTP = 2
export const ATTEMPTS = 3
export const RESEND_BLOCK = 4
export const OTP_BLOCK = 5

export const OTP_TOKEN_SEPARATOR = ","

const OTP_SEPARATOR = "|"


/**
 * @function createOtpToken
 * @param {OtpToken[CREDENTIAL]} credential
 * @param {OtpToken[EXPIRES]} expires
 * @param {NonNullable<OtpToken[OTP]>} otp
 * @param {NonNullable<OtpToken[RESEND_BLOCK]>} resendBlock
 * @returns {string}
 */
export function createEncodedOtpToken(
  credential,
  expires,
  otp,
  resendBlock
) {

  return (
    encodeCredential(credential) + OTP_SEPARATOR +
    compressNumber(expires) + OTP_SEPARATOR +
    otp + OTP_SEPARATOR +
    OTP_MAX_ATTEMPTS + OTP_SEPARATOR +
    compressNumber(resendBlock)
  )

}


/**
 * @function decodeOtpToken
 * @param {string} encodedOtpToken 
 * @param {number} [dateNow]
 * @returns {OtpToken|undefined} If it doesn't return anything, it means the token is invalid, and maybe the keys were compromised.
 */
export function decodeOtpToken(encodedOtpToken, dateNow = Date.now()) {

  /**
   * @type {any}
   */
  const otpToken = encodedOtpToken.split(OTP_SEPARATOR)

  otpToken[EXPIRES] = decompressNumber(otpToken[EXPIRES])

  if ((otpToken[EXPIRES] - dateNow) > OTP_MAX_AGE_MS) {
    return
  }

  try {
    otpToken[CREDENTIAL] = decodeCredential(otpToken[CREDENTIAL])
  } catch {
    return
  }

  if (!otpToken[CREDENTIAL]) {
    return
  }

  if (otpToken[OTP]) {
    if (otpToken[OTP].length !== OTP_LENGTH || !OTP_REGEX.test(otpToken[OTP])) {
      return
    }
    otpToken[ATTEMPTS] = +otpToken[ATTEMPTS]
    /**
     * `otpToken[ATTEMPTS]` can't be zero because it's automatically deleted.
     */
    if (isNaN(otpToken[ATTEMPTS]) || otpToken[ATTEMPTS] <= 0 || otpToken[ATTEMPTS] > OTP_MAX_ATTEMPTS) {
      return
    }
    if (otpToken[RESEND_BLOCK]) {
      otpToken[RESEND_BLOCK] = decompressNumber(otpToken[RESEND_BLOCK])
      if ((otpToken[RESEND_BLOCK] - dateNow) > OTP_RESEND_BLOCK_MS) {
        return
      }
    }
    if (otpToken[OTP_BLOCK]) {
      if (otpToken[ATTEMPTS] > OTP_ATTEMPTS_BLOCK) {
        return
      }
      otpToken[OTP_BLOCK] = decompressNumber(otpToken[OTP_BLOCK])
      if ((otpToken[OTP_BLOCK] - dateNow) > OTP_INVALID_BLOCK_MS) {
        return
      }
    }
  } else if (otpToken[ATTEMPTS] || otpToken[RESEND_BLOCK] || otpToken[OTP_BLOCK]) {
    return
  }

  return otpToken

}


/**
 * @async
 * @function decodeOtpTokenList
 * @param {string} encodedOtpTokenListString
 * @returns {string[]}
 */
export function decodeOtpTokenList(encodedOtpTokenListString) {
  return encodedOtpTokenListString.split(OTP_TOKEN_SEPARATOR)
}


/**
 * @function encodeOtpToken
 * @param {OtpToken} otpToken
 * @returns {string}
 */
export function encodeOtpToken(otpToken) {

  /**
   * @type {any}
   */
  const otpTokenCopy = otpToken.slice()

  otpTokenCopy[CREDENTIAL] = encodeCredential(otpTokenCopy[CREDENTIAL])

  otpTokenCopy[EXPIRES] = compressNumber(otpTokenCopy[EXPIRES])

  if (otpTokenCopy[OTP]) {
    otpTokenCopy[RESEND_BLOCK] &&= compressNumber(otpTokenCopy[RESEND_BLOCK])
    otpTokenCopy[OTP_BLOCK] &&= compressNumber(otpTokenCopy[OTP_BLOCK])
  } else {
    otpTokenCopy.length = OTP
  }

  /**
   * Remove empty elements from the end of the array.
   */

  let i = otpTokenCopy.length - 1

  while (!otpTokenCopy[i]) {
    i--
  }

  otpTokenCopy.length = i + 1

  return otpTokenCopy.join(OTP_SEPARATOR)

}