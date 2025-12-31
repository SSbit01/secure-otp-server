import { OTP_ATTEMPTS_BLOCK, OTP_LENGTH, OTP_MAX_ATTEMPTS, OTP_REGEX } from "@/custom/otp"

import { decodeCredential } from "@/lib/otp/encode/credential"
import { compressNumber, decompressNumber } from "@/lib/compression/number"
import { OTP_INVALID_BLOCK_MS, OTP_MAX_AGE_MS, OTP_RESEND_BLOCK_MS } from "@/lib/computed"
import { isLessThanDelay } from "@/lib/time"


export type OtpToken = [
  credential: string,
  expires: number,
  otp?: string,
  attempts?: number,
  resendBlock?: number,
  otpBlock?: number
]


export const CREDENTIAL = 0
export const EXPIRES = 1
export const OTP = 2
export const ATTEMPTS = 3
export const RESEND_BLOCK = 4
export const OTP_BLOCK = 5

export const OTP_SEPARATOR = "|"


/**
 * @function createOtpToken
 * @param {string} encodedCredential
 * @param {number} expires
 * @param {string} otp
 * @param {number} resendBlock
 * @returns {string}
 */
export function createEncodedOtpToken(
  encodedCredential: string,
  expires: number,
  otp: string,
  resendBlock: number
) {

  return (
    encodedCredential + OTP_SEPARATOR +
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
 * @returns {(OtpToken|undefined)} If it doesn't return anything, it means the token is invalid, and maybe the keys were compromised.
 */
export async function decodeOtpToken(encodedOtpToken: string, dateNow = Date.now()) {

  const otpToken: any = encodedOtpToken.split(OTP_SEPARATOR)

  const currentExpires = decompressNumber(otpToken[EXPIRES])

  if (!isLessThanDelay(currentExpires, dateNow, OTP_MAX_AGE_MS)) {
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
      if (!isLessThanDelay(otpToken[RESEND_BLOCK], dateNow, OTP_RESEND_BLOCK_MS)) {
        return
      }
    }
    if (otpToken[OTP_BLOCK]) {
      if (otpToken[ATTEMPTS] > OTP_ATTEMPTS_BLOCK) {
        return
      }
      otpToken[OTP_BLOCK] = decompressNumber(otpToken[OTP_BLOCK])
      if (otpToken[OTP_BLOCK] <= dateNow) {
        delete otpToken[OTP_BLOCK]
      } else if (!isLessThanDelay(otpToken[OTP_BLOCK], dateNow, OTP_INVALID_BLOCK_MS)) {
        return
      }
    }
  } else if (otpToken[ATTEMPTS] || otpToken[RESEND_BLOCK] || otpToken[OTP_BLOCK]) {
    return
  }

  return otpToken

}


/**
 * @function encodeOtpToken
 * @param {OtpToken} otpToken
 * @returns {string}
 */
export function encodeOtpToken(otpToken: OtpToken) {

  const encodedToken: any = otpToken.slice()

  encodedToken[EXPIRES] = compressNumber(encodedToken[EXPIRES])

  if (encodedToken[OTP]) {
    encodedToken[RESEND_BLOCK] &&= compressNumber(encodedToken[RESEND_BLOCK])
    encodedToken[OTP_BLOCK] &&= compressNumber(encodedToken[OTP_BLOCK])
  }

  /**
   * Remove empty elements from the end of the array.
   */

  let i = encodedToken.length - 1

  while (!encodedToken[i]) {
    i--
  }

  encodedToken.length = i + 1

  return encodedToken.join(OTP_SEPARATOR)

}