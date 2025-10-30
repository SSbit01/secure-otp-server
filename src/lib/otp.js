import { setCookie, deleteCookie } from "hono/cookie"

import { encryptOtp, decryptOtp } from "@/lib/crypto/otp"
import isProduction from "@/lib/production"
import { getReducedTimePrecision } from "@/lib/time"

import { deleteEncryptionKey } from "@/custom/kms"
import { RESEND_BLOCK_SECONDS, MAX_ATTEMPTS, MAX_DURATION_SECONDS, createOtp } from "@/custom/otp"
import sendOtp from "@/custom/send"

/**
 * @import { Context } from "hono"
 * @import { CookieOptions } from "hono/utils/cookie"
 */


const SEPARATOR = "; "
const MAX_DURATION_MS = MAX_DURATION_SECONDS * 1000
const DISABLE_RESENDING = !RESEND_BLOCK_SECONDS
const RESEND_BLOCK_MS = RESEND_BLOCK_SECONDS * 1000


export const COOKIE_KEY_ID = "e"
export const COOKIE_OTP = "t"


/**
 * @async
 * @function createOtpCookie
 * @param {Context} c
 * @param {(string|number)} credential
 * @param {(string|number)} otp
 * @param {number} lastAccessDate
 * @param {number} expires
 * @param {(string|number)} [resendBlockDate]
 * @param {(string|number)} [attempts]
 * @param {(string|number|false|null|undefined)} [otpBlockDate]
 * @returns {Promise<number>} When the OTP expires.
 */
export async function createOtpCookie(
  c,
  credential,
  otp,
  lastAccessDate,
  expires,
  resendBlockDate = "",
  attempts = MAX_ATTEMPTS,
  otpBlockDate = false
) {

  /**
   * When resendBlockDate is empty, another OTP has been resent and the client is not allowed to resend it again.
   */
  // expires:lastAccessDate:resendBlockDate:credential:otp:attempts:otpBlockDate(optional)
  let value = `${expires}${SEPARATOR}${lastAccessDate}${SEPARATOR}${resendBlockDate}${SEPARATOR}${credential}${SEPARATOR}${otp}${SEPARATOR}${attempts}`

  if (otpBlockDate) {
    value += `${SEPARATOR}${otpBlockDate}`
  }

  const lessPreciseExpiresDate = getReducedTimePrecision(expires)

  /** @type {CookieOptions} */
  const cookieOptions = {
    expires: new Date(lessPreciseExpiresDate),
    httpOnly: true,
    maxAge: MAX_DURATION_SECONDS,
    secure: isProduction(c),
    sameSite: "strict",
    partitioned: false
  }
  
  const [result, keyId] = await encryptOtp(c, value, expires)

  setCookie(c, COOKIE_OTP, result, cookieOptions)
  setCookie(c, COOKIE_KEY_ID, keyId, cookieOptions)

  return lessPreciseExpiresDate

}


/**
 * @typedef {Object} DataExpire
 * @property {number} expires
 * @property {number} [resendBlockDate]
 */

/**
 * @async
 * @function createOtpAndSend
 * @param {Context} c
 * @param {(string|number)} credential
 * @param {boolean} resent
 * @returns {Promise<DataExpire>}
 */
export async function createOtpAndSend(
  c,
  credential,
  resent = DISABLE_RESENDING
) {

  const otp = createOtp()

  await sendOtp(c, credential, otp)

  const dateNow = Date.now()

  const expires = dateNow + MAX_DURATION_MS

  if (resent) {
    return {
      expires: await createOtpCookie(c, credential, otp, dateNow, expires)
    }
  }

  const resendBlockDate = dateNow + RESEND_BLOCK_MS

  return {
    expires: await createOtpCookie(c, encodeURIComponent(credential), otp, dateNow, expires, resendBlockDate),
    resendBlockDate: getReducedTimePrecision(resendBlockDate, Math.ceil)
  }

}


/**
 * @function deleteOtpCookies
 * @param {Context} c
 * @returns {(string|undefined)} Key ID value.
 */
export function deleteOtpCookies(c) {

  deleteCookie(c, COOKIE_OTP)

  return deleteCookie(c, COOKIE_KEY_ID)

}


/**
 * @function deleteOtpData
 * @param {Context} c
 */
export function deleteOtpData(c) {

  const keyId = deleteOtpCookies(c)

  if (keyId) {
    /**
     * Fire and forget - delete old key
     */
    deleteEncryptionKey(c, keyId)
  }

}


/**
 * @async
 * @function getOtpTokenData
 * @param {Context} c
 * @param {string} keyId
 * @param {string} token
 * @returns {Promise<[expires:string,lastAccessDate:string,resendBlockDate:string,credential:string,otp:string,attempts:string,otpBlockDate?:string]|undefined|null>}
 */
export async function getOtpTokenData(
  c,
  keyId,
  token
) {

  try {
    // expires:lastAccessDate:resendBlockDate:credential:otp:attempts:otpBlockDate(optional)
    const result = await decryptOtp(c, keyId, token)

    if (result) {
      // @ts-expect-error: TS doesn't detect that result is compatible with the return type.
      return result.split(SEPARATOR)
    }

  } catch {
    return null
  }

}