import { setCookie, deleteCookie } from "hono/cookie"

import { encryptOtp, decryptOtp } from "@/lib/crypto/otp"
import isProduction from "@/lib/production"
import { getReducedTimePrecision, isLessThanDelay } from "@/lib/time"

import { deleteEncryptionKey } from "@/custom/kms"
import { RESEND_BLOCK_SECONDS, MAX_ATTEMPTS, MAX_DURATION_SECONDS, createOtp } from "@/custom/otp"
import sendOtp from "@/custom/send"

/**
 * @import { Context } from "hono"
 */


const SEPARATOR = "|"
const MAX_DURATION_MS = MAX_DURATION_SECONDS * 1000
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
  expires,
  lastAccessDate = Date.now(),
  resendBlockDate = "",
  attempts = MAX_ATTEMPTS,
  otpBlockDate = false
) {

  /**
   * When resendBlockDate is empty, another OTP has been resent and the client is not allowed to resend it again.
   */
  // lastAccessDate:expires:resendBlockDate:credential:otp:attempts:otpBlockDate(optional)
  let value = lastAccessDate + SEPARATOR + expires + SEPARATOR + resendBlockDate + SEPARATOR + credential + SEPARATOR + otp + SEPARATOR + attempts

  if (otpBlockDate) {
    value += SEPARATOR + otpBlockDate
  }

  const lessPreciseExpiresDate = getReducedTimePrecision(expires)

  /**
   * @type {import("hono/utils/cookie").CookieOptions}
   */
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
  resent = false
) {

  const otp = createOtp()

  await sendOtp(c, credential, otp)

  const dateNow = Date.now()

  const expires = dateNow + MAX_DURATION_MS

  credential = encodeURI(credential.toString())

  if (resent) {
    return {
      expires: await createOtpCookie(c, credential, otp, expires, dateNow)
    }
  }

  const resendBlockDate = dateNow + RESEND_BLOCK_MS

  return {
    expires: await createOtpCookie(c, credential, otp, expires, dateNow, resendBlockDate),
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
 * @function getOtpData
 * @param {Context} c
 * @param {string} keyId
 * @param {string} token
 * @returns {Promise<[expires:number,resendBlockDate:string,credential:string,otp:string,attempts:string,otpBlockDate?:string]|undefined|null|false>}
 */
export async function getOtpData(
  c,
  keyId,
  token
) {

  /**
   * @type {(string|undefined)}
   */
  let otpToken

  try {
    otpToken = await decryptOtp(c, keyId, token)
  } catch {
    return null
  }

  if (!otpToken) {
    return
  }

  const otpTokens = otpToken.split(",")

  if (!otpTokens.length) {
    return null
  }

  const currentOtpToken = otpTokens.shift()?.split(SEPARATOR)

  if (!currentOtpToken?.[1]) {
    return null
  }

  // @ts-expect-error: TS doesn't detect that `expires` must be a number.
  currentOtpToken[1] = +currentOtpToken[1]

  const dateNow = Date.now()

  // @ts-expect-error: TS doesn't detect that `expires` must be a number.
  if (dateNow >= currentOtpToken[1]) {
    return null
  }

  const lastValidAccess = currentOtpToken.shift()

  if (lastValidAccess && isLessThanDelay(+lastValidAccess, dateNow)) {
    return false
  }

  for (let i = 1; i < otpTokens.length; i++) {
    const expires = otpTokens[i].split(SEPARATOR)?.[0]
    if (!expires || dateNow >= +expires) {
      otpTokens.splice(i, 1)
    }
  }

  // @ts-expect-error: TS doesn't detect that result is compatible with the return type.
  return currentOtpToken

}