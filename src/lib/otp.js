import { setCookie, deleteCookie } from "hono/cookie"

import { encryptOtp, decryptOtp } from "@/lib/crypto/otp"
import isProduction from "@/lib/production"
import getReducedTimePrecision from "@/lib/time"

import { deleteEncryptionKey } from "@/custom/kms"
import { RESEND_BLOCK_SECONDS, MAX_ATTEMPTS, MAX_DURATION_SECONDS, createOtp } from "@/custom/otp"
import sendOtp from "@/custom/send"

/**
 * @import { Context } from "hono"
 * @import { CookieOptions } from "hono/utils/cookie"
 */


const SEPARATOR = ":"
const MAX_DURATION_MS = MAX_DURATION_SECONDS * 1000
const DISABLE_RESENDING = !RESEND_BLOCK_SECONDS
const RESEND_BLOCK_MS = RESEND_BLOCK_SECONDS * 1000


export const COOKIE_KEY_ID = "e"
export const COOKIE_OTP = "t"


/**
 * 
 * @param {Context} c
 * @param {(string|number)} otp
 * @param {(string|number)} credential
 * @param {number} expires 
 * @param {(string|number)} [resendBlockDate]
 * @param {number} [attempts]
 * @param {(string|number|false|null|undefined)} [otpBlockDate] 
 */
export async function createOtpCookie(
  c,
  otp,
  credential,
  expires,
  resendBlockDate = "",
  attempts = MAX_ATTEMPTS,
  otpBlockDate = false
) {

  /**
   * When resendBlockDate is empty, another OTP has been resent and the client is not allowed to resend it again.
   */
  // credential:expires:resendBlockDate:otp:attempts:otpBlockDate(optional)
  let value = `${credential}${SEPARATOR}${expires}${SEPARATOR}${resendBlockDate}${SEPARATOR}${otp}${SEPARATOR}${attempts}`

  if (otpBlockDate) {
    value += `${SEPARATOR}${otpBlockDate}`
  }

  /** @type {CookieOptions} */
  const cookieOptions = {
    expires: new Date(expires),
    httpOnly: true,
    maxAge: MAX_DURATION_SECONDS,
    secure: isProduction(c),
    sameSite: "strict",
    partitioned: false
  }
  
  const [result, keyID] = await encryptOtp(c, value, expires)

  setCookie(c, COOKIE_OTP, result, cookieOptions)
  setCookie(c, COOKIE_KEY_ID, keyID, cookieOptions)

}


/**
 * @typedef  {Object} DataExpire
 * @property {number} expires
 * @property {number} [resendBlockDate]
 */

/**
 * @async
 * @param   {Context} c
 * @param   {(string|number)} credential
 * @param   {boolean} resent
 * @param   {number} [dateNow]
 * @returns {Promise<DataExpire>}
 */
export async function createOtpAndSend(
  c,
  credential,
  resent = DISABLE_RESENDING,
  dateNow = getReducedTimePrecision()
) {

  const otp = createOtp()

  await sendOtp(c, credential, otp)

  const expires = dateNow + MAX_DURATION_MS

  if (resent) {
    await createOtpCookie(c, otp, credential, expires)
    return { expires }
  }

  const resendBlockDate = dateNow + RESEND_BLOCK_MS

  await createOtpCookie(c, otp, credential, expires, resendBlockDate)

  return { expires, resendBlockDate }

}


/**
 * 
 * @param {Context} c
 */
export async function deleteOtpData(c) {

  deleteCookie(c, COOKIE_OTP)

  const keyID = deleteCookie(c, COOKIE_KEY_ID)

  if (keyID) {
    await deleteEncryptionKey(c, keyID)
  }

}


/**
 * 
 * @param   {Context} c
 * @param   {string} keyID
 * @param   {string} token
 * @returns {Promise<[credential:string,expires:string,resendBlockDate:string,otp:string,attempts:string,otpBlockDate?:string]|undefined>}
 */
export async function getOtpTokenData(
  c,
  keyID,
  token
) {

  try {
    // credential:expires:resendBlockDate:otp:attempts:otpBlockDate(optional)
    const result = await decryptOtp(c, token, keyID)

    if (result) {
      // @ts-expect-error
      return result.split(SEPARATOR)
    }

  } catch {
    /**
     * The error occurs when the key is valid and the token invalid.
     */
    await deleteOtpData(c)
  }

}