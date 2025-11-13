import { setCookie, deleteCookie } from "hono/cookie"

import { encryptOtp, decryptOtp } from "@/lib/crypto/otp"
import isProduction from "@/lib/production"
import { getReducedTimePrecision, isLessThanDelay } from "@/lib/time"

import { RESEND_BLOCK_SECONDS, MAX_ATTEMPTS, MAX_DURATION_SECONDS, ATTEMPTS_BLOCK, INVALID_BLOCK_SECONDS, createOtp } from "@/custom/otp"
import sendOtp from "@/custom/send"

/**
 * @import { Context } from "hono"
 */


const ARRAY_SEPARATOR = ","
const OTP_SEPARATOR = "|"

const INVALID_BLOCK_MS = INVALID_BLOCK_SECONDS * 1000
const MAX_DURATION_MS = MAX_DURATION_SECONDS * 1000
const RESEND_BLOCK_MS = RESEND_BLOCK_SECONDS * 1000


export const COOKIE_KEY_ID = "e"
export const COOKIE_OTP = "t"


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
 */
export function deleteOtpCookies(c) {
  deleteCookie(c, COOKIE_OTP)
  deleteCookie(c, COOKIE_KEY_ID)
}


class OtpData {
  
  #attempts
  #context
  #credential
  #expires
  #otherTokens
  #otp
  #otpBlockDate
  #resendBlockDate


  constructor(c, [expires, credential, otp, attempts = MAX_ATTEMPTS, resendBlockDate = "", otpBlockDate = 0], ...otherTokens) {

    this.#attempts = attempts
    this.#context = c
    this.#credential = credential
    this.#expires = expires
    this.#otherTokens = otherTokens
    this.#otp = otp
    this.#otpBlockDate = otpBlockDate
    this.#resendBlockDate = resendBlockDate

    /**
     * Make functions immutable
     */
    Object.defineProperties(this, {
      check: {
        configurable: false,
        enumerable: false,
        value: this.check,
        writable: false
      },
      save: {
        configurable: false,
        enumerable: false,
        value: this.save,
        writable: false
      }
    })

  }


  /**
   * 
   * @param {string} otp
   * @returns {Promise<boolean|number>}
   */
  async check(otp, dateNow = Date.now()) {

    if (this.#otp === otp) {
      return true
    }

    this.#attempts--
  
    /**
     * Is `attempts` 0?
     */
    if (!this.#attempts) {
      deleteOtpCookies(this.#context)
      return false
    }

    if (INVALID_BLOCK_MS && this.#attempts <= ATTEMPTS_BLOCK) {
      this.#otpBlockDate = dateNow + INVALID_BLOCK_MS
    }

    await this.save(dateNow)

    return this.#otpBlockDate

  }


  async save(dateNow = Date.now()) {

    const lessPreciseExpiresDate = getReducedTimePrecision(this.#expires)

    /**
     * @type {import("hono/utils/cookie").CookieOptions}
     */
    const cookieOptions = {
      expires: new Date(lessPreciseExpiresDate),
      httpOnly: true,
      maxAge: MAX_DURATION_SECONDS,
      secure: isProduction(this.#context),
      sameSite: "strict",
      partitioned: false
    }

    /**
     * When resendBlockDate is empty, another OTP has been resent and the client is not allowed to resend it again.
     */
    // expires:credential:otp:attempts:resendBlockDate:otpBlockDate(optional)
    let currentOtpToken = this.#expires + OTP_SEPARATOR + this.#credential + OTP_SEPARATOR + this.#otp + OTP_SEPARATOR + this.#attempts + OTP_SEPARATOR + this.#resendBlockDate

    if (this.#otpBlockDate) {
      currentOtpToken += OTP_SEPARATOR + this.#otpBlockDate
    }

    for (let i = 1; i < this.#otherTokens.length; i++) {
      const expires = this.#otherTokens[i].split(OTP_SEPARATOR)?.[0]
      if (!expires || dateNow >= +expires) {
        this.#otherTokens.splice(i, 1)
      }
    }

    const [result, keyId] = await encryptOtp(
      this.#context,
      dateNow + ARRAY_SEPARATOR + currentOtpToken + ARRAY_SEPARATOR + this.#otherTokens.join(OTP_SEPARATOR),
      this.#expires
    )

    setCookie(this.#context, COOKIE_OTP, result, cookieOptions)
    setCookie(this.#context, COOKIE_KEY_ID, keyId, cookieOptions)

    return lessPreciseExpiresDate

  }

}


/**
 * @async
 * @function getOtpInstance
 * @param {Context} c
 * @param {string} keyId
 * @param {string} token
 * @returns {Promise<[expires:number,resendBlockDate:string,credential:string,otp:string,attempts:string,otpBlockDate?:string]|undefined|null|false>}
 */
export async function getOtpInstance(
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

  const otpTokens = otpToken.split(ARRAY_SEPARATOR)

  if (otpTokens.length < 2) {
    return null
  }

  const lastValidAccess = otpTokens.shift()

  if (!lastValidAccess) {
    return null
  }

  const dateNow = Date.now()

  if (isLessThanDelay(+lastValidAccess, dateNow)) {
    return false
  }

  const currentOtpToken = otpTokens[0]?.split(OTP_SEPARATOR)

  // @ts-expect-error: TS doesn't detect that the current token must be a `string[]`.
  otpTokens[0] = currentOtpToken

  if (!currentOtpToken[0]) {
    return null
  }

  // @ts-expect-error: TS doesn't detect that `expires` must be a number.
  currentOtpToken[0] = +currentOtpToken[0]

  // @ts-expect-error: TS doesn't detect that `expires` must be a number.
  if (dateNow >= currentOtpToken[0]) {
    return null
  }

  // @ts-expect-error: TS doesn't detect that result is compatible with the return type.
  return currentOtpToken

}