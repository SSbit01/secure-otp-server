import { setCookie, deleteCookie } from "hono/cookie"

import { encryptOtp, decryptOtp } from "@/lib/crypto/otp"
import isProduction from "@/lib/production"
import { getReducedTimePrecision, isLessThanDelay } from "@/lib/time"

import { ALLOW_ONLY_ONE_RESENDING, ATTEMPTS_BLOCK, INVALID_BLOCK_SECONDS, MAX_ATTEMPTS, MAX_DURATION_SECONDS, MAX_OTP_TOKENS_SESSION, RESEND_BLOCK_SECONDS, createOtp } from "@/custom/otp"
import sendOtp from "@/custom/send"

/**
 * @import { Context } from "hono"
 */

/**
 * @typedef {[credential:string,otp:string,attempts:number,expires:number,resendBlockDate?:number,otpBlockDate?:number]} OtpToken
 */

/**
 * @typedef {Object} OtpTokenResponse
 * @property {OtpToken[EXPIRES]} expires
 * @property {OtpToken[RESEND_BLOCK_DATE]} [resendBlockDate]
 * @property {OtpToken[OTP_BLOCK_DATE]} [otpBlockDate]
 */


const CREDENTIAL = 0
const OTP = 1
const ATTEMPTS = 2
const EXPIRES = 3
const RESEND_BLOCK_DATE = 4
const OTP_BLOCK_DATE = 5


const ARRAY_SEPARATOR = ","
const OTP_SEPARATOR = "|"

const INVALID_BLOCK_MS = INVALID_BLOCK_SECONDS * 1000
const MAX_DURATION_MS = MAX_DURATION_SECONDS * 1000
const RESEND_BLOCK_MS = RESEND_BLOCK_SECONDS * 1000


export const COOKIE_KEY_ID = "e"
export const COOKIE_OTP = "t"


/**
 * @function encodeCredential
 * @param {string} credential
 * @returns {string}
 */
function encodeCredential(credential) {
  return encodeURI(credential.toString())
}


/**
 * @function decodeCredential
 * @param {string} encodedCredential
 * @returns {string}
 */
function decodeCredential(encodedCredential) {
  return decodeURI(encodedCredential)
}


/**
 * @async
 * @function createOtpAndSend
 * @param {Context} c
 * @param {string} credential
 */
export async function createOtpAndSend(c, credential) {
  return await new OtpTokenList(c).set(credential)
}


/**
 * @function deleteOtpCookies
 * @param {Context} c
 */
export function deleteOtpCookies(c) {
  deleteCookie(c, COOKIE_OTP)
  deleteCookie(c, COOKIE_KEY_ID)
}



class OtpTokenList {

  #context
  #tokens


  /**
   * @param {Context} c
   * @param {OtpToken[]} tokens
   */
  constructor(c, tokens = []) {

    this.#context = c
    this.#tokens = tokens

  }


  get #current() {
    return this.#tokens[0]
  }


  /**
   * @param {string} otp
   * @returns {Promise<false|string|number|undefined>}
   */
  async check(otp) {

    if (this.#current[OTP_BLOCK_DATE] && this.#current[OTP_BLOCK_DATE] > Date.now()) {
      return false
    }

    if (this.#current[OTP] === otp) {
      return decodeCredential(this.#current[CREDENTIAL])
    }

    this.#current[ATTEMPTS]--
  
    /**
     * Is `attempts` 0?
     */
    if (this.#current[ATTEMPTS] <= 1) {
      return false
    }

    if (INVALID_BLOCK_MS && this.#current[ATTEMPTS] <= ATTEMPTS_BLOCK) {
      this.#current[OTP_BLOCK_DATE] = Date.now() + INVALID_BLOCK_MS
    }

    await this.save()

    return this.#current[OTP_BLOCK_DATE]

  }


  async resend() {

    if (!this.#current[RESEND_BLOCK_DATE] || Date.now() < this.#current[RESEND_BLOCK_DATE]) {
      return false
    }

    this.#current[OTP] = createOtp()

    await sendOtp(this.#context, decodeCredential(this.#current[CREDENTIAL]), this.#current[OTP])

    const dateNow = Date.now()

    /**
     * @type {OtpTokenResponse}
     */
    const res = { expires: dateNow + MAX_DURATION_MS }

    if (ALLOW_ONLY_ONE_RESENDING) {
      delete this.#current[RESEND_BLOCK_DATE]
    } else {
      this.#current[RESEND_BLOCK_DATE] = dateNow + RESEND_BLOCK_MS
      res.resendBlockDate = this.#current[RESEND_BLOCK_DATE]
    }

    await this.save(dateNow)

    return res

  }


  async save(dateNow = Date.now()) {

    const tokens = []

    let expires = 0

    for (const otpToken of this.#tokens) {
      if (dateNow < otpToken[EXPIRES]) {
        if (otpToken[EXPIRES] > expires) {
          expires = otpToken[EXPIRES]
        }
        tokens.push(otpToken.join(OTP_SEPARATOR))
      }
    }

    if (!tokens.length) {
      return false
    }

    const [result, keyId] = await encryptOtp(this.#context, tokens.join(ARRAY_SEPARATOR), expires)

    const lessPreciseExpiresDate = getReducedTimePrecision(expires)

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

    setCookie(this.#context, COOKIE_OTP, result, cookieOptions)
    setCookie(this.#context, COOKIE_KEY_ID, keyId, cookieOptions)

    return lessPreciseExpiresDate

  }


  /**
   * @param {string} credential
   * @returns {Promise<OtpTokenResponse|false>}
   */
  async set(credential) {

    const encodedCredential = encodeCredential(credential)

    for (let i = 0; i < this.#tokens.length; i++) {
      const otpToken = this.#tokens[i]
      if (otpToken[CREDENTIAL] === encodedCredential) {
        this.#tokens[i] = this.#tokens[0]
        this.#tokens[0] = otpToken
        await this.save()
        /**
         * @type {OtpTokenResponse}
         */
        const res = {
          expires: otpToken[EXPIRES]
        }
        if (otpToken[RESEND_BLOCK_DATE]) {
          res.resendBlockDate = otpToken[RESEND_BLOCK_DATE]
        }
        if (otpToken[OTP_BLOCK_DATE]) {
          res.otpBlockDate = otpToken[OTP_BLOCK_DATE]
        }
        return res
      }
    }

    if (this.#tokens.length >= MAX_OTP_TOKENS_SESSION) {
      return false
    }

    const otp = createOtp()

    await sendOtp(this.#context, credential, otp)

    const dateNow = Date.now()

    const expires = dateNow + MAX_DURATION_MS
    const resendBlockDate = dateNow + RESEND_BLOCK_MS

    this.#tokens.unshift([encodedCredential, otp, MAX_ATTEMPTS, expires, resendBlockDate])

    await this.save(dateNow)

    return {
      expires,
      resendBlockDate
    }

  }

}


/**
 * @async
 * @function getOtpInstance
 * @param {Context} c
 * @param {string} keyId
 * @param {string} token
 * @returns {Promise<Readonly<OtpTokenList>|undefined|false>}
 */
export async function getOtpInstance(c, keyId, token) {

  /**
   * @type {(string|undefined)}
   */
  let otpToken

  try {
    otpToken = await decryptOtp(c, keyId, token)
  } catch {
    return
  }

  if (!otpToken) {
    return
  }

  const otpStringTokens = otpToken.split(ARRAY_SEPARATOR)

  if (otpStringTokens.length < 2) {
    return
  }

  const lastValidAccess = otpStringTokens.shift()

  if (!lastValidAccess) {
    return
  }

  const dateNow = Date.now()

  if (isLessThanDelay(+lastValidAccess, dateNow)) {
    deleteOtpCookies(c)
    return false
  }

  /**
   * @type {OtpToken[]}
   */
  const otpTokens = []

  for (const otpStringToken of otpStringTokens) {
    /**
     * @type {OtpToken}
     */
    // @ts-expect-error TS doesn't know that this must be a `OtpToken` array.
    const otpToken = otpStringToken.split(OTP_SEPARATOR)
    otpToken[EXPIRES] = +otpToken[EXPIRES]
    if (dateNow < otpToken[EXPIRES]) {
      otpToken[ATTEMPTS] = +otpToken[ATTEMPTS]
      otpToken[RESEND_BLOCK_DATE] = otpToken[RESEND_BLOCK_DATE] ? +otpToken[RESEND_BLOCK_DATE] : undefined
      otpToken[OTP_BLOCK_DATE] = otpToken[OTP_BLOCK_DATE] ? +otpToken[OTP_BLOCK_DATE] : undefined
      otpTokens.push(otpToken)
    }
  }

  
  return Object.freeze(new OtpTokenList(c, otpTokens))

}