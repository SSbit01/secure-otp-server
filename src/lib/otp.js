import { setCookie, deleteCookie } from "hono/cookie"

import { isRandomIdValid } from "@/lib/crypto/id"
import { encryptOtp, decryptOtp } from "@/lib/crypto/otp"
import isProduction from "@/lib/production"
import { getReducedTimePrecision, isLessThanDelay } from "@/lib/time"

import { deleteEncryptionKey } from "@/custom/kms"

import {
  ALLOW_ONLY_ONE_RESENDING,
  ATTEMPTS_BLOCK,
  INVALID_BLOCK_SECONDS,
  MAX_ATTEMPTS,
  MAX_DURATION_SECONDS,
  MAX_OTP_CREDENTIALS,
  RESEND_BLOCK_SECONDS,
  createOtp
} from "@/custom/otp"

import sendOtp from "@/custom/send"


/**
 * @import { Context } from "hono"
 */


/**
 * @typedef {[credential:string,otp:string,attempts:number,expires:number,resendBlockUntil?:number,otpBlockUntil?:number]} OtpToken
 */

/**
 * @typedef {Object} OtpTokenTime
 * @property {OtpToken[EXPIRES]} expires
 * @property {OtpToken[RESEND_BLOCK_UNTIL]} [resendBlockUntil]
 * @property {OtpToken[OTP_BLOCK_UNTIL]} [otpBlockUntil]
 */



const CREDENTIAL = 0
const OTP = 1
const ATTEMPTS = 2
const EXPIRES = 3
const RESEND_BLOCK_UNTIL = 4
const OTP_BLOCK_UNTIL = 5


const ARRAY_SEPARATOR = ","
const OTP_SEPARATOR = "|"

const INVALID_BLOCK_MS = INVALID_BLOCK_SECONDS * 1000
const MAX_DURATION_MS = MAX_DURATION_SECONDS * 1000
const RESEND_BLOCK_MS = RESEND_BLOCK_SECONDS * 1000


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



export const COOKIE_KEY_ID = "e"
export const COOKIE_ENCRYPTED_TOKENS = "t"



/**
 * @function deleteOtpCookies
 * @param {Context} c
 */
function deleteOtpCookies(c) {
  deleteCookie(c, COOKIE_ENCRYPTED_TOKENS)
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
     * Fire and forget
     */
    deleteEncryptionKey(c, keyId)
  }

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


  get #time() {

    /**
     * @type {OtpTokenTime}
     */
    const time = {
      expires: this.#current[EXPIRES]
    }

    if (this.#current[RESEND_BLOCK_UNTIL]) {
      time.resendBlockUntil = this.#current[RESEND_BLOCK_UNTIL]
    }

    if (this.#current[OTP_BLOCK_UNTIL]) {
      time.otpBlockUntil = this.#current[OTP_BLOCK_UNTIL]
    }

    return time

  }


  async #save(dateNow = Date.now()) {

    deleteOtpData(this.#context)

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

    const [keyId, result] = await encryptOtp(this.#context, tokens.join(ARRAY_SEPARATOR), expires)

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

    setCookie(this.#context, COOKIE_KEY_ID, keyId, cookieOptions)
    setCookie(this.#context, COOKIE_ENCRYPTED_TOKENS, result, cookieOptions)

    return lessPreciseExpiresDate

  }


  /**
   * @param {string} otp
   * @returns {Promise<false|string|number|undefined>}
   */
  async check(otp) {

    if (this.#current[OTP_BLOCK_UNTIL] && this.#current[OTP_BLOCK_UNTIL] > Date.now()) {
      deleteOtpData(this.#context)
      return false
    }

    if (this.#current[OTP] === otp) {
      return decodeCredential(this.#current[CREDENTIAL])
    }

    this.#current[ATTEMPTS]--
  
    /**
     * Is `attempts` 0?
     */
    if (this.#current[ATTEMPTS] <= 0) {
      return false
    }

    const dateNow = Date.now()

    if (INVALID_BLOCK_MS && this.#current[ATTEMPTS] <= ATTEMPTS_BLOCK) {
      this.#current[OTP_BLOCK_UNTIL] = dateNow + INVALID_BLOCK_MS
    } else {
      delete this.#current[OTP_BLOCK_UNTIL]
    }

    await this.#save(dateNow)

    return this.#current[OTP_BLOCK_UNTIL]

  }


  async resend() {

    if (!this.#current[RESEND_BLOCK_UNTIL] || Date.now() < this.#current[RESEND_BLOCK_UNTIL]) {
      deleteOtpData(this.#context)
      return false
    }

    this.#current[OTP] = createOtp()

    await sendOtp(this.#context, decodeCredential(this.#current[CREDENTIAL]), this.#current[OTP])

    const dateNow = Date.now()

    /**
     * @type {OtpTokenTime}
     */
    const time = { expires: dateNow + MAX_DURATION_MS }

    if (ALLOW_ONLY_ONE_RESENDING) {
      delete this.#current[RESEND_BLOCK_UNTIL]
    } else {
      this.#current[RESEND_BLOCK_UNTIL] = dateNow + RESEND_BLOCK_MS
      time.resendBlockUntil = this.#current[RESEND_BLOCK_UNTIL]
    }

    await this.#save(dateNow)

    return time

  }


  /**
   * @param {string} credential
   * @returns {Promise<false|OtpTokenTime>}
   */
  async set(credential) {

    const encodedCredential = encodeCredential(credential)

    /**
     * Don't need to save and encrypt the token list again if the current token contains the `credential`.
     */
    if (encodedCredential === this.#current?.[CREDENTIAL]) {
      return this.#time
    }

    for (let i = 1; i < this.#tokens.length; i++) {
      const otpToken = this.#tokens[i]
      if (encodedCredential === otpToken[CREDENTIAL]) {
        this.#tokens[i] = this.#tokens[0]
        this.#tokens[0] = otpToken
        await this.#save()
        return this.#time
      }
    }

    if (this.#tokens.length >= MAX_OTP_CREDENTIALS) {
      return false
    }

    const otp = createOtp()

    await sendOtp(this.#context, credential, otp)

    const dateNow = Date.now()

    const expires = dateNow + MAX_DURATION_MS
    const resendBlockUntil = dateNow + RESEND_BLOCK_MS

    this.#tokens.unshift([encodedCredential, otp, MAX_ATTEMPTS, expires, resendBlockUntil])

    await this.#save(dateNow)

    return {
      expires,
      resendBlockUntil
    }

  }

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
 * @async
 * @function getOtpInstance
 * @param {Context} c
 * @param {string} keyId
 * @param {string} encryptedTokens
 * @returns {Promise<Readonly<OtpTokenList>|undefined|false>}
 */
export async function getOtpInstance(c, keyId, encryptedTokens) {

  if (!encryptedTokens || !keyId || !isRandomIdValid(keyId)) {
    deleteOtpCookies(c)
    return
  }

  /**
   * @type {(string|undefined)}
   */
  let tokens

  try {
    tokens = await decryptOtp(c, keyId, encryptedTokens)
  } catch {
    return
  }

  if (!tokens) {
    deleteOtpCookies(c)
    return
  }

  const otpStringTokens = tokens.split(ARRAY_SEPARATOR)

  if (otpStringTokens.length < 2) {
    deleteOtpData(c)
    return
  }

  const lastValidAccess = otpStringTokens.shift()

  if (!lastValidAccess) {
    deleteOtpData(c)
    return
  }

  /**
   * @type {OtpToken[]}
   */
  const otpTokens = []

  const dateNow = Date.now()

  for (const otpStringToken of otpStringTokens) {
    /**
     * @type {OtpToken}
     */
    // @ts-expect-error TS doesn't know that this must be a `OtpToken` array.
    const otpToken = otpStringToken.split(OTP_SEPARATOR)
    otpToken[EXPIRES] = +otpToken[EXPIRES]
    if (dateNow < otpToken[EXPIRES]) {
      otpToken[ATTEMPTS] = +otpToken[ATTEMPTS]
      otpToken[RESEND_BLOCK_UNTIL] = otpToken[RESEND_BLOCK_UNTIL] ? +otpToken[RESEND_BLOCK_UNTIL] : undefined
      otpToken[OTP_BLOCK_UNTIL] = otpToken[OTP_BLOCK_UNTIL] ? +otpToken[OTP_BLOCK_UNTIL] : undefined
      otpTokens.push(otpToken)
    }
  }

  if (!otpTokens.length) {
    deleteOtpData(c)
    return
  }

  if (isLessThanDelay(+lastValidAccess, dateNow)) {
    deleteOtpData(c)
    return false
  }
  
  return Object.freeze(new OtpTokenList(c, otpTokens))

}