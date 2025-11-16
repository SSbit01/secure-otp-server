import { setCookie, deleteCookie } from "hono/cookie"

import { createRandomId } from "@/lib/crypto/id"
import { createSymmetricKey, decryptSymmetricallyText, encryptSymmetricallyText } from "@/lib/crypto/symmetric"
import isProduction from "@/lib/production"
import { textEncoder, textDecoder } from "@/lib/text"
import { getReducedTimePrecision } from "@/lib/time"

import { doesEncryptionKeyExist, storeEncryptionKey, deleteEncryptionKey } from "@/custom/kms"

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
 * @typedef {[credential:string,otp:string,attempts:number,expires:number,resendBlock?:number,otpBlock?:number]} OtpToken
 */

/**
 * @typedef {Object} OtpTokenTime
 * @property {OtpToken[EXPIRES]} expires
 * @property {OtpToken[RESEND_BLOCK]} [resendBlock]
 * @property {(OtpToken[OTP_BLOCK]|boolean)} [otpBlock]
 */



const CREDENTIAL = 0
const OTP = 1
const ATTEMPTS = 2
const EXPIRES = 3
const RESEND_BLOCK = 4
const OTP_BLOCK = 5

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
 * @function decodeOtpTokenString
 * @param {string} otpTokenString 
 * @param {number} [dateNow]
 * @returns {(OtpToken|undefined)}
 */
export function decodeOtpTokenString(otpTokenString, dateNow = Date.now()) {

  /**
   * @type {OtpToken}
   */
  // @ts-expect-error TS doesn't know that this must be a `OtpToken` array.
  const otpToken = otpTokenString.split(OTP_SEPARATOR)

  otpToken[EXPIRES] = +otpToken[EXPIRES]

  if (dateNow < otpToken[EXPIRES]) {
    otpToken[ATTEMPTS] = +otpToken[ATTEMPTS]
    otpToken[RESEND_BLOCK] = otpToken[RESEND_BLOCK] ? +otpToken[RESEND_BLOCK] : undefined
    otpToken[OTP_BLOCK] = otpToken[OTP_BLOCK] ? +otpToken[OTP_BLOCK] : undefined
    return otpToken
  }

}


/**
 * @function deleteOtpCookies
 * @param {Context} c
 */
export function deleteOtpCookies(c) {
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


/**
 * @function getOtpTokenStrings
 * @param {Context} c
 * @param {CryptoKey} key
 * @param {string} encryptedTokens
 * @returns {Promise<string[]|undefined>}
 */
export async function decryptOtpTokenStrings(c, key, encryptedTokens) {

  try {
    return (await decryptSymmetricallyText(
      key,
      encryptedTokens,
      textDecoder
    ))?.split(ARRAY_SEPARATOR)
  } catch {
    deleteOtpData(c)
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



export class OtpTokenList {

  #verified = false

  #context
  #tokens
  #key
  #createdAt


  /**
   * @param {Context} c
   * @param {OtpToken[]} [tokens]
   * @param {CryptoKey} [key]
   * @param {number} [createdAt]
   */
  constructor(c, tokens = [], key, createdAt = Date.now()) {

    this.#context = c
    this.#tokens = tokens.length > MAX_OTP_CREDENTIALS ? tokens.slice(0, MAX_OTP_CREDENTIALS) : tokens
    this.#key = key
    this.#createdAt = createdAt

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

    if (this.#current[RESEND_BLOCK]) {
      time.resendBlock = this.#current[RESEND_BLOCK]
    }

    if (this.#current[OTP_BLOCK]) {
      time.otpBlock = this.#current[OTP_BLOCK]
    } else if (!this.#current[ATTEMPTS]) {
      time.otpBlock = true
    }

    return time

  }


  get credential() {
    if (this.#verified) {
      return decodeCredential(this.#current[CREDENTIAL])
    }
  }


  /**
   * @async
   * @param {number} [dateNow]
   * @param {CryptoKey} [key]
   * @returns {Promise<number|undefined>}
   */
  async #save(dateNow = this.#createdAt, key) {

    const tokens = []

    let expires = 0

    for (const otpToken of this.#tokens) {
      if (dateNow < otpToken[EXPIRES]) {
        if (expires < otpToken[EXPIRES]) {
          expires = otpToken[EXPIRES]
        }
        if (otpToken[RESEND_BLOCK] && dateNow >= otpToken[RESEND_BLOCK]) {
          delete otpToken[RESEND_BLOCK]
        }
        if (otpToken[OTP_BLOCK] && dateNow >= otpToken[OTP_BLOCK]) {
          delete otpToken[OTP_BLOCK]
        }
        tokens.push(otpToken.join(OTP_SEPARATOR))
      }
    }

    if (!tokens.length) {
      deleteOtpData(this.#context)
      return
    }

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

    if (!key) {
      key = await createSymmetricKey()
      let keyId
      do {
        keyId = createRandomId()
      } while (await doesEncryptionKeyExist(this.#context, keyId))
      await storeEncryptionKey(this.#context, keyId, key, expires)
      deleteOtpData(this.#context)
      setCookie(this.#context, COOKIE_KEY_ID, keyId, cookieOptions)
    }

    /**
     * Add `lastAccess` at the beginning
     */
    tokens.unshift(Date.now())
    
    setCookie(
      this.#context,
      COOKIE_ENCRYPTED_TOKENS,
      await encryptSymmetricallyText(key, tokens.join(ARRAY_SEPARATOR), textEncoder),
      cookieOptions
    )

    return lessPreciseExpiresDate

  }


  /**
   * @param {string} otp
   * @returns {Promise<boolean>}
   */
  async check(otp) {

    if (this.#current[OTP_BLOCK] && this.#current[OTP_BLOCK] > this.#createdAt) {
      return false
    }

    if (this.#current[OTP] === otp) {
      return this.#verified = true
    }

    this.#current[ATTEMPTS]--
  
    /**
     * Is `attempts` 0?
     */
    if (this.#current[ATTEMPTS] <= 0) {
      return false
    }

    if (INVALID_BLOCK_MS && this.#current[ATTEMPTS] <= ATTEMPTS_BLOCK) {
      this.#current[OTP_BLOCK] = this.#createdAt + INVALID_BLOCK_MS
    } else {
      delete this.#current[OTP_BLOCK]
    }

    await this.#save()

    return this.#current[OTP_BLOCK] || 0

  }


  async resend() {

    if (!this.#current[RESEND_BLOCK] || this.#current[ATTEMPTS] <= 0 || this.#createdAt < this.#current[RESEND_BLOCK]) {
      return
    }

    this.#current[OTP] = createOtp()

    await sendOtp(this.#context, decodeCredential(this.#current[CREDENTIAL]), this.#current[OTP])

    const dateNow = Date.now()

    this.#current[EXPIRES] = dateNow + MAX_DURATION_MS

    if (ALLOW_ONLY_ONE_RESENDING) {
      delete this.#current[RESEND_BLOCK]
    } else {
      this.#current[RESEND_BLOCK] = dateNow + RESEND_BLOCK_MS
    }

    await this.#save(dateNow)

    return this.#time

  }


  /**
   * @param {string} credential
   * @returns {Promise<OtpTokenTime|undefined>}
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
        /**
         * Don't create a new key, reuse the existing one, the expiration date doesn't need to change.
         */
        await this.#save(Date.now(), this.#key)
        return this.#time
      }
    }

    if (this.#tokens.length >= MAX_OTP_CREDENTIALS) {
      return
    }

    const otp = createOtp()

    await sendOtp(this.#context, credential, otp)

    const dateNow = Date.now()

    const expires = dateNow + MAX_DURATION_MS
    const resendBlock = dateNow + RESEND_BLOCK_MS

    this.#tokens.unshift([encodedCredential, otp, MAX_ATTEMPTS, expires, resendBlock])

    await this.#save(dateNow)

    return {
      expires,
      resendBlock
    }

  }

}
