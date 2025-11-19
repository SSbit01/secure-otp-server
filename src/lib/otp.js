import { deleteCookie, getCookie, setCookie } from "hono/cookie"
import { HTTPException } from "hono/http-exception"

import { createRandomId, isRandomIdValid } from "@/lib/crypto/id"
import { createSymmetricKey, decryptSymmetricallyText, encryptSymmetricallyText } from "@/lib/crypto/symmetric"
import { ERR_OTP_INVALID_COOKIE } from "@/lib/error/static"
import isProduction from "@/lib/production"
import { textEncoder, textDecoder } from "@/lib/text"
import { getReducedTimePrecision } from "@/lib/time"

import { storeEncryptionKey, deleteEncryptionKey } from "@/custom/kms"

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
 * @typedef {[credential:string,expires:number,otp?:string,attempts?:number,resendBlock?:number,otpBlock?:number]} OtpToken
 */

/**
 * @typedef {Object} OtpTokenObject
 * @property {Date} expires
 * @property {boolean} [blocked]
 * @property {Date} [resendBlock]
 * @property {Date} [otpBlock]
 */



const CREDENTIAL = 0
const EXPIRES = 1
const OTP = 2
const ATTEMPTS = 3
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


/**
 * @function handleDeleteEncryptionKeyException
 * @param {any} error
 */
function handleDeleteEncryptionKeyException(error) {
  console.error("ERROR DURING KEY ID DELETION", error)
}



export const COOKIE_KEY_ID = "e"
export const COOKIE_ENCRYPTED_TOKENS = "t"



/**
 * @function areOtpParametersValid
 * @param {string} keyId
 * @param {string} encryptedTokens
 * @returns {boolean}
 */
export function areOtpParametersValid(keyId, encryptedTokens) {
  return Boolean(encryptedTokens && keyId) && isRandomIdValid(keyId)
}


/**
 * @function decodeOtpTokenString
 * @param {string} otpTokenString 
 * @param {number} [dateNow]
 * @returns {(OtpToken|undefined)}
 */
export function decodeOtpTokenString(otpTokenString, dateNow = Date.now()) {

  /**
   * @type {any[]}
   */
  const otpToken = otpTokenString.split(OTP_SEPARATOR)

  otpToken[EXPIRES] = +otpToken[EXPIRES]

  if (dateNow >= otpToken[EXPIRES]) {
    return
  }

  if (otpToken[ATTEMPTS]) {
    otpToken[ATTEMPTS] = +otpToken[ATTEMPTS]
    if (otpToken[OTP_BLOCK]) {
      const otpBlock = +otpToken[OTP_BLOCK]
      if (dateNow < otpBlock) {
        otpToken[OTP_BLOCK] = otpBlock
        otpToken[RESEND_BLOCK] &&= +otpToken[RESEND_BLOCK]
      } else if (otpToken[RESEND_BLOCK]) {
        otpToken[RESEND_BLOCK] = +otpToken[RESEND_BLOCK]
        /** Trim the array to save space. */
        otpToken.length = OTP_BLOCK
      } else {
        /** Trim the array to save space. */
        otpToken.length = RESEND_BLOCK
      }
    } else {
      otpToken[RESEND_BLOCK] &&= +otpToken[RESEND_BLOCK]
    }
  }

  // @ts-expect-error TS doesn't know that this must be a `OtpToken` array.
  return otpToken

}


/**
 * @function decodeOtpTokenStringArray
 * @param {string[]} otpTokenStrings
 * @param {number} [dateNow]
 * @returns {OtpToken[]}
 */
export function decodeOtpTokenStringArray(otpTokenStrings, dateNow = Date.now()) {

  const otpTokens = []

  for (const otpTokenString of otpTokenStrings) {
    const otpToken = decodeOtpTokenString(otpTokenString, dateNow)
    if (otpToken) {
      otpTokens.push(otpToken)
    }
  }

  return otpTokens

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
    deleteEncryptionKey(c, keyId).catch(handleDeleteEncryptionKeyException)
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



export class OtpTokenList {

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
    return this.#tokens.at(-1)
  }


  get #object() {

    if (!this.#current) {
      return
    }

    /**
     * @type {OtpTokenObject}
     */
    const result = {
      expires: new Date(getReducedTimePrecision(this.#current[EXPIRES]))
    }

    if (this.blocked) {
      result.blocked = true
    } else {
      if (this.#current[RESEND_BLOCK]) {
        result.resendBlock = new Date(getReducedTimePrecision(this.#current[RESEND_BLOCK]))
      }
      if (this.#current[OTP_BLOCK]) {
        result.otpBlock = new Date(getReducedTimePrecision(this.#current[OTP_BLOCK]))
      }
    }

    return result

  }


  get blocked() {
    return this.#current && !this.#current[OTP]
  }


  get otpBlock() {
    return this.#current?.[OTP_BLOCK]
  }


  /**
   * @async
   * @param {number} [dateNow]
   * @param {CryptoKey} [key]
   * @returns {Promise<Date>}
   */
  async #save(dateNow = this.#createdAt, key) {

    const tokens = []

    let expires = 0

    for (const otpToken of this.#tokens) {
      if (dateNow < otpToken[EXPIRES]) {
        if (expires < otpToken[EXPIRES]) {
          expires = otpToken[EXPIRES]
        }
        if (otpToken[ATTEMPTS] && (!otpToken[OTP_BLOCK] || dateNow >= otpToken[OTP_BLOCK])) {
          /** Trim the array to save space. */
          otpToken.length = otpToken[RESEND_BLOCK] ? OTP_BLOCK : RESEND_BLOCK
        }
        tokens.push(otpToken.join(OTP_SEPARATOR))
      }

    }

    if (!tokens.length) {
      deleteOtpData(this.#context)
      throw new HTTPException(400, {
        res: Response.json(ERR_OTP_INVALID_COOKIE)
      })
    }

    const lessPreciseExpires = new Date(getReducedTimePrecision(expires))

    /**
     * @type {import("hono/utils/cookie").CookieOptions}
     */
    const cookieOptions = {
      expires: lessPreciseExpires,
      httpOnly: true,
      maxAge: MAX_DURATION_SECONDS,
      secure: isProduction(this.#context),
      sameSite: "strict",
      partitioned: false
    }

    if (key) {
      /**
       * Add `lastAccess` at the beginning
       */
      tokens.push(dateNow)
    } else {
      key = await createSymmetricKey()
      const expiresDate = new Date(expires)
      let keyId
      do {
        keyId = createRandomId()
      } while (!await storeEncryptionKey(this.#context, keyId, key, expiresDate))
      const oldKeyId = getCookie(this.#context, COOKIE_KEY_ID)
      if (oldKeyId) {
        deleteEncryptionKey(this.#context, oldKeyId).catch(handleDeleteEncryptionKeyException)
      }
      setCookie(this.#context, COOKIE_KEY_ID, keyId, cookieOptions)
      this.#key = key
    }

    /**
     * Add `lastAccess` at the beginning
     */
    tokens.push(Date.now())
    
    setCookie(
      this.#context,
      COOKIE_ENCRYPTED_TOKENS,
      await encryptSymmetricallyText(key, tokens.join(ARRAY_SEPARATOR), textEncoder),
      cookieOptions
    )

    return lessPreciseExpires

  }


  /**
   * @param {string} otp
   * @returns {Promise<string|undefined>}
   */
  async check(otp) {

    if (!this.#current || this.blocked || (this.#current[OTP_BLOCK] && this.#createdAt < this.#current[OTP_BLOCK])) {
      return
    }

    if (this.#current[OTP] === otp) {
      return decodeCredential(this.#current[CREDENTIAL])
    }

    /** @ts-expect-error TS doesn't know that this must be a `number`, because `this.blocked` is false. */
    this.#current[ATTEMPTS]--
  
    if (this.blocked) {
      /** Trim the array to save space. */
      this.#current.length = OTP
      /** @ts-expect-error TS doesn't know that this must be a `number`, because `this.blocked` is false. */
    } else if (INVALID_BLOCK_MS && this.#current[ATTEMPTS] <= ATTEMPTS_BLOCK) {
      this.#current[OTP_BLOCK] = this.#createdAt + INVALID_BLOCK_MS
    } else {
      /** Trim the array to save space. */
      this.#current.length = OTP_BLOCK
    }

    await this.#save()

  }


  async resend() {

    if (this.blocked || !this.#current?.[RESEND_BLOCK] || this.#createdAt < this.#current[RESEND_BLOCK]) {
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

    return this.#object

  }


  /**
   * @param {string} credential
   * @returns {Promise<OtpTokenObject|undefined>}
   */
  async set(credential) {

    const encodedCredential = encodeCredential(credential)

    /**
     * Don't need to save and encrypt the token list again if the current token contains the `credential`.
     */
    if (encodedCredential === this.#current?.[CREDENTIAL]) {
      return this.#object
    }

    for (let i = 1; i < this.#tokens.length; i++) {
      const otpToken = this.#tokens[i]
      if (encodedCredential === otpToken[CREDENTIAL]) {
        this.#tokens[i] = this.#tokens[0]
        this.#tokens[0] = otpToken
        /**
         * Don't create a new key, reuse the existing one, the expiration date doesn't need to change.
         */
        await this.#save(this.#createdAt, this.#key)
        return this.#object
      }
    }

    if (this.#tokens.length >= MAX_OTP_CREDENTIALS) {
      return
    }

    const otp = createOtp()

    await sendOtp(this.#context, credential, otp)

    const dateNow = Date.now()

    const resendBlock = dateNow + RESEND_BLOCK_MS

    this.#tokens.push([encodedCredential, dateNow + MAX_DURATION_MS, otp, MAX_ATTEMPTS, resendBlock])

    return {
      expires: await this.#save(dateNow),
      resendBlock: new Date(getReducedTimePrecision(resendBlock))
    }

  }

}