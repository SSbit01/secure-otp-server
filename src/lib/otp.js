import { deleteCookie, setCookie } from "hono/cookie"

import {
  OTP_INVALID_BLOCK_MS, 
  OTP_MAX_AGE_MINUS,
  OTP_MAX_AGE_MS,
  OTP_RESEND_BLOCK_MS
} from "@/lib/computed"

import { createSymmetricKey, decryptTextSymmetrically, encryptTextSymmetrically } from "@/lib/crypto/symmetric"
import isProduction from "@/lib/production"
import { textEncoder, textDecoder } from "@/lib/text"
import { getReducedTimePrecision } from "@/lib/time"

import { createId, deleteId, replaceId, updateExpires } from "@/custom/id"
import { getCurrentKey, getKey, storeKey } from "@/custom/kms"

import {
  OTP_ALLOW_ONLY_ONE_RESENDING,
  OTP_ATTEMPTS_BLOCK,
  OTP_MAX_ATTEMPTS,
  OTP_MAX_CREDENTIALS,
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



const ARRAY_SEPARATOR = ","
const OTP_SEPARATOR = "|"


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



export const CREDENTIAL = 0
export const EXPIRES = 1
export const OTP = 2
export const ATTEMPTS = 3
export const RESEND_BLOCK = 4
export const OTP_BLOCK = 5

export const COOKIE_OTP_ENCRYPTED_TOKENS = "t"
export const COOKIE_OTP_KEY_ID = "k"


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

  // @ts-expect-error: TS doesn't know that this must be a `OtpToken` array.
  return otpToken

}


/**
 * @function deleteOtpCookies
 * @param {Context} c
 */
export function deleteOtpCookies(c) {
  deleteCookie(c, COOKIE_OTP_ENCRYPTED_TOKENS)
  deleteCookie(c, COOKIE_OTP_KEY_ID)
}


/**
 * @function getOtpTokenStrings
 * @param {Context} c
 * @param {(string|number)} keyId
 * @param {string} encryptedOtpTokens
 * @returns {Promise<string[]|undefined>}
 */
export async function getOtpTokenStrings(c, keyId, encryptedOtpTokens) {

  if (!keyId || !encryptedOtpTokens) {
    return
  }

  const key = await getKey(c, keyId)

  if (!key) {
    return
  }

  try {
    return (await decryptTextSymmetrically(
      key,
      encryptedOtpTokens,
      textDecoder
    ))?.split(ARRAY_SEPARATOR)
  } catch {
    // It simply returns `undefined`
  }

}



export class OtpTokenList {

  #context
  #dateNow
  #expires
  #id
  #tokens


  /**
   * @param {Context} c
   * @param {OtpToken[]} [tokens]
   * @param {(string|number)} [id]
   * @param {number} [expires]
   * @param {number} [createdAt]
   */
  constructor(c, tokens = [], id, expires = 0, createdAt = Date.now()) {

    this.#context = c
    this.#id = id
    this.#expires = expires
    this.#tokens = tokens.length > OTP_MAX_CREDENTIALS ? tokens.slice(0, OTP_MAX_CREDENTIALS) : tokens
    this.#dateNow = createdAt

  }


  /**
   * @returns {(OtpToken|undefined)}
   */
  get #current() {
    return this.#tokens.at(-1)
  }


  /**
   * @returns {boolean}
   */
  get #idValid() {
    return this.#id != undefined  // #id might be `0`
  }


  /**
   * @returns {(OtpTokenObject|undefined)}
   */
  get #object() {

    if (!this.#current) {
      return undefined
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
      const otpBlock = this.otpBlock
      if (otpBlock) {
        result.otpBlock = otpBlock
      }
    }

    return result

  }


  /**
   * @returns {boolean}
   */
  get blocked() {
    return this.#current ? !this.#current[OTP] : false
  }


  /**
   * @returns {(Date|undefined)}
   */
  get otpBlock() {
    const otpBlock = this.#current?.[OTP_BLOCK]
    return otpBlock ? new Date(getReducedTimePrecision(otpBlock)) : undefined
  }


  /**
   * @async
   * @returns {Promise<Date|undefined>}
   */
  async #save() {

    if (
      !this.#tokens.length ||
      !this.#expires ||
      !this.#idValid
    ) {
      deleteOtpCookies(this.#context)
      return
    }

    const lessPreciseExpires = new Date(getReducedTimePrecision(this.#expires))

    /**
     * @type {import("hono/utils/cookie").CookieOptions}
     */
    const cookieOptions = {
      expires: lessPreciseExpires,
      httpOnly: true,
      maxAge: OTP_MAX_AGE_MINUS,
      secure: isProduction(this.#context),
      sameSite: "strict",
      partitioned: false
    }

    /**
     * @type {CryptoKey}
     */
    let key

    /**
     * @type {(string|number)}
     */
    let keyId

    const currentKey = await getCurrentKey(this.#context)

    if (currentKey) {
      key = currentKey.key
      keyId = currentKey.id
    } else {
      key = await createSymmetricKey()
      keyId = await storeKey(this.#context, key)
    }

    setCookie(this.#context, COOKIE_OTP_KEY_ID, keyId.toString(), cookieOptions)

    const tokens = []

    for (const otpToken of this.#tokens) {
      tokens.push(otpToken.join(OTP_SEPARATOR))
    }

    tokens.push(Date.now())

    tokens.push(this.#id)

    setCookie(
      this.#context,
      COOKIE_OTP_ENCRYPTED_TOKENS,
      await encryptTextSymmetrically(key, tokens.join(ARRAY_SEPARATOR), textEncoder),
      cookieOptions
    )

    return lessPreciseExpires

  }


  deleteData() {

    deleteOtpCookies(this.#context)

    if (this.#expires && this.#idValid) {
      /**
       * Fire and forget
       */
      // @ts-expect-error: `#idValid` is true
      deleteId(this.#context, this.#id, this.#expires)
    }

  }


  /**
   * @param {string} otp
   * @returns {Promise<string|undefined>}
   */
  async check(otp) {

    if (
      this.blocked ||
      !this.#expires ||
      !this.#idValid ||
      (this.#current?.[OTP_BLOCK] && this.#dateNow <= this.#current[OTP_BLOCK])
    ) {
      return
    }
    
    // @ts-expect-error: `#current` is defined.
    if (this.#current[OTP] === otp) {
      // @ts-expect-error: `#current` and `#idValid` are not falsy.
      return await deleteId(this.#context, this.#id, this.#expires) ? decodeCredential(this.#current[CREDENTIAL]) : undefined
    }

    // @ts-expect-error: `#idValid` is true.
    const id = await replaceId(this.#context, this.#id, this.#expires)

    if (!id) {
      deleteOtpCookies(this.#context)
      return
    }

    this.#id = id

    // @ts-expect-error: `#current` is defined.
    this.#current[ATTEMPTS]--

    const attempts = this.#current?.[ATTEMPTS]

    if (!attempts) {
      /** Trim the array to save space. */
      // @ts-expect-error: `#current` and `#idValid` are not falsy.
      this.#current.length = OTP
    } else if (OTP_INVALID_BLOCK_MS && attempts <= OTP_ATTEMPTS_BLOCK) {
      this.#current[OTP_BLOCK] = this.#dateNow + OTP_INVALID_BLOCK_MS
    } else {
      /** Trim the array to save space. */
      this.#current.length = OTP_BLOCK
    }

    await this.#save()

  }


  async resend() {

    if (
      this.blocked ||
      !this.#idValid ||
      !this.#expires ||
      !this.#current?.[RESEND_BLOCK] ||
      this.#dateNow <= this.#current[RESEND_BLOCK]
    ) {
      return
    }

    // @ts-expect-error: `#idValid` is true.
    const expires = await updateExpires(this.#context, this.#id, this.#expires)

    if (!expires) {
      deleteOtpCookies(this.#context)
      return 
    }

    this.#current[EXPIRES] = expires

    this.#current[OTP] = createOtp()

    sendOtp(this.#context, decodeCredential(this.#current[CREDENTIAL]), this.#current[OTP])

    this.#current[EXPIRES] = this.#dateNow + OTP_MAX_AGE_MS

    if (OTP_ALLOW_ONLY_ONE_RESENDING) {
      delete this.#current[RESEND_BLOCK]
    } else {
      this.#current[RESEND_BLOCK] = this.#dateNow + OTP_RESEND_BLOCK_MS
    }

    await this.#save()

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

    const lastIndex = this.#tokens.length - 1

    for (let i = lastIndex - 1; i >= 0; i--) {
      const otpToken = this.#tokens[i]
      if (encodedCredential === otpToken[CREDENTIAL]) {
        this.#tokens[i] = this.#tokens[lastIndex]
        this.#tokens[lastIndex] = otpToken
        /**
         * Don't create a new key, reuse the existing one, the expiration date doesn't need to change.
         */
        await this.#save()
        return this.#object
      }
    }

    if (this.#tokens.length >= OTP_MAX_CREDENTIALS) {
      return
    }

    if (this.#idValid && this.#expires) {
      // @ts-expect-error: `#idValid` is true.
      this.#expires = await updateExpires(this.#context, this.#id, this.#expires)
      if (!this.#expires) {
        deleteOtpCookies(this.#context)
        return
      }
    } else {
      const idData = await createId(this.#context)
      this.#id = idData.id
      this.#expires = idData.expires
    }

    const otp = createOtp()

    sendOtp(this.#context, credential, otp)

    const resendBlock = this.#dateNow + OTP_RESEND_BLOCK_MS

    this.#tokens.push([encodedCredential, this.#expires, otp, OTP_MAX_ATTEMPTS, resendBlock])

    const expiresDate = await this.#save()

    return expiresDate && {
      expires: expiresDate,
      resendBlock: new Date(getReducedTimePrecision(resendBlock))
    }

  }

}