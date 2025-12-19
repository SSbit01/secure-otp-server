import { setCookie } from "hono/cookie"

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

import { compressNumber } from "@/lib/compression/number"
import { OTP_INVALID_BLOCK_MS, OTP_RESEND_BLOCK_MS } from "@/lib/computed"
import { createSymmetricKey, decryptTextSymmetrically, encryptTextSymmetrically } from "@/lib/crypto/symmetric"
import deleteOtpCookies, { COOKIE_OTP_ENCRYPTED_TOKENS, COOKIE_OTP_KEY_ID } from "@/lib/otp/cookie"
import { encodeCredential, decodeCredential } from "@/lib/otp/encode/credential"
import { encodeOtpToken } from "@/lib/otp/encode/token"
import { CREDENTIAL, EXPIRES, OTP, ATTEMPTS, RESEND_BLOCK, OTP_BLOCK } from "@/lib/otp/order"
import isProduction from "@/lib/production"
import { textEncoder, textDecoder } from "@/lib/text"
import { getReducedTimePrecision } from "@/lib/time"



/**
 * @import { Context } from "hono"
 * @import { OtpToken } from "@/lib/otp/order"
 */


/**
 * @typedef {Object} OtpTokenData
 * @property {Date} expires
 * @property {boolean} [blocked]
 * @property {Date} [resendBlock]
 * @property {Date} [otpBlock]
 */



const ARRAY_SEPARATOR = ","



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
    // It simply returns `undefined`.
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
   * @returns {(OtpTokenData|undefined)}
   */
  get #data() {

    if (!this.#current) {
      return undefined
    }

    /**
     * @type {OtpTokenData}
     */
    const result = {
      expires: new Date(getReducedTimePrecision(this.#current[EXPIRES]))
    }

    if (this.blocked) {
      result.blocked = true
    } else {
      if (this.#current[RESEND_BLOCK]) {
        result.resendBlock = new Date(getReducedTimePrecision(this.#current[RESEND_BLOCK], Math.ceil))
      }
      const { otpBlock } = this
      if (otpBlock) {
        result.otpBlock = otpBlock
      }
    }

    return result

  }


  /**
   * @returns {boolean}
   */
  get #idValid() {
    return this.#id != undefined  // #id might be `0`.
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
    return otpBlock ? new Date(getReducedTimePrecision(otpBlock, Math.ceil)) : undefined
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

    const encodedTokens = this.#tokens.map(encodeOtpToken)

    // @ts-expect-error: `#idValid` is true.
    encodedTokens.push(this.#id)

    this.#dateNow = Date.now()

    encodedTokens.push(compressNumber(this.#dateNow))

    const encryptedTokens = await encryptTextSymmetrically(
      key,
      encodedTokens.join(ARRAY_SEPARATOR),
      textEncoder
    )

    const lessPreciseExpires = new Date(getReducedTimePrecision(this.#expires))

    /**
     * @type {import("hono/utils/cookie").CookieOptions}
     */
    const cookieOptions = {
      expires: lessPreciseExpires,
      httpOnly: true,
      secure: isProduction(this.#context),
      sameSite: "strict",
      partitioned: false
    }

    setCookie(
      this.#context,
      COOKIE_OTP_KEY_ID,
      keyId.toString(),
      cookieOptions
    )

    setCookie(
      this.#context,
      COOKIE_OTP_ENCRYPTED_TOKENS,
      encryptedTokens,
      cookieOptions
    )

    return lessPreciseExpires

  }


  /**
   * @param {string} otp
   * @returns {Promise<string|undefined>}
   */
  async check(otp) {

    /**
     * [OTP_BLOCK] already checked in decoding.
     */

    if (
      this.blocked ||
      !this.#expires ||
      !this.#idValid ||
      this.#current?.[OTP_BLOCK]
    ) {
      return
    }
    
    // @ts-expect-error: `#current` is defined.
    if (this.#current[OTP] === otp) {
      deleteOtpCookies(this.#context)
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

    /**
     * Presence of this.#current[RESEND_BLOCK] indicates that resending is available.
     */

    if (
      this.blocked ||
      !this.#idValid ||
      !this.#expires ||
      !this.#current?.[RESEND_BLOCK] ||
      this.#dateNow < this.#current[RESEND_BLOCK]
    ) {
      return
    }

    // @ts-expect-error: `#idValid` is true.
    this.#expires = await updateExpires(this.#context, this.#id, this.#expires)

    if (!this.#expires) {
      deleteOtpCookies(this.#context)
      return 
    }

    this.#current[EXPIRES] = this.#expires

    this.#current[OTP] = createOtp()

    sendOtp(this.#context, decodeCredential(this.#current[CREDENTIAL]), this.#current[OTP])

    if (OTP_ALLOW_ONLY_ONE_RESENDING) {
      if (this.#current[OTP_BLOCK]) {
        delete this.#current[RESEND_BLOCK]
      } else {
        /** Trim the array to save space. */
        this.#current.length = RESEND_BLOCK
      }
    } else {
      this.#current[RESEND_BLOCK] = this.#dateNow + OTP_RESEND_BLOCK_MS
    }

    await this.#save()

    return this.#data

  }


  /**
   * @param {string} credential
   * @returns {Promise<OtpTokenData|undefined>}
   */
  async set(credential) {

    const encodedCredential = encodeCredential(credential)

    /**
     * Don't need to save and encrypt the token list again if the current token contains the `credential`.
     */
    if (encodedCredential === this.#current?.[CREDENTIAL]) {
      return this.#data
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
        return this.#data
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
      resendBlock: new Date(getReducedTimePrecision(resendBlock, Math.ceil))
    }

  }

}