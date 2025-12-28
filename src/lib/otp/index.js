import { setCookie } from "hono/cookie"

import { createEncryptedOtpTokenListId, deleteOtpTokenId, replaceOtpTokenId, updateOtpTokenExpires } from "@/custom/id"
import { getCurrentKekId, getKek, storeKek } from "@/custom/kms"

import {
  OTP_ALLOW_ONLY_ONE_RESENDING,
  OTP_ATTEMPTS_BLOCK,
  OTP_MAX_ATTEMPTS,
  OTP_MAX_CREDENTIALS,
  createOtp
} from "@/custom/otp"

import sendOtp from "@/custom/send"

import { BASE64URL_OPTIONS } from "@/lib/base64"
import { compressNumber } from "@/lib/compression/number"
import { OTP_INVALID_BLOCK_MS, OTP_RESEND_BLOCK_MS } from "@/lib/computed"
import { SYMMETRIC_ENCRYPTION_ALGORITHM, createDek, encryptTextSymmetrically } from "@/lib/crypto/symmetric/dek"
import { createKek, wrapKey } from "@/lib/crypto/symmetric/kek"
import { createRandomIdString, KEK_ID_BYTES } from "@/lib/crypto/id"
import { deleteOtpCookie, setOtpCookie } from "@/lib/otp/cookie"
import { encodeCredential, decodeCredential } from "@/lib/otp/encode/credential"
import { CREDENTIAL, EXPIRES, OTP, ATTEMPTS, RESEND_BLOCK, OTP_BLOCK, encodeOtpToken } from "@/lib/otp/encode/token"
import isProduction from "@/lib/production"
import { textEncoder } from "@/lib/text"
import { getReducedTimePrecision } from "@/lib/time"



/**
 * @import { Context } from "hono"
 * @import { OtpToken } from "@/lib/otp/encode/token"
 */


/**
 * @typedef {Object} OtpTokenData
 * @property {Date} expires
 * @property {boolean} [blocked]
 * @property {Date} [resendBlock]
 * @property {Date} [otpBlock]
 */



/**
 * @function getOtpTokenData
 * @param {OtpToken} otpToken
 * @returns {OtpTokenData}
 */
export function getOtpTokenData(otpToken) {

  /**
   * @type {OtpTokenData}
   */
  const result = {
    expires: new Date(getReducedTimePrecision(otpToken[EXPIRES]))
  }

  if (!otpToken[OTP]) {
    result.blocked = true
  } else {
    if (otpToken[RESEND_BLOCK]) {
      result.resendBlock = new Date(getReducedTimePrecision(otpToken[RESEND_BLOCK], Math.ceil))
    }
    if (otpToken[OTP_BLOCK]) {
      result.otpBlock = new Date(getReducedTimePrecision(otpToken[OTP_BLOCK], Math.ceil))
    }
  }

  return result

}



/**
 * @function getOtpTokenList
 * @param {CryptoKey} key
 * @param {Uint8Array<ArrayBuffer>} data
 * @returns {Promise<string[]|undefined>}
 */
export async function getOtpTokenList(key, data) {

  try {
    return textDecoder.decode(
      await crypto.subtle.decrypt(
        { name: SYMMETRIC_ENCRYPTION_ALGORITHM, iv: data.subarray(0, IV_BYTES) },
        key,
        data.subarray(IV_BYTES)
      )
    )?.split(",")
  } catch {
    // It simply returns `undefined`.
  }

}



/**
 * @async
 * @function createEncryptedOtpTokenList
 * @param {Context} c
 * @param {string} encodedCredential
 * @return {Promise<OtpTokenData>}
 */
export async function createEncryptedOtpTokenList(c, encodedCredential) {

  let kekId = await getCurrentKekId(c)

  /**
   * @type {(CryptoKey|undefined)}
   */
  let kek

  if (kekId) {
    kek = await getKek(c, kekId)
  }

  if (!kek) {
    kek = await createKek()
    kekId = createRandomIdString(KEK_ID_BYTES)
    await storeKek(c, kek, kekId)
  }

  const dek = await createDek()
  const wrappedDekString = new Uint8Array(await wrapKey(kek, dek)).toBase64(BASE64URL_OPTIONS)

  const otp = createOtp()

  await sendOtp(c, encodedCredential, otp)

  const { id, expires } = await createEncryptedOtpTokenListId(c)

  const lessPreciseExpiresDate = new Date(getReducedTimePrecision(expires))
  const dateNow = Date.now()
  const resendBlock = dateNow + OTP_RESEND_BLOCK_MS

  setOtpCookie(
    c,
    (
      kekId +
      wrappedDekString +
      await encryptTextSymmetrically(
        dek,
        encodeOtpToken(encodedCredential, expires, otp, resendBlock) + "," +
        id + "," +
        compressNumber(dateNow),
        textEncoder
      )
    ),
    lessPreciseExpiresDate
  )

  return {
    expires: lessPreciseExpiresDate,
    resendBlock: new Date(getReducedTimePrecision(resendBlock, Math.ceil))
  }

}



export class OtpTokenList {

  #context
  #expires
  #id
  #tokens


  /**
   * @param {Context} c
   * @param {OtpToken[]} [tokens]
   * @param {(string|number)} [id]
   * @param {number} [expires]
   */
  constructor(c, tokens = [], id, expires = 0) {
    this.#context = c
    this.#id = id
    this.#expires = expires
    this.#tokens = tokens.length > OTP_MAX_CREDENTIALS ? tokens.slice(0, OTP_MAX_CREDENTIALS) : tokens
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
      deleteOtpCookie(this.#context)
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
      key = await createSymmetricEncryptionKey()
      keyId = await storeKek(this.#context, key)
    }

    const encodedTokens = this.#tokens.map(encodeOtpToken)

    // @ts-expect-error: `#idValid` is true.
    encodedTokens.push(this.#id)

    encodedTokens.push(compressNumber(Date.now()))

    const encryptedTokens = await encryptTextSymmetrically(
      key,
      encodedTokens.join(","),
      additionalData,
      textEncoder
    )

    const lessPreciseExpires = new Date(getReducedTimePrecision(this.#expires))

    /**
     * @type {import("hono/utils/cookie").CookieOptions}
     */
    const cookieOptions = {
      expires: lessPreciseExpires,
      httpOnly: true,
      path: "/",
      secure: isProduction(this.#context),
      sameSite: "strict",
      partitioned: false
    }

    setCookie(
      this.#context,
      getCookieName(this.#context, COOKIE_OTP_KEY_ID),
      keyId.toString(),
      cookieOptions
    )

    setCookie(
      this.#context,
      getCookieName(this.#context, COOKIE_OTP_ENCRYPTED_TOKENS),
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
      deleteOtpCookie(this.#context)
      // @ts-expect-error: `#current` and `#idValid` are not falsy.
      return await deleteId(this.#context, this.#id, this.#expires) ? decodeCredential(this.#current[CREDENTIAL]) : undefined
    }

    // @ts-expect-error: `#idValid` is true.
    const id = await replaceId(this.#context, this.#id, this.#expires)

    if (!id) {
      deleteOtpCookie(this.#context)
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
      const otpBlock = Date.now() + OTP_INVALID_BLOCK_MS
      otpBlock >= (this.#current[EXPIRES] - 1000)
        ? this.#current.length = OTP
        : this.#current[OTP_BLOCK] = otpBlock
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
      Date.now() < this.#current[RESEND_BLOCK]
    ) {
      return
    }

    // @ts-expect-error: `#idValid` is true.
    this.#expires = await updateExpires(this.#context, this.#id, this.#expires)

    if (!this.#expires) {
      deleteOtpCookie(this.#context)
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
      this.#current[RESEND_BLOCK] = Date.now() + OTP_RESEND_BLOCK_MS
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
        deleteOtpCookie(this.#context)
        return
      }
    } else {
      ({ id: this.#id, expires: this.#expires } = await createId(this.#context))
    }

    const otp = createOtp()

    sendOtp(this.#context, credential, otp)

    const resendBlock = Date.now() + OTP_RESEND_BLOCK_MS

    this.#tokens.push([encodedCredential, this.#expires, otp, OTP_MAX_ATTEMPTS, resendBlock])

    const expiresDate = await this.#save()

    return expiresDate && {
      expires: expiresDate,
      resendBlock: new Date(getReducedTimePrecision(resendBlock, Math.ceil))
    }

  }

}