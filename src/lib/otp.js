import { setCookie, deleteCookie } from "hono/cookie"

import { encryptOtp, decryptOtp } from "@/lib/crypto/otp"
import isProduction from "@/lib/production"
import { getReducedTimePrecision, isLessThanDelay } from "@/lib/time"

import { RESEND_BLOCK_SECONDS, MAX_ATTEMPTS, MAX_DURATION_SECONDS, ATTEMPTS_BLOCK, INVALID_BLOCK_SECONDS, createOtp } from "@/custom/otp"
import sendOtp from "@/custom/send"

/**
 * @import { Context } from "hono"
 */

/**
 * @typedef {[credential:string,otp:string,attempts:number,expires:number,resendBlockDate:number,otpBlockDate?:number]} OtpToken
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
 * @param {(string|number)} credential
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

  const otp = createOtp()

  await sendOtp(c, credential, otp)

  return {
    expires: await new OtpData(c, [encodeCredential(credential), otp]).save()
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


// class OtpToken {
  
//   #attempts
//   #credential
//   #expires
//   #otp
//   #otpBlockDate
//   #resendBlockDate


//   constructor(credential, otp, attempts = MAX_ATTEMPTS, expires = Date.now() + MAX_DURATION_MS, resendBlockDate = 0, otpBlockDate = 0) {

//     this.#attempts = attempts
//     this.#credential = credential
//     this.#expires = expires
//     this.#otp = otp
//     this.#otpBlockDate = otpBlockDate
//     this.#resendBlockDate = resendBlockDate

//   }


//   get encodedCredential() {
//     return this.#credential
//   }


//   /**
//    * @param {Context} c
//    * @param {string} otp
//    * @returns {Promise<false|string|number>}
//    */
//   async check(c, otp, dateNow = Date.now()) {

//     if (this.#otpBlockDate > dateNow) {
//       deleteOtpCookies(c)
//       return false
//     }

//     if (this.#otp === otp) {
//       return decodeCredential(this.#credential)
//     }

//     this.#attempts--
  
//     /**
//      * Is `attempts` 0?
//      */
//     if (!this.#attempts) {
//       deleteOtpCookies(c)
//       return false
//     }

//     if (INVALID_BLOCK_MS && this.#attempts <= ATTEMPTS_BLOCK) {
//       this.#otpBlockDate = dateNow + INVALID_BLOCK_MS
//     }

//     await this.save(dateNow)

//     return this.#otpBlockDate

//   }


//   /**
//    * @param {Context} c
//    */
//   async resend(c) {

//     if (!this.#resendBlockDate || Date.now() < this.#resendBlockDate) {
//       deleteOtpCookies(this.#context)
//       return false
//     }

//     this.#otp = createOtp()

//     await sendOtp(this.#context, decodeCredential(this.#credential), this.#otp)

//     return {
//       expires: await this.save(),
//       resendBlockDate: getReducedTimePrecision(Date.now() + RESEND_BLOCK_MS, Math.ceil)
//     }

//   }


//   toString() {

//     /**
//      * When resendBlockDate is empty, another OTP has been resent and the client is not allowed to resend it again.
//      */
//     // credential:otp:attempts:expires:resendBlockDate:otpBlockDate(optional)
//     let currentOtpToken = this.#expires + OTP_SEPARATOR + this.#credential + OTP_SEPARATOR + this.#otp + OTP_SEPARATOR + this.#attempts + OTP_SEPARATOR + this.#resendBlockDate

//     if (this.#otpBlockDate) {
//       currentOtpToken += OTP_SEPARATOR + this.#otpBlockDate
//     }

//     return currentOtpToken

//   }

// }


/**
 * @function isOtpTokenValid
 * @this {number}
 * @param {OtpToken} otpToken
 * @returns {boolean}
 */
function isOtpTokenValid(otpToken) {

  return this < otpToken[EXPIRES]

}



class OtpTokenList {

  #context
  #tokens


  /**
   * @param {Context} c
   * @param {OtpToken[]} tokens
   */
  constructor(c, tokens) {

    this.#context = c
    this.#tokens = tokens

  }


  get current() {
    return this.#tokens[0]
  }


  /**
   * 
   * @param {string} otp 
   * @param {number} dateNow 
   * @returns {Promise<false|string|number|undefined>}
   */
  async check(otp, dateNow = Date.now()) {

    if (this.current[OTP_BLOCK_DATE] && this.current[OTP_BLOCK_DATE] > dateNow) {
      deleteOtpCookies(this.#context)
      return false
    }

    if (this.current[OTP] === otp) {
      return decodeCredential(this.current[CREDENTIAL])
    }

    // attempts
    this.current[ATTEMPTS]--
  
    /**
     * Is `attempts` 0?
     */
    if (!this.current[ATTEMPTS]) {
      deleteOtpCookies(this.#context)
      return false
    }

    if (INVALID_BLOCK_MS && this.current[ATTEMPTS] <= ATTEMPTS_BLOCK) {
      this.current[OTP_BLOCK_DATE] = dateNow + INVALID_BLOCK_MS
    }

    await this.save(dateNow)

    return this.current[OTP_BLOCK_DATE]

  }


  async resend(dateNow = Date.now()) {

    if (!this.current[4] || dateNow < this.current[RESEND_BLOCK_DATE]) {
      deleteOtpCookies(this.#context)
      return false
    }

    this.current[OTP] = createOtp()

    await sendOtp(this.#context, decodeCredential(this.current[CREDENTIAL]), this.current[OTP])

    return {
      expires: await this.save(),
      resendBlockDate: getReducedTimePrecision(Date.now() + RESEND_BLOCK_MS, Math.ceil)
    }

  }


  async save(dateNow = Date.now()) {

    const tokens = []

    let expires = 0

    for (const otpToken of this.#tokens) {
      const otpTokenExpires = otpToken[EXPIRES]
      if (dateNow < otpTokenExpires) {
        if (otpTokenExpires > expires) {
          expires = otpTokenExpires
        }
        tokens.push(otpToken.join(OTP_SEPARATOR))
      }
    }

    const [result, keyId] = await encryptOtp(this.#context, tokens.join(ARRAY_SEPARATOR), expires)

    const lessPreciseExpiresDate = getReducedTimePrecision(this.current[EXPIRES])

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

  const otpTokens = otpToken.split(ARRAY_SEPARATOR)

  if (otpTokens.length < 2) {
    return
  }

  const lastValidAccess = otpTokens.shift()

  if (!lastValidAccess) {
    return
  }

  const dateNow = Date.now()

  if (isLessThanDelay(+lastValidAccess, dateNow)) {
    deleteOtpCookies(c)
    return false
  }

  // credential:otp:attempts:expires:resendBlockDate:otpBlockDate(optional)
  const currentOtpToken = otpTokens[0]?.split(OTP_SEPARATOR)

  // @ts-expect-error: TS doesn't detect that the current token must be a `string[]`.
  otpTokens[0] = currentOtpToken

  if (!currentOtpToken[3]) {
    return
  }

  // @ts-expect-error: TS doesn't detect that `expires` must be a number.
  currentOtpToken[3] = +currentOtpToken[3]

  // @ts-expect-error: TS doesn't detect that `expires` must be a number.
  if (dateNow >= currentOtpToken[3]) {
    return
  }

  
  return Object.freeze(new OtpTokenList(c, otpTokens))

}