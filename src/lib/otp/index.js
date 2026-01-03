import { createEncryptedOtpTokenListId } from "@/custom/id"
import { getCurrentKekId, getKek, storeKek } from "@/custom/kms"

import { createOtp } from "@/custom/otp"

import sendOtp from "@/custom/send"

import { BASE64URL_OPTIONS } from "@/lib/base64"
import { compressNumber } from "@/lib/compression/number"
import { OTP_RESEND_BLOCK_MS } from "@/lib/computed"
import { createRandomIdString, KEK_ID_BYTES } from "@/lib/crypto/id"
import { createDek, encryptTextSymmetrically, decryptTextSymmetrically } from "@/lib/crypto/symmetric/dek"
import { createKek, wrapKey } from "@/lib/crypto/symmetric/kek"
import { setOtpCookie } from "@/lib/otp/cookie"
import { EXPIRES, OTP, ATTEMPTS, RESEND_BLOCK, OTP_BLOCK, createEncodedOtpToken } from "@/lib/otp/encode/token"
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
 * @function blockOtpToken
 * @param {OtpToken} otpToken
 */
export function blockOtpToken(otpToken) {
  delete otpToken[OTP]
  delete otpToken[ATTEMPTS]
  delete otpToken[RESEND_BLOCK]
  delete otpToken[OTP_BLOCK]
}


/**
 * @async
 * @function createEncryptedOtpTokenList
 * @param {Context} c
 * @param {string} credential
 * @return {Promise<OtpTokenData>}
 */
export async function createEncryptedOtpTokenList(c, credential) {

  const otp = createOtp()

  await sendOtp(c, credential, otp)

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
  const wrappedDekString = new Uint8Array(await wrapKey(dek, kek)).toBase64(BASE64URL_OPTIONS)

  const { id, expires } = await createEncryptedOtpTokenListId(c)

  const lessPreciseExpiresDate = new Date(getReducedTimePrecision(expires))
  const dateNow = Date.now()
  const resendBlock = dateNow + OTP_RESEND_BLOCK_MS

  setOtpCookie(
    c,
    kekId +
    wrappedDekString +
    await encryptTextSymmetrically(
      dek,
      createEncodedOtpToken(credential, expires, otp, resendBlock) + "," +
      id + "," +
      compressNumber(dateNow)
    ),
    lessPreciseExpiresDate
  )

  return {
    expires: lessPreciseExpiresDate,
    resendBlock: new Date(getReducedTimePrecision(resendBlock, Math.ceil))
  }

}


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
 * @param {string} ciphertext
 * @returns {Promise<string[]|undefined>}
 */
export async function getOtpTokenList(key, ciphertext) {

  try {
    return (await decryptTextSymmetrically(key, ciphertext))?.split(",")
  } catch {
    // It simply returns `undefined`.
  }

}