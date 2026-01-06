import { validator } from "hono/validator"

import { getCurrentKekId, getKek, storeKek } from "@/custom/kms"
import { OTP_MAX_CREDENTIALS } from "@/custom/otp"

import { BASE64URL_OPTIONS } from "@/lib/base64"
import { OTP_METADATA_STRING_LENGTH } from "@/lib/computed"
import { KEK_ID_BYTES, KEK_ID_LENGTH, createRandomIdString } from "@/lib/crypto/id"
import { WRAPPED_DEK_BYTES, createKek, wrapKey, unwrapKey } from "@/lib/crypto/symmetric/kek"

import {
  ERR_OTP_EXPIRED,
  ERR_OTP_INVALID_COOKIE
} from "@/lib/error/static"

import { rotateKek } from "@/lib/kms"
import { getOtpTokenList } from "@/lib/otp"
import { deleteOtpCookie, getOtpCookieName } from "@/lib/otp/cookie"
import { EXPIRES, decodeOtpToken, encodeOtpToken } from "@/lib/otp/encode/token"



const otpCookieValidator = validator("cookie", async (cookies, c) => {
  
  const otpData = cookies[getOtpCookieName(c)]?.trim()
  
  if (!otpData) {
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  let kekId = otpData.substring(0, KEK_ID_LENGTH)

  if (kekId.length !== KEK_ID_LENGTH) {
    deleteOtpCookie(c)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  let kek = await getKek(c, kekId)

  if (!kek) {
    deleteOtpCookie(c)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  /**
   * @type {Uint8Array<ArrayBuffer>}
   */
  let wrappedDek
  
  try {
    wrappedDek = Uint8Array.fromBase64(otpData.substring(KEK_ID_LENGTH, OTP_METADATA_STRING_LENGTH), BASE64URL_OPTIONS)
  } catch {
    deleteOtpCookie(c)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  if (wrappedDek.length !== WRAPPED_DEK_BYTES) {
    deleteOtpCookie(c)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  const dek = await unwrapKey(wrappedDek, kek)

  const encodedOtpTokenList = await getOtpTokenList(dek, otpData.substring(OTP_METADATA_STRING_LENGTH))

  if (!encodedOtpTokenList) {
    deleteOtpCookie(c)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  const id = encodedOtpTokenList.pop()
  const currentOtpToken = decodeOtpToken(encodedOtpTokenList.pop() || "")

  if (!id || !currentOtpToken || encodedOtpTokenList.length >= OTP_MAX_CREDENTIALS) {
    await rotateKek(c, kekId)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  /**
   * @type {string[]}
   */
  const newEncodedOtpTokenList = []

  let expires = currentOtpToken[EXPIRES]

  const dateNow = Date.now()

  for (const encodedOtpToken of encodedOtpTokenList) {
    const otpToken = decodeOtpToken(encodedOtpToken)
    if (!otpToken) {
      await rotateKek(c, kekId)
      return c.json(ERR_OTP_INVALID_COOKIE, 400)
    }
    if (dateNow < otpToken[EXPIRES]) {
      if (expires < otpToken[EXPIRES]) {
        expires = otpToken[EXPIRES]
      }
      newEncodedOtpTokenList.push(encodeOtpToken(otpToken))
    }
  }

  /**
   * It should be verified after checking all OTP tokens.
   */
  if (dateNow >= currentOtpToken[EXPIRES]) {
    return c.json(ERR_OTP_EXPIRED, 400)
  }

  /**
   * Kek ID + Wrapped DEK.
   * 
   * @type {string}
   */
  let metadata

  const currentKekId = await getCurrentKekId(c)

  if (currentKekId) {
    if (currentKekId === kekId) {
      metadata = otpData.substring(0, OTP_METADATA_STRING_LENGTH)
    } else {
      kek = await getKek(c, currentKekId)
      if (kek) {
        kekId = currentKekId
      } else {
        kekId = createRandomIdString(KEK_ID_BYTES)
        kek = await createKek()
        await storeKek(c, kek, kekId)
      }
      metadata = kekId + new Uint8Array(await wrapKey(dek, kek)).toBase64(BASE64URL_OPTIONS)
    }
  } else {
    kekId = createRandomIdString(KEK_ID_BYTES)
    kek = await createKek()
    await storeKek(c, kek, kekId)
    metadata = kekId + new Uint8Array(await wrapKey(dek, kek)).toBase64(BASE64URL_OPTIONS)
  }

  return {
    currentOtpToken,
    dek,
    encodedOtpTokenList: newEncodedOtpTokenList,
    expires,
    id,
    metadata
  }

})



export default otpCookieValidator