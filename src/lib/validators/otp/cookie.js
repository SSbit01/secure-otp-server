import { validator } from "hono/validator"

import { getCurrentKekId, getKek, storeKek } from "@/custom/kms"
import { OTP_MAX_CREDENTIALS } from "@/custom/otp"

import { BASE64URL_OPTIONS } from "@/lib/base64"
import { decompressNumber } from "@/lib/compression/number"
import { METADATA_STRING_LENGTH } from "@/lib/computed"
import { KEK_ID_BYTES, KEK_ID_LENGTH, createRandomIdString } from "@/lib/crypto/id"
import { WRAPPED_DEK_BYTES, createKek, wrapKey, unwrapKey } from "@/lib/crypto/symmetric/kek"

import {
  ERR_OTP_EXPIRED,
  ERR_OTP_INVALID_COOKIE,
  ERR_OTP_TOO_MANY_REQUESTS
} from "@/lib/error/static"

import { rotateKek } from "@/lib/kms"
import { getOtpTokenList } from "@/lib/otp"
import { deleteOtpCookie, getOtpCookieName } from "@/lib/otp/cookie"
import { EXPIRES, decodeOtpToken, encodeOtpToken } from "@/lib/otp/encode/token"
import { isLessThanDelay, getReducedTimePrecision } from "@/lib/time"



const otpCookieValidator = validator("cookie", async (cookies, c) => {
  
  const encryptedOtpData = cookies[getOtpCookieName(c)]
  
  if (!encryptedOtpData) {
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  let kekId = encryptedOtpData.substring(0, KEK_ID_LENGTH)

  if (kekId.length !== KEK_ID_LENGTH) {
    deleteOtpCookie(c)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  let kek = await getKek(c, kekId)

  if (!kek) {
    deleteOtpCookie(c)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  const otpData = Uint8Array.fromBase64(encryptedOtpData.substring(KEK_ID_LENGTH), BASE64URL_OPTIONS)

  const wrappedDek = otpData.subarray(0, WRAPPED_DEK_BYTES)

  if (wrappedDek.length !== WRAPPED_DEK_BYTES) {
    deleteOtpCookie(c)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  const dek = await unwrapKey(wrappedDek, kek)

  const encodedOtpTokenList = await getOtpTokenList(dek, otpData.subarray(WRAPPED_DEK_BYTES))

  if (!encodedOtpTokenList || !encodedOtpTokenList.length) {
    deleteOtpCookie(c)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  const lastAccessString = encodedOtpTokenList.pop()
  const id = encodedOtpTokenList.pop()
  const currentOtpToken = decodeOtpToken(encodedOtpTokenList.pop() || "")

  if (!lastAccessString || !id || !currentOtpToken || encodedOtpTokenList.length >= OTP_MAX_CREDENTIALS) {
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
  if (isLessThanDelay(decompressNumber(lastAccessString))) {
    return c.json(ERR_OTP_TOO_MANY_REQUESTS, 429)
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
      metadata = encryptedOtpData.substring(0, METADATA_STRING_LENGTH)
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