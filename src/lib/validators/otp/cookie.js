import { validator } from "hono/validator"

import { getCurrentKekId, getKek, storeKek } from "@/custom/kms"
import { OTP_MAX_CREDENTIALS } from "@/custom/otp"

import { BASE64URL_OPTIONS } from "@/lib/base64"
import { KEK_ID_LENGTH } from "@/lib/computed"
import { createRandomIdString } from "@/lib/crypto/id"
import { createKek, wrapKey } from "@/lib/crypto/symmetric/kek"
import { ERR_OTP_EXPIRED, ERR_OTP_INVALID_COOKIE } from "@/lib/error/static"
import { KEK_ID_BYTES, getDek, rotateKek } from "@/lib/kms"
import { getOtpTokenList } from "@/lib/otp"
import { ENVELOPE_ENCRYPTION_WRAP_LENGTH } from "@/lib/computed"
import { deleteOtpCookie, getOtpCookieName } from "@/lib/otp/cookie"
import { EXPIRES, decodeOtpToken, encodeOtpToken } from "@/lib/otp/encode/token"



const otpCookieValidator = validator("cookie", async (cookies, c) => {
  
  const otpData = cookies[getOtpCookieName(c)]?.trim()
  
  if (!otpData) {
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  let kekId = otpData.substring(0, KEK_ID_LENGTH)

  const dek = await getDek(c, kekId, otpData.substring(KEK_ID_LENGTH, ENVELOPE_ENCRYPTION_WRAP_LENGTH))
  
  if (!dek) {
    deleteOtpCookie(c)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  const encodedOtpTokenList = await getOtpTokenList(dek, otpData.substring(ENVELOPE_ENCRYPTION_WRAP_LENGTH))

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
  let envelopeWrap

  const currentKekId = await getCurrentKekId(c)

  if (currentKekId) {
    if (currentKekId === kekId) {
      envelopeWrap = otpData.substring(0, ENVELOPE_ENCRYPTION_WRAP_LENGTH)
    } else {
      let kek = await getKek(c, currentKekId)
      if (kek) {
        kekId = currentKekId
      } else {
        kekId = createRandomIdString(KEK_ID_BYTES)
        kek = await createKek()
        await storeKek(c, kek, kekId)
      }
      envelopeWrap = kekId + new Uint8Array(await wrapKey(dek, kek)).toBase64(BASE64URL_OPTIONS)
    }
  } else {
    kekId = createRandomIdString(KEK_ID_BYTES)
    const kek = await createKek()
    await storeKek(c, kek, kekId)
    envelopeWrap = kekId + new Uint8Array(await wrapKey(dek, kek)).toBase64(BASE64URL_OPTIONS)
  }

  return {
    currentOtpToken,
    dek,
    encodedOtpTokenList: newEncodedOtpTokenList,
    expires,
    id,
    envelopeWrap
  }

})



export default otpCookieValidator