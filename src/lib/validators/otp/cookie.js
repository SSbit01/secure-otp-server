import { validator } from "hono/validator"

import { deleteOtpTokenId } from "@/custom/id"
import { OTP_MAX_CREDENTIALS } from "@/custom/otp"

import { KEK_ID_LENGTH } from "@/lib/computed"
import { ERR_OTP_EXPIRED, ERR_OTP_INVALID_COOKIE } from "@/lib/error/static"
import { getDek, rotateKek } from "@/lib/kms"
import { getOtpTokenList } from "@/lib/otp"
import { ENVELOPE_ENCRYPTION_WRAP_LENGTH } from "@/lib/computed"
import { deleteOtpCookie, getOtpCookieName } from "@/lib/otp/cookie"
import { EXPIRES, decodeOtpToken, encodeOtpToken } from "@/lib/otp/encode/token"



const otpCookieValidator = validator("cookie", async (cookies, c) => {

  const otpData = cookies[getOtpCookieName(c)]?.trim()

  if (!otpData) {
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  const kekId = otpData.substring(0, KEK_ID_LENGTH)

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

  if (!id) {
    deleteOtpCookie(c)
    await rotateKek(c, kekId)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  const currentOtpToken = decodeOtpToken(encodedOtpTokenList.pop() || "")

  if (!currentOtpToken || encodedOtpTokenList.length >= OTP_MAX_CREDENTIALS) {
    deleteOtpCookie(c)
    await Promise.allSettled([deleteOtpTokenId(c, id), rotateKek(c, kekId)])
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
      deleteOtpCookie(c)
      await Promise.allSettled([deleteOtpTokenId(c, id), rotateKek(c, kekId)])
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

  return {
    currentOtpToken,
    dek,
    encodedOtpTokenList: newEncodedOtpTokenList,
    expires,
    id,
    kekId,
    otpData
  }

})



export default otpCookieValidator