import { validator } from "hono/validator"

import { decompressNumber } from "@/lib/compression/number"
import { ERR_OTP_EXPIRED, ERR_OTP_INVALID_COOKIE, ERR_OTP_TOO_MANY_REQUESTS } from "@/lib/error/static"

import { getOtpTokenStrings, OtpTokenList } from "@/lib/otp"
import deleteOtpCookies, { COOKIE_OTP_ENCRYPTED_TOKENS, COOKIE_OTP_KEY_ID } from "@/lib/otp/cookie"
import { decodeOtpToken } from "@/lib/otp/encode/token"
import { EXPIRES } from "@/lib/otp/order"

import { isLessThanDelay } from "@/lib/time"



const otpCookieValidator = validator("cookie", async ({ [COOKIE_OTP_ENCRYPTED_TOKENS]: encryptedOtpTokens, [COOKIE_OTP_KEY_ID]: keyId }, c) => {

  const otpTokenStrings = await getOtpTokenStrings(c, keyId, encryptedOtpTokens)

  if (!otpTokenStrings) {
    deleteOtpCookies(c)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  const lastAccessString = otpTokenStrings.pop()

  if (!lastAccessString) {
    deleteOtpCookies(c)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  const dateNow = Date.now()

  if (isLessThanDelay(decompressNumber(lastAccessString), dateNow)) {
    deleteOtpCookies(c)
    return c.json(ERR_OTP_TOO_MANY_REQUESTS, 429)
  }

  const id = otpTokenStrings.pop()

  if (!id) {
    deleteOtpCookies(c)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  const currentString = otpTokenStrings.pop()

  if (!currentString) {
    deleteOtpCookies(c)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  const current = decodeOtpToken(currentString, dateNow)

  if (!current) {
    deleteOtpCookies(c)
    return c.json(ERR_OTP_EXPIRED, 400)
  }

  let expires = current[EXPIRES]

  const otpTokens = []

  for (const otpTokenString of otpTokenStrings) {
    const otpToken = decodeOtpToken(otpTokenString, dateNow)
    if (otpToken) {
      otpTokens.push(otpToken)
      if (expires < otpToken[EXPIRES]) {
        expires = otpToken[EXPIRES]
      }
    }
  }

  otpTokens.push(current)

  return new OtpTokenList(c, otpTokens, id, expires, dateNow)

})



export default otpCookieValidator