import { validator } from "hono/validator"

import { ERR_OTP_EXPIRED, ERR_OTP_INVALID_COOKIE, ERR_OTP_TOO_MANY_REQUESTS } from "@/lib/error/static"

import {
  COOKIE_OTP_ENCRYPTED_TOKENS,
  COOKIE_OTP_KEY_ID,
  EXPIRES,
  decodeOtpTokenString,
  deleteOtpCookies,
  getOtpTokenStrings,
  OtpTokenList
} from "@/lib/otp"

import { isLessThanDelay } from "@/lib/time"



const otpCookieValidator = validator("cookie", async ({ [COOKIE_OTP_ENCRYPTED_TOKENS]: encryptedOtpTokens, [COOKIE_OTP_KEY_ID]: keyId }, c) => {

  const otpTokenStrings = await getOtpTokenStrings(c, keyId, encryptedOtpTokens)

  if (!otpTokenStrings) {
    deleteOtpCookies(c)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  const lastAccess = otpTokenStrings.pop()

  if (!lastAccess) {
    deleteOtpCookies(c)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  const dateNow = Date.now()

  if (isLessThanDelay(+lastAccess, dateNow)) {
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

  const current = decodeOtpTokenString(currentString, dateNow)

  if (!current) {
    deleteOtpCookies(c)
    return c.json(ERR_OTP_EXPIRED, 400)
  }

  let expires = current[EXPIRES]

  const otpTokens = []

  for (const otpTokenString of otpTokenStrings) {
    const otpToken = decodeOtpTokenString(otpTokenString, dateNow)
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