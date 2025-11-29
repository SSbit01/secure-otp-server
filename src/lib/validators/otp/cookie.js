import { validator } from "hono/validator"

import { ERR_OTP_EXPIRED, ERR_OTP_INVALID_COOKIE, ERR_OTP_TOO_MANY_REQUESTS } from "@/lib/error/static"

import {
  COOKIE_ENCRYPTED_OTP_TOKENS,
  COOKIE_KEY_ID,
  decodeOtpTokenString,
  decodeOtpTokenStringArray,
  deleteOtpCookies,
  deleteOtpData,
  getOtpTokenStrings,
  OtpTokenList
} from "@/lib/otp"

import { isLessThanDelay } from "@/lib/time"

import { getKey } from "@/custom/kms"



const otpCookieValidator = validator("cookie", async ({ [COOKIE_ENCRYPTED_OTP_TOKENS]: encryptedOtpTokens, [COOKIE_KEY_ID]: keyId }, c) => {

  const otpTokenStrings = await getOtpTokenStrings(c, keyId, encryptedOtpTokens)

  if (!otpTokenStrings) {
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  const id = otpTokenStrings.pop()

  if (!id) {
    deleteOtpCookies(c)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  const lastAccess = otpTokenStrings.pop()

  if (!lastAccess) {
    deleteOtpData(c, id)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  const dateNow = Date.now()

  if (isLessThanDelay(+lastAccess, dateNow)) {
    return c.json(ERR_OTP_TOO_MANY_REQUESTS, 429)
  }

  const currentString = otpTokenStrings.pop()

  if (!currentString) {
    deleteOtpData(c, id)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  const current = decodeOtpTokenString(currentString, dateNow)

  if (!current) {
    return c.json(ERR_OTP_EXPIRED, 400)
  }

  const otpTokens = decodeOtpTokenStringArray(otpTokenStrings, dateNow)

  otpTokens.push(current)

  return Object.freeze(new OtpTokenList(c, otpTokens, id, dateNow))

})



export default otpCookieValidator