import { validator } from "hono/validator"

import { isRandomIdValid } from "@/lib/crypto/id"
import { ERR_OTP_EXPIRED, ERR_OTP_INVALID_COOKIE, ERR_OTP_TOO_MANY_REQUESTS } from "@/lib/error/static"

import {
  COOKIE_ENCRYPTED_TOKENS,
  COOKIE_KEY_ID,
  decodeOtpTokenString,
  deleteOtpCookies,
  decryptOtpTokenStrings,
  OtpTokenList
} from "@/lib/otp"

import { isLessThanDelay } from "@/lib/time"

import { getEncryptionKey } from "@/custom/kms"



const otpCookieValidator = validator("cookie", async({ [COOKIE_KEY_ID]: keyId, [COOKIE_ENCRYPTED_TOKENS]: encryptedTokens }, c) => {

  if (!encryptedTokens || !keyId || !isRandomIdValid(keyId)) {
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  const key = await getEncryptionKey(c, keyId)

  if (!key) {
    deleteOtpCookies(c)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  const otpTokenStrings = await decryptOtpTokenStrings(c, key, encryptedTokens)

  if (!otpTokenStrings) {
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  if (otpTokenStrings.length < 2) {
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  const lastAccess = otpTokenStrings.pop()

  if (!lastAccess) {
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  const currentString = otpTokenStrings.pop()

  if (!currentString) {
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  const dateNow = Date.now()

  const current = decodeOtpTokenString(currentString, dateNow)

  if (!current) {
    return c.json(ERR_OTP_EXPIRED, 400)
  }

  if (isLessThanDelay(+lastAccess, dateNow)) {
    return c.json(ERR_OTP_TOO_MANY_REQUESTS, 429)
  }

  const otpTokens = [current]

  for (const otpTokenString of otpTokenStrings) {
    const otpToken = decodeOtpTokenString(otpTokenString, dateNow)
    if (otpToken) {
      otpTokens.push(otpToken)
    }
  }
  
  return Object.freeze(new OtpTokenList(c, otpTokens, key, dateNow))

})



export default otpCookieValidator