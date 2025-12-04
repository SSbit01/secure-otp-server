import { getCookie } from "hono/cookie"

import app from "@/setup"

import {
  ERR_OTP_INCORRECT,
  ERR_OTP_INVALID_COOKIE,
  ERR_OTP_RESENT_NOT_ALLOWED,
  ERR_OTP_TOO_MANY_ATTEMPTS,
  ERR_OTP_TOO_MANY_REQUESTS
} from "@/lib/error/static"

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

import otpCookieValidator from "@/lib/validators/otp/cookie"
import otpValueValidator from "@/lib/validators/otp"

import credentialValidator from "@/custom/credential"
import finalAction from "@/custom/final"


app.post("/api/otp/create", credentialValidator, async (c) => {

  const { [COOKIE_OTP_KEY_ID]: keyId, [COOKIE_OTP_ENCRYPTED_TOKENS]: encryptedTokens } = getCookie(c)

  const otpTokenStrings = await getOtpTokenStrings(c, keyId, encryptedTokens)

  if (!otpTokenStrings) {
    return c.json(await new OtpTokenList(c).set(c.req.valid("json")))
  }

  const id = otpTokenStrings.pop()

  if (!id) {
    return c.json(await new OtpTokenList(c).set(c.req.valid("json")))
  }

  const lastAccess = otpTokenStrings.pop()

  if (!lastAccess) {
    return c.json(await new OtpTokenList(c).set(c.req.valid("json")))
  }

  const dateNow = Date.now()

  if (isLessThanDelay(+lastAccess, dateNow)) {
    return c.json(ERR_OTP_TOO_MANY_REQUESTS, 429)
  }

  let expires = 0

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

  /**
   * Check if all OTP tokens are expired.
   */
  if (!expires) {
    return c.json(await new OtpTokenList(c).set(c.req.valid("json")))
  }

  const otpTokenObject = await new OtpTokenList(c, otpTokens, id, expires, dateNow).set(c.req.valid("json"))

  if (!otpTokenObject) {
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  return c.json(otpTokenObject)

})


app.post("/api/otp/resend", otpCookieValidator, async (c) => {

  const otpTokenObject = await c.req.valid("cookie").resend()

  if (!otpTokenObject) {
    return c.json(ERR_OTP_RESENT_NOT_ALLOWED, 400)
  }

  return c.json(otpTokenObject)

})


app.post("/api/otp/verify", otpValueValidator, otpCookieValidator, async (c) => {

  const otpTokenList = c.req.valid("cookie")

  const credential = await otpTokenList.check(c.req.valid("form"))

  if (credential) {
    /**
     * VERIFIED
     */
    return await finalAction(c, credential)
  }

  if (otpTokenList.blocked) {
    return c.json(ERR_OTP_TOO_MANY_ATTEMPTS, 400)
  }

  const otpBlock = otpTokenList.otpBlock

  if (otpBlock) {
    return c.json({
      ...ERR_OTP_INCORRECT,
      otpBlock: otpBlock
    }, 400)
  }

  return c.json(ERR_OTP_INCORRECT, 400)

})


export default app