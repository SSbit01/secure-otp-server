import { getCookie } from "hono/cookie"

import app from "@/setup"

import {
  ERR_OTP_BLOCKED,
  ERR_OTP_EXPIRED,
  ERR_OTP_INCORRECT,
  ERR_OTP_RESENT_NOT_ALLOWED,
  ERR_OTP_TOO_MANY_CREDENTIALS,
  ERR_OTP_TOO_MANY_REQUESTS
} from "@/lib/error/static"

import {
  COOKIE_ENCRYPTED_TOKENS,
  COOKIE_KEY_ID,
  createOtpAndSend,
  deleteOtpData
} from "@/lib/otp"

import otpCookieValidator from "@/lib/validators/otp/cookie"
import otpValueValidator from "@/lib/validators/otp"

import credentialValidator from "@/custom/credential"
import finalAction from "@/custom/final"


app.post("/api/otp/create", credentialValidator, async(c) => {

  const { [COOKIE_KEY_ID]: keyId, [COOKIE_ENCRYPTED_TOKENS]: encryptedTokens } = getCookie(c)
  
  const otpTokenList = await getOtpInstance(c, keyId, encryptedTokens)

  switch (otpTokenList) {
    case undefined:
      return c.json(await createOtpAndSend(c, c.req.valid("json")))
    case null:
      return c.json(ERR_OTP_EXPIRED, 400)
    case false:
      return c.json(ERR_OTP_TOO_MANY_REQUESTS, 429)
  }

  const time = await otpTokenList.set(c.req.valid("json"))

  if (time === false) {
    return c.json(ERR_OTP_TOO_MANY_CREDENTIALS, 400)
  }

  return c.json(time)

})


app.post("/api/otp/resend", otpCookieValidator, async(c) => {

  const time = await c.req.valid("cookie").resend()

  if (!time) {
    return c.json(ERR_OTP_RESENT_NOT_ALLOWED, 400)
  }

  return c.json(time)

})


app.post("/api/otp/verify", otpValueValidator, otpCookieValidator, async(c) => {

  const otpTokenList = c.req.valid("cookie")

  const credential = await otpTokenList.check(c.req.valid("form"))

  if (credential) {
    /**
     * VERIFIED
     * In case of error, don't delete OTP data
     */
    const res = await finalAction(c, credential)
    deleteOtpData(c)
    return res
  }

  if (otpTokenList.blocked) {
    return c.json(ERR_OTP_BLOCKED, 400)
  }

  if (otpTokenList.otpBlock) {
    return c.json({
      ...ERR_OTP_INCORRECT,
      otpBlock: otpTokenList.otpBlock
    }, 400)
  }

  return c.json(ERR_OTP_INCORRECT, 400)

})


export default app