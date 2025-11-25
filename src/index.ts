import { getCookie } from "hono/cookie"

import app from "@/setup"

import {
  ERR_OTP_INCORRECT,
  ERR_OTP_RESENT_NOT_ALLOWED,
  ERR_OTP_TOO_MANY_ATTEMPTS,
  ERR_OTP_TOO_MANY_CREDENTIALS,
  ERR_OTP_TOO_MANY_REQUESTS
} from "@/lib/error/static"

import {
  COOKIE_ENCRYPTED_OTP_TOKENS,
  COOKIE_KEY_ID,
  areOtpParametersValid,
  decodeOtpTokenString,
  decodeOtpTokenStringArray,
  decryptOtpTokenStrings,
  deleteOtpData,
  OtpTokenList
} from "@/lib/otp"

import { isLessThanDelay } from "@/lib/time"

import otpCookieValidator from "@/lib/validators/otp/cookie"
import otpValueValidator from "@/lib/validators/otp"

import credentialValidator from "@/custom/credential"
import finalAction from "@/custom/final"
import { deleteEncryptionKey, getEncryptionKey } from "@/custom/id"


app.post("/api/otp/create", credentialValidator, async (c) => {

  const { [COOKIE_KEY_ID]: keyId, [COOKIE_ENCRYPTED_OTP_TOKENS]: encryptedTokens } = getCookie(c)

  if (!areOtpParametersValid(keyId, encryptedTokens)) {
    return c.json(await new OtpTokenList(c).set(c.req.valid("json")))
  }

  const key = await getEncryptionKey(c, keyId)

  if (!key) {
    return c.json(await new OtpTokenList(c).set(c.req.valid("json")))
  }

  const otpTokenStrings = await decryptOtpTokenStrings(c, key, encryptedTokens)

  if (!otpTokenStrings) {
    return c.json(await new OtpTokenList(c).set(c.req.valid("json")))
  }

  const lastAccess = otpTokenStrings.pop()

  if (!lastAccess) {
    deleteEncryptionKey(c, keyId)
    return c.json(await new OtpTokenList(c).set(c.req.valid("json")))
  }

  const dateNow = Date.now()

  if (isLessThanDelay(+lastAccess, dateNow)) {
    return c.json(ERR_OTP_TOO_MANY_REQUESTS, 429)
  }

  const otpTokenObject = await new OtpTokenList(c, decodeOtpTokenStringArray(otpTokenStrings), key, dateNow).set(c.req.valid("json"))

  if (!otpTokenObject) {
    return c.json(ERR_OTP_TOO_MANY_CREDENTIALS, 400)
  }

  return c.json(otpTokenObject)

})


app.post("/api/otp/resend", otpCookieValidator, async (c) => {

  const time = await c.req.valid("cookie").resend()

  if (!time) {
    return c.json(ERR_OTP_RESENT_NOT_ALLOWED, 400)
  }

  return c.json(time)

})


app.post("/api/otp/verify", otpValueValidator, otpCookieValidator, async (c) => {

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
    return c.json(ERR_OTP_TOO_MANY_ATTEMPTS, 400)
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