import { getCookie } from "hono/cookie"

import credentialValidator from "@/custom/credential"
import finalAction from "@/custom/final"
import { getKey } from "@/custom/kms"

import { decompressNumber } from "@/lib/compression/number"
import { KEK_ID_BYTES } from "@/lib/crypto/id"

import {
  ERR_OTP_INCORRECT,
  ERR_OTP_INVALID_COOKIE,
  ERR_OTP_RESENT_NOT_ALLOWED,
  ERR_OTP_TOO_MANY_ATTEMPTS,
  ERR_OTP_TOO_MANY_REQUESTS
} from "@/lib/error/static"

import { getOtpTokenStrings, OtpTokenList } from "@/lib/otp"
import { getOtpCookieName, deleteOtpCookies } from "@/lib/otp/cookie"
import { decodeOtpToken } from "@/lib/otp/encode/token"
import { EXPIRES } from "@/lib/otp/order"

import { isLessThanDelay } from "@/lib/time"

import otpCookieValidator from "@/lib/validators/otp/cookie"
import otpValueValidator from "@/lib/validators/otp"

import app from "@/setup"


/**
 * AES-KW adds 8 extra bytes of authenticated integrity value (AIV).
 * That's why we need to add 8 to 32 (AES-256) = 40.
 */
const OTP_TOKEN_INDEX = KEK_ID_BYTES + 40


app.post("/api/otp/create", credentialValidator, async (c) => {

  const { [getOtpCookieName(c)]: encryptedOtpData } = getCookie(c)

  if (!encryptedOtpData) {
    return c.json(await new OtpTokenList(c).set(c.req.valid("json")))
  }

  const otpData = Uint8Array.fromBase64(encryptedOtpData)

  const kekId = otpData.subarray(0, KEK_ID_BYTES)

  if (kekId.length !== KEK_ID_BYTES) {
    return c.json(await new OtpTokenList(c).set(c.req.valid("json")))
  }

  const kek = await getKey(c, kekId)

  if (!kek) {
    return c.json(await new OtpTokenList(c).set(c.req.valid("json")))
  }

  const wrappedDek = otpData.subarray(KEK_ID_BYTES, OTP_TOKEN_INDEX)

  const dek = await crypto.subtle.unwrapKey(
    "raw",
    wrappedDek,
    kek,
    { name: "AES-KW" },
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  )

  const otpTokenStrings = await getOtpTokenStrings(c, dek, otpData.subarray(OTP_TOKEN_INDEX))

  if (!otpTokenStrings) {
    return c.json(await new OtpTokenList(c).set(c.req.valid("json")))
  }

  const lastAccessString = otpTokenStrings.pop()

  if (!lastAccessString) {
    return c.json(await new OtpTokenList(c).set(c.req.valid("json")))
  }

  if (isLessThanDelay(decompressNumber(lastAccessString))) {
    deleteOtpCookies(c)
    return c.json(ERR_OTP_TOO_MANY_REQUESTS, 429)
  }

  const id = otpTokenStrings.pop()

  if (!id) {
    return c.json(await new OtpTokenList(c).set(c.req.valid("json")))
  }

  let expires = 0

  const otpTokens = []

  const dateNow = Date.now()

  for (const otpTokenString of otpTokenStrings) {
    const otpToken = decodeOtpToken(otpTokenString, dateNow)
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

  const data = await new OtpTokenList(c, otpTokens, id, expires).set(c.req.valid("json"))

  if (!data) {
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  return c.json(data)

})


app.post("/api/otp/resend", otpCookieValidator, async (c) => {

  const data = await c.req.valid("cookie").resend()

  if (!data) {
    return c.json(ERR_OTP_RESENT_NOT_ALLOWED, 400)
  }

  return c.json(data)

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