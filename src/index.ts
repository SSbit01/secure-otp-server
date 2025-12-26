import { getCookie } from "hono/cookie"

import credentialValidator from "@/custom/credential"
import finalAction from "@/custom/final"
import { getCurrentKekId, getKek } from "@/custom/kms"
import { OTP_MAX_ATTEMPTS } from "@/custom/otp"

import { compressNumber, decompressNumber } from "@/lib/compression/number"
import { KEK_ID_BYTES, KEK_ID_LENGTH } from "@/lib/crypto/id"
import { unwrapKey } from "@/lib/crypto/symmetric/kek"

import {
  ERR_OTP_INCORRECT,
  ERR_OTP_INVALID_COOKIE,
  ERR_OTP_RESENT_NOT_ALLOWED,
  ERR_OTP_TOO_MANY_ATTEMPTS,
  ERR_OTP_TOO_MANY_REQUESTS
} from "@/lib/error/static"

import { getOtpTokenList, getOtpTokenData, OtpTokenList } from "@/lib/otp"
import { getOtpCookieName, deleteOtpCookies } from "@/lib/otp/cookie"
import { encodeCredential } from "@/lib/otp/encode/credential"
import { OTP_SEPARATOR } from "@/lib/otp/encode/token"
import { CREDENTIAL, EXPIRES, OTP, ATTEMPTS, RESEND_BLOCK, OTP_BLOCK } from "@/lib/otp/order"

import { isLessThanDelay } from "@/lib/time"

import otpCookieValidator from "@/lib/validators/otp/cookie"
import otpValueValidator from "@/lib/validators/otp"

import app from "@/setup"


/**
 * AES-KW adds 8 extra bytes of authenticated integrity value (AIV).
 * That's why we need to add 8 to 32 (AES-256) = 40.
 */
const DEK_BYTES = 40


app.post("/api/otp/create", credentialValidator, async (c) => {

  const { [getOtpCookieName(c)]: encryptedOtpData } = getCookie(c)

  const kekId = encryptedOtpData.substring(0, KEK_ID_LENGTH)

  if (kekId.length !== KEK_ID_LENGTH) {
    return c.json(await new OtpTokenList(c).set(c.req.valid("json")))
  }

  let kek = await getKek(c, kekId)

  if (!kek) {
    return c.json(await new OtpTokenList(c).set(c.req.valid("json")))
  }

  const otpData = Uint8Array.fromBase64(encryptedOtpData.substring(KEK_ID_LENGTH))

  const wrappedDek = otpData.subarray(0, DEK_BYTES)

  if (wrappedDek.length !== DEK_BYTES) {
    return c.json(await new OtpTokenList(c).set(c.req.valid("json")))
  }

  const dek = await unwrapKey(wrappedDek, kek)

  const encodedOtpTokenList = await getOtpTokenList(dek, otpData.subarray(DEK_BYTES))

  if (!encodedOtpTokenList) {
    return c.json(await new OtpTokenList(c).set(c.req.valid("json")))
  }

  const lastAccessString = encodedOtpTokenList.pop()

  if (!lastAccessString) {
    return c.json(await new OtpTokenList(c).set(c.req.valid("json")))
  }

  if (isLessThanDelay(decompressNumber(lastAccessString))) {
    deleteOtpCookies(c)
    return c.json(ERR_OTP_TOO_MANY_REQUESTS, 429)
  }

  const id = encodedOtpTokenList.pop()

  if (!id) {
    return c.json(await new OtpTokenList(c).set(c.req.valid("json")))
  }

  let currentEncodedOtpToken
  let currentOtpTokenData
  let expires = 0

  const encodedCredential = encodeCredential(c.req.valid("json"))
  const newEncodedOtpTokenList = []
  const dateNow = Date.now()

  for (let encodedOtpToken of encodedOtpTokenList) {
    const otpToken: any = encodedOtpToken.split(OTP_SEPARATOR)
    const currentExpires = decompressNumber(otpToken[EXPIRES])
    if (dateNow < currentExpires) {
      if (otpToken[ATTEMPTS]) {
        otpToken[ATTEMPTS] = +otpToken[ATTEMPTS]
        /**
         * `otpToken[ATTEMPTS]` can't be zero because it's automatically deleted.
         */
        if (
          isNaN(otpToken[ATTEMPTS]) ||
          otpToken[ATTEMPTS] > OTP_MAX_ATTEMPTS ||
          otpToken[ATTEMPTS] <= 0
        ) {
          // KEYS MIGHT BE COMPROMISED, TRIGGER KEY ROTATION.
          return c.json(ERR_OTP_INVALID_COOKIE, 400)
        }
        if (otpToken[OTP_BLOCK] && dateNow >= decompressNumber(otpToken[OTP_BLOCK])) {
          otpToken.length = otpToken[RESEND_BLOCK] ? OTP_BLOCK : RESEND_BLOCK
          encodedOtpToken = otpToken.join(OTP_SEPARATOR)
        }
      }
      if (expires < currentExpires) {
        expires = currentExpires
      }
      if (!currentEncodedOtpToken && encodedCredential === otpToken[CREDENTIAL]) {
        currentEncodedOtpToken = encodedOtpToken
        currentOtpTokenData = getOtpTokenData(otpToken)
      } else {
        newEncodedOtpTokenList.push(encodedOtpToken)
      }
    }
  }

  /**
   * Check if all OTP tokens are expired.
   */
  if (!expires) {
    return c.json(await new OtpTokenList(c).set(c.req.valid("json")))
  }

  if (currentEncodedOtpToken) {
    newEncodedOtpTokenList.push(currentEncodedOtpToken, id, compressNumber(dateNow))
  } else {
    expires = await updateExpires(c, id, expires)
    if (!expires) {
      deleteOtpCookies(c)
      return
    }
  }

  const currentKekId = await getCurrentKekId(c)

  if (!currentKekId) {
    
  } else if (currentKekId !== kekId) {
    kek &&= await getKek(c, currentKekId)
  }

  return c.json(currentOtpTokenData)

  const data = await new OtpTokenList(c, newEncodedOtpTokenList, id, expires).set(c.req.valid("json"))

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