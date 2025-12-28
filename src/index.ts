import { getCookie } from "hono/cookie"

import credentialValidator from "@/custom/credential"
import finalAction from "@/custom/final"
import { updateOtpTokenExpires } from "@/custom/id"
import { getCurrentKekId, getKek, storeKek } from "@/custom/kms"
import { createOtp, OTP_MAX_ATTEMPTS } from "@/custom/otp"
import sendOtp from "@/custom/send"

import { BASE64URL_OPTIONS } from "@/lib/base64"
import { compressNumber, decompressNumber } from "@/lib/compression/number"
import { OTP_RESEND_BLOCK_MS } from "@/lib/computed"
import { KEK_ID_BYTES, KEK_ID_LENGTH, createRandomIdString } from "@/lib/crypto/id"
import { encryptTextSymmetrically } from "@/lib/crypto/symmetric/dek"
import { WRAPPED_DEK_BYTES, createKek, wrapKey, unwrapKey } from "@/lib/crypto/symmetric/kek"

import {
  ERR_OTP_INCORRECT,
  ERR_OTP_INVALID_COOKIE,
  ERR_OTP_RESENT_NOT_ALLOWED,
  ERR_OTP_TOO_MANY_ATTEMPTS,
  ERR_OTP_TOO_MANY_REQUESTS
} from "@/lib/error/static"

import { createEncryptedOtpTokenList, getOtpTokenList, getOtpTokenData } from "@/lib/otp"
import { deleteOtpCookie, getOtpCookieName, setOtpCookie } from "@/lib/otp/cookie"
import { encodeCredential } from "@/lib/otp/encode/credential"
import { CREDENTIAL, EXPIRES, OTP, ATTEMPTS, RESEND_BLOCK, OTP_BLOCK, OTP_SEPARATOR, encodeOtpToken } from "@/lib/otp/encode/token"

import { textEncoder } from "@/lib/text"
import { isLessThanDelay, getReducedTimePrecision } from "@/lib/time"

import otpCookieValidator from "@/lib/validators/otp/cookie"
import otpValueValidator from "@/lib/validators/otp"

import app from "@/setup"

import type { OtpTokenData } from "@/lib/otp"



app.post("/api/otp/create", credentialValidator, async (c) => {

  const encryptedOtpData = getCookie(c, getOtpCookieName(c))

  if (!encryptedOtpData) {
    return c.json(await createEncryptedOtpTokenList(c, encodeCredential(c.req.valid("json"))))
  }

  let kekId = encryptedOtpData.substring(0, KEK_ID_LENGTH)

  if (kekId.length !== KEK_ID_LENGTH) {
    return c.json(await createEncryptedOtpTokenList(c, encodeCredential(c.req.valid("json"))))
  }

  let kek = await getKek(c, kekId)

  if (!kek) {
    return c.json(await createEncryptedOtpTokenList(c, encodeCredential(c.req.valid("json"))))
  }

  const otpData = Uint8Array.fromBase64(encryptedOtpData.substring(KEK_ID_LENGTH), BASE64URL_OPTIONS)

  let wrappedDek: Uint8Array<ArrayBuffer> | ArrayBuffer = otpData.subarray(0, WRAPPED_DEK_BYTES)

  if (wrappedDek.length !== WRAPPED_DEK_BYTES) {
    return c.json(await createEncryptedOtpTokenList(c, encodeCredential(c.req.valid("json"))))
  }

  let dek = await unwrapKey(wrappedDek, kek)

  const encodedOtpTokenList = await getOtpTokenList(dek, otpData.subarray(WRAPPED_DEK_BYTES))

  if (!encodedOtpTokenList) {
    return c.json(await createEncryptedOtpTokenList(c, encodeCredential(c.req.valid("json"))))
  }

  const lastAccessString = encodedOtpTokenList.pop()

  let id = encodedOtpTokenList.pop()

  if (!lastAccessString || !id) {
    // KEYS MIGHT BE COMPROMISED, TRIGGER KEY ROTATION.
    await storeKek(c, await createKek(), await createRandomIdString(KEK_ID_BYTES))
    deleteOtpCookie(c)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  if (isLessThanDelay(decompressNumber(lastAccessString))) {
    deleteOtpCookie(c)
    return c.json(ERR_OTP_TOO_MANY_REQUESTS, 429)
  }

  const encodedCredential = encodeCredential(c.req.valid("json"))
  const newEncodedOtpTokenList = []

  let currentOtpTokenData: OtpTokenData | undefined
  
  let currentEncodedOtpToken = ""
  let expires = 0
  let dateNow = Date.now()

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
          await storeKek(c, await createKek(), await createRandomIdString(KEK_ID_BYTES))
          deleteOtpCookie(c)
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
    return c.json(await createEncryptedOtpTokenList(c, encodedCredential))
  }

  const currentKekId = await getCurrentKekId(c)

  if (currentKekId) {
    if (currentKekId !== kekId) {
      kek = await getKek(c, currentKekId)
      if (!kek) {
        kek = await createKek()
        kekId = createRandomIdString(KEK_ID_BYTES)
        await storeKek(c, kek, kekId)
      }
      wrappedDek = await wrapKey(dek, kek)
    }
  } else {
    kek = await createKek()
    kekId = createRandomIdString(KEK_ID_BYTES)
    await storeKek(c, kek, kekId)
    wrappedDek = await wrapKey(dek, kek)
  }

  if (!currentEncodedOtpToken) {
    expires = await updateOtpTokenExpires(c, +id, expires)
    if (!expires) {
      return c.json(ERR_OTP_INVALID_COOKIE, 400)
    }
    const otp = createOtp()
    await sendOtp(c, encodedCredential, otp)
    dateNow = Date.now()
    const resendBlock = dateNow + OTP_RESEND_BLOCK_MS
    currentEncodedOtpToken = encodeOtpToken(encodedCredential, expires, otp, resendBlock)
    currentOtpTokenData = {
      expires: new Date(getReducedTimePrecision(expires)),
      resendBlock: new Date(getReducedTimePrecision(resendBlock, Math.ceil))
    }
  }

  newEncodedOtpTokenList.push(
    currentEncodedOtpToken,
    id,
    compressNumber(dateNow)
  )


  setOtpCookie(
    c,
    (
      currentKekId +
      new Uint8Array(wrappedDek).toBase64(BASE64URL_OPTIONS) +
      await encryptTextSymmetrically(
        dek,
        newEncodedOtpTokenList.join(","),
        textEncoder
      )
    ),
    currentOtpTokenData?.expires
  )

  
  return c.json(currentOtpTokenData)

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