import { getCookie } from "hono/cookie"

import app from "@/setup"

import { isRandomIdValid } from "@/lib/crypto/id"
import { ERR_OTP_BLOCKED, ERR_OTP_RESENT_NOT_ALLOWED, ERR_OTP_TOO_MANY_ATTEMPTS, ERR_OTP_TOO_MANY_REQUESTS } from "@/lib/error/static"
import { OTP_INCORRECT } from "@/lib/error/names"
import { COOKIE_KEY_ID, COOKIE_OTP, createOtpCookie, createOtpAndSend, deleteOtpData, getOtpData } from "@/lib/otp"
import { isLessThanDelay } from "@/lib/time"

import otpCookieValidator from "@/lib/validators/cookie"
import otpValueValidator from "@/lib/validators/otp"

import credentialValidator from "@/custom/credential"
import { deleteEncryptionKey } from "@/custom/kms"
import { ALLOW_ONLY_ONE_RESENDING, ATTEMPTS_BLOCK, INVALID_BLOCK_SECONDS } from "@/custom/otp"
import finalAction from "@/custom/final"



interface ResponseOtpIncorrect {
  error: typeof OTP_INCORRECT
  message: string
  blockedUntil?: number
}



const INVALID_BLOCK_MS = INVALID_BLOCK_SECONDS * 1000



app.post("/api/otp/create", credentialValidator, async(c) => {

  const { [COOKIE_KEY_ID]: keyId, [COOKIE_OTP]: token } = getCookie(c)

  const credential = c.req.valid("json")

  if (!keyId || !isRandomIdValid(keyId) || !token) {
    return c.json(
      await createOtpAndSend(c, credential)
    )
  }
  
  // expires:resendBlockDate:credential:otp:attempts:otpBlockDate(optional)
  const otpTokenData = await getOtpData(c, keyId, token)

  switch (otpTokenData) {
    case false:
      deleteOtpData(c)
      return c.json(ERR_OTP_TOO_MANY_REQUESTS, 429)
    case undefined:
      return c.json(
        await createOtpAndSend(c, credential)
      )
    case null:
      /**
       * Fire and forget - delete old key
       */
      deleteEncryptionKey(c, keyId)
      return c.json(
        await createOtpAndSend(c, credential)
      )
  }

  if (otpTokenData === undefined) {
    return c.json(
      await createOtpAndSend(c, credential)
    )
  }

  if (otpTokenData === null) {
    /**
     * Fire and forget - delete old key
     */
    deleteEncryptionKey(c, keyId)
    return c.json(
      await createOtpAndSend(c, credential)
    )
  }

  // expires:resendBlockDate:credential:otp:attempts:otpBlockDate(optional)
  const [, resendBlockDate, storedCredential] = otpTokenData

  const dateNow = Date.now()

  if (storedCredential !== credential) {
    /**
     * Fire and forget - delete old key
     */
    deleteEncryptionKey(c, keyId)
    return c.json(
      await createOtpAndSend(c, credential)
    )
  }

  if (!resendBlockDate || dateNow < +resendBlockDate) {
    deleteOtpData(c)
    return c.json(ERR_OTP_RESENT_NOT_ALLOWED, 400)
  }

  /**
   * Fire and forget - delete old key
   */
  deleteEncryptionKey(c, keyId)

  return c.json(await createOtpAndSend(c, credential, ALLOW_ONLY_ONE_RESENDING))

})



app.post("/api/otp/resend", otpCookieValidator, async(c) => {
    
  // expires:resendBlockDate:credential:otp:attempts:otpBlockDate(optional)
  const [, resendBlockDate, credential] = c.req.valid("cookie")

  if (!resendBlockDate || Date.now() < +resendBlockDate) {
    deleteOtpData(c)
    return c.json(ERR_OTP_RESENT_NOT_ALLOWED, 400)
  }

  /**
   * Fire and forget - delete old key
   */
  deleteEncryptionKey(c, getCookie(c)[COOKIE_KEY_ID])

  return c.json(await createOtpAndSend(c, credential, ALLOW_ONLY_ONE_RESENDING))

})



app.post("/api/otp/verify", otpValueValidator, otpCookieValidator, async(c) => {

  // expires:resendBlockDate:credential:otp:attempts:otpBlockDate(optional)
  const [expires, resendBlockDate, credential, otpValid, attempts, otpBlockDate] = c.req.valid("cookie")


  if (otpBlockDate) {

    const timeDifference = (+otpBlockDate) - Date.now()

    if (timeDifference > 0) {
      deleteOtpData(c)
      return c.json(ERR_OTP_BLOCKED, 400)
    }

  }

  
  if (otpValid !== c.req.valid("form")) {

    const currentAttempts = +attempts - 1

    /**
     * Is `currentAttempts` 0?
     */
    if (!currentAttempts) {
      deleteOtpData(c)
      return c.json(ERR_OTP_TOO_MANY_ATTEMPTS, 400)  // User has to log in again
    }

    const res: ResponseOtpIncorrect = {
      error: OTP_INCORRECT,
      message: "Incorrect OTP value"
    }

    let newOtpDateBlocked = 0

    const dateNow = Date.now()

    if (INVALID_BLOCK_MS && currentAttempts <= ATTEMPTS_BLOCK) {
      newOtpDateBlocked = dateNow + INVALID_BLOCK_MS
      res.blockedUntil = newOtpDateBlocked
    }

    /**
     * Fire and forget - delete old key
     */
    deleteEncryptionKey(c, getCookie(c)[COOKIE_KEY_ID])

    await createOtpCookie(c, credential, otpValid, expires, dateNow, resendBlockDate, currentAttempts, newOtpDateBlocked)

    return c.json(res, 400)

  }


  /**
   * The OTP and the credential/ID have been verified, so delete all related data.
   */
  deleteOtpData(c)

  
  return await finalAction(c, decodeURIComponent(credential))

})



export default app