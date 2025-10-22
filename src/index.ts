import { getCookie } from "hono/cookie"

import app from "@/setup"

import { isRandomIdValid } from "@/lib/crypto/id"
import { ERR_OTP_BLOCKED, ERR_OTP_RESENT_NOT_ALLOWED, ERR_OTP_TOO_MANY_ATTEMPTS, ERR_OTP_TOO_MANY_REQUESTS } from "@/lib/error/static"
import { OTP_INCORRECT } from "@/lib/error/names"
import { COOKIE_KEY_ID, COOKIE_OTP, createOtpCookie, createOtpAndSend, deleteOtpData, getOtpTokenData } from "@/lib/otp"
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

  const { [COOKIE_KEY_ID]: keyId, [COOKIE_OTP]: token } = getCookie(c) as Record<string, string | undefined>

  const credential = c.req.valid("json")

  if (!keyId || !isRandomIdValid(keyId) || !token) {
    return c.json(
      await createOtpAndSend(c, credential)
    )
  }
  
  // expires:lastAccessDate:resendBlockDate:credential:otp:attempts:otpBlockDate(optional)
  const otpTokenData = await getOtpTokenData(c, keyId, token)

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

  // expires:lastAccessDate:resendBlockDate:credential:otp:attempts:otpBlockDate(optional)
  const [expires, lastAccessDate, resendBlockDate, storedCredential] = otpTokenData

  const dateNow = Date.now()

  if (dateNow >= +expires) {
    /**
     * Fire and forget - delete old key
     */
    deleteEncryptionKey(c, keyId)
    return c.json(
      await createOtpAndSend(c, credential)
    )
  }

  if (isLessThanDelay(+lastAccessDate, dateNow)) {
    deleteOtpData(c)
    return c.json(ERR_OTP_TOO_MANY_REQUESTS, 429)
  }

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
    
  // resendBlockDate:credential:otp:attempts:otpBlockDate(optional)
  const [[resendBlockDate, credential], keyId, dateNow] = c.req.valid("cookie")

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



app.post("/api/otp/verify", otpValueValidator, otpCookieValidator, async(c) => {

  // resendBlockDate:credential:otp:attempts:otpBlockDate(optional)
  const [[resendBlockDate, credential, otpValid, attempts, otpBlockDate], keyId, dateNow, expiresNumber] = c.req.valid("cookie")


  if (otpBlockDate) {

    const timeDifference = (+otpBlockDate) - dateNow

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

    if (INVALID_BLOCK_MS && currentAttempts <= ATTEMPTS_BLOCK) {
      newOtpDateBlocked = dateNow + INVALID_BLOCK_MS
      res.blockedUntil = newOtpDateBlocked
    }

    /**
     * Fire and forget - delete old key
     */
    deleteEncryptionKey(c, keyId)

    await createOtpCookie(c, credential, otpValid, dateNow, expiresNumber, resendBlockDate, currentAttempts, newOtpDateBlocked)

    return c.json(res, 400)

  }


  /**
   * The OTP and the credential/ID have been verified, so delete all related data.
   */
  deleteOtpData(c)

  
  return await finalAction(c, decodeURIComponent(credential))

})



export default app