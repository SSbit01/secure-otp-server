import { getCookie } from "hono/cookie"

import app from "@/setup"

import { ERR_OTP_ALREADY_RESENT, ERR_OTP_EXPIRED_COOKIE, ERR_OTP_RESENT_NOT_ALLOWED, ERR_OTP_TOO_MANY_ATTEMPTS, ERR_OTP_TOO_MANY_REQUESTS } from "@/lib/error/static"
import { OTP_BLOCKED, OTP_INCORRECT } from "@/lib/error/names"
import { COOKIE_KEY_ID, COOKIE_OTP, createOtpCookie, createOtpAndSend, deleteOtpData, getOtpTokenData } from "@/lib/otp"
import { isLessThanDelay } from "@/lib/time"

import otpCookieValidator from "@/lib/validators/cookie"
import otpValueValidator from "@/lib/validators/value"

import credentialValidator from "@/custom/credential"
import { deleteEncryptionKey } from "@/custom/kms"
import { RESEND_BLOCK_SECONDS, ALLOW_ONLY_ONE_RESENDING, ATTEMPTS_BLOCK, INVALID_BLOCK_SECONDS } from "@/custom/otp"
import finalAction from "@/custom/final"



const otpInvalidBlockMs = INVALID_BLOCK_SECONDS * 1000



app.post("/api/otp/create", credentialValidator, async(c) => {

  const { [COOKIE_KEY_ID]: keyId, [COOKIE_OTP]: token } = getCookie(c) as Record<string, string | undefined>

  const credential = c.req.valid("json")

  if (!keyId || !token) {
    return c.json(
      await createOtpAndSend(c, credential)
    )
  }
  
  // lastAccessDate:expires:resendBlockDate:credential:otp:attempts:otpBlockDate(optional)
  const otpTokenData = await getOtpTokenData(c, keyId, token)

  if (!otpTokenData || otpTokenData[3] !== credential) {
    return c.json(
      await createOtpAndSend(c, credential)
    )
  }

  // lastAccessDate:expires:resendBlockDate:credential:otp:attempts:otpBlockDate(optional)
  const [lastAccessDate, expires, resendBlockDate] = otpTokenData  // Skipping credential

  const dateNow = Date.now()

  if (isLessThanDelay(+lastAccessDate, dateNow)) {
    return c.json(ERR_OTP_TOO_MANY_REQUESTS, 429)
  }

  if (dateNow >= +expires) {
    return c.json(
      await createOtpAndSend(c, credential)
    )
  }

  if (!resendBlockDate) {
    return c.json(ERR_OTP_ALREADY_RESENT, 400)
  }

  if (dateNow < +resendBlockDate) {
    return c.json(ERR_OTP_RESENT_NOT_ALLOWED, 400)
  }

  /**
   * Fire and forget - delete old key
   */
  deleteEncryptionKey(c, keyId)

  return c.json(await createOtpAndSend(c, credential, ALLOW_ONLY_ONE_RESENDING))

})



app.post("/api/otp/verify", otpValueValidator, otpCookieValidator, async(c) => {

  const [[expires, resendBlockDate, credential, otpValid, attempts, otpBlockDate], keyId, dateNow] = c.req.valid("cookie")
  
  const expiresNumber = +expires

  if (dateNow >= expiresNumber) {
    deleteOtpData(c)
    return c.json(ERR_OTP_EXPIRED_COOKIE, 400)
  }


  if (otpBlockDate) {

    const timeDifference = dateNow - (+otpBlockDate)

    if (timeDifference < 0) {
      return c.json({
        error: OTP_BLOCKED,
        message: `You are blocked from verifying the OTP until ${Math.ceil(timeDifference / 1000)} seconds have passed.`,
      }, 400)
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

    let newOtpDateBlocked = 0

    if (currentAttempts <= ATTEMPTS_BLOCK) {
      newOtpDateBlocked = dateNow + otpInvalidBlockMs
    }

    /**
     * Fire and forget - delete old key
     */
    deleteEncryptionKey(c, keyId)

    await createOtpCookie(c, otpValid, credential, expiresNumber, resendBlockDate, currentAttempts, newOtpDateBlocked)

    return c.json({
      error: OTP_INCORRECT,
      message: "Incorrect OTP value",
      blockedUntil: newOtpDateBlocked
    }, 400)

  }

  
  return await finalAction(c, credential)

})



if (RESEND_BLOCK_SECONDS) {

  app.post("/api/otp/resend", otpCookieValidator, async(c) => {
  
    const [[expires, resendBlockDate, credential], keyId, dateNow] = c.req.valid("cookie")

    if (dateNow >= +expires) {
      deleteOtpData(c)
      return c.json(ERR_OTP_EXPIRED_COOKIE, 400)
    }

    if (!resendBlockDate) {
      return c.json(ERR_OTP_ALREADY_RESENT, 400)
    }

    if (dateNow < +resendBlockDate) {
      return c.json(ERR_OTP_RESENT_NOT_ALLOWED, 400)
    }

    /**
     * Fire and forget - delete old key
     */
    deleteEncryptionKey(c, keyId)

    return c.json(await createOtpAndSend(c, credential, ALLOW_ONLY_ONE_RESENDING))

  })

} else {
  console.warn("Resend route disabled (`/api/otp/resend`), if unintentional, check if `RSEND_BLOCK_SECONDS` is falsy in `./src/custom/otp.ts`.")
}



export default app