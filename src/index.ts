import { getCookie } from "hono/cookie"

import app from "@/setup"

import {
  ERR_OTP_ALREADY_RESENT,
  ERR_OTP_EXPIRED_COOKIE,
  ERR_OTP_RESENT_NOT_ALLOWED,
  ERR_OTP_TOO_MANY_ATTEMPTS
} from "@/lib/errors"
import { COOKIE_KEY_ID, COOKIE_OTP, createOtpCookie, createOtpAndSend, deleteOtpData, getOtpTokenData } from "@/lib/otp"
import getReducedTimePrecision from "@/lib/time"

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
  
  // credential:expires:resendBlockDate:otp:attempts:otpBlockDate(optional)
  const otpTokenData = await getOtpTokenData(c, keyId, token)

  if (!otpTokenData || otpTokenData[0] !== credential) {
    return c.json(
      await createOtpAndSend(c, credential)
    )
  }

  // credential:expires:resendBlockDate:otp:attempts:otpBlockDate(optional)
  const [, expires, resendBlockDate] = otpTokenData

  const dateNow = getReducedTimePrecision()

  if (dateNow > +expires) {
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

  await deleteEncryptionKey(c, keyId)

  return c.json(await createOtpAndSend(c, credential, ALLOW_ONLY_ONE_RESENDING, dateNow))

})



app.post("/api/otp/verify", otpValueValidator, otpCookieValidator, async(c) => {

  const {
    keyId,
    // credential:expires:resendBlockDate:otp:attempts:otpBlockDate(optional)
    value: [credential, expires, resendBlockDate, otpValid, attempts, otpBlockDate]
  } = c.req.valid("cookie")

  
  const expiresNumber = +expires

  const dateNow = getReducedTimePrecision()


  if (dateNow > expiresNumber) {
    await deleteOtpData(c)
    return c.json(ERR_OTP_EXPIRED_COOKIE, 400)
  }


  if (otpBlockDate) {

    const timeDifference = dateNow - (+otpBlockDate)

    if (timeDifference < 0) {
      return c.json({
        error: "OTP:BLOCKED",
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
      await deleteOtpData(c)
      return c.json(ERR_OTP_TOO_MANY_ATTEMPTS, 400)  // User has to log in again
    }

    let newOtpDateBlocked = 0

    if (currentAttempts <= ATTEMPTS_BLOCK) {
      newOtpDateBlocked = dateNow + otpInvalidBlockMs
    }

    await deleteEncryptionKey(c, keyId)

    await createOtpCookie(c, otpValid, credential, expiresNumber, resendBlockDate, currentAttempts, newOtpDateBlocked)

    return c.json({
      error: "OTP:INCORRECT",
      message: "Incorrect OTP value.",
      blockedUntil: newOtpDateBlocked
    }, 400)

  }

  
  return await finalAction(c, credential)

})



if (RESEND_BLOCK_SECONDS) {

  app.post("/api/otp/resend", otpCookieValidator, async(c) => {
  
    const {
      keyId,
      // credential:expires:resendBlockDate:otp:attempts:otpBlockDate(optional)
      value: [credential, expires, resendBlockDate]
    } = c.req.valid("cookie")


    const dateNow = getReducedTimePrecision()


    if (dateNow > +expires) {
      await deleteOtpData(c)
      return c.json(ERR_OTP_EXPIRED_COOKIE, 400)
    }


    if (!resendBlockDate) {
      return c.json(ERR_OTP_ALREADY_RESENT, 400)
    }


    if (dateNow < +resendBlockDate) {
      return c.json(ERR_OTP_RESENT_NOT_ALLOWED, 400)
    }


    await deleteEncryptionKey(c, keyId)

    return c.json(await createOtpAndSend(c, credential, ALLOW_ONLY_ONE_RESENDING, dateNow))

  })

} else {
  console.warn("Resend route disabled (`/api/otp/resend`), if unintentional, check if `RSEND_BLOCK_SECONDS` is falsy in `./src/custom/otp.ts`.")
}



export default app