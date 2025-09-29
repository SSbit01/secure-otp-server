import app from "@/setup"

import {
  ERR_OTP_ALREADY_RESENT,
  ERR_OTP_EXPIRED_COOKIE,
  ERR_OTP_RESENT_NOT_ALLOWED,
  ERR_OTP_TOO_MANY_ATTEMPTS
} from "@/lib/errors"
import { createOtpCookie, createOtpAndSend, deleteOtpData } from "@/lib/otp"
import getReducedTimePrecision from "@/lib/time"

import otpCookieValidator from "@/lib/validators/cookie"
import otpValueValidator from "@/lib/validators/value"

import inputValidator from "@/custom/input"
import { otpInvalidBlockSeconds } from "@/custom/otp"
import finalAction from "@/custom/final"



const otpInvalidBlockMs = otpInvalidBlockSeconds * 1000



app.post("/api/otp/create", inputValidator, async(c) => {

  return c.json(
    await createOtpAndSend(c, c.req.valid("json"))
  )

})


app.post("/api/otp/resend", otpCookieValidator, async(c) => {
  
  const {
    keyID,
    // credential:expires:resendBlockDate:otp:attempts:otpBlockDate(optional)
    value: [credential, expires, resendBlockDate]
  } = c.req.valid("cookie")

  const dateNow = getReducedTimePrecision()

  if (dateNow > +expires) {
    await deleteOtpData(c, keyID)
    return c.json(ERR_OTP_EXPIRED_COOKIE, 400)
  }

  if (!resendBlockDate) {
    return c.json(ERR_OTP_ALREADY_RESENT, 400)
  }

  if (dateNow < +resendBlockDate) {
    return c.json(ERR_OTP_RESENT_NOT_ALLOWED, 400)
  }

  return c.json(await createOtpAndSend(c, credential, true, dateNow))

})


app.post("/api/otp/verify", otpValueValidator, otpCookieValidator, async(c) => {

  const {
    keyID,
    // credential:expires:resendBlockDate:otp:attempts:otpBlockDate(optional)
    value: [credential, expires, resendBlockDate, otpValid, attempts, otpBlockDate]
  } = c.req.valid("cookie")
  
  const expiresNumber = +expires
  const dateNow = getReducedTimePrecision()

  if (dateNow > expiresNumber) {
    await deleteOtpData(c, keyID)
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
    let newOtpDateBlocked = 0
    switch (currentAttempts) {
      case 2:
      case 1:
        newOtpDateBlocked = dateNow + otpInvalidBlockMs
        break
      case 0:
        await deleteOtpData(c, keyID)
        return c.json(ERR_OTP_TOO_MANY_ATTEMPTS, 400)  // User has to log in again
    }
    await createOtpCookie(c, otpValid, credential, expiresNumber, resendBlockDate, currentAttempts, newOtpDateBlocked)
    return c.json({
      error: "OTP:INCORRECT",
      message: "Incorrect OTP value.",
      blockedUntil: newOtpDateBlocked
    }, 400)
  }
  
  return await finalAction(c, credential)

})



export default app