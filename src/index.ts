import { Hono } from "hono"

import { bodyLimit } from "hono/body-limit"
import { cors } from "hono/cors"
import { secureHeaders } from "hono/secure-headers"

import { env } from "hono/adapter"

import otpCookieValidator from "./lib/validators/cookie.js"
import otpValueValidator from "./lib/validators/value.js"

import { createOtpAndSend, deleteOtpData } from "./lib/otp.js"
import {
  ERR_OTP_ALREADY_RESENT,
  ERR_OTP_EXPIRED_COOKIE,
  ERR_OTP_RESENT_NOT_ALLOWED,
  ERR_OTP_TOO_MANY_ATTEMPTS,
  ERR_SERVER
} from "./lib/errors.js"

import errorHandler from "./lib/custom/error.js"
import inputValidator from "./lib/custom/input.js"
import { otpInvalidBlockSeconds } from "./lib/custom/otp.js"
import finalAction from "./lib/custom/final.js"


const app = new Hono()


app.use(bodyLimit({ maxSize: 102400 }))  // 100 KiB
app.use(cors({
  origin(origin, c) {
    return env(c).ORIGIN || "*"
  },
  allowMethods: ["GET", "HEAD", "POST"],
}))
app.use(secureHeaders())


/**
 * Error handler
 */
app.onError(async(err, c) => {
  await errorHandler(err, c)
  return c.json(ERR_SERVER, 500)
})


app.post("/api/otp/create", inputValidator, async(c) => {
  return c.json(await createOtpAndSend(c, c.req.valid("form")))
})


app.post("/api/otp/resend", otpCookieValidator, async(c) => {
  
  const {
    keyId,
    // credential:expires:resendBlockDate:otp:attempts:otpBlockDate(optional)
    value: [credential, expires, resendBlockDate]
  } = c.req.valid("cookie")

  const dateNow = Date.now()

  if (dateNow > +expires) {
    await deleteOtpData(c, keyId)
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


const otpInvalidBlockMs = otpInvalidBlockSeconds * 1000


app.post("/api/otp/verify",
  otpValueValidator,
  otpCookieValidator,
  async(c) => {

    const {
      keyId,
      // credential:expires:resendBlockDate:otp:attempts:otpBlockDate(optional)
      value: [credential, expires, resendBlockDate, otpValid, attempts, otpBlockDate]
    } = c.req.valid("cookie")
    
    const expiresNumber = +expires
    const dateNow = Date.now()

    if (dateNow > expiresNumber) {
      await deleteOtpData(c, keyId)
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
          await deleteOtpData(c, keyId)
          return c.json(ERR_OTP_TOO_MANY_ATTEMPTS, 400)  // User has to log in again
      }
      return c.json({
        error: "OTP:INCORRECT",
        message: "Incorrect OTP value.",
        blockedUntil: newOtpDateBlocked
      }, 400)
    }
    
    return await finalAction(c, credential)

})


export default app