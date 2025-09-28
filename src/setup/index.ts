import { Hono } from "hono"

import { bodyLimit } from "hono/body-limit"
import { cors } from "hono/cors"
import { secureHeaders } from "hono/secure-headers"

import { env } from "hono/adapter"

import {
  ERR_OTP_ALREADY_RESENT,
  ERR_OTP_EXPIRED_COOKIE,
  ERR_OTP_RESENT_NOT_ALLOWED,
  ERR_OTP_TOO_MANY_ATTEMPTS,
  ERR_SERVER
} from "./lib/errors.js"
import { createOtpCookie, createOtpAndSend, deleteOtpData } from "./lib/otp.js"
import getReducedTimePrecision from "./lib/time.js"

import otpCookieValidator from "./lib/validators/cookie.js"
import otpValueValidator from "./lib/validators/value.js"

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