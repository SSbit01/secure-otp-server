import { validator } from "hono/validator"

import { COOKIE_KEY_ID, COOKIE_OTP, getOtpTokenData } from "@/lib/otp"
import { ERR_OTP_EXPIRED_COOKIE, ERR_OTP_INVALID_COOKIE, ERR_OTP_TOO_MANY_REQUESTS } from "@/lib/error/static"
import { isLessThanDelay } from "@/lib/time"

import { createOtpCookie, deleteOtpData } from "@/lib/otp"



const otpCookieValidator = validator("cookie", async({ [COOKIE_KEY_ID]: keyId, [COOKIE_OTP]: token }, c) => {

  if (!keyId || !token) {
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  // expires:lastAccessDate:resendBlockDate:credential:otp:attempts:otpBlockDate(optional)
  const otpTokenData = await getOtpTokenData(c, keyId, token)

  if (!otpTokenData) {
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  const [expires, lastAccessDate, ...restOtpTokenData] = otpTokenData

  const expiresNum = +expires

  const dateNow = Date.now()

  if (dateNow >= expiresNum) {
    deleteOtpData(c)
    return c.json(ERR_OTP_EXPIRED_COOKIE, 400)
  }

  if (isLessThanDelay(+lastAccessDate, dateNow)) {
    return c.json(ERR_OTP_TOO_MANY_REQUESTS, 429)
  }

  return /** @type {const} */ ([restOtpTokenData, keyId, dateNow, expiresNum])  // as const

})



export default otpCookieValidator