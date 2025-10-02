import { deleteCookie } from "hono/cookie"
import { validator } from "hono/validator"

import { COOKIE_KEY_ID, COOKIE_OTP, getOtpTokenData } from "@/lib/otp"
import { ERR_OTP_INVALID_COOKIE, ERR_OTP_TOO_MANY_REQUESTS } from "@/lib/error/static"
import { isLessThanDelay } from "@/lib/time"



const otpCookieValidator = validator("cookie", async({ [COOKIE_KEY_ID]: keyId, [COOKIE_OTP]: token }, c) => {

  if (!keyId || !token) {
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  // lastAccessDate:expires:resendBlockDate:credential:otp:attempts:otpBlockDate(optional)
  const otpTokenData = await getOtpTokenData(c, keyId, token)

  if (!otpTokenData) {
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  const [lastAccessDate, ...restOtpTokenData] = otpTokenData

  const dateNow = Date.now()

  if (isLessThanDelay(+lastAccessDate, dateNow)) {
    return c.json(ERR_OTP_TOO_MANY_REQUESTS, 429)
  }

  return /** @type {const} */ ([restOtpTokenData, keyId, dateNow])  // as const

})



export default otpCookieValidator