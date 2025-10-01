import { deleteCookie } from "hono/cookie"
import { validator } from "hono/validator"

import { COOKIE_KEY_ID, COOKIE_OTP, getOtpTokenData } from "@/lib/otp"
import { ERR_OTP_INVALID_COOKIE } from "@/lib/error/static"



const otpCookieValidator = validator("cookie", async(cookies, c) => {

  const keyId = cookies[COOKIE_KEY_ID]

  if (!keyId) {
    deleteCookie(c, COOKIE_OTP)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  const token = cookies[COOKIE_OTP]

  if (!token) {
    deleteCookie(c, COOKIE_KEY_ID)
    deleteCookie(c, COOKIE_OTP)
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  // credential:expires:resendBlockDate:otp:attempts:otpBlockDate(optional)
  const otpTokenData = await getOtpTokenData(c, keyId, cookies[COOKIE_OTP])

  if (!otpTokenData) {
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  return {
    keyId,
    value: otpTokenData
  }

})



export default otpCookieValidator