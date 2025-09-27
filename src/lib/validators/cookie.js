import { validator } from "hono/validator"

import { cookieOtpName, getOtpTokenData } from "../otp.js"
import { ERR_OTP_INVALID_COOKIE } from "../errors.js"


const otpCookieValidator = validator("cookie", async(cookies, c) => {

  // credential:expires:resendBlockDate:otp:attempts:otpBlockDate(optional)
  const otpTokenData = await getOtpTokenData(c, cookies[cookieOtpName])

  if (!otpTokenData) {
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  return otpTokenData

})


export default otpCookieValidator