import { validator } from "hono/validator"

import { cookieKeyIdName, cookieOtpName, getOtpTokenData } from "../otp.js"
import { ERR_OTP_INVALID_COOKIE } from "../errors.js"


const otpCookieValidator = validator("cookie", async(cookies, c) => {

  const keyId = cookies[cookieKeyIdName]

  // credential:expires:resendBlockDate:otp:attempts:otpBlockDate(optional)
  const otpTokenData = await getOtpTokenData(c, keyId, cookies[cookieOtpName])

  if (!otpTokenData) {
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  return {
    keyId,
    value: otpTokenData
  }

})


export default otpCookieValidator