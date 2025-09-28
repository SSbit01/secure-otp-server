import { validator } from "hono/validator"

import { cookiekeyIDName, cookieOtpName, getOtpTokenData } from "@/lib/otp"
import { ERR_OTP_INVALID_COOKIE } from "@/lib/errors"


const otpCookieValidator = validator("cookie", async(cookies, c) => {

  const keyID = cookies[cookiekeyIDName]

  // credential:expires:resendBlockDate:otp:attempts:otpBlockDate(optional)
  const otpTokenData = await getOtpTokenData(c, keyID, cookies[cookieOtpName])

  if (!otpTokenData) {
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  return {
    keyID,
    value: otpTokenData
  }

})


export default otpCookieValidator