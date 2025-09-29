import { validator } from "hono/validator"

import { COOKIE_KEY_ID, COOKIE_OTP, getOtpTokenData } from "@/lib/otp"
import { ERR_OTP_INVALID_COOKIE } from "@/lib/errors"


const otpCookieValidator = validator("cookie", async(cookies, c) => {

  const keyID = cookies[COOKIE_KEY_ID]

  // credential:expires:resendBlockDate:otp:attempts:otpBlockDate(optional)
  const otpTokenData = await getOtpTokenData(c, keyID, cookies[COOKIE_OTP])

  if (!otpTokenData) {
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  return {
    keyID,
    value: otpTokenData
  }

})


export default otpCookieValidator