import { validator } from "hono/validator"

import { ERR_OTP_EXPIRED, ERR_OTP_INVALID_COOKIE, ERR_OTP_TOO_MANY_REQUESTS } from "@/lib/error/static"
import { COOKIE_KEY_ID, COOKIE_ENCRYPTED_TOKENS, getOtpInstance } from "@/lib/otp"



const otpCookieValidator = validator("cookie", async({ [COOKIE_KEY_ID]: keyId, [COOKIE_ENCRYPTED_TOKENS]: token }, c) => {

  const otpTokenList = await getOtpInstance(c, keyId, token)

  switch (otpTokenList) {
    case undefined:
      return c.json(ERR_OTP_INVALID_COOKIE, 400)
    case null:
      return c.json(ERR_OTP_EXPIRED, 400)
    case false:
      return c.json(ERR_OTP_TOO_MANY_REQUESTS, 429)
  }

  return otpTokenList

})



export default otpCookieValidator