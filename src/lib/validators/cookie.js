import { validator } from "hono/validator"

import { isRandomIdValid } from "@/lib/crypto/id"
import { ERR_OTP_INVALID_COOKIE, ERR_OTP_TOO_MANY_REQUESTS } from "@/lib/error/static"
import { COOKIE_KEY_ID, COOKIE_OTP, deleteOtpCookies, deleteOtpData, getOtpData } from "@/lib/otp"



const otpCookieValidator = validator("cookie", async({ [COOKIE_KEY_ID]: keyId, [COOKIE_OTP]: token }, c) => {

  if (!keyId || !isRandomIdValid(keyId) || !token) {
    return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  // lastAccessDate:expires:resendBlockDate:credential:otp:attempts:otpBlockDate(optional)
  const otpTokenData = await getOtpData(c, keyId, token)

  switch (otpTokenData) {
    case false:
      deleteOtpData(c)
      return c.json(ERR_OTP_TOO_MANY_REQUESTS, 429)
    case undefined:
      deleteOtpCookies(c)
      return c.json(ERR_OTP_INVALID_COOKIE, 400)
    case null:
      deleteOtpData(c)
      return c.json(ERR_OTP_INVALID_COOKIE, 400)
  }

  return otpTokenData

})



export default otpCookieValidator