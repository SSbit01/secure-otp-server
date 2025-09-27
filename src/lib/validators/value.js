import { validator } from "hono/validator"

import { otpLength } from "../custom/otp.js"
import { ERR_OTP_INVALID_FORMAT } from "../errors.js"


const otpRegex = /\w+/


const otpValueValidator = validator("form", async({ otp }, c) => {

  if (typeof otp !== "string") {
    return c.json(ERR_OTP_INVALID_FORMAT, 400)
  }

  otp = otp.trim()

  if (otp.length !== otpLength || !otpRegex.test(otp)) {
    return c.json(ERR_OTP_INVALID_FORMAT, 400)
  }

  return otp.toLowerCase()

})


export default otpValueValidator