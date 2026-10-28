import { validator } from "hono/validator";
import { ERR_OTP_INVALID_FORMAT } from "#src/lib/error";
import { regexOtp } from "#src/lib/otp";

export const otpValueValidator = validator("form", async ({ otp }, c) => {
  if (typeof otp !== "string") {
    return c.json(ERR_OTP_INVALID_FORMAT, 400);
  }

  otp = otp.trim();

  if (!regexOtp.test(otp)) {
    return c.json(ERR_OTP_INVALID_FORMAT, 400);
  }

  return otp;
});
