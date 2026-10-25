import { validator } from "hono/validator";
import { ERR_OTP_INVALID_FORMAT } from "#src/lib/error";
import { OTP_LENGTH, OTP_REGEX } from "#src/custom/config";

export const otpValueValidator = validator("form", async ({ otp }, c) => {
  if (typeof otp !== "string") {
    return c.json(ERR_OTP_INVALID_FORMAT, 400);
  }

  otp = otp.trim();

  if (otp.length !== OTP_LENGTH || !OTP_REGEX.test(otp)) {
    return c.json(ERR_OTP_INVALID_FORMAT, 400);
  }

  return otp;
});
