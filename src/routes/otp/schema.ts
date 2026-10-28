import { validator } from "hono/validator";
import { OTP_LENGTH } from "#src/custom/default";
import { ERR_OTP_INVALID_FORMAT } from "#src/lib/error";
import { regexOtp } from "#src/lib/otp";

export const otpValueValidator = validator("form", async ({ otp }, c) => {
  if (typeof otp !== "string") {
    return c.json(ERR_OTP_INVALID_FORMAT, 400);
  }

  otp = otp.trim();

  if (otp.length !== OTP_LENGTH || !regexOtp.test(otp)) {
    return c.json(ERR_OTP_INVALID_FORMAT, 400);
  }

  return otp;
});
