import { validator } from "hono/validator";

import { ERR_OTP_INVALID_FORMAT } from "@/lib/error/static";
import { OTP_LENGTH, OTP_REGEX } from "@/custom/otp";

const otpValueValidator = validator( "form", async ( { otp }, c ) => {
  if ( typeof otp !== "string" ) {
    return c.json( ERR_OTP_INVALID_FORMAT, 400 );
  }

  otp = otp.trim();

  if ( otp.length !== OTP_LENGTH || !OTP_REGEX.test( otp ) ) {
    return c.json( ERR_OTP_INVALID_FORMAT, 400 );
  }

  return otp;
} );

export default otpValueValidator;
