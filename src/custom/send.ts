import type { Context } from "hono";
import type { generateOtp } from "@/custom/config";

type Otp = ReturnType<typeof generateOtp>;

/**
 * Implement here the sending of the OTP code to the credential/ID.
 *
 * @param c - Hono context.
 * @param credential - Client credential / ID.
 * @param otp - OTP string code.
 * @returns Indicates whether the sending was successful or not. In case an internal error happened, just throw it.
 */
export default async function sendOtp(c: Context, credential: string, otp: Otp): Promise<boolean> {
  return true;
}
