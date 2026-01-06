import type { Context } from "hono"
import type { createOtp } from "@/custom/otp"


type Otp = ReturnType<typeof createOtp>


/**
 * Implement here the sending of the OTP code to the credential/ID.
 * 
 * @async
 * @function
 * @param {Context} c - Hono context.
 * @param {string} credential - Client credential / ID.
 * @param {Otp} otp - OTP string code.
 * @returns {Promise<boolean>} Indicates whether the sending was successful or not. In case an internal error happened, just throw it.
 */
export default async function sendOtp(c: Context, credential: string, otp: Otp): Promise<boolean> {

  return true

}