import type { Context } from "hono"

/**
 * Implement here the sending of the OTP code to the credential/ID.
 * It only needs to accept the Hono context.
 * 
 * @param   {Context}       c          - Hono context.
 * @param   {(string|number)} credential - Client identification string.
 * @param   {string}        otp        - Otp string code.
 */
export default async function sendOtp(
  c: Context,
  credential: string | number,
  otp: string | number
) {

  return 1

}