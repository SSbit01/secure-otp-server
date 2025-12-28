import { OTP_MAX_ATTEMPTS } from "@/custom/otp"
import { compressNumber } from "@/lib/compression/number"


export type OtpToken = [
  credential: string,
  expires: number,
  otp?: string,
  attempts?: number,
  resendBlock?: number,
  otpBlock?: number
]


export const CREDENTIAL = 0
export const EXPIRES = 1
export const OTP = 2
export const ATTEMPTS = 3
export const RESEND_BLOCK = 4
export const OTP_BLOCK = 5

export const OTP_SEPARATOR = "|"


/**
 * @function createOtpToken
 * @param {string} encodedCredential
 * @param {number} expires
 * @param {string} otp
 * @param {number} resendBlock
 * @returns {string}
 */
export function encodeOtpToken(
  encodedCredential: string,
  expires: number,
  otp: string,
  resendBlock: number
) {

  return (
    encodedCredential + OTP_SEPARATOR +
    compressNumber(expires) + OTP_SEPARATOR +
    otp + OTP_SEPARATOR +
    OTP_MAX_ATTEMPTS + OTP_SEPARATOR +
    compressNumber(resendBlock)
  )

}


// /**
//  * @function decodeOtpToken
//  * @param {string} otpTokenString 
//  * @param {number} [dateNow]
//  * @returns {(OtpToken|undefined)}
//  */
// export function decodeOtpToken(otpTokenString: string, dateNow = Date.now()) {

//   /**
//    * @type {any[]}
//    */
//   const otpToken = otpTokenString.split(OTP_SEPARATOR)

//   if (dateNow >= decompressNumber(otpToken[EXPIRES])) {
//     return
//   }

//   /**
//    * Presence of [RESEND_BLOCK] indicates that resending is available.
//    * That's why it is not removed, unlike [OTP_BLOCK].
//    */

//   /**
//    * TODO: Check if otpToken[ATTEMPTS] corresponds to MAX_ATTEMPTS.
//    * If that's not the case, return bad request to the client and rotate KEK.
//    */

//   if (otpToken[ATTEMPTS]) {
//     otpToken[ATTEMPTS] = +otpToken[ATTEMPTS]
//     if (otpToken[OTP_BLOCK]) {
//       const otpBlock = decompressNumber(otpToken[OTP_BLOCK])
//       if (dateNow < otpBlock) {
//         otpToken[OTP_BLOCK] = otpBlock
//       } else if (otpToken[RESEND_BLOCK]) {
//         /** Trim the array to save space. */
//         otpToken.length = OTP_BLOCK
//       } else {
//         /** Trim the array to save space. */
//         otpToken.length = RESEND_BLOCK
//       }
//     }
//   }

//   return otpToken

// }


// /**
//  * @function encodeOtpToken
//  * @param {OtpToken} otpToken
//  * @returns {string}
//  */
// export function encodeOtpToken2(otpToken: OtpToken) {

//   /**
//    * @type {any[]}
//    */
//   const encodedToken = otpToken.slice()

//   encodedToken[EXPIRES] = compressNumber(encodedToken[EXPIRES])

//   if (encodedToken[OTP]) {
//     encodedToken[RESEND_BLOCK] &&= compressNumber(encodedToken[RESEND_BLOCK])
//     encodedToken[OTP_BLOCK] &&= compressNumber(encodedToken[OTP_BLOCK])
//   }

//   return encodedToken.join(OTP_SEPARATOR)

// }