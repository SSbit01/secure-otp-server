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