import {
  BODY_TOO_LARGE,
  CREDENTIAL_INVALID,
  OTP_EXPIRED,
  OTP_INCORRECT,
  OTP_INVALID_COOKIE,
  OTP_INVALID_FORMAT,
  OTP_RESENT_NOT_ALLOWED,
  OTP_TOO_MANY_ATTEMPTS,
  OTP_TOO_MANY_CREDENTIALS,
  OTP_TOO_MANY_REQUESTS,
  SERVER
} from "@/lib/error/names"


export const ERR_BODY_TOO_LARGE = {
  error: BODY_TOO_LARGE,
  message: "The body of your request is too large."
}

export const ERR_CREDENTIAL_INVALID = {
  error: CREDENTIAL_INVALID,
  message: "Invalid credential."
}

export const ERR_OTP_EXPIRED = {
  error: OTP_EXPIRED,
  message: "The current OTP is expired. Please request a new code."
}

export const ERR_OTP_INCORRECT = {
  error: OTP_INCORRECT,
  message: "Incorrect OTP value."
}

export const ERR_OTP_INVALID_COOKIE = {
  error: OTP_INVALID_COOKIE,
  message: "The OTP cookies are invalid."
}

export const ERR_OTP_INVALID_FORMAT = {
  error: OTP_INVALID_FORMAT,
  message: "Invalid OTP format."
}

export const ERR_OTP_RESENT_NOT_ALLOWED = {
  error: OTP_RESENT_NOT_ALLOWED,
  message: "Resend not allowed."
}

export const ERR_OTP_TOO_MANY_ATTEMPTS = {
  error: OTP_TOO_MANY_ATTEMPTS,
  message: "Too many attempts. For security reasons, the OTP has been blocked. Please wait for it to expire and then try again."
}

export const ERR_OTP_TOO_MANY_CREDENTIALS = {
  error: OTP_TOO_MANY_CREDENTIALS,
  message: "Too many credentials."
}

export const ERR_OTP_TOO_MANY_REQUESTS = {
  error: OTP_TOO_MANY_REQUESTS,
  message: "Too many requests, slow down :)"
}

export const ERR_SERVER = {
  error: SERVER,
  message: "The server has some issues, it's not your fault."
}