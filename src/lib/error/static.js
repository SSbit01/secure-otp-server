import {
  BODY_TOO_LARGE,
  CREDENTIAL_INVALID,
  OTP_ALREADY_RESENT,
  OTP_EXPIRED,
  OTP_INVALID_COOKIE,
  OTP_INVALID_FORMAT,
  OTP_RESENT_NOT_ALLOWED,
  OTP_TOO_MANY_ATTEMPTS,
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

export const ERR_OTP_ALREADY_RESENT = {
  error: OTP_ALREADY_RESENT,
  message: "The cookie that contains the encrypted OTP has been already resent."
}

export const ERR_OTP_EXPIRED_COOKIE = {
  error: OTP_EXPIRED,
  message: "The OTP is expired."
}

export const ERR_OTP_INVALID_COOKIE = {
  error: OTP_INVALID_COOKIE,
  message: "The cookie that contains the encrypted OTP data is invalid."
}

export const ERR_OTP_INVALID_FORMAT = {
  error: OTP_INVALID_FORMAT,
  message: "The OTP value you sent has an invalid format."
}

export const ERR_OTP_RESENT_NOT_ALLOWED = {
  error: OTP_RESENT_NOT_ALLOWED,
  message: "You are still not allowed to resend the OTP."
}

export const ERR_OTP_TOO_MANY_ATTEMPTS = {
  error: OTP_TOO_MANY_ATTEMPTS,
  message: "Too many attempts, you have to retry again."
}

export const ERR_OTP_TOO_MANY_REQUESTS = {
  error: OTP_TOO_MANY_REQUESTS,
  message: "Too many requests, please slow down."
}

export const ERR_SERVER = {
  error: SERVER,
  message: "The server has some issues, it's not your fault."
}