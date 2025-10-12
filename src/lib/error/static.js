import {
  BODY_TOO_LARGE,
  CREDENTIAL_INVALID,
  OTP_BLOCKED,
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

export const ERR_OTP_BLOCKED = {
  error: OTP_BLOCKED,
  message: "Incorrect use of the systems, token invalidated."
}

export const ERR_OTP_EXPIRED_COOKIE = {
  error: OTP_EXPIRED,
  message: "The OTP is expired."
}

export const ERR_OTP_INVALID_COOKIE = {
  error: OTP_INVALID_COOKIE,
  message: "The OTP cookies are invalid."
}

export const ERR_OTP_INVALID_FORMAT = {
  error: OTP_INVALID_FORMAT,
  message: "Incorrect use of the systems, token invalidated."
}

export const ERR_OTP_RESENT_NOT_ALLOWED = {
  error: OTP_RESENT_NOT_ALLOWED,
  message: "Incorrect use of the systems, token invalidated."
}

export const ERR_OTP_TOO_MANY_ATTEMPTS = {
  error: OTP_TOO_MANY_ATTEMPTS,
  message: "Too many attempts, you have to retry again."
}

export const ERR_OTP_TOO_MANY_REQUESTS = {
  error: OTP_TOO_MANY_REQUESTS,
  message: "Incorrect use of the systems, token invalidated."
}

export const ERR_SERVER = {
  error: SERVER,
  message: "The server has some issues, it's not your fault."
}