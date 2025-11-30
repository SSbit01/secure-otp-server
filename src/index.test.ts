import { sleep } from "bun"
import { describe, it, expect } from "bun:test"

import {
  CREDENTIAL_INVALID,
  GENERIC,
  OTP_INCORRECT,
  OTP_INVALID_COOKIE,
  OTP_INVALID_FORMAT,
  OTP_RESENT_NOT_ALLOWED,
  OTP_TOO_MANY_ATTEMPTS,
} from "@/lib/error/names"

import {
  RESEND_BLOCK_SECONDS,
  MAX_ATTEMPTS,
  ATTEMPTS_BLOCK,
  INVALID_BLOCK_SECONDS,
  MINIMUM_DELAY_BETWEEN_REQUESTS_MS as ORIGINAL_MINIMUM_DELAY_BETWEEN_REQUESTS_MS,
  createOtp
} from "@/custom/otp"

import app from "@/index"


/**
 * Prevent TOO MANY REQUESTS error
 */
const MINIMUM_DELAY_BETWEEN_REQUESTS_MS = ORIGINAL_MINIMUM_DELAY_BETWEEN_REQUESTS_MS * 1.5

const INVALID_BLOCK_MS = INVALID_BLOCK_SECONDS * 1000

const ATTEMPTS_WITHOUT_BLOCK = MAX_ATTEMPTS - ATTEMPTS_BLOCK



function getCookieFromResponse(res: Response) {

  const arr = res.headers.getSetCookie()

  const result = []

  for (const cookie of arr) {
    result.push(cookie.split(";")[0])
  }

  return result.join("; ")

}



async function fetchOtpcookie() {

  const res = await app.request("/api/otp/create", {
    method: "POST",
    body: `"${Math.random().toString(36)}"`,
    headers: {
      "Content-Type": "application/json"
    }
  })

  const data = await res.json()
  
  const date = new Date()

  if (RESEND_BLOCK_SECONDS) {
    expect(new Date(data.resendBlock) > date).toBeTrue()
  }
  expect(new Date(data.expires) > date).toBeTrue()

  return getCookieFromResponse(res)

}



describe("OTP 1", () => {

  let cookie: string


  it("Generate OTP without `Content-Type` and body", async() => {

    const res = await app.request("/api/otp/create", {
      method: "POST"
    })

    const data = await res.json()
    
    expect(data.error).toBe(CREDENTIAL_INVALID)

  })


  it("Generate OTP without body", async() => {

    const res = await app.request("/api/otp/create", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      }
    })

    const data = await res.json()
    
    expect(data.error).toBe(GENERIC)

  })


  it("Generate OTP with an invalid `Content-Type`", async() => {

    const res = await app.request("/api/otp/create", {
      method: "POST",
      body: '["test"]',
      headers: {
        "Content-Type": "text/plain"
      }
    })

    const data = await res.json()
    
    expect(data.error).toBe(CREDENTIAL_INVALID)

  })


  it("Generate OTP with an invalid credential type", async() => {

    const res = await app.request("/api/otp/create", {
      method: "POST",
      body: 'test',
      headers: {
        "Content-Type": "application/json"
      }
    })

    const data = await res.json()
    
    expect(data.error).toBe(GENERIC)

  })


  it("Generate OTP with an invalid credential", async() => {

    const res = await app.request("/api/otp/create", {
      method: "POST",
      body: 'false',
      headers: {
        "Content-Type": "application/json"
      }
    })

    const data = await res.json()
    
    expect(data.error).toBe(CREDENTIAL_INVALID)

  })


  it("Generate OTP", async() => {

    cookie = await fetchOtpcookie()

  })



  it("Resend OTP without sending the cookie", async() => {

    const res = await app.request("/api/otp/resend", {
      method: "POST"
    })

    const data = await res.json()
    
    expect(data.error).toBe(OTP_INVALID_COOKIE)

  })


  it("Resend OTP without a key", async() => {

    const res = await app.request("/api/otp/resend", {
      method: "POST",
      headers: {
        cookie: cookie.split("; ")[0]
      }
    })

    const data = await res.json()
    
    expect(data.error).toBe(OTP_INVALID_COOKIE)

  })


  it("Resend OTP without the encrypted data", async() => {

    const res = await app.request("/api/otp/resend", {
      method: "POST",
      headers: {
        cookie: cookie.split("; ")[1]
      }
    })

    const data = await res.json()
    
    expect(data.error).toBe(OTP_INVALID_COOKIE)

  })


  it("Resend OTP with a wrong key", async() => {

    const cookieArray = cookie.split("; ")

    const partToBeReplaced = cookieArray[1].substring(5, 10)

    cookieArray[1] = cookieArray[1].replace(partToBeReplaced, "aaaaa")

    const res = await app.request("/api/otp/resend", {
      method: "POST",
      headers: {
        cookie: cookieArray.join("; ")
      }
    })

    const data = await res.json()
    
    expect(data.error).toBe(OTP_INVALID_COOKIE)

  })


  it("Resend OTP with invalid token", async() => {

    const cookieArray = cookie.split("; ")

    const partToBeReplaced = cookieArray[0].substring(5, 10)

    cookieArray[0] = cookieArray[0].replace(partToBeReplaced, "aaaaa")

    const res = await app.request("/api/otp/resend", {
      method: "POST",
      headers: {
        cookie: cookieArray.join("; ")
      }
    })

    const data = await res.json()
    
    expect(data.error).toBe(OTP_INVALID_COOKIE)

  })

})



describe("OTP 2", () => {

  let cookie: string


  it("Generate OTP again (because the server deletes the key if it detects misuse)", async() => {

    cookie = await fetchOtpcookie()

  })


  it("Resend OTP without waiting", async() => {

    await sleep(MINIMUM_DELAY_BETWEEN_REQUESTS_MS)

    const res = await app.request("/api/otp/resend", {
      method: "POST",
      headers: {
        cookie
      }
    })

    const data = await res.json()
    
    expect(data.error).toBe(OTP_RESENT_NOT_ALLOWED)

  })

})



describe("OTP 3", () => {

  let cookie: string


  it("Generate OTP again (because the server deletes the key if it detects misuse)", async() => {

    cookie = await fetchOtpcookie()

  })


  it("Send invalid OTP format", async() => {

    const res = await app.request("/api/otp/verify", {
      method: "POST",
      body: `otp=${Math.random().toString(36)}`,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        cookie
      }
    })

    const data = await res.json()
    
    expect(data.error).toBe(OTP_INVALID_FORMAT)

  })


  it("Send an OTP without sending the cookie", async() => {

    const res = await app.request("/api/otp/verify", {
      method: "POST",
      body: `otp=${createOtp()}`,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      }
    })

    const data = await res.json()
    
    expect(data.error).toBe(OTP_INVALID_COOKIE)

  })


  it("Send an OTP without a key", async() => {

    const res = await app.request("/api/otp/verify", {
      method: "POST",
      body: `otp=${createOtp()}`,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        cookie: cookie.split("; ")[0]
      }
    })

    const data = await res.json()
    
    expect(data.error).toBe(OTP_INVALID_COOKIE)

  })


  it("Send an OTP without the encrypted data", async() => {

    const res = await app.request("/api/otp/verify", {
      method: "POST",
      body: `otp=${createOtp()}`,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        cookie: cookie.split("; ")[1]
      }
    })

    const data = await res.json()
    
    expect(data.error).toBe(OTP_INVALID_COOKIE)

  })


  it("Send an OTP with a wrong key", async() => {

    const cookieArray = cookie.split("; ")

    const partToBeReplaced = cookieArray[1].substring(5, 10)

    cookieArray[1] = cookieArray[1].replace(partToBeReplaced, "aaaaa")

    const res = await app.request("/api/otp/verify", {
      method: "POST",
      body: `otp=${createOtp()}`,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        cookie: cookieArray.join("; ")
      }
    })

    const data = await res.json()
    
    expect(data.error).toBe(OTP_INVALID_COOKIE)

  })


  it("Send an OTP with invalid data", async() => {

    const cookieArray = cookie.split("; ")

    const partToBeReplaced = cookieArray[0].substring(5, 10)

    cookieArray[0] = cookieArray[0].replace(partToBeReplaced, "aaaaa")

    const res = await app.request("/api/otp/verify", {
      method: "POST",
      body: `otp=${createOtp()}`,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        cookie: cookieArray.join("; ")
      }
    })

    const data = await res.json()
    
    expect(data.error).toBe(OTP_INVALID_COOKIE)

  })

})



describe("OTP 4", async() => {

  let cookie: string


  it("Generate OTP again (because the server deletes the key if it detects misuse)", async() => {

    cookie = await fetchOtpcookie()

  })


  it("Verify with an invalid `Content-Type`", async() => {

    const res = await app.request("/api/otp/verify", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        cookie
      }
    })

    const data = await res.json()
    
    expect(data.error).toBe(OTP_INVALID_FORMAT)

    return data

  })


  it("Verify without body", async() => {

    const res = await app.request("/api/otp/verify", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        cookie
      }
    })

    const data = await res.json()
    
    expect(data.error).toBe(OTP_INVALID_FORMAT)

    return data

  })


  it("Verify with invalid body", async() => {

    const res = await app.request("/api/otp/verify", {
      method: "POST",
      body: `ot=${createOtp()}`,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        cookie
      }
    })

    const data = await res.json()
    
    expect(data.error).toBe(OTP_INVALID_FORMAT)

    return data

  })

})



describe("OTP 5", () => {
  
  let cookie: string


  it("Generate OTP again (because the server deletes the key if it detects misuse)", async() => {

    cookie = await fetchOtpcookie()

  })


  async function sendInvalidOtp() {

    await sleep(MINIMUM_DELAY_BETWEEN_REQUESTS_MS)

    const res = await app.request("/api/otp/verify", {
      method: "POST",
      body: `otp=${createOtp()}`,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        cookie
      }
    })

    cookie = getCookieFromResponse(res)

    const data = await res.json()
    
    expect(data.error).toBe(OTP_INCORRECT)

    return data

  }


  for (let i = 1; i < ATTEMPTS_WITHOUT_BLOCK; i++) {
    it(`(1) Send an invalid OTP - attempt: ${i}`, sendInvalidOtp)
  }


  it(`(1) Send an invalid OTP - attempt: ${ATTEMPTS_WITHOUT_BLOCK}`, async() => {
    const data = await sendInvalidOtp()
    if (INVALID_BLOCK_SECONDS) {
      expect(new Date(data.otpBlock) > new Date()).toBeTrue()
    }
  })


  if (INVALID_BLOCK_SECONDS) {
    it(`(1) Send an invalid OTP - attempt: ${ATTEMPTS_WITHOUT_BLOCK + 1}`, async() => {

      await sleep(MINIMUM_DELAY_BETWEEN_REQUESTS_MS)

      const res = await app.request("/api/otp/verify", {
        method: "POST",
        body: `otp=${createOtp()}`,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          cookie
        }
      })

      const data = await res.json()

      expect(data.error).toBe(OTP_TOO_MANY_ATTEMPTS)

    })
  }

})



describe("OTP 6", () => {

  let cookie: string


  it("Generate OTP again (because the server deletes the key if it detects misuse)", async() => {

    cookie = await fetchOtpcookie()

  })


  async function sendInvalidOtp() {

    await sleep(MINIMUM_DELAY_BETWEEN_REQUESTS_MS)

    const res = await app.request("/api/otp/verify", {
      method: "POST",
      body: `otp=${createOtp()}`,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        cookie
      }
    })

    cookie = getCookieFromResponse(res)

    const data = await res.json()
    
    expect(data.error).toBe(OTP_INCORRECT)

    return data

  }


  for (let i = 1; i < ATTEMPTS_WITHOUT_BLOCK; i++) {
    it(`(2) Send an invalid OTP - attempt: ${i}`, sendInvalidOtp)
  }


  it(`(2) Send an invalid OTP - attempt: ${ATTEMPTS_WITHOUT_BLOCK}`, async() => {
    const data = await sendInvalidOtp()
    if (INVALID_BLOCK_SECONDS) {
      expect(data.blockedUntil).toBeGreaterThan(Date.now())
    }
  })

  
  let attempts = ATTEMPTS_WITHOUT_BLOCK + 1


  if (INVALID_BLOCK_SECONDS < 5) {

    while (attempts < MAX_ATTEMPTS) {
      it(`Wait and send an invalid OTP - attempt: ${attempts}`, async() => {
        await sleep(INVALID_BLOCK_MS || MINIMUM_DELAY_BETWEEN_REQUESTS_MS)
        const data = await sendInvalidOtp()
        if (INVALID_BLOCK_SECONDS) {
          expect(data.blockedUntil).toBeGreaterThan(Date.now())
        }
      })
      attempts++
    }


    it(`Wait and send an invalid OTP (expect too many attempts)`, async() => {

      await sleep(INVALID_BLOCK_MS || MINIMUM_DELAY_BETWEEN_REQUESTS_MS)

      const res = await app.request("/api/otp/verify", {
        method: "POST",
        body: `otp=${createOtp()}`,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          cookie
        }
      })

      cookie = getCookieFromResponse(res)

      const data = await res.json()
      
      expect(data.error).toBe(OTP_TOO_MANY_ATTEMPTS)

    })

  } else {
    console.warn("'Wait and send invalid OTP' tests skipped because they are set to more than 5 seconds.")
  }

})