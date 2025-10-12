import { sleep } from "bun"
import { describe, it, expect } from "bun:test"

import { RESEND_BLOCK_SECONDS, ALLOW_ONLY_ONE_RESENDING, MAX_ATTEMPTS, ATTEMPTS_BLOCK, INVALID_BLOCK_SECONDS, MINIMUM_DELAY_BETWEEN_REQUESTS_MS, createOtp } from "@/custom/otp"

import app from "@/index"



const INVALID_BLOCK_MS = INVALID_BLOCK_SECONDS * 1000

const ATTEMPTS_WITHOUT_BLOCK = MAX_ATTEMPTS - ATTEMPTS_BLOCK



function getCookieFromResponse(res: Response) {

  const arr = res.headers.getSetCookie()

  let result = []

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
  
  const dateNow = Date.now()

  if (RESEND_BLOCK_SECONDS) {
    expect(data.resendBlockDate).toBeGreaterThan(dateNow)
  }
  expect(data.expires).toBeGreaterThan(dateNow)

  return getCookieFromResponse(res)

}



describe("OTP 1", () => {

  let cookie: string


  it("Generate OTP without `Content-Type` and body", async() => {

    const res = await app.request("/api/otp/create", {
      method: "POST"
    })

    const data = await res.json()
    
    expect(data.error).toBe("CREDENTIAL:INVALID")

  })


  it("Generate OTP without body", async() => {

    const res = await app.request("/api/otp/create", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      }
    })

    const data = await res.json()
    
    expect(data.error).toBe("GENERIC")

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
    
    expect(data.error).toBe("CREDENTIAL:INVALID")

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
    
    expect(data.error).toBe("GENERIC")

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
    
    expect(data.error).toBe("CREDENTIAL:INVALID")

  })


  it("Generate OTP", async() => {

    cookie = await fetchOtpcookie()

  })


  it(`Generate OTP with the same credentials`, async() => {

    await sleep(MINIMUM_DELAY_BETWEEN_REQUESTS_MS)

    const res = await app.request("/api/otp/create", {
      method: "POST",
      body: "",
      headers: {
        "Content-Type": "application/json",
        cookie
      }
    })

    const data = await res.json()
    
    expect(data.error).toBe("GENERIC")

  })



  it("Resend OTP without sending the cookie", async() => {

    const res = await app.request("/api/otp/resend", {
      method: "POST"
    })

    const data = await res.json()
    
    expect(data.error).toBe("OTP:INVALID_COOKIE")

  })


  it("Resend OTP without a key", async() => {

    const res = await app.request("/api/otp/resend", {
      method: "POST",
      headers: {
        cookie: cookie.split("; ")[0]
      }
    })

    const data = await res.json()
    
    expect(data.error).toBe("OTP:INVALID_COOKIE")

  })


  it("Resend OTP without the encrypted data", async() => {

    const res = await app.request("/api/otp/resend", {
      method: "POST",
      headers: {
        cookie: cookie.split("; ")[1]
      }
    })

    const data = await res.json()
    
    expect(data.error).toBe("OTP:INVALID_COOKIE")

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
    
    expect(data.error).toBe("OTP:INVALID_COOKIE")

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
    
    expect(data.error).toBe("OTP:INVALID_COOKIE")

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
    
    expect(data.error).toBe("OTP:RESENT_NOT_ALLOWED")

  })


  it("Generate OTP again (because the server deletes the key if it detects misuse)", async() => {

    cookie = await fetchOtpcookie()

  })


  if (RESEND_BLOCK_SECONDS < 5) {

    it(`Wait the resend block seconds (${RESEND_BLOCK_SECONDS}s) and try to resend OTP again`, async() => {

      await sleep((RESEND_BLOCK_SECONDS * 1000) || MINIMUM_DELAY_BETWEEN_REQUESTS_MS)

      const res = await app.request("/api/otp/resend", {
        method: "POST",
        headers: {
          cookie
        }
      })

      cookie = getCookieFromResponse(res)

      const data = await res.json()
      const dateNow = Date.now()

      if (ALLOW_ONLY_ONE_RESENDING) {
        expect(data).not.toHaveProperty("resendBlockDate")
      } else {
        expect(data.resendBlockDate).toBeGreaterThan(dateNow)
      }
      expect(data.expires).toBeGreaterThan(dateNow)

    })


    if (ALLOW_ONLY_ONE_RESENDING) {

      it("Resend OTP again (it is expected to not work)", async() => {

        await sleep(MINIMUM_DELAY_BETWEEN_REQUESTS_MS)

        const res = await app.request("/api/otp/resend", {
          method: "POST",
          headers: {
            cookie
          }
        })

        const data = await res.json()
        
        expect(data.error).toBe("OTP:ALREADY_RESENT")

      })

    }

  } else {
    console.warn("'Wait the resend block seconds' tests skipped because they are set to more than 5 seconds.")
  }


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
    
    expect(data.error).toBe("OTP:INVALID_FORMAT")

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
    
    expect(data.error).toBe("OTP:INVALID_COOKIE")

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
    
    expect(data.error).toBe("OTP:INVALID_COOKIE")

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
    
    expect(data.error).toBe("OTP:INVALID_COOKIE")

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
    
    expect(data.error).toBe("OTP:INVALID_COOKIE")

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
    
    expect(data.error).toBe("OTP:INVALID_COOKIE")

  })

})



describe("OTP 3", async() => {

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
    
    expect(data.error).toBe("OTP:INVALID_FORMAT")

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
    
    expect(data.error).toBe("OTP:INVALID_FORMAT")

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
    
    expect(data.error).toBe("OTP:INVALID_FORMAT")

    return data

  })

})



describe("OTP 4", () => {
  
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
    
    expect(data.error).toBe("OTP:INCORRECT")

    return data

  }


  for (let i = 1; i < ATTEMPTS_WITHOUT_BLOCK; i++) {
    it(`(1) Send an invalid OTP - attempt: ${i}`, sendInvalidOtp)
  }


  it(`(1) Send an invalid OTP - attempt: ${ATTEMPTS_WITHOUT_BLOCK}`, async() => {
    const data = await sendInvalidOtp()
    expect(data.blockedUntil).toBeGreaterThan(Date.now())
  })


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

    expect(data.error).toBe("OTP:BLOCKED")

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
    
    expect(data.error).toBe("OTP:INCORRECT")

    return data

  }


  for (let i = 1; i < ATTEMPTS_WITHOUT_BLOCK; i++) {
    it(`(2) Send an invalid OTP - attempt: ${i}`, sendInvalidOtp)
  }


  it(`(2) Send an invalid OTP - attempt: ${ATTEMPTS_WITHOUT_BLOCK}`, async() => {
    const data = await sendInvalidOtp()
    expect(data.blockedUntil).toBeGreaterThan(Date.now())
  })

  
  let attempts = ATTEMPTS_WITHOUT_BLOCK + 1


  if (INVALID_BLOCK_SECONDS < 5) {

    while (attempts < MAX_ATTEMPTS) {
      it(`Wait and send an invalid OTP - attempt: ${attempts + 1}`, async() => {
        await sleep(INVALID_BLOCK_MS || MINIMUM_DELAY_BETWEEN_REQUESTS_MS)
        const data = await sendInvalidOtp()
        expect(data.blockedUntil).toBeGreaterThan(Date.now())
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
      
      expect(data.error).toBe("OTP:TOO_MANY_ATTEMPTS")

    })

  } else {
    console.warn("'Wait and send invalid OTP' tests skipped because they are set to more than 5 seconds.")
  }

})