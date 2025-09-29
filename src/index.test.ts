import { sleep } from "bun"
import { describe, it, expect } from "bun:test"

import { RESEND_BLOCK_SECONDS, MAX_ATTEMPTS, INALID_BLOCK_SECONDS, createOtp } from "@/custom/otp"

import app from "@/index"



function getCookies(res: Response) {

  const arr = res.headers.getSetCookie()

  let result = []

  for (const cookie of arr) {
    result.push(cookie.split(";")[0])
  }

  return result.join("; ")

}



describe("Tests with the same cookie", () => {

  let cookies: string | null


  it("Generate OTP", async() => {

    const res = await app.request("/api/otp/create", {
      method: "POST",
      body: `"${Math.random().toString(36)}"`,
      headers: {
        "Content-Type": "application/json"
      }
    })

    cookies = getCookies(res)

    const data = await res.json()
    
    const dateNow = Date.now()

    expect(data.resendBlockDate).toBeGreaterThan(dateNow)
    expect(data.expires).toBeGreaterThan(dateNow)

  })



  it("Resend OTP without sending the cookie", async() => {

    const res = await app.request("/api/otp/resend", {
      method: "POST"
    })

    const data = await res.json()
    
    expect(data.error).toBe("OTP:INVALID_COOKIE")

  })


  it("Resend OTP without waiting", async() => {

    const res = await app.request("/api/otp/resend", {
      method: "POST",
      headers: {
        cookie: cookies || ""
      }
    })

    const data = await res.json()
    
    expect(data.error).toBe("OTP:RESENT_NOT_ALLOWED")

  })


  if (RESEND_BLOCK_SECONDS < 5) {

    it(`Waiting the resend block seconds (${RESEND_BLOCK_SECONDS}s) and try to resend OTP again`, async() => {

      await sleep(RESEND_BLOCK_SECONDS * 1000)

      const res = await app.request("/api/otp/resend", {
        method: "POST",
        headers: {
          cookie: cookies || ""
        }
      })

      cookies = getCookies(res)

      const data = await res.json()
      const dateNow = Date.now()

      expect(data).not.toHaveProperty("resendBlockDate")
      expect(data.expires).toBeGreaterThan(dateNow)

    })


    it("Resend OTP again (it is expected to not work)", async() => {

      const res = await app.request("/api/otp/resend", {
        method: "POST",
        headers: {
          cookie: cookies || ""
        }
      })

      const data = await res.json()
      
      expect(data.error).toBe("OTP:ALREADY_RESENT")

    })

  } else {
    console.log("'Waiting the resend block seconds' test skipped because it is set to more than 5 seconds.")
  }


  it("Send invalid OTP format", async() => {

    const res = await app.request("/api/otp/verify", {
      method: "POST",
      body: `otp=${Math.random().toString(36)}`,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        cookie: cookies || ""
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


  async function sendInvalidOtp() {

    const res = await app.request("/api/otp/verify", {
      method: "POST",
      body: `otp=${createOtp()}`,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        cookie: cookies || ""
      }
    })

    cookies = getCookies(res)

    const data = await res.json()
    
    expect(data.error).toBe("OTP:INCORRECT")

    return data

  }


  for (let i = 1; i < MAX_ATTEMPTS - 2; i++) {
    it(`Send an invalid OTP - attempt: ${i}`, sendInvalidOtp)
  }


  it(`Send an invalid OTP - attempt: ${MAX_ATTEMPTS - 2}`, async() => {
    const data = await sendInvalidOtp()
    expect(data.blockedUntil).toBeGreaterThan(Date.now())
  })


  it(`Send an invalid OTP - attempt: ${MAX_ATTEMPTS - 1}`, async() => {

    const res = await app.request("/api/otp/verify", {
      method: "POST",
      body: `otp=${createOtp()}`,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        cookie: cookies || ""
      }
    })

    const data = await res.json()

    expect(data.error).toBe("OTP:BLOCKED")

  })


  if (INALID_BLOCK_SECONDS < 5) {

    it("Wait and send an invalid OTP", async() => {
      await sleep(INALID_BLOCK_SECONDS * 1000)
      const data = await sendInvalidOtp()
      expect(data.blockedUntil).toBeGreaterThan(Date.now())
    })

  } else {
    console.log("'Wait and send invalid OTP' tests skipped because they are set to more than 5 seconds.")
  }

})
