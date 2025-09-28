import { sleep } from "bun"
import { it, expect } from "bun:test"

import { resendBlockSeconds, maxAttempts, otpInvalidBlockSeconds, createOtp } from "@/lib/custom/otp"

import app from "@/index"


let cookies: string | null


it("Generate OTP", async() => {

  const res = await app.request("/api/otp/create", {
    method: "POST",
    body: `credential=${Math.random().toString(36)}`,
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    }
  })

  cookies = res.headers.get("set-cookie")

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


if (resendBlockSeconds < 5) {

  it(`Waiting the resend block seconds (${resendBlockSeconds}s) and try to resend OTP again`, async() => {

    await sleep(resendBlockSeconds * 1000)

    const res = await app.request("/api/otp/resend", {
      method: "POST",
      headers: {
        cookie: cookies || ""
      }
    })

    cookies = res.headers.get("set-cookie")

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

  cookies = res.headers.get("set-cookie")

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

  cookies = res.headers.get("set-cookie")

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

  cookies = res.headers.get("set-cookie")

  const data = await res.json()
  
  expect(data.error).toBe("OTP:INCORRECT")

  return data

}


for (let i = 1; i < maxAttempts - 2; i++) {
  it(`Send an invalid OTP - attempt: ${i}`, sendInvalidOtp)
}


it(`Send an invalid OTP - attempt: ${maxAttempts - 2}`, async() => {
  const data = await sendInvalidOtp()
  expect(data.blockedUntil).toBeGreaterThan(Date.now())
})


it(`Send an invalid OTP - attempt: ${maxAttempts - 1}`, async() => {

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


if (otpInvalidBlockSeconds < 5) {

  it("Wait and send an invalid OTP", async() => {
    await sleep(otpInvalidBlockSeconds * 1050)
    const data = await sendInvalidOtp()
    expect(data.blockedUntil).toBeGreaterThan(Date.now())
  })

} else {
  console.log("'Wait and send invalid OTP' tests skipped because they are set to more than 5 seconds.")
}
