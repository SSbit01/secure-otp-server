import { Hono } from "hono"

import { bodyLimit } from "hono/body-limit"
import { cors } from "hono/cors"
import { secureHeaders } from "hono/secure-headers"

import { env } from "hono/adapter"

import { ERR_SERVER } from "@/lib/errors"
import errorHandler from "@/custom/error"



/**
 * The main Hono server instance.
 */
const app = new Hono()



/**
 * === MIDDLEWARES ===
 */
app.use(secureHeaders())


app.use(bodyLimit({
  maxSize: 102400  // 100 KiB
})) 


app.use(cors({

  origin(origin, c) {
    return env(c).ORIGIN || "*"
  },

  allowMethods: ["GET", "HEAD", "POST"],

}))



/**
 * Error handler.
 */
app.onError(async(err, c) => {
  await errorHandler(err, c)
  return c.json(ERR_SERVER, 500)
})



export default app